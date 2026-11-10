//! Step 5: union object set over the testkit fixtures and hand-written files
//! (hybrid xref, `/Extends`, indirect `/Length`, limits).

mod common;

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::{fixture, fixtures, object_offsets};
use quelda_core::error::IssueCode;
use quelda_core::limits::{Budget, Limits};
use quelda_core::parser::document::{Location, MismatchKind};
use quelda_core::parser::xref::XrefKind;
use quelda_core::parser::{Document, ObjRef, PdfObject, StreamLength};

fn parse(pdf: &[u8]) -> Document {
    parse_with(pdf, &Limits::default())
}

fn parse_with(pdf: &[u8], limits: &Limits) -> Document {
    Document::parse(pdf, limits, &mut Budget::new(limits))
}

/// Parses on another thread; fails if it takes longer than `secs`.
fn parse_within(pdf: &'static [u8], secs: u64) -> Document {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(parse(pdf));
    });
    rx.recv_timeout(Duration::from_secs(secs))
        .expect("Document::parse did not finish in time")
}

fn codes(d: &Document) -> Vec<&'static str> {
    d.issues.iter().map(|i| i.code.as_str()).collect()
}

fn members(d: &Document) -> Vec<u32> {
    let mut v: Vec<u32> = d
        .objects
        .iter()
        .filter(|e| matches!(e.location, Location::ObjStm { .. }))
        .map(|e| e.id.num)
        .collect();
    v.sort_unstable();
    v
}

fn top_level_offsets(d: &Document) -> Vec<usize> {
    let mut v: Vec<usize> = d
        .objects
        .iter()
        .filter_map(|e| match e.location {
            Location::File { offset } => Some(offset),
            _ => None,
        })
        .collect();
    v.sort_unstable();
    v
}

#[test]
fn benign_object_and_revision_counts() {
    let expect: &[(&str, usize, &[u32])] = &[
        ("benign/minimal.pdf", 1, &[]),
        ("benign/pdf-2.0.pdf", 1, &[]),
        ("benign/multipage-text.pdf", 1, &[]),
        ("benign/content-flate.pdf", 1, &[]),
        ("benign/content-two-filters.pdf", 1, &[]),
        ("benign/image-rgb-flate.pdf", 1, &[]),
        ("benign/xref-stream-objstm.pdf", 1, &[1, 2, 3, 5, 10]),
        ("benign/incremental-update.pdf", 2, &[]),
        ("benign/link-uri.pdf", 1, &[]),
        ("benign/acroform-text-field.pdf", 1, &[]),
        ("benign/a0-large-image.pdf", 1, &[]),
    ];
    assert_eq!(
        expect.len(),
        fixtures()
            .iter()
            .filter(|f| f.path.starts_with("benign/"))
            .count(),
        "every benign fixture is listed"
    );
    for &(path, revisions, objstm_members) in expect {
        let pdf = &fixture(path).bytes;
        let d = parse(pdf);
        assert!(d.issues.is_empty(), "{path}: {:?}", d.issues);
        assert_eq!(top_level_offsets(&d), object_offsets(pdf), "{path}");
        assert_eq!(members(&d), objstm_members, "{path}");
        assert_eq!(d.revisions.len(), revisions, "{path}");
        assert_eq!(d.facts.chain.len(), revisions, "{path}: chain");
        assert!(d.facts.xref_mismatches.is_empty(), "{path}");
        assert!(d.facts.unlisted.is_empty(), "{path}");
        assert!(d.facts.broken_objects.is_empty(), "{path}");
        assert!(!d.facts.prev_loop && !d.facts.startxref_invalid, "{path}");
        assert!(!d.facts.linearized, "{path}");
        assert!(d.objects.iter().all(|e| !e.listed_in.is_empty()), "{path}");
        assert!(d.objects.iter().all(|e| e.revision.is_some()), "{path}");
        assert_eq!(d.trailers.len(), revisions, "{path}");
        assert!(d.trailers.iter().all(|t| t.root().is_some()), "{path}");
        let s = &d.structure;
        assert_eq!(s.header.as_ref().map(|h| h.offset), Some(0), "{path}");
        assert_eq!(s.eofs.len(), revisions, "{path}");
        assert_eq!(s.startxrefs.len(), revisions, "{path}");
        assert_eq!(s.trailing_bytes, Some(1), "{path}");
    }
}

#[test]
fn xref_stream_members_are_listed() {
    let d = parse(&fixture("benign/xref-stream-objstm.pdf").bytes);
    let r = &d.revisions[0];
    assert!(matches!(d.sections[r.section].kind, XrefKind::Stream(_)));
    for e in d.objects.iter().filter(|e| !e.is_top_level()) {
        assert_eq!(e.listed_in, vec![r.section], "{}", e.id);
        assert_eq!(e.revision, Some(0));
    }
    let info = d.trailers[0].info().and_then(PdfObject::as_reference);
    assert_eq!(info, Some(ObjRef::new(10, 0)));
    assert!(d.definitions(ObjRef::new(10, 0)).next().is_some());
}

#[test]
fn incremental_update_keeps_old_and_new() {
    let d = parse(&fixture("benign/incremental-update.pdf").bytes);
    let defs: Vec<_> = d.definitions(ObjRef::new(4, 0)).collect();
    assert_eq!(defs.len(), 2);
    let revs: Vec<_> = defs.iter().map(|e| e.revision).collect();
    assert_eq!(revs, vec![Some(0), Some(1)]);
    let g = &d.facts.duplicates;
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].id, ObjRef::new(4, 0));
    assert!(!g[0].identical);
    assert!(!g[0].conflict_in_revision);
    // Revision 2's xref lists only object 4; `/Prev` reaches revision 1.
    assert_eq!(d.facts.chain.len(), 2);
    assert_eq!(d.facts.chain[0], d.revisions[1].section);
}

#[test]
fn wrong_offsets_found_by_linear_scan() {
    let pdf = &fixture("malformed/xref-wrong-offsets.pdf").bytes;
    let d = parse(pdf);
    assert!(d.issues.is_empty(), "{:?}", d.issues);
    assert_eq!(top_level_offsets(&d), object_offsets(pdf));
    // All 5 in-use entries miss.
    assert_eq!(d.facts.xref_mismatches.len(), 5);
    assert!(
        d.facts
            .xref_mismatches
            .iter()
            .all(|m| m.kind == MismatchKind::NoObject)
    );
    assert!(d.objects.iter().all(|e| e.listed_in.is_empty() && e.linear));
}

#[test]
fn no_xref_found_by_linear_scan() {
    let pdf = &fixture("malformed/no-xref.pdf").bytes;
    let d = parse(pdf);
    assert!(d.issues.is_empty(), "{:?}", d.issues);
    assert_eq!(top_level_offsets(&d), object_offsets(pdf));
    assert_eq!(d.objects.len(), 5);
    assert!(d.sections.is_empty() && d.revisions.is_empty());
    assert!(d.facts.startxref_invalid);
    assert_eq!(d.facts.unlisted.len(), 5);
    assert!(d.objects.iter().all(|e| e.revision.is_none()));
}

#[test]
fn prev_loop_terminates() {
    let d = parse_within(&fixture("malformed/prev-loop.pdf").bytes, 10);
    assert!(d.facts.prev_loop);
    assert!(d.issues.is_empty(), "{:?}", d.issues);
    // Both sections are still loaded (the first one from the file scan).
    assert_eq!(d.revisions.len(), 2);
    assert_eq!(d.definitions(ObjRef::new(10, 0)).count(), 1);
}

#[test]
fn truncated_does_not_panic() {
    let pdf = &fixture("malformed/truncated.pdf").bytes;
    let d = parse(pdf);
    assert!(d.issues.is_empty(), "{:?}", d.issues);
    assert!(d.structure.eofs.is_empty());
    assert_eq!(d.structure.trailing_bytes, None);
    assert!(d.facts.startxref_invalid);
    assert!(d.sections.is_empty());
    // Every complete object is there; the cut one is a broken-object fact
    // (or parsed without `endobj`).
    let found = top_level_offsets(&d).len() + d.facts.broken_objects.len();
    assert_eq!(found, object_offsets(pdf).len());
}

#[test]
fn deep_nesting_is_a_limit_issue() {
    let d = parse(&fixture("malformed/deep-nesting.pdf").bytes);
    // Once, although both the scan and the xref point at the object.
    assert_eq!(codes(&d), vec!["LIMIT.NESTING_DEPTH"]);
}

#[test]
fn objstm_unknown_filter_is_an_engine_issue() {
    let d = parse(&fixture("malformed/objstm-unknown-filter.pdf").bytes);
    assert_eq!(codes(&d), vec!["ENGINE.UNDECODABLE"]);
    assert!(members(&d).is_empty());
}

/// Engine issues only where the manifest expects `ERROR` (decoding content
/// streams, e.g. bombs, is Step 6: parsing them here raises nothing).
#[test]
fn issues_only_where_expected() {
    for f in fixtures() {
        if f.kind.key() == "filetype" {
            continue;
        }
        let d = parse(&f.bytes);
        if f.engine_error.is_none() {
            assert!(d.issues.is_empty(), "{}: {:?}", f.path, d.issues);
        }
    }
}

#[test]
fn every_fixture_parses() {
    for f in fixtures() {
        let d = parse(&f.bytes);
        // Every `N G obj` at a line start is in the union set or recorded broken.
        let found: Vec<usize> = top_level_offsets(&d);
        for off in object_offsets(&f.bytes) {
            let broken = d.facts.broken_objects.iter().any(|b| b.offset == off);
            assert!(
                found.binary_search(&off).is_ok() || broken || !d.issues.is_empty(),
                "{}: object at {off} missing",
                f.path
            );
        }
    }
}

#[test]
fn evasion_variants_reach_the_union_set() {
    let mut seen = (0, 0);
    for f in fixtures().iter().filter(|f| f.kind.key() == "bad") {
        match f.variant.as_str() {
            "in-objstm" => {
                seen.0 += 1;
                let d = parse(&f.bytes);
                assert!(d.issues.is_empty(), "{}: {:?}", f.path, d.issues);
                let m = members(&d);
                assert!(!m.is_empty(), "{}", f.path);
                for e in d.objects.iter().filter(|e| !e.is_top_level()) {
                    assert!(!e.listed_in.is_empty(), "{} {}", f.path, e.id);
                }
                // The payload object is only in the ObjStm.
                assert!(
                    m.iter()
                        .all(|&n| d.definitions(ObjRef::new(n, 0)).count() == 1),
                    "{}",
                    f.path
                );
            }
            "old-revision" => {
                seen.1 += 1;
                let d = parse(&f.bytes);
                assert!(d.issues.is_empty(), "{}: {:?}", f.path, d.issues);
                assert!(d.revisions.len() >= 2, "{}", f.path);
                assert_eq!(
                    top_level_offsets(&d),
                    object_offsets(&f.bytes),
                    "{}",
                    f.path
                );
                // The overwritten (payload) definition is still there, in revision 0.
                let old = d
                    .facts
                    .duplicates
                    .iter()
                    .filter(|g| !g.identical)
                    .flat_map(|g| g.entries.iter())
                    .any(|&i| d.objects[i].revision == Some(0));
                let crypt_or_struct = f.path.contains("CRYPT.") || f.path.contains("STRUCT.");
                assert!(old || crypt_or_struct, "{}", f.path);
            }
            _ => {}
        }
    }
    assert!(seen.0 > 10 && seen.1 > 10, "{seen:?}");
}

#[test]
fn conflicting_objects_facts() {
    let conflict = |p: &str| {
        let d = parse(&fixture(p).bytes);
        let g: Vec<_> = d
            .facts
            .duplicates
            .iter()
            .map(|g| (g.id.num, g.identical, g.conflict_in_revision))
            .collect();
        g
    };
    let base = "rules/STRUCT.CONFLICTING_OBJECTS";
    assert_eq!(
        conflict(&format!("{base}/bad/duplicate-in-body.pdf")),
        vec![(5, false, true)]
    );
    assert_eq!(
        conflict(&format!("{base}/good/identical-duplicate.pdf")),
        vec![(5, true, false)]
    );
    assert_eq!(
        conflict(&format!("{base}/good/incremental-overwrite.pdf")),
        vec![(5, false, false)]
    );
}

#[test]
fn xref_mismatch_facts() {
    let base = "rules/STRUCT.XREF_MISMATCH";
    for good in ["xref-stream", "xref-table"] {
        let d = parse(&fixture(&format!("{base}/good/{good}.pdf")).bytes);
        assert!(d.facts.xref_mismatches.is_empty(), "{good}");
        assert!(d.facts.unlisted.is_empty(), "{good}");
        assert!(!d.facts.startxref_invalid && !d.facts.prev_loop, "{good}");
    }
    let d = parse(&fixture(&format!("{base}/bad/wrong-offsets.pdf")).bytes);
    assert!(!d.facts.xref_mismatches.is_empty());
    let d = parse(&fixture(&format!("{base}/bad/missing-entry.pdf")).bytes);
    assert!(d.facts.xref_mismatches.is_empty());
    let unlisted: Vec<_> = d.facts.unlisted.iter().map(|&i| d.objects[i].id).collect();
    assert_eq!(unlisted, vec![ObjRef::new(20, 0)]);
}

#[test]
fn encrypt_in_any_trailer() {
    let has_encrypt = |p: &str| {
        let d = parse(&fixture(p).bytes);
        d.trailers.iter().any(|t| t.encrypt().is_some())
    };
    let base = "rules/CRYPT.ENCRYPTED";
    for bad in ["plain", "name-encoded", "xref-stream", "old-revision"] {
        assert!(has_encrypt(&format!("{base}/bad/{bad}.pdf")), "{bad}");
    }
    for good in ["encrypt-in-string", "encrypt-key-outside-trailer"] {
        assert!(!has_encrypt(&format!("{base}/good/{good}.pdf")), "{good}");
    }
    let d = parse(&fixture(&format!("{base}/bad/old-revision.pdf")).bytes);
    assert!(
        d.revision_trailer(0)
            .is_some_and(|t| t.contains_key("Encrypt"))
    );
    assert!(
        d.revision_trailer(1)
            .is_some_and(|t| !t.contains_key("Encrypt"))
    );
}

#[test]
fn trailing_and_eof_facts() {
    let d = parse(&fixture("rules/STRUCT.TRAILING_DATA/bad/binary-2k.pdf").bytes);
    assert_eq!(d.structure.trailing_bytes, Some(2001));
    let d = parse(&fixture("rules/STRUCT.MISSING_EOF/bad/omitted.pdf").bytes);
    assert!(d.structure.eofs.is_empty());
    let d = parse(&fixture("rules/STRUCT.MULTIPLE_HEADERS/bad/second-header.pdf").bytes);
    assert_eq!(d.structure.header_lines.len(), 2);
}

// ---- hand-written files -------------------------------------------------

/// Writes a file with objects at known offsets; `{N}` in later parts is
/// replaced with the offset of the object (or marker) named `N`.
struct Writer {
    out: Vec<u8>,
    marks: Vec<(String, usize)>,
}

impl Writer {
    fn new() -> Self {
        Writer {
            out: b"%PDF-1.7\n".to_vec(),
            marks: Vec::new(),
        }
    }

    fn mark(&mut self, name: &str) -> &mut Self {
        self.marks.push((name.to_string(), self.out.len()));
        self
    }

    fn put(&mut self, bytes: &[u8]) -> &mut Self {
        let mut s = bytes.to_vec();
        for (name, off) in &self.marks {
            let key = format!("{{{name}}}");
            while let Some(p) = s.windows(key.len()).position(|w| w == key.as_bytes()) {
                s.splice(p..p + key.len(), off.to_string().bytes());
            }
        }
        self.out.extend(s);
        self
    }

    fn obj(&mut self, name: &str, bytes: &[u8]) -> &mut Self {
        self.mark(name).put(bytes)
    }

    fn row(&self, name: &str) -> String {
        let off = self
            .marks
            .iter()
            .find(|m| m.0 == name)
            .map(|m| m.1)
            .unwrap();
        format!("{off:010} 00000 n \n")
    }
}

fn xref_stream_body(rows: &[(u8, u32, u16)]) -> Vec<u8> {
    let mut data = Vec::new();
    for &(t, f2, f3) in rows {
        data.push(t);
        data.extend(f2.to_be_bytes());
        data.extend(f3.to_be_bytes());
    }
    data
}

#[test]
fn objstm_extends_is_in_union_set() {
    // ObjStm 8 holds object 11; ObjStm 9 holds object 10 and /Extends 8.
    // No xref lists anything: only the scan + /Extends find them.
    let base = b"11 0 << /QueldaInBase true >>";
    let ext = b"10 0 << /QueldaInExtending true >>";
    let mut w = Writer::new();
    w.obj(
        "8",
        format!(
            "8 0 obj\n<< /Type /ObjStm /N 1 /First 5 /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            base.len(),
            String::from_utf8_lossy(base)
        )
        .as_bytes(),
    );
    w.obj(
        "9",
        format!(
            "9 0 obj\n<< /Type /ObjStm /N 1 /First 5 /Extends 8 0 R /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            ext.len(),
            String::from_utf8_lossy(ext)
        )
        .as_bytes(),
    );
    let d = parse(&w.out);
    assert!(d.issues.is_empty(), "{:?}", d.issues);
    assert_eq!(members(&d), vec![10, 11]);
    let e = d.definitions(ObjRef::new(11, 0)).next().unwrap();
    let Location::ObjStm { container, .. } = e.location else {
        panic!()
    };
    assert_eq!(d.objects[container].id, ObjRef::new(8, 0));
}

#[test]
fn extends_target_without_objstm_type_is_expanded() {
    // Object 8 has no /Type: it is only an object stream because 9 extends it.
    let base = b"11 0 << /QueldaInBase true >>";
    let mut w = Writer::new();
    w.put(
        format!(
            "8 0 obj\n<< /N 1 /First 5 /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            base.len(),
            String::from_utf8_lossy(base)
        )
        .as_bytes(),
    );
    w.put(b"9 0 obj\n<< /Type /ObjStm /N 0 /First 0 /Extends 8 0 R /Length 0 >>\nstream\n\nendstream\nendobj\n");
    let d = parse(&w.out);
    assert_eq!(members(&d), vec![11]);
}

#[test]
fn hybrid_xref_is_one_revision() {
    // Table lists 1 (catalog) and 3 (ObjStm); /XRefStm stream lists 2 (in ObjStm 3).
    let mut w = Writer::new();
    w.obj("1", b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    let members = b"2 0 << /Type /Pages /Kids [] /Count 0 >>";
    w.obj(
        "3",
        format!(
            "3 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            members.len(),
            String::from_utf8_lossy(members)
        )
        .as_bytes(),
    );
    let rows = xref_stream_body(&[(2, 3, 0)]);
    w.mark("4");
    w.put(
        format!(
            "4 0 obj\n<< /Type /XRef /Size 5 /W [1 4 2] /Index [2 1] /Length {} >>\nstream\n",
            rows.len()
        )
        .as_bytes(),
    );
    w.put(&rows).put(b"\nendstream\nendobj\n");
    let table = format!(
        "xref\n0 2\n0000000000 65535 f \n{}3 1\n{}",
        w.row("1"),
        w.row("3")
    );
    w.mark("xref").put(table.as_bytes());
    w.put(b"trailer\n<< /Size 5 /Root 1 0 R /XRefStm {4} >>\nstartxref\n{xref}\n%%EOF\n");
    let d = parse(&w.out);
    assert!(d.issues.is_empty(), "{:?}", d.issues);
    assert_eq!(d.sections.len(), 2);
    assert_eq!(d.revisions.len(), 1);
    let r = &d.revisions[0];
    assert_eq!(d.sections[r.section].kind, XrefKind::Table);
    assert_eq!(r.hybrid.len(), 1);
    assert!(
        d.facts.xref_mismatches.is_empty(),
        "{:?}",
        d.facts.xref_mismatches
    );
    // Object 4 (the xref stream) is in no xref: that is how hybrid files look.
    let unlisted: Vec<_> = d
        .facts
        .unlisted
        .iter()
        .map(|&i| d.objects[i].id.num)
        .collect();
    assert_eq!(unlisted, vec![4]);
    let pages = d.definitions(ObjRef::new(2, 0)).next().unwrap();
    assert_eq!(pages.listed_in, r.hybrid);
}

#[test]
fn compressed_entry_mismatches() {
    let mut w = Writer::new();
    let members = b"2 0 (x)";
    w.obj(
        "3",
        format!(
            "3 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            members.len(),
            String::from_utf8_lossy(members)
        )
        .as_bytes(),
    );
    // 2 → (3, 0) ok; 5 → (3, 0) wrong member; 6 → (3, 7) wrong member; 7 → (99, 0) no ObjStm.
    let rows = xref_stream_body(&[(2, 3, 0), (2, 3, 0), (2, 3, 7), (2, 99, 0)]);
    w.mark("x");
    w.put(
        format!(
            "4 0 obj\n<< /Type /XRef /Size 8 /W [1 4 2] /Index [2 1 5 3] /Length {} >>\nstream\n",
            rows.len()
        )
        .as_bytes(),
    );
    w.put(&rows)
        .put(b"\nendstream\nendobj\nstartxref\n{x}\n%%EOF\n");
    let d = parse(&w.out);
    let m: Vec<_> = d
        .facts
        .xref_mismatches
        .iter()
        .map(|m| (m.num, m.kind))
        .collect();
    assert_eq!(
        m,
        vec![
            (5, MismatchKind::WrongMember),
            (6, MismatchKind::WrongMember),
            (7, MismatchKind::NoObjStm)
        ]
    );
}

#[test]
fn table_entry_mismatches() {
    let mut w = Writer::new();
    w.obj("1", b"1 0 obj\n(a)\nendobj\n");
    w.obj("2", b"2 1 obj\n(b)\nendobj\n");
    let table = format!(
        "xref\n1 4\n{}{}{}9999999999 00000 n \n",
        w.row("1"),
        w.row("1"),
        w.row("2"),
    );
    w.mark("xref").put(table.as_bytes());
    w.put(b"trailer\n<< /Size 5 >>\nstartxref\n{xref}\n%%EOF\n");
    let d = parse(&w.out);
    let m: Vec<_> = d
        .facts
        .xref_mismatches
        .iter()
        .map(|m| (m.num, m.kind))
        .collect();
    assert_eq!(
        m,
        vec![
            (2, MismatchKind::WrongId(ObjRef::new(1, 0))),
            (3, MismatchKind::WrongId(ObjRef::new(2, 1))),
            (4, MismatchKind::OutOfRange),
        ]
    );
    // Numbers 1 and 2 are listed (by wrong rows): neither is unlisted.
    assert!(d.facts.unlisted.is_empty());
}

#[test]
fn object_hidden_from_pattern_search_found_through_xref() {
    let mut w = Writer::new();
    w.obj(
        "1",
        b"1 0 % comment\nobj\n<< /QueldaHidden true >>\nendobj\n",
    );
    let table = format!("xref\n1 1\n{}", w.row("1"));
    w.mark("xref").put(table.as_bytes());
    w.put(b"trailer\n<< /Size 2 >>\nstartxref\n{xref}\n%%EOF\n");
    let d = parse(&w.out);
    let e = d.definitions(ObjRef::new(1, 0)).next().unwrap();
    assert!(!e.linear);
    assert_eq!(e.listed_in.len(), 1);
    assert!(d.facts.xref_mismatches.is_empty());
}

#[test]
fn indirect_length_is_resolved() {
    // The data contains `endstream`: scanning cuts it short, /Length 2 0 R does not.
    let data = b"BT (endstream) Tj ET";
    let mut w = Writer::new();
    w.put(b"1 0 obj\n<< /Length 2 0 R >>\nstream\n");
    w.put(data).put(b"\nendstream\nendobj\n");
    w.put(format!("2 0 obj\n{}\nendobj\n", data.len()).as_bytes());
    let d = parse(&w.out);
    let s = d
        .definitions(ObjRef::new(1, 0))
        .next()
        .and_then(|e| e.object.as_stream())
        .unwrap();
    assert_eq!(s.length, StreamLength::ResolvedIndirect(ObjRef::new(2, 0)));
    assert_eq!(&w.out[s.data.clone()], data);
    assert!(d.facts.ambiguous_lengths.is_empty());
}

#[test]
fn ambiguous_indirect_length_uses_longest() {
    let data = b"AAAA\nendstream\nBBBB";
    let mut w = Writer::new();
    w.put(b"1 0 obj\n<< /Length 2 0 R >>\nstream\n");
    w.put(data).put(b"\nendstream\nendobj\n");
    w.put(b"2 0 obj\n4\nendobj\n");
    w.put(format!("2 0 obj\n{}\nendobj\n", data.len()).as_bytes());
    let d = parse(&w.out);
    let i = d.definitions(ObjRef::new(1, 0)).count();
    assert_eq!(i, 1);
    let e = d.definitions(ObjRef::new(1, 0)).next().unwrap();
    let s = e.object.as_stream().unwrap();
    assert_eq!(&w.out[s.data.clone()], data);
    assert_eq!(d.facts.ambiguous_lengths.len(), 1);
}

#[test]
fn unresolvable_length_keeps_scanned_range() {
    let mut w = Writer::new();
    w.put(b"1 0 obj\n<< /Length 7 0 R >>\nstream\nabc\nendstream\nendobj\n");
    let d = parse(&w.out);
    let s = d.objects[0].object.as_stream().unwrap();
    assert_eq!(s.length, StreamLength::Indirect(ObjRef::new(7, 0)));
    assert_eq!(&w.out[s.data.clone()], b"abc");
}

#[test]
fn linearized_flag() {
    let mut w = Writer::new();
    w.put(b"1 0 obj\n<< /Linearized 1 /L 100 >>\nendobj\n2 0 obj\n<< >>\nendobj\n");
    assert!(parse(&w.out).facts.linearized);
}

#[test]
fn orphan_trailer_is_kept() {
    let mut w = Writer::new();
    w.put(b"1 0 obj\n<< >>\nendobj\ntrailer\n<< /Encrypt 1 0 R >>\n");
    let d = parse(&w.out);
    assert_eq!(d.trailers.len(), 1);
    assert_eq!(d.trailers[0].section, None);
    assert!(d.trailers[0].encrypt().is_some());
}

#[test]
fn max_objects_limit() {
    let pdf = &fixture("benign/multipage-text.pdf").bytes;
    let limits = Limits {
        max_objects: 3,
        ..Limits::default()
    };
    let d = parse_with(pdf, &limits);
    assert_eq!(d.objects.len(), 3);
    assert_eq!(codes(&d), vec!["LIMIT.OBJECTS"]);
}

#[test]
fn max_revisions_limit() {
    let pdf = &fixture("rules/STRUCT.INCREMENTAL_UPDATE/bad/three-revisions.pdf").bytes;
    let d = parse(pdf);
    assert_eq!(d.revisions.len(), 3);
    let limits = Limits {
        max_revisions: 2,
        ..Limits::default()
    };
    let d = parse_with(pdf, &limits);
    assert_eq!(d.revisions.len(), 2);
    assert_eq!(codes(&d), vec!["LIMIT.REVISIONS"]);
}

#[test]
fn objstm_decode_limit() {
    let pdf = &fixture("benign/xref-stream-objstm.pdf").bytes;
    let limits = Limits {
        max_decoded_bytes_total: 10,
        ..Limits::default()
    };
    let d = parse_with(pdf, &limits);
    assert!(codes(&d).contains(&"LIMIT.DECODED_BYTES"), "{:?}", d.issues);
}

#[test]
fn overlapping_candidates_hit_the_work_limit() {
    // 200 000 × `1 0 obj (`: each candidate's string runs to the end of the
    // file. Unbounded, that is ~10^11 bytes of lexing.
    let pdf: &'static [u8] = Box::leak(b"1 0 obj (".repeat(200_000).into_boxed_slice());
    let d = parse_within(pdf, 30);
    assert_eq!(codes(&d), vec![IssueCode::LimitParseWork.as_str()]);
}

#[test]
fn unterminated_streams_hit_the_work_limit() {
    let pdf: &'static [u8] = Box::leak(
        b"1 0 obj <<>> stream\nxx\n"
            .repeat(100_000)
            .into_boxed_slice(),
    );
    let d = parse_within(pdf, 30);
    assert_eq!(codes(&d), vec![IssueCode::LimitParseWork.as_str()]);
}

#[test]
fn every_truncation_parses() {
    for path in [
        "benign/xref-stream-objstm.pdf",
        "benign/incremental-update.pdf",
    ] {
        let pdf = &fixture(path).bytes;
        for cut in 0..pdf.len() {
            let d = parse(&pdf[..cut]);
            // Only object stream damage may stop inspection.
            for i in &d.issues {
                assert!(
                    matches!(
                        i.code,
                        IssueCode::EngineUndecodable | IssueCode::EngineParse
                    ),
                    "{path} cut at {cut}: {i}"
                );
            }
        }
    }
}
