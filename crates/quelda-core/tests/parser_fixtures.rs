//! Parser on the testkit fixtures (generated in memory, no `gen-fixtures` run
//! needed). Object offsets are found by looking for `N G obj` at line starts,
//! independently of the xref (Step 5 parses xrefs).

mod common;

use common::{fixture, fixtures, object_offsets};
use quelda_core::error::IssueCode;
use quelda_core::limits::Limits;
use quelda_core::parser::{
    IndirectObject, PdfObject, StreamLength, parse_indirect_object, parse_object,
};
use quelda_testkit::fixtures::{Fixture, Kind};

/// Header numbers written at `off`, read without the parser.
fn header_numbers(pdf: &[u8], off: usize) -> (u32, u16) {
    let text = String::from_utf8_lossy(&pdf[off..off + 32]).into_owned();
    let mut it = text.split(' ');
    let num = it.next().unwrap().parse().unwrap();
    let generation = it.next().unwrap().parse().unwrap();
    (num, generation)
}

fn parse_all(f: &Fixture) -> Vec<Result<IndirectObject, quelda_core::parser::ParseError>> {
    object_offsets(&f.bytes)
        .into_iter()
        .map(|off| parse_indirect_object(&f.bytes, off, &Limits::default()))
        .collect()
}

/// Every name anywhere in `obj` (keys and values), depth-first.
fn names(obj: &PdfObject, out: &mut Vec<String>) {
    match obj {
        PdfObject::Name(n) => out.push(String::from_utf8_lossy(n.as_bytes()).into_owned()),
        PdfObject::Array(items) => items.iter().for_each(|o| names(o, out)),
        PdfObject::Dict(_) | PdfObject::Stream(_) => {
            for (k, v) in obj.as_dict().unwrap().entries() {
                out.push(String::from_utf8_lossy(k.as_bytes()).into_owned());
                names(v, out);
            }
        }
        _ => {}
    }
}

#[test]
fn benign_objects_parse_at_their_offsets() {
    let benign: Vec<_> = fixtures()
        .iter()
        .filter(|f| f.kind == Kind::Benign)
        .collect();
    assert!(benign.len() >= 10);
    for f in benign {
        let offsets = object_offsets(&f.bytes);
        // ObjStm members (Step 5) are not top-level objects.
        assert!(offsets.len() >= 3, "{}: {} objects", f.path, offsets.len());
        for off in offsets {
            let o = parse_indirect_object(&f.bytes, off, &Limits::default())
                .unwrap_or_else(|e| panic!("{} @{off}: {e}", f.path));
            let (num, generation) = header_numbers(&f.bytes, off);
            assert_eq!((o.id.num, o.id.generation), (num, generation), "{}", f.path);
            assert_eq!(o.offset, off);
            assert!(o.has_endobj, "{} object {}", f.path, o.id);
            assert!(f.bytes[..o.end].ends_with(b"endobj"));
            if let PdfObject::Stream(s) = &o.object {
                // The builder always writes a correct direct /Length.
                assert_eq!(s.length, StreamLength::Declared, "{} {}", f.path, o.id);
                let declared = s.dict.get("Length").and_then(PdfObject::as_int).unwrap();
                assert_eq!(s.data.len() as i64, declared);
            }
        }
    }
}

#[test]
fn minimal_pdf_has_expected_objects() {
    let f = fixture("benign/minimal.pdf");
    let objs: Vec<_> = parse_all(f).into_iter().map(Result::unwrap).collect();
    let ids: Vec<u32> = objs.iter().map(|o| o.id.num).collect();
    assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    let catalog = objs[0].object.as_dict().unwrap();
    assert!(catalog.get("Type").unwrap().is_name("Catalog"));
    assert_eq!(
        catalog.get("Pages").and_then(PdfObject::as_reference),
        Some(quelda_core::parser::ObjRef::new(2, 0))
    );
    let content = objs[3].object.as_stream().unwrap();
    assert!(f.bytes[content.data.clone()].starts_with(b"BT /F1 24 Tf"));
}

#[test]
fn trailer_dict_parses_as_direct_object() {
    let f = fixture("benign/minimal.pdf");
    let at = f.bytes.windows(7).rposition(|w| w == b"trailer").unwrap() + 7;
    let (trailer, _) = parse_object(&f.bytes, at, &Limits::default()).unwrap();
    let d = trailer.as_dict().unwrap();
    assert!(d.contains_key("Root"));
    assert!(d.contains_key("Size"));
}

#[test]
fn deep_nesting_fixture_is_limit_issue() {
    let f = fixture("malformed/deep-nesting.pdf");
    let errors: Vec<_> = parse_all(f).into_iter().filter_map(Result::err).collect();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].issue_code(), IssueCode::LimitNestingDepth);
    assert_eq!(errors[0].issue_code().as_str(), "LIMIT.NESTING_DEPTH");
}

#[test]
fn name_encoded_payloads_are_decoded() {
    for (path, expect) in [
        (
            "rules/ACTIVE.JAVASCRIPT/bad/name-encoded.pdf",
            &["JavaScript", "JS"][..],
        ),
        ("rules/ACTIVE.LAUNCH/bad/name-encoded.pdf", &["Launch"][..]),
    ] {
        let f = fixture(path);
        assert!(f.bytes.contains(&b'#'), "{path} is not name-encoded");
        let mut all = Vec::new();
        for o in parse_all(f) {
            names(&o.unwrap().object, &mut all);
        }
        for want in expect {
            assert!(
                all.iter().any(|n| n == want),
                "{path}: no /{want} in {all:?}"
            );
        }
        assert!(
            !all.iter().any(|n| n.contains('#')),
            "{path}: undecoded name"
        );
    }
}

/// Every object in every fixture: no panic, and objects in well-formed
/// fixtures parse. Fixtures that are deliberately broken may fail.
#[test]
fn every_fixture_object_parses_without_panic() {
    let mut parsed = 0;
    for f in fixtures() {
        let broken = matches!(f.kind, Kind::Malformed | Kind::Filetype)
            || f.path.starts_with("rules/FILETYPE.")
            || f.path.starts_with("rules/STRUCT.");
        for r in parse_all(f) {
            match r {
                Ok(_) => parsed += 1,
                Err(e) => assert!(broken, "{}: {e} at {}", f.path, e.offset),
            }
        }
    }
    assert!(parsed > 1000, "{parsed}");
}
