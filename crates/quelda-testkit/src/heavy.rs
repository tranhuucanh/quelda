//! "Heavy" PDFs for benchmarks (plan Step 16 Phase 0, ADR #28): large or
//! structurally expensive files, deterministic and harmless. They are written
//! on demand by `gen-heavy` (never by `gen-fixtures`, never in `cargo test`
//! at full size): the biggest is 1 GiB.
//!
//! Every kind has a full-size [`catalog`] entry and a tiny one
//! ([`small_catalog`]) that the unit tests and `quelda-core`'s heavy test scan.

use std::fmt::Write as _;
use std::io::{self, Write};

use miniz_oxide::deflate::compress_to_vec_zlib;

use crate::builder::{PdfBuilder, Xref, raw_stream_body};

const MIB: u64 = 1 << 20;

/// Zlib level for heavy files: level 9 is several times slower on 100 MiB+
/// inputs and buys nothing here.
const LEVEL: u8 = 6;

/// One kind of heavy file and its size knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One page drawing one huge DCT image (random bytes): data the engine
    /// never decodes. Written streaming, so 1 GiB needs no 1 GiB buffer.
    Opaque { bytes: u64 },
    /// `pages` pages, each with its own Flate text content stream.
    FlatePages { pages: u32 },
    /// One page whose Flate content stream holds `ops` operators.
    ManyOps { ops: u32 },
    /// `count` small objects in a classic xref table (default `max_objects`
    /// is 1 000 000).
    ManyObjects { count: u32 },
    /// One Flate object stream with `members` objects (≤ 65 535).
    BigObjStm { members: u32 },
    /// `streams` object streams of `members` objects each.
    ManyObjStms { streams: u32, members: u32 },
    /// `revs` incremental updates, each adding `objects` objects and
    /// replacing the page content.
    Revisions { revs: u32, objects: u32 },
    /// `objects` objects nested `depth` levels (arrays and dicts alternating),
    /// plus one array of `len` integers and one dict of `len / 4` keys.
    DeepLong { objects: u32, depth: u32, len: u32 },
    /// One image whose (random) data is full of fake `obj` / `stream` /
    /// `endobj` / `xref` keywords that a linear scan must look at.
    FakeKeywords { bytes: u64 },
    /// `objects` objects whose names use `#xx` and strings use escapes.
    Escapes { objects: u32 },
    /// `streams` pages, each with a Flate content stream decoding to
    /// `decoded` bytes (defaults: 128 MiB per stream, 512 MiB total).
    NearLimit { streams: u32, decoded: u64 },
    /// `functions` Type 4 functions of ~60 KiB (allowlisted operators) and
    /// one page with `annots` link annotations, each with a GoTo action.
    Type4Annots { functions: u32, annots: u32 },
}

/// A named heavy file.
#[derive(Clone, Copy, Debug)]
pub struct Heavy {
    /// File stem (`<name>.pdf`).
    pub name: &'static str,
    pub kind: Kind,
    pub note: &'static str,
}

const fn h(name: &'static str, kind: Kind, note: &'static str) -> Heavy {
    Heavy { name, kind, note }
}

/// The benchmark set (ADR #28). Total on disk ≈ 1.6 GiB.
pub fn catalog() -> Vec<Heavy> {
    vec![
        h(
            "opaque-50m",
            Kind::Opaque { bytes: 50 * MIB },
            "one 50 MiB DCT image",
        ),
        h(
            "opaque-200m",
            Kind::Opaque { bytes: 200 * MIB },
            "one 200 MiB DCT image",
        ),
        h(
            "opaque-1g",
            Kind::Opaque { bytes: 1024 * MIB },
            "one 1 GiB DCT image",
        ),
        h(
            "flate-pages-5000",
            Kind::FlatePages { pages: 5000 },
            "5000 pages, Flate text content each",
        ),
        h(
            "ops-2m",
            Kind::ManyOps { ops: 2_000_000 },
            "one content stream, 2M operators",
        ),
        h(
            "objects-900k",
            Kind::ManyObjects { count: 900_000 },
            "900k small objects, classic xref",
        ),
        h(
            "objstm-big",
            Kind::BigObjStm { members: 65_000 },
            "one ObjStm with 65k members",
        ),
        h(
            "objstm-many",
            Kind::ManyObjStms {
                streams: 5000,
                members: 100,
            },
            "5000 ObjStms x 100 members",
        ),
        h(
            "revisions-1000",
            Kind::Revisions {
                revs: 999,
                objects: 100,
            },
            "1000 revisions (999 updates x 100 objects)",
        ),
        h(
            "deep-long",
            Kind::DeepLong {
                objects: 10_000,
                depth: 120,
                len: 1_000_000,
            },
            "10k objects nested 120 deep + 1M-element array + 250k-key dict",
        ),
        h(
            "fake-keywords-50m",
            Kind::FakeKeywords { bytes: 50 * MIB },
            "50 MiB image full of fake obj/stream/xref keywords",
        ),
        h(
            "escapes-200k",
            Kind::Escapes { objects: 200_000 },
            "200k objects with #xx names and escaped strings",
        ),
        h(
            "near-limit",
            Kind::NearLimit {
                streams: 4,
                decoded: 120 * MIB,
            },
            "4 content streams x 120 MiB decoded (limits 128 / 512 MiB)",
        ),
        h(
            "type4-annots",
            Kind::Type4Annots {
                functions: 50,
                annots: 5000,
            },
            "50 Type 4 functions of ~60 KiB + 5000 link annotations",
        ),
    ]
}

/// Same kinds, tiny sizes (tests).
pub fn small_catalog() -> Vec<Heavy> {
    catalog()
        .into_iter()
        .map(|h| Heavy {
            kind: small(h.kind),
            ..h
        })
        .collect()
}

fn small(kind: Kind) -> Kind {
    match kind {
        Kind::Opaque { .. } => Kind::Opaque { bytes: 64 << 10 },
        Kind::FlatePages { .. } => Kind::FlatePages { pages: 5 },
        Kind::ManyOps { .. } => Kind::ManyOps { ops: 1000 },
        Kind::ManyObjects { .. } => Kind::ManyObjects { count: 200 },
        Kind::BigObjStm { .. } => Kind::BigObjStm { members: 50 },
        Kind::ManyObjStms { .. } => Kind::ManyObjStms {
            streams: 5,
            members: 4,
        },
        Kind::Revisions { .. } => Kind::Revisions {
            revs: 5,
            objects: 3,
        },
        Kind::DeepLong { .. } => Kind::DeepLong {
            objects: 3,
            depth: 20,
            len: 100,
        },
        Kind::FakeKeywords { .. } => Kind::FakeKeywords { bytes: 64 << 10 },
        Kind::Escapes { .. } => Kind::Escapes { objects: 20 },
        Kind::NearLimit { .. } => Kind::NearLimit {
            streams: 2,
            decoded: 64 << 10,
        },
        Kind::Type4Annots { .. } => Kind::Type4Annots {
            functions: 2,
            annots: 10,
        },
    }
}

/// Writes the file for `kind`; returns its length.
pub fn write(kind: Kind, out: &mut impl Write) -> io::Result<u64> {
    if let Kind::Opaque { bytes } = kind {
        return write_image_file(bytes, out, |rng, buf| rng.fill(buf));
    }
    if let Kind::FakeKeywords { bytes } = kind {
        return write_image_file(bytes, out, fill_fake_keywords);
    }
    let pdf = build(kind);
    out.write_all(&pdf)?;
    Ok(pdf.len() as u64)
}

/// Builds the file in memory (every kind but the streamed images).
pub fn build(kind: Kind) -> Vec<u8> {
    match kind {
        Kind::Opaque { .. } | Kind::FakeKeywords { .. } => {
            let mut v = Vec::new();
            // Writing to a Vec cannot fail.
            let _ = write(kind, &mut v);
            v
        }
        Kind::FlatePages { pages } => flate_pages(pages),
        Kind::ManyOps { ops } => {
            let mut b = one_page_doc();
            b.stream_raw(4, "/Filter /FlateDecode", &zlib(&ops_content(ops)));
            b.build()
        }
        Kind::ManyObjects { count } => {
            let mut b = one_page_doc();
            for i in 0..count {
                b.object(100 + i, format!("<< /K {i} /V (v{i}) >>"));
            }
            b.build()
        }
        Kind::BigObjStm { members } => objstms(1, members),
        Kind::ManyObjStms { streams, members } => objstms(streams, members),
        Kind::Revisions { revs, objects } => revisions(revs, objects),
        Kind::DeepLong {
            objects,
            depth,
            len,
        } => deep_long(objects, depth, len),
        Kind::Escapes { objects } => {
            let mut b = one_page_doc();
            for i in 0..objects {
                b.object(
                    100 + i,
                    format!(
                        "<< /Q#41#42#43{i} (s\\101\\102\\n\\(p\\)\\\\{i}) /R#2Fx#20y [/A#41 /B#23#42 (\\377\\376) <48656C6C6F>] /T (line\\\ncontinued) >>"
                    ),
                );
            }
            b.build()
        }
        Kind::NearLimit { streams, decoded } => near_limit(streams, decoded),
        Kind::Type4Annots { functions, annots } => type4_annots(functions, annots),
    }
}

fn zlib(data: &[u8]) -> Vec<u8> {
    compress_to_vec_zlib(data, LEVEL)
}

const CATALOG: &str = "<< /Type /Catalog /Pages 2 0 R >>";
const FONT: &str = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

fn page(parent: u32, contents: u32, extra: &str) -> String {
    format!(
        "<< /Type /Page /Parent {parent} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents {contents} 0 R{extra} >>"
    )
}

/// Catalog 1, Pages 2, Page 3, content 4 (not written: callers add it), font 5.
fn one_page_doc() -> PdfBuilder {
    let mut b = PdfBuilder::new("1.7");
    b.object(1, CATALOG)
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(3, page(2, 4, ""))
        .object(5, FONT);
    b
}

/// Page tree for pages `first..first+count` (page `n` uses content `n + count`).
fn pages_doc(count: u32, first: u32) -> PdfBuilder {
    let mut b = PdfBuilder::new("1.7");
    let kids: Vec<String> = (first..first + count).map(|n| format!("{n} 0 R")).collect();
    b.object(1, CATALOG)
        .object(
            2,
            format!(
                "<< /Type /Pages /Kids [{}] /Count {count} >>",
                kids.join(" ")
            ),
        )
        .object(5, FONT);
    for n in first..first + count {
        b.object(n, page(2, n + count, ""));
    }
    b
}

/// A page of text: ~40 lines, varied so Flate cannot collapse it.
fn text_page(seed: u32) -> Vec<u8> {
    let mut s = String::from("BT /F1 10 Tf 12 TL 50 800 Td\n");
    for line in 0..40u32 {
        let x = seed.wrapping_mul(2_654_435_761).wrapping_add(line * 97) % 100_000;
        let _ = writeln!(
            s,
            "(Page {seed} line {line}: lorem ipsum dolor sit amet {x}) Tj T*"
        );
    }
    s.push_str("ET\n");
    s.into_bytes()
}

fn flate_pages(pages: u32) -> Vec<u8> {
    let first = 10;
    let mut b = pages_doc(pages, first);
    for i in 0..pages {
        b.stream_raw(
            first + pages + i,
            "/Filter /FlateDecode",
            &zlib(&text_page(i)),
        );
    }
    b.build()
}

/// Graphics content with exactly `ops` operators (cycle of 5).
fn ops_content(ops: u32) -> Vec<u8> {
    const CYCLE: [&str; 5] = ["q", "1 0 0 1 {x} {y} cm", "0.5 g", "0 0 {w} 4 re", "f Q"];
    let mut s = String::with_capacity(ops as usize * 10);
    for i in 0..ops {
        let x = i % 500;
        let y = (i / 500) % 800;
        let op = CYCLE[(i % 5) as usize]
            .replace("{x}", &x.to_string())
            .replace("{y}", &y.to_string())
            .replace("{w}", &(i % 7 + 1).to_string());
        s.push_str(&op);
        s.push('\n');
    }
    s.into_bytes()
}

fn objstms(streams: u32, members: u32) -> Vec<u8> {
    let mut b = PdfBuilder::new("1.5");
    b.object(1, CATALOG)
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(3, page(2, 4, ""))
        .stream_raw(4, "/Filter /FlateDecode", &zlib(&text_page(0)))
        .object(5, FONT);
    let first_stm = 10;
    let first_member = first_stm + streams;
    for s in 0..streams {
        let base = first_member + s * members;
        let nums: Vec<u32> = (base..base + members).collect();
        for &n in &nums {
            b.object(
                n,
                format!("<< /K {n} /A [1 2 3] /N /Name{n} /S (member {n}) >>"),
            );
        }
        b.objstm(first_stm + s, &nums, &[crate::Filter::Flate]);
    }
    b.xref(Xref::Stream);
    b.build()
}

fn revisions(revs: u32, objects: u32) -> Vec<u8> {
    let mut b = one_page_doc();
    b.stream_raw(4, "/Filter /FlateDecode", &zlib(&text_page(0)));
    let mut next = 100;
    for r in 1..=revs {
        b.revision();
        b.stream_raw(4, "/Filter /FlateDecode", &zlib(&text_page(r)));
        for _ in 0..objects {
            b.object(next, format!("<< /Rev {r} /K {next} >>"));
            next += 1;
        }
    }
    b.build()
}

fn deep_long(objects: u32, depth: u32, len: u32) -> Vec<u8> {
    let mut b = one_page_doc();
    b.stream_raw(4, "", &text_page(0));
    let mut nested = String::from("0");
    for d in 0..depth.saturating_sub(1) {
        nested = if d % 2 == 0 {
            format!("[{nested}]")
        } else {
            format!("<< /D {nested} >>")
        };
    }
    for i in 0..objects {
        b.object(100 + i, format!("<< /Deep {nested} >>"));
    }
    let mut arr = String::with_capacity(len as usize * 8);
    arr.push('[');
    for i in 0..len {
        let _ = write!(arr, "{i} ");
    }
    arr.push(']');
    b.object(100 + objects, arr);
    let mut dict = String::from("<<");
    for i in 0..len / 4 {
        let _ = write!(dict, " /K{i} {i}");
    }
    dict.push_str(" >>");
    b.object(101 + objects, dict);
    b.build()
}

fn near_limit(streams: u32, decoded: u64) -> Vec<u8> {
    let first = 10;
    let mut b = pages_doc(streams, first);
    for i in 0..streams {
        let mut data = Vec::with_capacity(decoded as usize + 4096);
        let mut seed = i * 1_000_000;
        while (data.len() as u64) < decoded {
            data.extend_from_slice(&text_page(seed));
            seed += 1;
        }
        data.truncate(decoded as usize);
        // End on a line boundary so the cut does not split a token.
        while data.last().is_some_and(|&c| c != b'\n') {
            data.pop();
        }
        b.stream_raw(first + streams + i, "/Filter /FlateDecode", &zlib(&data));
    }
    b.build()
}

/// A ~60 KiB calculator program using only allowlisted operators.
fn type4_program(seed: u32) -> Vec<u8> {
    let mut s = String::from("{ ");
    let mut i = seed;
    while s.len() < 60 * 1024 {
        let _ = write!(s, "dup {}.5 mul exch pop 1 index add 2 div ", i % 1000);
        i += 1;
    }
    s.push_str("}\n");
    s.into_bytes()
}

fn type4_annots(functions: u32, annots: u32) -> Vec<u8> {
    let first_annot = 100;
    let refs: Vec<String> = (first_annot..first_annot + annots)
        .map(|n| format!("{n} 0 R"))
        .collect();
    let mut b = PdfBuilder::new("1.7");
    b.object(1, CATALOG)
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(3, page(2, 4, &format!(" /Annots [{}]", refs.join(" "))))
        .stream_raw(4, "", &text_page(0))
        .object(5, FONT);
    for (i, n) in (first_annot..first_annot + annots).enumerate() {
        let x = (i % 50) as u32 * 10;
        let y = (i / 50 % 80) as u32 * 10;
        b.object(
            n,
            format!(
                "<< /Type /Annot /Subtype /Link /Rect [{x} {y} {} {}] /Border [0 0 0] /A << /S /GoTo /D [3 0 R /Fit] >> >>",
                x + 8,
                y + 8
            ),
        );
    }
    let first_fn = first_annot + annots;
    for i in 0..functions {
        b.stream_raw(
            first_fn + i,
            "/FunctionType 4 /Domain [0 1] /Range [0 1] /Filter /FlateDecode",
            &zlib(&type4_program(i)),
        );
    }
    b.build()
}

/// xorshift64*: deterministic filler, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Random bytes with a fake object or stream keyword every ~1 KiB, and one
/// fake xref section per buffer (1 MiB): more would hit `max_revisions`.
fn fill_fake_keywords(rng: &mut Rng, buf: &mut [u8]) {
    const XREF: &[u8] = b"\nxref\n0 1\n0000000000 65535 f\r\ntrailer\n<< /Size 1 >>\n";
    const FAKES: [&[u8]; 3] = [
        b"\n7 0 obj\n<< /Type /Fake /Length 10 >>\nstream\n",
        b"\nendstream\nendobj\n",
        b"\n12 0 obj\n[1 2 3]\nendobj\nstartxref\n0\n",
    ];
    rng.fill(buf);
    // Clear of the JPEG head the first buffer gets.
    let mut pos = 64;
    let mut i = 0;
    while pos < buf.len() {
        let fake = if i == 0 { XREF } else { FAKES[i % FAKES.len()] };
        let end = (pos + fake.len()).min(buf.len());
        buf[pos..end].copy_from_slice(&fake[..end - pos]);
        pos += 1024 + (rng.next() % 256) as usize;
        i += 1;
    }
}

/// One page drawing one DCT image of `data_len` bytes made by `fill`, written
/// in 1 MiB chunks with a classic xref.
fn write_image_file(
    data_len: u64,
    out: &mut impl Write,
    fill: impl Fn(&mut Rng, &mut [u8]),
) -> io::Result<u64> {
    let mut w = Counting { out, n: 0 };
    let mut offsets = Vec::new();
    w.write_all(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")?;
    let content = b"q 595 0 0 842 0 0 cm /Im1 Do Q\n";
    let objects: [(u32, Vec<u8>); 4] = [
        (1, CATALOG.into()),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into()),
        (
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>".into(),
        ),
        (4, raw_stream_body("", content)),
    ];
    for (num, body) in &objects {
        offsets.push(w.n);
        writeln!(w, "{num} 0 obj")?;
        w.write_all(body)?;
        w.write_all(b"\nendobj\n")?;
    }
    offsets.push(w.n);
    write!(
        w,
        "5 0 obj\n<< /Type /XObject /Subtype /Image /Width 8000 /Height 6000 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {data_len} >>\nstream\n"
    )?;
    // JPEG SOI + APP0 marker, random body, EOI.
    let head: &[u8] = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00";
    let tail: &[u8] = b"\xFF\xD9";
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut left = data_len;
    let mut buf = vec![0u8; MIB as usize];
    let mut first = true;
    while left > 0 {
        let n = left.min(MIB) as usize;
        let chunk = &mut buf[..n];
        fill(&mut rng, chunk);
        if first {
            let k = head.len().min(n);
            chunk[..k].copy_from_slice(&head[..k]);
            first = false;
        }
        left -= n as u64;
        if left == 0 && n >= tail.len() {
            chunk[n - tail.len()..].copy_from_slice(tail);
        }
        w.write_all(chunk)?;
    }
    w.write_all(b"\nendstream\nendobj\n")?;
    let xref = w.n;
    w.write_all(b"xref\n0 6\n0000000000 65535 f\r\n")?;
    for off in offsets {
        write!(w, "{off:010} 00000 n\r\n")?;
    }
    write!(
        w,
        "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    )?;
    Ok(w.n)
}

struct Counting<'a, W: Write> {
    out: &'a mut W,
    n: u64,
}

impl<W: Write> Write for Counting<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.n += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(hay: &[u8], needle: &[u8]) -> usize {
        hay.windows(needle.len()).filter(|w| *w == needle).count()
    }

    #[test]
    fn names_unique_and_catalogs_match() {
        let full = catalog();
        let small = small_catalog();
        assert_eq!(full.len(), small.len());
        let mut names: Vec<&str> = full.iter().map(|h| h.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), full.len());
        for (f, s) in full.iter().zip(&small) {
            assert_eq!(f.name, s.name);
            assert_eq!(
                std::mem::discriminant(&f.kind),
                std::mem::discriminant(&s.kind)
            );
        }
    }

    #[test]
    fn deterministic() {
        for h in small_catalog() {
            assert_eq!(build(h.kind), build(h.kind), "{}", h.name);
        }
    }

    #[test]
    fn write_matches_build_and_reports_length() {
        for h in small_catalog() {
            let mut v = Vec::new();
            let n = write(h.kind, &mut v).unwrap();
            assert_eq!(n, v.len() as u64, "{}", h.name);
            assert_eq!(v, build(h.kind), "{}", h.name);
            assert!(v.starts_with(b"%PDF-1."), "{}", h.name);
            assert!(v.ends_with(b"%%EOF\n"), "{}", h.name);
        }
    }

    #[test]
    fn image_file_layout() {
        let len = 3 * MIB + 17; // several chunks, odd tail
        let pdf = build(Kind::Opaque { bytes: len });
        let data_start = find(&pdf, b"stream\n\xFF\xD8").unwrap() + 7;
        assert!(pdf[data_start + len as usize - 2..].starts_with(b"\xFF\xD9\nendstream"));
        assert!(contains(&pdf, format!("/Length {len} >>").as_bytes()));
        // xref offsets point at the objects.
        let xref = find(&pdf, b"xref\n0 6\n").unwrap();
        let table = &pdf[xref + 9..];
        for (i, line) in table.split(|&c| c == b'\n').skip(1).take(5).enumerate() {
            let off: usize = std::str::from_utf8(&line[..10]).unwrap().parse().unwrap();
            assert!(
                pdf[off..].starts_with(format!("{} 0 obj", i + 1).as_bytes()),
                "object {}",
                i + 1
            );
        }
        let startxref = format!("startxref\n{xref}\n");
        assert!(contains(&pdf, startxref.as_bytes()));
    }

    #[test]
    fn image_tiny_lengths() {
        // Shorter than the JPEG head/tail: still well formed.
        for len in [0, 1, 2, 5, 12, 13] {
            let pdf = build(Kind::Opaque { bytes: len });
            assert!(contains(&pdf, format!("/Length {len} >>").as_bytes()));
            assert!(pdf.ends_with(b"%%EOF\n"));
        }
    }

    #[test]
    fn fake_keywords_are_planted() {
        let pdf = build(Kind::FakeKeywords { bytes: 64 << 10 });
        // ~50 fakes, a third each, and one xref per 1 MiB buffer.
        assert!(count(&pdf, b"<< /Type /Fake") >= 10);
        assert_eq!(count(&pdf, b"\nxref\n0 1\n"), 1);
        let opaque = build(Kind::Opaque { bytes: 64 << 10 });
        assert_eq!(count(&opaque, b"/Type /Fake"), 0);
    }

    #[test]
    fn ops_content_counts() {
        let c = ops_content(10);
        assert_eq!(c.iter().filter(|&&b| b == b'\n').count(), 10);
        assert!(c.starts_with(b"q\n1 0 0 1 1 0 cm\n0.5 g\n0 0 4 4 re\nf Q\n"));
    }

    #[test]
    fn object_counts() {
        let pdf = build(Kind::ManyObjects { count: 200 });
        assert_eq!(count(&pdf, b" 0 obj\n"), 4 + 200);
        let pdf = build(Kind::ManyObjStms {
            streams: 5,
            members: 4,
        });
        assert_eq!(count(&pdf, b"/Type /ObjStm /N 4 "), 5);
        let pdf = build(Kind::Revisions {
            revs: 5,
            objects: 3,
        });
        assert_eq!(count(&pdf, b"%%EOF\n"), 6);
        let pdf = build(Kind::Type4Annots {
            functions: 2,
            annots: 10,
        });
        assert_eq!(count(&pdf, b"/Subtype /Link"), 10);
        assert_eq!(count(&pdf, b"/FunctionType 4"), 2);
    }

    #[test]
    fn nesting_depth() {
        let pdf = build(Kind::DeepLong {
            objects: 1,
            depth: 6,
            len: 8,
        });
        // depth 6 = the object dict + 5 levels: [ << [ << [ 0 ] >> ] >> ]
        assert!(contains(&pdf, b"<< /Deep [<< /D [<< /D [0] >>] >>] >>"));
        assert!(contains(&pdf, b"[0 1 2 3 4 5 6 7 ]"));
        assert!(contains(&pdf, b"<< /K0 0 /K1 1 >>"));
    }

    #[test]
    fn near_limit_decodes_to_size() {
        let pdf = build(Kind::NearLimit {
            streams: 1,
            decoded: 64 << 10,
        });
        let start = find(&pdf, b"/FlateDecode /Length").unwrap();
        let data = find(&pdf[start..], b"stream\n").unwrap() + start + 7;
        let end = find(&pdf[data..], b"\nendstream").unwrap() + data;
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&pdf[data..end]).unwrap();
        assert!(raw.len() <= 64 << 10 && raw.len() > (64 << 10) - 200);
        assert!(raw.ends_with(b"\n"));
    }

    #[test]
    fn type4_program_size() {
        let p = type4_program(0);
        assert!(p.len() > 60 * 1024 && p.len() < 64 * 1024);
        assert!(p.starts_with(b"{ ") && p.ends_with(b"}\n"));
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        find(hay, needle).is_some()
    }
}
