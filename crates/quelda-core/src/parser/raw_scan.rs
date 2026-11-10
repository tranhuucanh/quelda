//! The one pass over the whole input (design §4.2, plan Step 16 Phase A):
//! every file-level keyword ([`Structure`]), every `N G obj` candidate (linear
//! scan) and every foreign-format signature (polyglot facts) are found
//! together, chunk by chunk, with SIMD byte search (`memchr`). Nothing else
//! scans the raw bytes from start to end; rules read these offsets from `Ctx`.
//!
//! Each pattern is found through one anchor byte, so every occurrence is
//! seen exactly once whatever the chunk boundaries; matches are confirmed
//! against the whole input, so a pattern may straddle two chunks.

use memchr::memmem;

use super::input::Input;
use super::lexer::is_regular;
use super::linear_scan::header_start_before;
use super::parse::Bytes;
use super::structure::{Header, StartXref, Structure, at_line_start, int_after, keyword_at};

/// Bytes searched per step: small enough to stay in L1/L2 cache while the
/// few searches below run over it.
const CHUNK: usize = 64 * 1024;

/// A foreign-format structure, wherever it is (stream data included:
/// deciding which ones matter needs the object set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureKind {
    ZipLocal,
    ZipCentral,
    ZipEnd,
    Zip64End,
    Script,
    Html,
    Svg,
}

impl SignatureKind {
    pub fn describe(self) -> &'static str {
        match self {
            SignatureKind::ZipLocal => "ZIP local file header",
            SignatureKind::ZipCentral => "ZIP central directory",
            SignatureKind::ZipEnd => "ZIP end of central directory",
            SignatureKind::Zip64End => "ZIP64 end of central directory",
            SignatureKind::Script => "HTML <script>",
            SignatureKind::Html => "HTML document",
            SignatureKind::Svg => "SVG document",
        }
    }
}

/// ZIP records (exact bytes).
const ZIP: &[(&[u8], SignatureKind)] = &[
    (b"PK\x03\x04", SignatureKind::ZipLocal),
    (b"PK\x01\x02", SignatureKind::ZipCentral),
    (b"PK\x05\x06", SignatureKind::ZipEnd),
    (b"PK\x06\x06", SignatureKind::Zip64End),
];
/// Markup (ASCII case-insensitive).
const MARKUP: &[(&[u8], SignatureKind)] = &[
    (b"<script", SignatureKind::Script),
    (b"<html", SignatureKind::Html),
    (b"<svg", SignatureKind::Svg),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub offset: usize,
    pub kind: SignatureKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawScan {
    pub structure: Structure,
    /// Start offsets (of `N`) of every `N G obj` candidate, in file order
    /// (see [`super::linear_scan::object_candidates`]).
    pub object_candidates: Vec<usize>,
    /// Every foreign-format signature, in file order.
    pub signatures: Vec<Signature>,
    /// Every `endstream`, in file order: only when asked for (a source
    /// input locates stream data with it instead of searching again).
    pub endstreams: Vec<usize>,
}

impl RawScan {
    pub fn scan(src: &[u8]) -> RawScan {
        scan_chunked(src, CHUNK)
    }

    /// The pass over an input: a slice at once, a source block by block
    /// (one block in memory; `endstream` offsets recorded too).
    pub(crate) fn scan_input(input: &Input<'_>) -> RawScan {
        if let Some(src) = input.as_slice() {
            return RawScan::scan(src);
        }
        let len = input.len();
        let block = input.tuning().block;
        let chunk = CHUNK.min(block);
        let mut scan = Scan::new(true);
        let mut buf = Vec::new();
        let mut start = 0;
        while start < len {
            let end = start.saturating_add(block).min(len);
            // Enough after the block for every pattern that starts in it.
            let read_end = end.saturating_add(LOOKAHEAD).min(len);
            buf.resize(read_end - start, 0);
            if !input.fetch(start, &mut buf) {
                break;
            }
            let win = Win {
                base: start,
                data: &buf,
                len,
                input: Some(input),
            };
            let mut s = start;
            while s < end {
                let e = s.saturating_add(chunk).min(end);
                scan.chunk(&win, s, e);
                s = e;
            }
            start = end;
        }
        scan.finish(&Win {
            base: 0,
            data: &[],
            len,
            input: Some(input),
        })
    }
}

/// Bytes after a chunk the patterns may need: the longest needle, and the
/// confirmations that look ahead (`int_after`'s 64 bytes are read through
/// the input when past it).
const LOOKAHEAD: usize = 64;

/// The file seen through `data` (the file from `base`); bytes outside it come
/// from the input (rare: long look-behind, look-ahead past the block).
struct Win<'w, 'i> {
    base: usize,
    data: &'w [u8],
    len: usize,
    input: Option<&'w Input<'i>>,
}

impl Win<'_, '_> {
    /// The bytes of `[start, end)` plus up to `extra` after (within `data`).
    fn rel(&self, start: usize, end: usize, extra: usize) -> &[u8] {
        let a = start - self.base;
        let b = (end - self.base).saturating_add(extra).min(self.data.len());
        &self.data[a..b]
    }
}

impl Bytes for Win<'_, '_> {
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn byte(&self, i: usize) -> Option<u8> {
        match i.checked_sub(self.base).and_then(|k| self.data.get(k)) {
            Some(&b) => Some(b),
            None => self.input?.byte(i),
        }
    }

    fn find_endstream(&self, _from: usize) -> Option<usize> {
        None
    }

    fn starts_with_at(&self, i: usize, pat: &[u8]) -> bool {
        match i
            .checked_sub(self.base)
            .and_then(|k| self.data.get(k..k + pat.len()))
        {
            Some(w) => w == pat,
            None => pat
                .iter()
                .enumerate()
                .all(|(k, &b)| self.byte(i + k) == Some(b)),
        }
    }
}

/// `needle` occurrences starting in `[start, end)` (they may end after).
fn starts_in<'f>(
    f: &'f memmem::Finder<'f>,
    win: &'f Win<'_, '_>,
    start: usize,
    end: usize,
) -> impl Iterator<Item = usize> + 'f {
    let tail = win.rel(start, end, f.needle().len() - 1);
    let n = end - start;
    f.find_iter(tail)
        .take_while(move |&i| i < n)
        .map(move |i| start + i)
}

struct Scan {
    pdf: memmem::Finder<'static>,
    eof: memmem::Finder<'static>,
    xref: memmem::Finder<'static>,
    obj: memmem::Finder<'static>,
    pk: memmem::Finder<'static>,
    trailer: memmem::Finder<'static>,
    endstream: Option<memmem::Finder<'static>>,
    first_header: Option<usize>,
    out: RawScan,
}

impl Scan {
    fn new(endstreams: bool) -> Scan {
        Scan {
            pdf: memmem::Finder::new(b"%PDF-"),
            eof: memmem::Finder::new(b"%%EOF"),
            xref: memmem::Finder::new(b"xref"),
            obj: memmem::Finder::new(b"obj"),
            pk: memmem::Finder::new(b"PK"),
            trailer: memmem::Finder::new(b"trailer"),
            endstream: endstreams.then(|| memmem::Finder::new(b"endstream")),
            first_header: None,
            out: RawScan::default(),
        }
    }

    /// Everything starting in `[start, end)`; `win` holds those bytes and
    /// [`LOOKAHEAD`] more (or up to the end of the file).
    fn chunk(&mut self, src: &Win<'_, '_>, start: usize, end: usize) {
        let out = &mut self.out;
        let s = &mut out.structure;
        for p in starts_in(&self.pdf, src, start, end) {
            self.first_header.get_or_insert(p);
            if at_line_start(src, p) {
                s.header_lines.push(p);
            }
        }
        s.eofs.extend(starts_in(&self.eof, src, start, end));
        for p in starts_in(&self.xref, src, start, end) {
            if p >= 5 && keyword_at(src, p - 5, b"startxref") {
                s.startxrefs.push(StartXref {
                    offset: p - 5,
                    target: int_after(src, p + 4),
                });
            }
            if at_line_start(src, p) && keyword_at(src, p, b"xref") {
                s.xref_tables.push(p);
            }
        }
        for kw in starts_in(&self.obj, src, start, end) {
            if src.byte(kw + 3).is_none_or(|b| !is_regular(b))
                && let Some(n) = header_start_before(src, kw)
            {
                out.object_candidates.push(n);
            }
        }
        let sig_from = out.signatures.len();
        for p in starts_in(&self.pk, src, start, end) {
            if let Some(&(_, kind)) = ZIP.iter().find(|(sig, _)| src.starts_with_at(p, sig)) {
                out.signatures.push(Signature { offset: p, kind });
            }
        }
        for i in memchr::memchr_iter(b'<', src.rel(start, end, 0)) {
            let p = start + i;
            if !matches!(src.byte(p + 1), Some(b's' | b'S' | b'h' | b'H')) {
                continue;
            }
            let hit = MARKUP.iter().find(|(sig, _)| {
                sig.iter()
                    .enumerate()
                    .all(|(k, c)| src.byte(p + k).is_some_and(|b| b.eq_ignore_ascii_case(c)))
            });
            if let Some(&(_, kind)) = hit {
                out.signatures.push(Signature { offset: p, kind });
            }
        }
        out.signatures[sig_from..].sort_unstable_by_key(|g| g.offset);
        for p in starts_in(&self.trailer, src, start, end) {
            if keyword_at(src, p, b"trailer") {
                s.trailers.push(p);
            }
        }
        if let Some(f) = &self.endstream {
            out.endstreams.extend(starts_in(f, src, start, end));
        }
    }

    fn finish(mut self, src: &Win<'_, '_>) -> RawScan {
        let s = &mut self.out.structure;
        s.header = self.first_header.map(|offset| Header {
            offset,
            version: (offset + 5..src.len())
                .map_while(|i| src.byte(i))
                .take_while(|&b| !super::lexer::is_whitespace(b))
                .take(16)
                .collect(),
        });
        s.trailing_bytes = s.eofs.last().map(|&e| src.len() - (e + b"%%EOF".len()));
        self.out
    }
}

pub(crate) fn scan_chunked(src: &[u8], chunk: usize) -> RawScan {
    let chunk = chunk.max(1);
    let win = Win {
        base: 0,
        data: src,
        len: src.len(),
        input: None,
    };
    let mut scan = Scan::new(false);
    let mut start = 0;
    while start < src.len() {
        let end = start.saturating_add(chunk).min(src.len());
        scan.chunk(&win, start, end);
        start = end;
    }
    scan.finish(&win)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::structure::find_all;

    /// The scan before Step 16: one byte-by-byte pass per pattern.
    fn oracle(src: &[u8]) -> RawScan {
        let header_lines: Vec<usize> = find_all(src, b"%PDF-")
            .filter(|&i| at_line_start(src, i))
            .collect();
        let header = find_all(src, b"%PDF-").next().map(|offset| Header {
            offset,
            version: src[offset + 5..]
                .iter()
                .take_while(|&&b| !crate::parser::lexer::is_whitespace(b))
                .take(16)
                .copied()
                .collect(),
        });
        let startxrefs = find_all(src, b"startxref")
            .filter(|&i| keyword_at(src, i, b"startxref"))
            .map(|offset| StartXref {
                offset,
                target: int_after(src, offset + b"startxref".len()),
            })
            .collect();
        let eofs: Vec<usize> = find_all(src, b"%%EOF").collect();
        let trailing_bytes = eofs.last().map(|&e| src.len() - (e + b"%%EOF".len()));
        let xref_tables = find_all(src, b"xref")
            .filter(|&i| at_line_start(src, i) && keyword_at(src, i, b"xref"))
            .collect();
        let trailers = find_all(src, b"trailer")
            .filter(|&i| keyword_at(src, i, b"trailer"))
            .collect();
        let object_candidates = find_all(src, b"obj")
            .filter(|&i| src.get(i + 3).is_none_or(|&b| !is_regular(b)))
            .filter_map(|i| header_start_before(src, i))
            .collect();
        let mut signatures = Vec::new();
        for (i, &b) in src.iter().enumerate() {
            let hit = match b {
                b'P' => ZIP.iter().find(|(sig, _)| src[i..].starts_with(sig)),
                b'<' => MARKUP.iter().find(|(sig, _)| {
                    src.get(i..i + sig.len())
                        .is_some_and(|w| w.eq_ignore_ascii_case(sig))
                }),
                _ => None,
            };
            if let Some(&(_, kind)) = hit {
                signatures.push(Signature { offset: i, kind });
            }
        }
        RawScan {
            structure: Structure {
                header,
                header_lines,
                startxrefs,
                eofs,
                trailing_bytes,
                xref_tables,
                trailers,
            },
            object_candidates,
            signatures,
            endstreams: Vec::new(),
        }
    }

    /// Deterministic xorshift.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Inputs made of pattern pieces, so matches are dense, overlap and
    /// land on every chunk boundary.
    fn pieces(seed: u64, n: usize) -> Vec<u8> {
        const P: &[&[u8]] = &[
            b"%PDF-1.7",
            b"%PDF-",
            b"%%EOF",
            b"%%%EOF",
            b"%",
            b"startxref",
            b"start",
            b"xref",
            b"xre",
            b"trailer",
            b"trai",
            b"ler",
            b"obj",
            b"ob",
            b"j",
            b"endobj",
            b"1 0 ",
            b"12 3\r\n",
            b" 7 ",
            b"\n",
            b"\r",
            b" ",
            b"\t",
            b"\0",
            b"<<",
            b"/",
            b"PK\x03\x04",
            b"PK\x05",
            b"\x06\x06",
            b"P",
            b"K",
            b"<sCrIpT",
            b"<HTML",
            b"<svg",
            b"<sv",
            b"x",
            b"a",
            b"9",
        ];
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut v = Vec::new();
        for _ in 0..n {
            v.extend_from_slice(P[(r.next() % P.len() as u64) as usize]);
        }
        v
    }

    #[test]
    fn same_as_oracle_any_chunk_size() {
        for seed in 0..200 {
            let src = pieces(seed, 300);
            let want = oracle(&src);
            for chunk in [1, 2, 3, 4, 5, 6, 7, 8, 13, 64, CHUNK] {
                assert_eq!(scan_chunked(&src, chunk), want, "seed {seed} chunk {chunk}");
            }
        }
    }

    #[test]
    fn same_as_oracle_on_fixtures() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");
        let mut n = 0;
        for e in walk(std::path::Path::new(dir)) {
            let src = std::fs::read(&e).unwrap();
            let want = oracle(&src);
            assert_eq!(RawScan::scan(&src), want, "{}", e.display());
            assert_eq!(scan_chunked(&src, 7), want, "{}", e.display());
            n += 1;
        }
        assert!(n > 100, "run gen-fixtures first ({n} files)");
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else if p.extension().is_some_and(|x| x == "pdf") {
                out.push(p);
            }
        }
        out
    }

    /// The pass over a source, block by block (blocks and pages of a few
    /// bytes: look-behind and look-ahead go through the page cache).
    fn over_source(src: &[u8], block: usize, page: usize) -> RawScan {
        let tuning = crate::parser::input::Tuning {
            page,
            pages: 2,
            block,
            window: 1,
        };
        let input = Input::source(&src, tuning).unwrap();
        RawScan::scan_input(&input)
    }

    #[test]
    fn source_pass_same_as_oracle() {
        for seed in 0..120 {
            let mut src = pieces(seed, 300);
            src.extend_from_slice(b"endstream\nendstreamendstream");
            let mut want = oracle(&src);
            want.endstreams = find_all(&src, b"endstream").collect();
            for (block, page) in [
                (1, 1),
                (2, 3),
                (5, 7),
                (13, 4),
                (64, 64),
                (1 << 20, 1 << 16),
            ] {
                assert_eq!(
                    over_source(&src, block, page),
                    want,
                    "seed {seed} block {block}"
                );
            }
        }
    }

    #[test]
    fn source_pass_long_look_behind() {
        // `N G obj` with a run of whitespace far longer than a block.
        let mut src = b"12".to_vec();
        src.extend(std::iter::repeat_n(b' ', 5000));
        src.extend_from_slice(b"0");
        src.extend(std::iter::repeat_n(b'\n', 3000));
        src.extend_from_slice(b"obj startxref");
        src.extend(std::iter::repeat_n(b' ', 50));
        src.extend_from_slice(b"123");
        let mut want = oracle(&src);
        want.endstreams = Vec::new();
        assert_eq!(want.object_candidates, vec![0]);
        assert_eq!(want.structure.startxrefs[0].target, Some(123));
        assert_eq!(over_source(&src, 16, 8), want);
    }

    #[test]
    fn edges() {
        assert_eq!(RawScan::scan(b""), RawScan::default());
        let s = RawScan::scan(b"obj");
        assert!(s.object_candidates.is_empty());
        let s = scan_chunked(b"1 0 obj%PDF-x\nstartxref 5 trailer", 1);
        assert_eq!(s.object_candidates, vec![0]);
        assert_eq!(s.structure.header.map(|h| h.version), Some(b"x".to_vec()));
        assert_eq!(s.structure.startxrefs[0].target, Some(5));
        assert_eq!(s.structure.trailers, vec![26]);
        let s = RawScan::scan(b"<ScRiPt PK\x06\x06");
        let kinds: Vec<_> = s.signatures.iter().map(|g| (g.offset, g.kind)).collect();
        assert_eq!(
            kinds,
            vec![(0, SignatureKind::Script), (8, SignatureKind::Zip64End)]
        );
    }
}
