//! File-level structure found by scanning raw bytes (design §4.2): header,
//! every `startxref`, every `%%EOF`, bytes after the last `%%EOF`, and where
//! `xref` tables and `trailer` dictionaries start. Nothing here trusts
//! offsets written in the file.

use super::lexer::{is_regular, is_whitespace};
use super::parse::Bytes;

/// The first `%PDF-` in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub offset: usize,
    /// Bytes after `%PDF-` up to whitespace, e.g. `1.7` (not validated).
    pub version: Vec<u8>,
}

/// One `startxref` keyword and the offset written after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartXref {
    /// Offset of the keyword.
    pub offset: usize,
    /// The integer that follows; `None` if missing or not a valid offset.
    pub target: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Structure {
    pub header: Option<Header>,
    /// Offsets of every `%PDF-` at the start of a line (including the
    /// header), wherever it is, stream data included: deciding which ones are
    /// outside stream data needs the object set (facts layer).
    pub header_lines: Vec<usize>,
    /// Every `startxref`, in file order.
    pub startxrefs: Vec<StartXref>,
    /// Offsets of every `%%EOF`, in file order.
    pub eofs: Vec<usize>,
    /// Bytes after the last `%%EOF` marker; `None` without any `%%EOF`.
    pub trailing_bytes: Option<usize>,
    /// Offsets of `xref` keywords at the start of a line (`startxref` excluded).
    pub xref_tables: Vec<usize>,
    /// Offsets of `trailer` keywords.
    pub trailers: Vec<usize>,
}

impl Structure {
    /// Scans `src` (see [`super::raw_scan`], which finds everything in one
    /// pass; prefer it when the other offsets are needed too).
    pub fn scan(src: &[u8]) -> Structure {
        super::raw_scan::RawScan::scan(src).structure
    }

    /// The `startxref` a reader starts from: the last one with a target.
    pub fn last_startxref(&self) -> Option<usize> {
        self.startxrefs.iter().rev().find_map(|s| s.target)
    }
}

/// Offsets of every occurrence of `needle` (overlapping allowed), byte by
/// byte: the reference the one-pass scan is tested against.
#[cfg(test)]
pub(crate) fn find_all<'a>(hay: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let first = needle.first().copied();
    hay.iter()
        .enumerate()
        .filter(move |&(_, &b)| Some(b) == first)
        .map(|(i, _)| i)
        .filter(move |&i| hay[i..].starts_with(needle))
}

/// Start of file or right after CR/LF, with optional spaces/tabs before.
pub(crate) fn at_line_start<B: Bytes + ?Sized>(src: &B, i: usize) -> bool {
    let mut j = i;
    while j > 0 && matches!(src.byte(j - 1), Some(b' ' | b'\t' | 0)) {
        j -= 1;
    }
    j == 0 || matches!(src.byte(j - 1), Some(b'\n' | b'\r'))
}

/// `kw` at `i` is a whole token (not part of a longer regular run).
pub(crate) fn keyword_at<B: Bytes + ?Sized>(src: &B, i: usize, kw: &[u8]) -> bool {
    let before = i.checked_sub(1).and_then(|j| src.byte(j));
    let after = src.byte(i + kw.len());
    src.starts_with_at(i, kw) && !before.is_some_and(is_regular) && !after.is_some_and(is_regular)
}

/// Non-negative integer after whitespace/comments at `pos` (bounded look-ahead).
pub(crate) fn int_after<B: Bytes + ?Sized>(src: &B, pos: usize) -> Option<usize> {
    let mut i = pos;
    let limit = pos.saturating_add(64).min(src.len());
    let at = |i: usize| src.byte(i).unwrap_or(0);
    while i < limit && (is_whitespace(at(i)) || at(i) == b'%') {
        if at(i) == b'%' {
            while i < limit && !matches!(at(i), b'\n' | b'\r') {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    // More than 19 digits is never an offset: 20 are enough to know.
    let mut digits = [0u8; 20];
    let mut n = 0;
    while n < digits.len() {
        match src.byte(i + n) {
            Some(b) if b.is_ascii_digit() => {
                digits[n] = b;
                n += 1;
            }
            _ => break,
        }
    }
    if n == 0 || n > 19 || src.byte(i + n).is_some_and(is_regular) {
        return None;
    }
    std::str::from_utf8(&digits[..n]).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_layout() {
        let src = b"%PDF-1.7\n%\xE2\xE3\n1 0 obj\n<<>>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n32\n%%EOF\n";
        let s = Structure::scan(src);
        assert_eq!(
            s.header,
            Some(Header {
                offset: 0,
                version: b"1.7".to_vec()
            })
        );
        assert_eq!(s.header_lines, vec![0]);
        assert_eq!(s.startxrefs.len(), 1);
        assert_eq!(s.startxrefs[0].target, Some(32));
        assert_eq!(s.last_startxref(), Some(32));
        assert_eq!(s.eofs.len(), 1);
        assert_eq!(s.trailing_bytes, Some(1));
        assert_eq!(s.xref_tables.len(), 1);
        assert!(src[s.xref_tables[0]..].starts_with(b"xref\n0 1"));
        assert_eq!(s.trailers.len(), 1);
    }

    #[test]
    fn header_not_at_start() {
        let s = Structure::scan(b"junk%PDF-1.4\nmore\n%PDF-2.0\r\n");
        assert_eq!(s.header.as_ref().map(|h| h.offset), Some(4));
        assert_eq!(s.header_lines, vec![18]);
        assert_eq!(Structure::scan(b"").header, None);
    }

    #[test]
    fn startxref_variants() {
        let s = Structure::scan(b"startxref\n% c\n 77 \nstartxref abc\nstartxref\nstartxref 99x\n");
        let targets: Vec<_> = s.startxrefs.iter().map(|x| x.target).collect();
        assert_eq!(targets, vec![Some(77), None, None, None]);
        assert_eq!(s.last_startxref(), Some(77));
        // `startxref` is not counted as an `xref` table.
        assert!(s.xref_tables.is_empty());
        let s = Structure::scan(b"startxref 99999999999999999999999\n");
        assert_eq!(s.startxrefs[0].target, None);
    }

    #[test]
    fn eof_and_trailing() {
        let s = Structure::scan(b"%%EOF\nabc%%EOF");
        assert_eq!(s.eofs, vec![0, 9]);
        assert_eq!(s.trailing_bytes, Some(0));
        assert_eq!(Structure::scan(b"no eof").trailing_bytes, None);
    }

    #[test]
    fn keywords_must_be_whole_tokens() {
        let s = Structure::scan(b"xrefs\n trailerx\n/trailer\n  xref\n");
        assert_eq!(s.xref_tables, vec![27]);
        // `/trailer` is a name, but the keyword check only looks at regular
        // characters: `/` is a delimiter, so it counts (harmless: its parse fails).
        assert_eq!(s.trailers, vec![17]);
    }

    #[test]
    fn find_all_overlapping() {
        assert_eq!(find_all(b"aaa", b"aa").collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(find_all(b"", b"a").count(), 0);
    }
}
