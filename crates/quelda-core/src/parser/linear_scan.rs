//! Linear scan (design §4.2): every `N G obj` in the file, whatever the xref
//! says, stream data and orphans included. Finding candidates is one pass;
//! parsing them is up to the caller (and bounded by its work budget).

use super::lexer::is_whitespace;

/// Start offsets (of `N`) of every `<digits> <ws> <digits> <ws> obj` where
/// `obj` is not followed by a regular character, in file order. Generous on
/// purpose: a run of digits glued to the previous token still counts, as a
/// repairing reader's pattern search would match it.
/// Found by the one-pass [`super::raw_scan`]; this runs it alone.
pub fn object_candidates(src: &[u8]) -> Vec<usize> {
    super::raw_scan::RawScan::scan(src).object_candidates
}

/// Walks back from `obj` at `kw` over `ws digits ws digits`.
pub(crate) fn header_start_before(src: &[u8], kw: usize) -> Option<usize> {
    let mut i = kw;
    for _ in 0..2 {
        let ws_end = i;
        while i > 0 && is_whitespace(src[i - 1]) {
            i -= 1;
        }
        if i == ws_end {
            return None;
        }
        let digits_end = i;
        while i > 0 && src[i - 1].is_ascii_digit() {
            i -= 1;
        }
        if i == digits_end {
            return None;
        }
    }
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_headers() {
        let src = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n12  3\r\nobj 5\nendobj\n";
        assert_eq!(object_candidates(src), vec![9, 29]);
    }

    #[test]
    fn rejects_non_headers() {
        assert!(object_candidates(b"0 obj").is_empty());
        assert!(object_candidates(b"1 0obj").is_empty());
        assert!(object_candidates(b"1 0 objx").is_empty());
        assert!(object_candidates(b"a 0 obj").is_empty());
        assert!(object_candidates(b"endobj").is_empty());
        assert!(object_candidates(b"").is_empty());
    }

    #[test]
    fn generous_about_what_precedes() {
        // `endobj12 0 obj`: still a candidate at `12`.
        assert_eq!(object_candidates(b"endobj12 0 obj"), vec![6]);
        assert_eq!(object_candidates(b"1 0 obj"), vec![0]);
        assert_eq!(object_candidates(b"1 0 obj<<"), vec![0]);
    }
}
