//! `STRUCT.SIGNATURE_MODIFIED`: a signed file whose signature no longer
//! covers what is shown: bytes after the signed ranges (an update saved
//! after signing), signed ranges that leave out something other than the
//! signature value, or a `/ByteRange` that cannot be right.
//!
//! Structural only: the signature value itself (cryptography,
//! certificates) is not verified.

use std::ops::Range;

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::values;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct SignatureModified;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.SIGNATURE_MODIFIED",
    category: Category::Structure,
    severity: Severity::Medium,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.3.0",
    message: "File was changed after it was signed",
    description: "A signature dictionary whose /ByteRange (ISO 32000-2 §12.8.1) does not \
        cover the file as it is: bytes follow the signed ranges (an incremental update \
        saved after signing, which can change what is shown while the signature still \
        verifies), the bytes left out between the signed ranges are not just the \
        signature value (a hex string), or the /ByteRange itself is malformed (not pairs \
        of non-negative integers, not starting at 0, overlapping, out of order, or past the \
        end of the file). Only the structure is checked, not the signature's cryptography. \
        Filling a form or adding a second signature after the first also adds bytes, so \
        balanced only warns.",
};

/// Bytes read at a time when looking past the signed ranges.
const CHUNK: usize = 64 << 10;

/// PDF whitespace (NUL, tab, LF, FF, CR, space).
fn is_space(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// The signed ranges of `/ByteRange` values `v`, or why they are wrong.
fn ranges(v: &PdfObject, file_len: usize) -> Result<Vec<Range<usize>>, String> {
    let items = v.as_array().ok_or("/ByteRange is not an array")?;
    if items.len() < 4 || items.len() % 2 != 0 {
        return Err(format!("/ByteRange has {} numbers (pairs, at least 2)", items.len()));
    }
    let mut out: Vec<Range<usize>> = Vec::with_capacity(items.len() / 2);
    for pair in items.chunks(2) {
        let (Some(start), Some(len)) = (pair[0].as_int(), pair[1].as_int()) else {
            return Err("/ByteRange holds a value that is not an integer".to_string());
        };
        let (Ok(start), Ok(len)) = (usize::try_from(start), usize::try_from(len)) else {
            return Err(format!("/ByteRange has a negative value ({start} {len})"));
        };
        let end = start
            .checked_add(len)
            .filter(|&e| e <= file_len)
            .ok_or_else(|| format!("/ByteRange {start} {len} ends past the file ({file_len} bytes)"))?;
        if let Some(prev) = out.last() {
            if start < prev.end {
                return Err(format!(
                    "/ByteRange ranges overlap or go backwards ({}..{} then {start}..{end})",
                    prev.start, prev.end
                ));
            }
        } else if start != 0 {
            return Err(format!("/ByteRange starts at {start}, not 0"));
        }
        out.push(start..end);
    }
    Ok(out)
}

/// The bytes between two signed ranges are one hex string, `< … >`.
fn is_hex_string(gap: &[u8]) -> bool {
    match gap {
        [b'<', inner @ .., b'>'] => inner.iter().all(|&b| b.is_ascii_hexdigit() || is_space(b)),
        _ => false,
    }
}

/// Bytes after `from` that are not whitespace: their count from the first
/// one to the end of the file (`0`: only whitespace, or nothing).
fn data_after(ctx: &Ctx, from: usize) -> usize {
    let len = ctx.file_len();
    let mut at = from;
    while at < len {
        let end = len.min(at + CHUNK);
        let Some(chunk) = ctx.raw(at..end) else { return len - at };
        if let Some(i) = chunk.iter().position(|&b| !is_space(b)) {
            return len - (at + i);
        }
        at = end;
    }
    0
}

fn check(ctx: &Ctx, v: &PdfObject) -> Option<String> {
    let ranges = match ranges(v, ctx.file_len()) {
        Ok(r) => r,
        Err(why) => return Some(why),
    };
    for pair in ranges.windows(2) {
        let gap = pair[0].end..pair[1].start;
        let ok = ctx.raw(gap.clone()).is_some_and(|g| is_hex_string(&g));
        if !ok {
            return Some(format!(
                "bytes {}..{} left out of the signed ranges are not the signature value",
                gap.start, gap.end
            ));
        }
    }
    let end = ranges.last().map_or(0, |r| r.end);
    match data_after(ctx, end) {
        0 => None,
        n => Some(format!("{n} bytes after the signed ranges (end at {end})")),
    }
}

impl Rule for SignatureModified {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if !dict.contains_key("ByteRange") {
            return;
        }
        if let Some(why) = values(ctx, dict, "ByteRange").find_map(|v| check(ctx, v)) {
            out.report(&META, loc, Some(why));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&SignatureModified])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    /// A file with signature dictionary 2: its `/ByteRange` covers the
    /// whole file except `/Contents <…>`, then `after` is appended.
    fn signed(after: &[u8]) -> Vec<u8> {
        const BR: &str = "[0000000000 0000000000 0000000000 0000000000]";
        let mut f = format!(
            "%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n2 0 obj << /Type /Sig /Filter /Adobe.PPKLite /ByteRange {BR} /Contents <{}> >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n",
            "0".repeat(64)
        )
        .into_bytes();
        let lt = f.windows(10).position(|w| w == b"/Contents ").map(|i| i + 10);
        let lt = lt.unwrap_or_default();
        let gt = lt + 65;
        let br = format!("[0 {lt} {} {}]", gt + 1, f.len() - gt - 1);
        let at = f.windows(BR.len()).position(|w| w == BR.as_bytes()).unwrap_or_default();
        f.splice(at..at + BR.len(), format!("{br:<width$}", width = BR.len()).into_bytes());
        f.extend_from_slice(after);
        f
    }

    #[test]
    fn intact_signatures_pass() {
        assert!(hits(&signed(b"")).is_empty());
        // Whitespace after the signed ranges is not a change.
        assert!(hits(&signed(b"\r\n\0 ")).is_empty());
        // Not a signature: no `/ByteRange`.
        assert!(hits(b"1 0 obj << /Type /Sig /Contents <00> >> endobj\n").is_empty());
    }

    #[test]
    fn changed_after_signing() {
        let end = signed(b"").len();
        let f = signed(b"3 0 obj << /Type /Annot >> endobj\n%%EOF\n");
        assert_eq!(
            hits(&f),
            vec![format!("2 0: 40 bytes after the signed ranges (end at {end})")]
        );
    }

    #[test]
    fn gap_is_not_the_signature_value() {
        // The first range stops 10 bytes early: `/Contents ` is left out
        // too (a key or object hidden from the signature).
        let f = signed(b"");
        let text = String::from_utf8_lossy(&f).into_owned();
        let at = text.find("/ByteRange [0 ").unwrap_or_default() + 14;
        let lt: usize = text[at..].split(' ').next().unwrap_or_default().parse().unwrap_or_default();
        let gt = lt + 65;
        let moved = text.replacen(&format!("[0 {lt} "), &format!("[0 {} ", lt - 10), 1);
        assert_eq!(
            hits(moved.as_bytes()),
            vec![format!(
                "2 0: bytes {}..{} left out of the signed ranges are not the signature value",
                lt - 10,
                gt + 1
            )]
        );
    }

    #[test]
    fn malformed_byte_ranges() {
        let one = |br: &str| {
            let src = format!("1 0 obj << /ByteRange {br} /Contents <00> >> endobj\n{}", " ".repeat(200));
            hits(src.as_bytes())
        };
        assert_eq!(one("5    "), vec!["1 0: /ByteRange is not an array"]);
        assert_eq!(one("[0 10]"), vec!["1 0: /ByteRange has 2 numbers (pairs, at least 2)"]);
        assert_eq!(one("[0 1 2]"), vec!["1 0: /ByteRange has 3 numbers (pairs, at least 2)"]);
        assert_eq!(
            one("[0 1 2 3.5]"),
            vec!["1 0: /ByteRange holds a value that is not an integer"]
        );
        assert_eq!(one("[0 1 -2 3]"), vec!["1 0: /ByteRange has a negative value (-2 3)"]);
        assert_eq!(one("[5 1 9 3]"), vec!["1 0: /ByteRange starts at 5, not 0"]);
        assert_eq!(
            one("[0 10 5 3]"),
            vec!["1 0: /ByteRange ranges overlap or go backwards (0..10 then 5..8)"]
        );
        assert!(one("[0 1 9 9999]")[0].starts_with("1 0: /ByteRange 9 9999 ends past the file ("));
        // Through an indirect value.
        let src = format!(
            "1 0 obj << /ByteRange 2 0 R >> endobj\n2 0 obj [0 1 2] endobj\n{}",
            " ".repeat(100)
        );
        assert_eq!(
            hits(src.as_bytes()),
            vec!["1 0: /ByteRange has 3 numbers (pairs, at least 2)"]
        );
    }
}
