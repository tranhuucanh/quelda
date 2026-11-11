//! Markup in embedded XML (XFA packets, XMP), in every encoding an XML
//! parser accepts: rules look for ASCII markup in "views" of the data.

use std::borrow::Cow;

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};

/// The wide encoding an XML parser reads `data` in, from its first bytes
/// (XML 1.0 appendix F: a byte order mark, or `<?` in that encoding):
/// `(name, code unit size, big endian)`. `None`: UTF-8 (or another ASCII
/// superset).
fn wide_encoding(data: &[u8]) -> Option<(&'static str, usize, bool)> {
    Some(match data.get(..4).unwrap_or(data) {
        [0, 0, 0xFE, 0xFF] | [0, 0, 0, b'<'] => ("UTF-32", 4, true),
        [0xFF, 0xFE, 0, 0] | [b'<', 0, 0, 0] => ("UTF-32", 4, false),
        [0xFE, 0xFF, ..] | [0, b'<', 0, b'?'] => ("UTF-16", 2, true),
        [0xFF, 0xFE, ..] | [b'<', 0, b'?', 0] => ("UTF-16", 2, false),
        _ => return None,
    })
}

/// `data` as ASCII: as is (UTF-8), and, when its first bytes say it is
/// UTF-16 or UTF-32, also read in that encoding, where a code unit that is
/// an ASCII byte padded with zeros becomes that byte and any other `0xFF`.
pub(crate) fn ascii_views(data: &[u8]) -> Vec<(&'static str, Cow<'_, [u8]>)> {
    let mut out = vec![("UTF-8", Cow::Borrowed(data))];
    if let Some((name, unit, big_endian)) = wide_encoding(data) {
        let view = data
            .chunks_exact(unit)
            .map(|cu| {
                let (byte, zeros) = if big_endian {
                    (cu[unit - 1], &cu[..unit - 1])
                } else {
                    (cu[0], &cu[1..])
                };
                if byte.is_ascii() && zeros.iter().all(|&z| z == 0) {
                    byte
                } else {
                    0xFF
                }
            })
            .collect();
        out.push((name, Cow::Owned(view)));
    }
    out
}

/// A start tag `<name …>` or `<prefix:name …>` in an ASCII view.
pub(crate) struct Tag {
    /// Offset of `<`.
    pub start: usize,
    /// Offset just past the closing `>` (the end of the view if unclosed).
    pub end: usize,
    /// `<… />`.
    pub empty: bool,
}

/// Start tags whose local name is `local` (ASCII case-insensitive).
pub(crate) fn start_tags<'v>(view: &'v [u8], local: &'v str) -> impl Iterator<Item = Tag> + 'v {
    memchr::memchr_iter(b'<', view).filter_map(move |start| {
        let name_end = view[start + 1..]
            .iter()
            .position(|&b| b.is_ascii_whitespace() || b == b'>' || b == b'/')
            .map_or(view.len(), |p| start + 1 + p);
        let name = &view[start + 1..name_end];
        let local_name = name.rsplit(|&b| b == b':').next().unwrap_or(name);
        if name.first().is_some_and(|b| matches!(b, b'!' | b'?'))
            || !local_name.eq_ignore_ascii_case(local.as_bytes())
        {
            return None;
        }
        let end = tag_end(view, name_end);
        let empty =
            end >= 2 && view.get(end - 2) == Some(&b'/') && view.get(end - 1) == Some(&b'>');
        Some(Tag { start, end, empty })
    })
}

/// Just past the `>` that closes a tag whose attributes start at `from`
/// (quoted values may hold `>`); the end of `view` if there is none.
fn tag_end(view: &[u8], from: usize) -> usize {
    let mut quote = None;
    for (i, &b) in view.iter().enumerate().skip(from) {
        match (quote, b) {
            (None, b'"' | b'\'') => quote = Some(b),
            (Some(q), _) if b == q => quote = None,
            (None, b'>') => return i + 1,
            _ => {}
        }
    }
    view.len()
}

/// `needle` (ASCII, case-insensitive) in `hay`.
pub(crate) fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, rest) = needle.split_first()?;
    memchr::memchr2_iter(first.to_ascii_lowercase(), first.to_ascii_uppercase(), hay).find(|&i| {
        hay.get(i + 1..i + needle.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(rest))
    })
}

/// Where embedded XML is: a stream (object index) or a string.
pub(crate) enum Packet<'s> {
    Stream(usize),
    String(&'s [u8], Location),
}

/// XFA packets named by `dict`'s `/XFA` (a stream, a string, or an array
/// of names and packets; references followed through every definition).
pub(crate) fn xfa_packets<'s>(ctx: &'s Ctx, dict: &'s Dict, loc: &Location) -> Vec<Packet<'s>> {
    let doc = ctx.document();
    let mut out = Vec::new();
    let add = |o: &'s PdfObject, out: &mut Vec<Packet<'s>>, depth: u8| {
        let mut stack = vec![(o, depth)];
        while let Some((o, depth)) = stack.pop() {
            match o {
                PdfObject::Ref(r) => {
                    for i in doc.definition_indices(*r) {
                        match &doc.objects[i].object {
                            PdfObject::Stream(_) => out.push(Packet::Stream(i)),
                            other if depth > 0 => stack.push((other, depth - 1)),
                            _ => {}
                        }
                    }
                }
                PdfObject::Array(items) if depth > 0 => {
                    stack.extend(items.iter().map(|i| (i, depth - 1)));
                }
                PdfObject::String(s) => out.push(Packet::String(s, loc.clone())),
                _ => {}
            }
        }
    };
    for v in dict.get_all("XFA") {
        add(v, &mut out, 2);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_and_tags() {
        let views = ascii_views(b"<a/>");
        assert_eq!(views.len(), 1);
        let wide: Vec<u8> = "\u{FEFF}<x:Script a='>'>1</x:Script>"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        let views = ascii_views(&wide);
        assert_eq!(views.len(), 2);
        // NUL bytes alone do not make it wide: the start decides.
        assert_eq!(ascii_views(b"<a>\0\0</a>").len(), 1);
        for (start, name) in [
            (&b"\0\0\xFE\xFF"[..], "UTF-32"),
            (b"<\0\0\0", "UTF-32"),
            (b"\xFF\xFE<\0", "UTF-16"),
            (b"<\0?\0", "UTF-16"),
        ] {
            assert_eq!(ascii_views(start)[1].0, name);
        }
        let (name, be) = &views[1];
        assert_eq!(*name, "UTF-16");
        let tags: Vec<Tag> = start_tags(be, "script").collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(&be[tags[0].start..tags[0].end], b"<x:Script a='>'>");
        assert!(!tags[0].empty);
        let tags: Vec<Tag> = start_tags(b"<script/><scripts></script><script", "script").collect();
        assert_eq!(tags.len(), 2);
        assert!(tags[0].empty);
        assert_eq!(tags[1].end, 34);
        assert_eq!(find_ci(b"aXInClUdE", b"xinclude"), Some(1));
        assert_eq!(find_ci(b"xinclud", b"xinclude"), None);
        assert_eq!(find_ci(b"<?XML-stylesheet", b"<?xml-stylesheet"), Some(0));
    }
}
