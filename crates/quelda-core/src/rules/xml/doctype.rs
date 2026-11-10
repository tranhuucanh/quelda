//! `XML.DOCTYPE`: embedded XML (XMP metadata, XFA) declares a DOCTYPE or an
//! ENTITY.

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::values;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct Doctype;

static META: RuleMeta = RuleMeta {
    id: "XML.DOCTYPE",
    category: Category::Xml,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Embedded XML declares a DOCTYPE or ENTITY (XXE risk)",
    description: "A decoded XML stream (XMP metadata, XFA packet) — or a stream of unknown \
        role, which a reader could still parse as XML, or an XFA packet written as a string — \
        contains `<!DOCTYPE` or `<!ENTITY` \
        (ASCII case-insensitive, in UTF-8, UTF-16 or UTF-32). Document type declarations \
        enable XML external entity (XXE) and entity expansion (billion laughs) attacks on \
        the XML parser of the reader or of server-side tools.",
};

const MARKERS: [&str; 2] = ["<!DOCTYPE", "<!ENTITY"];

/// `(name, code unit size, big endian)`. ASCII text in UTF-16BE also reads
/// as UTF-16LE shifted by one byte (same for UTF-32), so the detail does not
/// name the byte order.
const ENCODINGS: [(&str, usize, bool); 5] = [
    ("UTF-8", 1, false),
    ("UTF-16", 2, true),
    ("UTF-16", 2, false),
    ("UTF-32", 4, true),
    ("UTF-32", 4, false),
];

/// `marker` (ASCII) encoded with `unit`-byte code units, at `at` in `data`.
fn encoded_at(data: &[u8], at: usize, marker: &str, unit: usize, big_endian: bool) -> bool {
    let len = marker.len() * unit;
    let Some(window) = data.get(at..at.saturating_add(len)) else {
        return false;
    };
    marker.bytes().enumerate().all(|(i, m)| {
        let cu = &window[i * unit..(i + 1) * unit];
        let (byte, zeros) = if big_endian {
            (cu[unit - 1], &cu[..unit - 1])
        } else {
            (cu[0], &cu[1..])
        };
        byte.eq_ignore_ascii_case(&m) && zeros.iter().all(|&z| z == 0)
    })
}

/// The first DOCTYPE/ENTITY declaration in `data`: `(marker, encoding)`.
fn find_declaration(data: &[u8]) -> Option<(&'static str, &'static str)> {
    for i in memchr::memchr_iter(b'<', data) {
        // Both markers start `<!`: in every encoding the `!` byte is 1, 2
        // or 4 bytes after this `<`.
        if ![1, 2, 4].iter().any(|&d| data.get(i + d) == Some(&b'!')) {
            continue;
        }
        for (enc, unit, big_endian) in ENCODINGS {
            // Big endian: the `<` byte is the last of its code unit.
            let Some(start) = (if big_endian {
                i.checked_sub(unit - 1)
            } else {
                Some(i)
            }) else {
                continue;
            };
            for marker in MARKERS {
                if encoded_at(data, start, marker, unit, big_endian) {
                    return Some((marker, enc));
                }
            }
        }
    }
    None
}

impl Rule for Doctype {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        // XFA packets written as strings (`/XFA (…)` or `[(name) (…) …]`,
        // directly or through references).
        for v in values(ctx, dict, "XFA") {
            let items = match v {
                PdfObject::Array(items) => items.as_slice(),
                v => std::slice::from_ref(v),
            };
            let found = items
                .iter()
                .flat_map(|i| ctx.resolve(i))
                .filter_map(PdfObject::as_string)
                .find_map(find_declaration);
            if let Some((marker, enc)) = found {
                out.report(&META, loc, Some(format!("{marker} in XFA string ({enc})")));
                break;
            }
        }
        // A stream object's own dictionary.
        if !loc.is_object()
            || ctx
                .objects()
                .get(loc.object)
                .and_then(|e| e.object.as_stream())
                .is_none()
        {
            return;
        }
        let roles = ctx.stream_roles(loc.object);
        if !(roles.xml || roles.speculative()) {
            return;
        }
        let Some(data) = ctx.decoded_stream(loc) else {
            return;
        };
        if let Some((marker, enc)) = find_declaration(&data) {
            let what = if roles.xml { "XML" } else { "unknown-role" };
            out.report(&META, loc, Some(format!("{marker} in {what} stream ({enc})")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn encode(s: &str, unit: usize, big_endian: bool) -> Vec<u8> {
        s.bytes()
            .flat_map(|b| {
                let mut cu = vec![0u8; unit];
                if big_endian {
                    cu[unit - 1] = b;
                } else {
                    cu[0] = b;
                }
                cu
            })
            .collect()
    }

    #[test]
    fn finds_declarations_in_every_encoding() {
        assert_eq!(
            find_declaration(b"<?xml?><!DOCTYPE x>"),
            Some(("<!DOCTYPE", "UTF-8"))
        );
        assert_eq!(
            find_declaration(b"<x><!entity a 'b'></x>"),
            Some(("<!ENTITY", "UTF-8"))
        );
        assert_eq!(
            find_declaration(b"<!dOcTyPe html>"),
            Some(("<!DOCTYPE", "UTF-8"))
        );
        for (enc, unit, be) in ENCODINGS {
            let mut data = vec![0xFF, 0xFE, 0, 0];
            data.extend(encode("<?xml version='1.0'?><!DOCTYPE x [<!ENTITY a 'b'>]>", unit, be));
            assert_eq!(find_declaration(&data), Some(("<!DOCTYPE", enc)), "{enc}");
            // At the very start too.
            let data = encode("<!ENTITY a 'b'>", unit, be);
            assert_eq!(find_declaration(&data), Some(("<!ENTITY", enc)), "{enc}");
        }
    }

    #[test]
    fn near_misses() {
        for data in [
            &b"<x>&lt;!DOCTYPE x&gt;</x>"[..],
            b"<!-- DOCTYPE -->",
            b"< !DOCTYPE x>",
            b"<!DOCTYP",
            b"<!ELEMENT a ANY>",
            b"",
            b"<",
        ] {
            assert_eq!(find_declaration(data), None, "{:?}", String::from_utf8_lossy(data));
        }
        // UTF-16 with a non-zero high byte is another character.
        let mut data = encode("<!DOCTYPE", 2, false);
        data[3] = 1;
        assert_eq!(find_declaration(&data), None);
    }

    /// Before Step 16: every encoding tried at every `<`.
    fn find_declaration_oracle(data: &[u8]) -> Option<(&'static str, &'static str)> {
        for (i, _) in data.iter().enumerate().filter(|&(_, &b)| b == b'<') {
            for (enc, unit, big_endian) in ENCODINGS {
                let Some(start) = (if big_endian {
                    i.checked_sub(unit - 1)
                } else {
                    Some(i)
                }) else {
                    continue;
                };
                for marker in MARKERS {
                    if encoded_at(data, start, marker, unit, big_endian) {
                        return Some((marker, enc));
                    }
                }
            }
        }
        None
    }

    #[test]
    fn same_as_oracle() {
        let pieces: Vec<Vec<u8>> = ["<!DOCTYPE", "<!entity", "<!DOC", "<", "!", "x"]
            .iter()
            .flat_map(|m| [1, 2, 4].map(|u| [encode(m, u, false), encode(m, u, true)]))
            .flatten()
            .chain([vec![0], vec![0, 0, 0]])
            .collect();
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..3000 {
            let mut data = Vec::new();
            for _ in 0..12 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                data.extend_from_slice(&pieces[(x % pieces.len() as u64) as usize]);
            }
            assert_eq!(find_declaration(&data), find_declaration_oracle(&data), "{data:?}");
        }
    }

    fn details(src: &[u8]) -> Vec<Option<String>> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&Doctype]).iter().map(|f| f.detail.clone()).collect()
    }

    fn stream(num: u32, dict: &str, data: &[u8]) -> Vec<u8> {
        [
            format!("{num} 0 obj << {dict} /Length {} >> stream\n", data.len()).as_bytes(),
            data,
            b"\nendstream endobj\n",
        ]
        .concat()
    }

    const DTD: &[u8] = b"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><x/>";

    #[test]
    fn xml_streams() {
        let src = [
            &b"1 0 obj << /Metadata 2 0 R >> endobj\n"[..],
            &stream(2, "/Filter /AHx", &hex(DTD)),
        ]
        .concat();
        assert_eq!(
            details(&src),
            vec![Some("<!DOCTYPE in XML stream (UTF-8)".into())]
        );
        let src = stream(2, "/Type /Metadata /Subtype /XML", DTD);
        assert_eq!(details(&src).len(), 1);
        // XFA packet in an array.
        let src = [
            &b"1 0 obj << /XFA [(template) 2 0 R] >> endobj\n"[..],
            &stream(2, "", DTD),
        ]
        .concat();
        assert_eq!(
            details(&src),
            vec![Some("<!DOCTYPE in XML stream (UTF-8)".into())]
        );
    }

    #[test]
    fn unknown_role_stream_counts() {
        let src = [&b"1 0 obj << /Q 2 0 R >> endobj\n"[..], &stream(2, "", DTD)].concat();
        assert_eq!(
            details(&src),
            vec![Some("<!DOCTYPE in unknown-role stream (UTF-8)".into())]
        );
        // `/XFA 3 0 R` → array → stream: the role follows the array.
        let src = [
            &b"1 0 obj << /XFA 3 0 R >> endobj\n3 0 obj [(template) 2 0 R] endobj\n"[..],
            &stream(2, "", DTD),
        ]
        .concat();
        assert_eq!(
            details(&src),
            vec![Some("<!DOCTYPE in XML stream (UTF-8)".into())]
        );
    }

    #[test]
    fn xfa_string_packets() {
        let dtd = String::from_utf8_lossy(DTD).replace('"', "'");
        for src in [
            format!("1 0 obj << /XFA [(template) ({dtd})] >> endobj\n"),
            format!("1 0 obj << /XFA ({dtd}) >> endobj\n"),
            format!("1 0 obj << /XFA 2 0 R >> endobj\n2 0 obj [(template) 3 0 R] endobj\n3 0 obj ({dtd}) endobj\n"),
            format!("1 0 obj << /XFA 2 0 R >> endobj\n2 0 obj [(a) (b)] endobj\n2 0 obj [(template) ({dtd})] endobj\n"),
        ] {
            assert_eq!(
                details(src.as_bytes()),
                vec![Some("<!DOCTYPE in XFA string (UTF-8)".into())],
                "{src}"
            );
        }
        let clean = b"1 0 obj << /XFA [(template) (<template/>)] >> endobj\n";
        assert!(details(clean).is_empty());
    }

    #[test]
    fn content_image_and_clean_xml_do_not_count() {
        let src = [
            &b"1 0 obj << /Contents 2 0 R /Metadata 4 0 R >> endobj\n"[..],
            &stream(2, "", b"BT (<!DOCTYPE) Tj ET"),
            &stream(3, "/Subtype /Image /Width 1 /Height 1", b"<!DOCTYPE"),
            &stream(4, "", b"<x:xmpmeta xmlns:x='adobe:ns:meta/'/>"),
            &stream(5, "/Type /EmbeddedFile", b"<!DOCTYPE html>"),
            b"6 0 obj << /Note (<!DOCTYPE x>) >> endobj\n",
        ]
        .concat();
        assert!(details(&src).is_empty());
    }

    fn hex(data: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = data.iter().flat_map(|b| format!("{b:02X}").into_bytes()).collect();
        v.push(b'>');
        v
    }
}
