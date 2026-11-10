//! Reading dictionary values in code rules the way declarative rules do
//! (ADR #19): every value of a duplicate key, and an indirect value through
//! every definition of the referenced object (one level; union).

use crate::facts::Ctx;
use crate::parser::{Dict, Name, PdfObject};

/// Every value `key` may stand for in `dict`.
pub(crate) fn values<'s>(
    ctx: &'s Ctx,
    dict: &'s Dict,
    key: &'s str,
) -> impl Iterator<Item = &'s PdfObject> + 's {
    dict.get_all(key).flat_map(move |v| ctx.resolve(v))
}

/// A `/Filter` value as filter chains: one per definition the value stands
/// for. A chain has one entry per position, holding the names that position
/// may stand for (an element that is a reference: every definition).
/// A value that is neither a name nor an array gives no chain.
pub(crate) fn filter_chains<'s>(ctx: &'s Ctx, value: &'s PdfObject) -> Vec<Vec<Vec<&'s Name>>> {
    ctx.resolve(value)
        .filter_map(|v| match v {
            PdfObject::Name(n) => Some(vec![vec![n]]),
            PdfObject::Array(items) => Some(
                items
                    .iter()
                    .map(|i| ctx.resolve(i).filter_map(PdfObject::as_name).collect())
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// The full name of a filter, given in full or abbreviated (inline image
/// abbreviations; readers also accept them on streams).
pub(crate) fn canonical_filter(name: &Name) -> &[u8] {
    match name.as_bytes() {
        b"AHx" => b"ASCIIHexDecode",
        b"A85" => b"ASCII85Decode",
        b"LZW" => b"LZWDecode",
        b"Fl" => b"FlateDecode",
        b"RL" => b"RunLengthDecode",
        b"CCF" => b"CCITTFaxDecode",
        b"DCT" => b"DCTDecode",
        other => other,
    }
}

/// The first of `keys` whose filter chain (any position, any definition)
/// names `filter`.
pub(crate) fn names_filter(
    ctx: &Ctx,
    dict: &Dict,
    keys: &[&'static str],
    filter: &str,
) -> Option<&'static str> {
    keys.iter().copied().find(|key| {
        dict.get_all(key).any(|v| {
            filter_chains(ctx, v)
                .iter()
                .flatten()
                .flatten()
                .any(|n| canonical_filter(n) == filter.as_bytes())
        })
    })
}

/// A number for finding details: integers without a fraction.
pub(crate) fn num(v: f64) -> String {
    if v.abs() >= 1e15 {
        format!("{v:e}")
    } else if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};

    fn ctx(src: &[u8]) -> Ctx<'_> {
        Ctx::new(src, Limits::default(), Thresholds::default())
    }

    fn dict_of<'c>(c: &'c Ctx, num: u32) -> &'c Dict {
        c.objects()
            .iter()
            .find(|e| e.id.num == num)
            .and_then(|e| match &e.object {
                PdfObject::Dict(d) => Some(d),
                PdfObject::Stream(s) => Some(&s.dict),
                _ => None,
            })
            .unwrap()
    }

    fn numbers(ctx: &Ctx, dict: &Dict, key: &str) -> Vec<Option<f64>> {
        values(ctx, dict, key).map(PdfObject::as_number).collect()
    }

    fn text(name: &Name) -> String {
        String::from_utf8_lossy(name.as_bytes()).into_owned()
    }

    #[test]
    fn values_follow_duplicates_and_every_definition() {
        let src = b"1 0 obj << /W 2 0 R /W 5 /H /x >> endobj\n2 0 obj 3 endobj\n2 0 obj 4.5 endobj";
        let c = ctx(src);
        let d = dict_of(&c, 1);
        assert_eq!(numbers(&c, d, "W"), vec![Some(3.0), Some(4.5), Some(5.0)]);
        assert_eq!(numbers(&c, d, "H"), vec![None]);
        assert!(numbers(&c, d, "Missing").is_empty());
        // Dangling reference: nothing.
        let c2 = ctx(b"1 0 obj << /W 9 0 R >> endobj");
        assert!(numbers(&c2, dict_of(&c2, 1), "W").is_empty());
    }

    #[test]
    fn filter_chains_resolve_arrays_and_elements() {
        let src = b"1 0 obj << /Filter 2 0 R /F2 [/AHx 3 0 R] /F3 (x) >> endobj\n\
            2 0 obj [/FlateDecode /JBIG2Decode] endobj\n2 0 obj /JPXDecode endobj\n\
            3 0 obj /A85 endobj\n3 0 obj /LZW endobj";
        let c = ctx(src);
        let d = dict_of(&c, 1);
        let names = |key: &str| -> Vec<Vec<Vec<String>>> {
            filter_chains(&c, d.get(key).unwrap())
                .into_iter()
                .map(|ch| {
                    ch.into_iter()
                        .map(|p| p.into_iter().map(text).collect())
                        .collect()
                })
                .collect()
        };
        assert_eq!(
            names("Filter"),
            vec![
                vec![vec!["FlateDecode".to_string()], vec!["JBIG2Decode".into()]],
                vec![vec!["JPXDecode".to_string()]],
            ]
        );
        assert_eq!(
            names("F2"),
            vec![vec![
                vec!["AHx".to_string()],
                vec!["A85".into(), "LZW".into()]
            ]]
        );
        assert!(names("F3").is_empty());
        assert_eq!(
            names_filter(&c, d, &["Filter"], "JPXDecode"),
            Some("Filter")
        );
        assert_eq!(names_filter(&c, d, &["X", "F2"], "LZWDecode"), Some("F2"));
        assert_eq!(names_filter(&c, d, &["F2"], "ASCIIHexDecode"), Some("F2"));
        assert_eq!(names_filter(&c, d, &["Filter", "F2"], "DCTDecode"), None);
    }

    #[test]
    fn canonical_names() {
        for (a, f) in [
            ("AHx", "ASCIIHexDecode"),
            ("A85", "ASCII85Decode"),
            ("LZW", "LZWDecode"),
            ("Fl", "FlateDecode"),
            ("RL", "RunLengthDecode"),
            ("CCF", "CCITTFaxDecode"),
            ("DCT", "DCTDecode"),
            ("JBIG2Decode", "JBIG2Decode"),
        ] {
            assert_eq!(canonical_filter(&Name::from(a)), f.as_bytes());
        }
    }

    #[test]
    fn number_text() {
        assert_eq!(num(100000.0), "100000");
        assert_eq!(num(-1.0), "-1");
        assert_eq!(num(1.5), "1.5");
        assert_eq!(num(1e300), "1e300");
    }
}
