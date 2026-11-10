//! `CODEC.JBIG2`: a stream or inline image uses the JBIG2Decode filter.

use crate::facts::{ContentOp, Ctx, Location, OpLocation};
use crate::parser::Dict;
use crate::rules::values::names_filter;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct Jbig2;

static META: RuleMeta = RuleMeta {
    id: "CODEC.JBIG2",
    category: Category::Codecs,
    severity: Severity::Medium,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Image uses the JBIG2 codec",
    description: "A /Filter (or /FFilter) chain naming JBIG2Decode, on any dictionary — \
        name, array, or indirect values, any position — or on an inline image (ISO 32000-2 \
        §7.4.7). JBIG2 decoders are complex and were exploited in the wild (e.g. \
        CVE-2021-30860 FORCEDENTRY, CVE-2009-0658).",
};

const FILTER: &str = "JBIG2Decode";

impl Rule for Jbig2 {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if let Some(key) = names_filter(ctx, dict, &["Filter", "FFilter"], FILTER) {
            out.report(&META, loc, Some(format!("/{key} {FILTER}")));
        }
    }

    fn check_content_op(&self, op: &ContentOp<'_>, loc: &OpLocation, ctx: &Ctx, out: &mut Findings) {
        let Some(img) = &op.inline_image else { return };
        if names_filter(ctx, &img.dict, &["Filter", "F"], FILTER).is_some() {
            out.report(&META, loc, Some(format!("inline image {FILTER}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    fn hits(src: &[u8]) -> Vec<(String, Option<String>)> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&Jbig2])
            .iter()
            .map(|f| {
                let site = match &f.site {
                    Site::Object(l) => format!("{} {}", l.id, l.path.len()),
                    Site::Op(o) => format!("op {}", o.stream.id),
                    other => format!("{other:?}"),
                };
                (site, f.detail.clone())
            })
            .collect()
    }

    fn image(filter: &str) -> Vec<u8> {
        format!("1 0 obj << /Subtype /Image /Width 8 /Height 8 /Filter {filter} /Length 1 >> stream\nx\nendstream endobj\n").into_bytes()
    }

    #[test]
    fn filter_forms() {
        let detail = Some("/Filter JBIG2Decode".to_string());
        for f in [
            "/JBIG2Decode",
            "/JBIG#32Decode",
            "[/JBIG2Decode]",
            "[/FlateDecode /JBIG2Decode]",
        ] {
            assert_eq!(hits(&image(f)), vec![("1 0 0".into(), detail.clone())], "{f}");
        }
        // Indirect value, indirect element, second definition.
        let mut src = image("2 0 R");
        src.extend_from_slice(b"2 0 obj /FlateDecode endobj\n2 0 obj /JBIG2Decode endobj\n");
        assert_eq!(hits(&src).len(), 1);
        let mut src = image("[/AHx 3 0 R]");
        src.extend_from_slice(b"3 0 obj /JBIG2Decode endobj\n");
        assert_eq!(hits(&src).len(), 1);
        // Nested dictionary, /FFilter.
        let src = b"1 0 obj << /A << /FFilter /JBIG2Decode >> >> endobj";
        assert_eq!(
            hits(src),
            vec![("1 0 1".into(), Some("/FFilter JBIG2Decode".into()))]
        );
    }

    #[test]
    fn inline_image() {
        let data = b"q BI /W 8 /H 8 /IM true /F [/AHx /JBIG2Decode] ID 00> EI Q";
        let src = [
            format!("1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length {} >> stream\n", data.len()).as_bytes(),
            data,
            b"\nendstream endobj",
        ]
        .concat();
        assert_eq!(
            hits(&src),
            vec![("op 2 0".into(), Some("inline image JBIG2Decode".into()))]
        );
    }

    #[test]
    fn near_misses() {
        for src in [
            image("/FlateDecode"),
            image("[/DCTDecode /JPXDecode]"),
            b"1 0 obj << /Note (/Filter /JBIG2Decode) /JBIG2Globals 2 0 R >> endobj".to_vec(),
            // A name elsewhere in the dictionary, not in the filter chain.
            b"1 0 obj << /Filter /FlateDecode /Name /JBIG2Decode >> endobj".to_vec(),
            // `/F` is a filter only in an inline image.
            b"1 0 obj << /F /JBIG2Decode >> endobj".to_vec(),
            image("/JBIG2"),
        ] {
            assert!(hits(&src).is_empty(), "{}", String::from_utf8_lossy(&src));
        }
    }
}
