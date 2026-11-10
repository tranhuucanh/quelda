//! `CODEC.JPX`: a stream or inline image uses the JPXDecode (JPEG 2000) filter.

use crate::facts::{ContentOp, Ctx, Location, OpLocation};
use crate::parser::Dict;
use crate::rules::values::names_filter;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct Jpx;

static META: RuleMeta = RuleMeta {
    id: "CODEC.JPX",
    category: Category::Codecs,
    severity: Severity::Low,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Image uses the JPEG 2000 (JPX) codec",
    description: "A /Filter (or /FFilter) chain naming JPXDecode, on any dictionary — name, \
        array, or indirect values, any position — or on an inline image (ISO 32000-2 \
        §7.4.9). JPEG 2000 decoders (OpenJPEG, Kakadu, vendor codecs) have had many memory \
        safety bugs.",
};

const FILTER: &str = "JPXDecode";

impl Rule for Jpx {
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
    use crate::rules::run;

    fn details(src: &[u8]) -> Vec<Option<String>> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&Jpx]).iter().map(|f| f.detail.clone()).collect()
    }

    fn image(filter: &str) -> Vec<u8> {
        format!("1 0 obj << /Subtype /Image /Width 8 /Height 8 /Filter {filter} /Length 1 >> stream\nx\nendstream endobj\n2 0 obj /JPXDecode endobj\n").into_bytes()
    }

    #[test]
    fn detects() {
        let want = vec![Some("/Filter JPXDecode".to_string())];
        for f in ["/JPXDecode", "/JPX#44ecode", "[/JPXDecode]", "2 0 R", "[/Fl 2 0 R]"] {
            assert_eq!(details(&image(f)), want, "{f}");
        }
        let data = b"BI /W 1 /H 1 /CS /G /BPC 8 /Filter /JPXDecode ID x EI";
        let src = [
            format!("1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length {} >> stream\n", data.len()).as_bytes(),
            data,
            b"\nendstream endobj",
        ]
        .concat();
        assert_eq!(details(&src), vec![Some("inline image JPXDecode".to_string())]);
    }

    #[test]
    fn near_misses() {
        for f in ["/DCTDecode", "[/JBIG2Decode /FlateDecode]", "(JPXDecode)", "/JPX"] {
            assert!(details(&image(f)).is_empty(), "{f}");
        }
    }
}
