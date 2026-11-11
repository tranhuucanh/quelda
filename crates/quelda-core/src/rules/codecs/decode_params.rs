//! `CODEC.DECODE_PARAMS`: filter parameters (`/DecodeParms`, `/DP`) outside
//! the values ISO 32000-2 §7.4 defines: decoders size their buffers from
//! them.

use crate::facts::{ContentOp, Ctx, Location, OpLocation};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::num;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct DecodeParams;

static META: RuleMeta = RuleMeta {
    id: "CODEC.DECODE_PARAMS",
    category: Category::Codecs,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.2.0",
    message: "Filter parameters outside the spec",
    description: "Decode parameters (/DecodeParms or /DP, of a stream or an inline image) \
        with a value the spec does not allow (ISO 32000-2 §7.4.4.4, §7.4.6, §7.4.8): \
        /Predictor other than 1, 2 or 10–15, /Colors outside 1–32, /BitsPerComponent \
        other than 1, 2, 4, 8 or 16, /Columns outside 1–16777216, /Rows outside \
        0–16777216, /EarlyChange or /ColorTransform other than 0 or 1, /K not an integer, \
        or a parameter that is not a dictionary. Decoders compute buffer sizes from these \
        values; out-of-range ones have caused overflows in renderers. Real files pass.",
};

/// Largest `/Columns` and `/Rows` accepted (the decoder's own limit).
const MAX_DIM: f64 = (1 << 24) as f64;

/// An integer-valued number (`8` or `8.0`).
fn int(o: &PdfObject) -> Option<f64> {
    o.as_number().filter(|n| n.fract() == 0.0)
}

/// What is wrong with the value of `key`, if anything.
fn bad_value(key: &[u8], v: &PdfObject) -> Option<String> {
    let ok = |allowed: &dyn Fn(f64) -> bool| int(v).is_some_and(allowed);
    let fine = match key {
        b"Predictor" => ok(&|n| n == 1.0 || n == 2.0 || (10.0..=15.0).contains(&n)),
        b"Colors" => ok(&|n| (1.0..=32.0).contains(&n)),
        b"BitsPerComponent" => ok(&|n| [1.0, 2.0, 4.0, 8.0, 16.0].contains(&n)),
        b"Columns" => ok(&|n| (1.0..=MAX_DIM).contains(&n)),
        b"Rows" => ok(&|n| (0.0..=MAX_DIM).contains(&n)),
        b"EarlyChange" | b"ColorTransform" => ok(&|n| n == 0.0 || n == 1.0),
        b"K" => ok(&|_| true),
        _ => true,
    };
    if fine || matches!(v, PdfObject::Null) {
        return None;
    }
    let shown = match v {
        PdfObject::Int(_) | PdfObject::Real(_) => v.as_number().map(num).unwrap_or_default(),
        _ => "(not an integer)".to_string(),
    };
    Some(format!("/{} {shown}", String::from_utf8_lossy(key)))
}

/// The first problem in one parameter dictionary.
fn check_parms(ctx: &Ctx, parms: &Dict) -> Option<String> {
    parms.entries().iter().find_map(|(k, v)| {
        ctx.resolve(v)
            .find_map(|v| bad_value(k.as_bytes(), v))
    })
}

/// The first problem in a `/DecodeParms` value: a dictionary, `null`, or an
/// array of them (one per filter).
fn check_value(ctx: &Ctx, value: &PdfObject) -> Option<String> {
    ctx.resolve(value).find_map(|v| match v {
        PdfObject::Dict(d) => check_parms(ctx, d),
        PdfObject::Null => None,
        PdfObject::Array(items) => items.iter().find_map(|i| {
            ctx.resolve(i).find_map(|i| match i {
                PdfObject::Dict(d) => check_parms(ctx, d),
                PdfObject::Null => None,
                _ => Some("parameter is not a dictionary".to_string()),
            })
        }),
        _ => Some("parameters are not a dictionary or an array".to_string()),
    })
}

fn check(ctx: &Ctx, dict: &Dict) -> Option<String> {
    ["DecodeParms", "DP"]
        .iter()
        .flat_map(|k| dict.get_all(k))
        .find_map(|v| check_value(ctx, v))
}

impl Rule for DecodeParams {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if let Some(d) = check(ctx, dict) {
            out.report(&META, loc, Some(d));
        }
    }

    fn check_content_op(&self, op: &ContentOp<'_>, loc: &OpLocation, ctx: &Ctx, out: &mut Findings) {
        if let Some(d) = op.inline_image.as_ref().and_then(|i| check(ctx, &i.dict)) {
            out.report(&META, loc, Some(d));
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
        run(&ctx, &[&DecodeParams])
            .iter()
            .map(|f| {
                let at = match &f.site {
                    Site::Object(l) => format!("{}", l.id),
                    Site::Op(o) => format!("op {}", o.stream.id),
                    other => format!("{other:?}"),
                };
                format!("{at}: {}", f.detail.clone().unwrap_or_default())
            })
            .collect()
    }

    fn image(n: u32, parms: &str) -> String {
        format!(
            "{n} 0 obj << /Type /XObject /Subtype /Image /Width 1 /Height 1 /Filter /FlateDecode {parms} /Length 0 >> stream\n\nendstream endobj\n"
        )
    }

    #[test]
    fn real_parameters_pass() {
        let src = [
            image(1, "/DecodeParms << /Predictor 15 /Colors 3 /BitsPerComponent 8 /Columns 2480 >>"),
            image(2, "/DecodeParms [null << /Predictor 12 /Columns 5 >>]"),
            image(3, "/DecodeParms << /K -1 /Columns 1728 /Rows 2200 /BlackIs1 true >>"),
            image(4, "/DecodeParms << /ColorTransform 0 >> /DP << /EarlyChange 1 >>"),
            image(5, "/DecodeParms << /Predictor 1 /Columns 8.0 /Rows 0 >>"),
            image(6, "/DecodeParms null /Foo << /Columns 0 >>"),
            image(7, "/DecodeParms << /JBIG2Globals 20 0 R /Colors null >>"),
        ]
        .concat();
        assert!(hits(src.as_bytes()).is_empty(), "{:?}", hits(src.as_bytes()));
    }

    #[test]
    fn out_of_spec_parameters() {
        let src = [
            image(1, "/DecodeParms << /Predictor 3 >>"),
            image(2, "/DecodeParms << /Predictor 12 /Colors 0 >>"),
            image(3, "/DecodeParms << /Colors 100000 >>"),
            image(4, "/DecodeParms << /BitsPerComponent 3 >>"),
            image(5, "/DecodeParms << /Columns 2147483647 >>"),
            image(6, "/DecodeParms << /Columns -1 >>"),
            image(7, "/DecodeParms [null << /Rows 99999999 >>]"),
            image(8, "/DecodeParms << /EarlyChange 2 >>"),
            image(9, "/DP << /K (x) >>"),
            image(10, "/DecodeParms [/Bogus]"),
            image(11, "/DecodeParms 42"),
            image(12, "/DecodeParms 30 0 R"),
            "30 0 obj << /Columns 2.5 >> endobj\n".to_string(),
            "13 0 obj << /A << /DecodeParms << /Predictor 99 >> >> >> endobj\n".to_string(),
        ]
        .concat();
        assert_eq!(
            hits(src.as_bytes()),
            vec![
                "1 0: /Predictor 3",
                "2 0: /Colors 0",
                "3 0: /Colors 100000",
                "4 0: /BitsPerComponent 3",
                "5 0: /Columns 2147483647",
                "6 0: /Columns -1",
                "7 0: /Rows 99999999",
                "8 0: /EarlyChange 2",
                "9 0: /K (not an integer)",
                "10 0: parameter is not a dictionary",
                "11 0: parameters are not a dictionary or an array",
                "12 0: /Columns 2.5",
                "13 0: /Predictor 99",
            ]
        );
    }

    #[test]
    fn inline_image_parameters() {
        let data = b"q BI /W 1 /H 1 /BPC 8 /CS /G /F /Fl /DP << /Predictor 12 /Columns 0 >> ID x EI Q\n";
        let src = [
            format!(
                "1 0 obj << /Type /Page /Contents 2 0 R >> endobj\n2 0 obj << /Length {} >> stream\n",
                data.len()
            )
            .as_bytes(),
            data,
            b"\nendstream endobj\n",
        ]
        .concat();
        assert_eq!(hits(&src), vec!["op 2 0: /Columns 0"]);
    }
}
