//! `RESOURCE.IMAGE_DIMENSIONS`: an image declares a huge or invalid size.

use crate::facts::{ContentOp, Ctx, Location, OpLocation};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::{num, values};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct ImageDimensions;

static META: RuleMeta = RuleMeta {
    id: "RESOURCE.IMAGE_DIMENSIONS",
    category: Category::Resource,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Image declares huge or invalid dimensions",
    description: "An image XObject (/Subtype /Image, any dictionary) or inline image whose \
        Width × Height exceeds `thresholds.max_image_pixels` (default 1e9), or whose Width \
        or Height is ≤ 0 or not a number. A few bytes of data can declare an image that \
        makes a server-side renderer (Ghostscript, ImageMagick, pdf.js) allocate gigabytes \
        (pixel bomb). Abbreviated keys (/W, /H) are read too, since some readers accept \
        them outside inline images; every value counts (duplicate keys, every definition \
        of an indirect value).",
};

/// Every value of the full and abbreviated key, resolved.
fn sizes(ctx: &Ctx, dict: &Dict, full: &str, abbrev: &str) -> Vec<Option<f64>> {
    values(ctx, dict, full)
        .chain(values(ctx, dict, abbrev))
        .map(PdfObject::as_number)
        .collect()
}

/// What is wrong with the image dictionary `dict`, if anything.
fn problem(ctx: &Ctx, dict: &Dict) -> Option<String> {
    let widths = sizes(ctx, dict, "Width", "W");
    let heights = sizes(ctx, dict, "Height", "H");
    for (key, vals) in [("Width", &widths), ("Height", &heights)] {
        for v in vals.iter() {
            match v {
                None => return Some(format!("{key} is not a number")),
                Some(x) if *x <= 0.0 => return Some(format!("{key} {} ≤ 0", num(*x))),
                _ => {}
            }
        }
    }
    let max = ctx.thresholds().max_image_pixels;
    let w = widths.iter().flatten().copied().fold(0.0, f64::max);
    let h = heights.iter().flatten().copied().fold(0.0, f64::max);
    // f64 is exact for products far beyond any threshold that matters; an
    // overflow is +inf, still over.
    (w * h > max as f64).then(|| format!("{} x {} pixels (max {max})", num(w), num(h)))
}

fn is_image(ctx: &Ctx, dict: &Dict) -> bool {
    values(ctx, dict, "Subtype").any(|s| s.is_name("Image"))
}

impl Rule for ImageDimensions {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if !is_image(ctx, dict) {
            return;
        }
        if let Some(p) = problem(ctx, dict) {
            out.report(&META, loc, Some(p));
        }
    }

    fn check_content_op(&self, op: &ContentOp<'_>, loc: &OpLocation, ctx: &Ctx, out: &mut Findings) {
        let Some(img) = &op.inline_image else { return };
        if let Some(p) = problem(ctx, &img.dict) {
            out.report(&META, loc, Some(format!("inline image: {p}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    fn details_with(src: &[u8], max: u64) -> Vec<Option<String>> {
        let t = Thresholds {
            max_image_pixels: max,
            ..Thresholds::default()
        };
        let ctx = Ctx::new(src, Limits::default(), t);
        run(&ctx, &[&ImageDimensions])
            .iter()
            .map(|f| f.detail.clone())
            .collect()
    }

    fn details(src: &[u8]) -> Vec<Option<String>> {
        details_with(src, 1_000_000_000)
    }

    fn image(dims: &str) -> Vec<u8> {
        format!("1 0 obj << /Type /XObject /Subtype /Image {dims} /BitsPerComponent 8 /Length 1 >> stream\nx\nendstream endobj\n").into_bytes()
    }

    fn some(s: &str) -> Vec<Option<String>> {
        vec![Some(s.to_string())]
    }

    #[test]
    fn threshold_boundary() {
        // 1e9 exactly is allowed; one more pixel row is not.
        assert!(details(&image("/Width 40000 /Height 25000")).is_empty());
        assert_eq!(
            details(&image("/Width 40000 /Height 25001")),
            some("40000 x 25001 pixels (max 1000000000)")
        );
        assert!(details(&image("/Width 30000 /Height 30000")).is_empty());
        // Policy threshold.
        assert_eq!(
            details_with(&image("/Width 100 /Height 100"), 9999),
            some("100 x 100 pixels (max 9999)")
        );
        assert!(details_with(&image("/Width 100 /Height 100"), 10000).is_empty());
        // Overflowing product.
        let huge = format!("/Width {0}.0 /Height {0}.0", "9".repeat(300));
        assert_eq!(details(&image(&huge)).len(), 1);
    }

    #[test]
    fn invalid_sizes() {
        assert_eq!(details(&image("/Width -1 /Height 8")), some("Width -1 ≤ 0"));
        assert_eq!(details(&image("/Width 8 /Height 0")), some("Height 0 ≤ 0"));
        assert_eq!(
            details(&image("/Width /Huge /Height 8")),
            some("Width is not a number")
        );
        assert_eq!(
            details(&image("/Width (8) /Height 8")),
            some("Width is not a number")
        );
    }

    #[test]
    fn evasions() {
        // Name-encoded key, indirect value (every definition), duplicate key,
        // abbreviated keys, indirect /Subtype, nested dictionary.
        let big = |dims: &str| details(&image(dims)).len();
        assert_eq!(big("/W#69dth 100000 /Height 100000"), 1);
        let mut src = image("/Width 2 0 R /Height 100000");
        src.extend_from_slice(b"2 0 obj 8 endobj\n2 0 obj 100000 endobj\n");
        assert_eq!(details(&src).len(), 1);
        assert_eq!(big("/Width 8 /Width 100000 /Height 100000"), 1);
        assert_eq!(big("/W 100000 /H 100000"), 1);
        assert_eq!(big("/Width 8 /W 100000 /Height 100000"), 1);
        let src = b"1 0 obj << /Subtype 2 0 R /Width 100000 /Height 100000 >> endobj\n2 0 obj /Image endobj";
        assert_eq!(details(src).len(), 1);
        let src = b"1 0 obj << /A << /B << /Subtype /Image /Width 100000 /Height 100000 >> >> >> endobj";
        assert_eq!(details(src).len(), 1);
    }

    #[test]
    fn inline_images() {
        let content = |data: &[u8]| {
            [
                format!("1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length {} >> stream\n", data.len()).as_bytes(),
                data,
                b"\nendstream endobj",
            ]
            .concat()
        };
        let src = content(b"BI /W 100000 /H 100000 /BPC 8 /CS /G ID xxxx EI");
        let ctx = Ctx::new(&src, Limits::default(), Thresholds::default());
        let f = run(&ctx, &[&ImageDimensions]);
        let x = f.iter().next().unwrap();
        assert!(matches!(x.site, Site::Op(_)));
        assert_eq!(
            x.detail.as_deref(),
            Some("inline image: 100000 x 100000 pixels (max 1000000000)")
        );
        assert_eq!(
            details(&content(b"BI /Width -5 /H 1 /BPC 8 /CS /G ID x EI")),
            some("inline image: Width -5 ≤ 0")
        );
        assert!(details(&content(b"BI /W 8 /H 8 /BPC 8 /CS /G ID xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx EI")).is_empty());
    }

    #[test]
    fn near_misses() {
        for src in [
            image("/Width 14043 /Height 9933"),
            // Not an image: a form, a dictionary that only mentions the size.
            b"1 0 obj << /Subtype /Form /Width 100000 /Height 100000 >> endobj".to_vec(),
            b"1 0 obj << /Width 100000 /Height 100000 >> endobj".to_vec(),
            b"1 0 obj << /Note (/Subtype /Image /Width 100000) >> endobj".to_vec(),
            // Missing size: the image is broken, not a resource problem.
            image(""),
        ] {
            assert!(details(&src).is_empty(), "{}", String::from_utf8_lossy(&src));
        }
    }
}
