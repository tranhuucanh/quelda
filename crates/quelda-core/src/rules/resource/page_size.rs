//! `RESOURCE.PAGE_SIZE`: a page box is huge or degenerate.

use std::collections::HashSet;

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::{num, values};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct PageSize;

static META: RuleMeta = RuleMeta {
    id: "RESOURCE.PAGE_SIZE",
    category: Category::Resource,
    severity: Severity::Medium,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Page box is huge or degenerate",
    description: "A dictionary (any: page, /Pages node, nested) with a MediaBox, CropBox, \
        BleedBox, TrimBox or ArtBox whose longest side × the dictionary's own /UserUnit \
        exceeds `thresholds.max_page_side_pt` (default 28800 pt ≈ 10 m), or that is \
        degenerate (zero width or height, not an array of 4 numbers). Rendering such a \
        page at a normal resolution makes a server-side renderer allocate a huge bitmap \
        (Ghostscript can render any of the five boxes); degenerate boxes break scaling \
        code. Every value counts (duplicate keys, every definition of an indirect value or \
        element).",
};

const BOXES: [&str; 5] = ["MediaBox", "CropBox", "BleedBox", "TrimBox", "ArtBox"];

/// Candidate numbers of each coordinate of a box value; `None` if the value
/// is not an array of 4 numbers.
fn coords(ctx: &Ctx, value: &PdfObject) -> Option<[Vec<f64>; 4]> {
    let items = value.as_array()?;
    if items.len() != 4 {
        return None;
    }
    let mut out: [Vec<f64>; 4] = Default::default();
    for (slot, item) in out.iter_mut().zip(items) {
        for v in ctx.resolve(item) {
            slot.push(v.as_number()?);
        }
        if slot.is_empty() {
            return None;
        }
    }
    Some(out)
}

fn min(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::INFINITY, f64::min)
}

fn max(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::NEG_INFINITY, f64::max)
}

/// Largest side length any combination of candidates gives.
fn longest(a: &[f64], b: &[f64]) -> f64 {
    (max(b) - min(a)).max(max(a) - min(b))
}

/// Some combination of candidates gives a zero length.
fn can_be_zero(a: &[f64], b: &[f64]) -> bool {
    let key = |x: f64| (x + 0.0).to_bits(); // -0.0 → 0.0
    let set: HashSet<u64> = a.iter().map(|&x| key(x)).collect();
    b.iter().any(|&x| set.contains(&key(x)))
}

fn problem(ctx: &Ctx, dict: &Dict) -> Option<String> {
    let unit = values(ctx, dict, "UserUnit")
        .filter_map(PdfObject::as_number)
        .filter(|&u| u > 0.0)
        .fold(None, |m: Option<f64>, u| Some(m.map_or(u, |m| m.max(u))))
        .unwrap_or(1.0);
    let limit = ctx.thresholds().max_page_side_pt;
    for key in BOXES {
        for value in values(ctx, dict, key) {
            let Some([x0, y0, x1, y1]) = coords(ctx, value) else {
                return Some(format!("{key} is not an array of 4 numbers"));
            };
            if can_be_zero(&x0, &x1) || can_be_zero(&y0, &y1) {
                return Some(format!("{key} has zero width or height"));
            }
            let (w, h) = (longest(&x0, &x1) * unit, longest(&y0, &y1) * unit);
            if w.max(h) > limit {
                return Some(format!(
                    "{key} {} x {} pt (max side {})",
                    num(w),
                    num(h),
                    num(limit)
                ));
            }
        }
    }
    None
}

impl Rule for PageSize {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if let Some(p) = problem(ctx, dict) {
            out.report(&META, loc, Some(p));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn details_with(src: &[u8], max: f64) -> Vec<Option<String>> {
        let t = Thresholds {
            max_page_side_pt: max,
            ..Thresholds::default()
        };
        let ctx = Ctx::new(src, Limits::default(), t);
        run(&ctx, &[&PageSize]).iter().map(|f| f.detail.clone()).collect()
    }

    fn details(src: &[u8]) -> Vec<Option<String>> {
        details_with(src, 28_800.0)
    }

    fn page(entries: &str) -> Vec<u8> {
        format!("1 0 obj << /Type /Page {entries} >> endobj\n9 0 obj 100000 endobj\n9 0 obj 50 endobj\n8 0 obj [0 0 100000 100000] endobj\n").into_bytes()
    }

    fn some(s: &str) -> Vec<Option<String>> {
        vec![Some(s.to_string())]
    }

    #[test]
    fn threshold_boundary() {
        assert!(details(&page("/MediaBox [0 0 28800 100]")).is_empty());
        assert_eq!(
            details(&page("/MediaBox [0 0 28800.5 100]")),
            some("MediaBox 28800.5 x 100 pt (max side 28800)")
        );
        assert!(details(&page("/MediaBox [0 0 2384 3370]")).is_empty());
        assert!(details(&page("/MediaBox [0 0 14400 14400]")).is_empty());
        // Negative coordinates: the side is the distance.
        assert_eq!(details(&page("/MediaBox [-20000 0 20000 10]")).len(), 1);
        // Policy threshold.
        assert_eq!(details_with(&page("/MediaBox [0 0 595 842]"), 800.0).len(), 1);
        assert!(details_with(&page("/MediaBox [0 0 595 842]"), 842.0).is_empty());
    }

    #[test]
    fn user_unit_of_the_same_dictionary() {
        assert_eq!(
            details(&page("/MediaBox [0 0 14400 14400] /UserUnit 10")),
            some("MediaBox 144000 x 144000 pt (max side 28800)")
        );
        assert!(details(&page("/MediaBox [0 0 14400 14400] /UserUnit 2")).is_empty());
        assert!(details(&page("/MediaBox [0 0 50000 50000] /UserUnit 0.5")).is_empty());
        // Non-positive or non-numeric UserUnit: ignored (1).
        assert!(details(&page("/MediaBox [0 0 1000 1000] /UserUnit -50")).is_empty());
        assert!(details(&page("/MediaBox [0 0 1000 1000] /UserUnit /x")).is_empty());
        // Indirect UserUnit: every definition (9 0 obj is 100000 and 50).
        assert_eq!(details(&page("/MediaBox [0 0 1000 1000] /UserUnit 9 0 R")).len(), 1);
    }

    #[test]
    fn every_box_and_evasion() {
        for e in [
            "/CropBox [0 0 50000 50000]",
            "/BleedBox [0 0 50000 10]",
            "/TrimBox [0 0 10 50000]",
            "/ArtBox [0 0 50000 50000]",
            "/MediaBox 8 0 R",
            "/MediaBox [0 0 9 0 R 10]",
            "/Media#42ox [0 0 50000 50000]",
            "/MediaBox [0 0 595 842] /MediaBox [0 0 50000 50000]",
            "/QueldaNest << /L2 << /MediaBox [0 0 50000 50000] >> >>",
        ] {
            assert_eq!(details(&page(e)).len(), 1, "{e}");
        }
    }

    #[test]
    fn degenerate_boxes() {
        for (e, want) in [
            ("/MediaBox [0 0 0 0]", "MediaBox has zero width or height"),
            ("/MediaBox [10 0 10 842]", "MediaBox has zero width or height"),
            ("/MediaBox [0 -0.0 595 0]", "MediaBox has zero width or height"),
            ("/MediaBox [0 0 595]", "MediaBox is not an array of 4 numbers"),
            ("/MediaBox [0 0 595 842 1]", "MediaBox is not an array of 4 numbers"),
            ("/MediaBox [0 0 /a 842]", "MediaBox is not an array of 4 numbers"),
            ("/MediaBox (0 0 595 842)", "MediaBox is not an array of 4 numbers"),
            ("/CropBox [0 0 7 0 R 842]", "CropBox is not an array of 4 numbers"),
        ] {
            assert_eq!(details(&page(e)), some(want), "{e}");
        }
    }

    #[test]
    fn near_misses() {
        for e in [
            "/MediaBox [0 0 28000 2000]",
            "/Note (/MediaBox [0 0 100000 100000])",
            "/BBox [0 0 100000 100000]",
            "/MediaBoxX [0 0 0 0]",
        ] {
            assert!(details(&page(e)).is_empty(), "{e}");
        }
    }
}
