//! `STRUCT.FILTER_CHAIN`: a stream (or inline image) has a long filter
//! chain, or repeats a filter.

use crate::facts::{ContentOp, Ctx, Location, OpLocation};
use crate::parser::{Dict, Name};
use crate::rules::values::{canonical_filter, filter_chains};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct FilterChain;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.FILTER_CHAIN",
    category: Category::Structure,
    severity: Severity::Medium,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Stream uses an unusual filter chain",
    description: "A stream's /Filter chain (or an inline image's) has more than \
        `thresholds.max_filter_chain` (default 2) filters, or uses the same filter twice \
        (abbreviations count as their full name). Real files almost never need more than \
        two; stacked encodings are used to hide content from scanners and to multiply \
        decoding work.",
};

/// What is wrong with `chains` (one per definition of the `/Filter` value).
fn problem(chains: &[Vec<Vec<&Name>>], max: u32) -> Option<String> {
    for chain in chains {
        if chain.len() as u64 > u64::from(max) {
            return Some(format!("{} filters (max {max})", chain.len()));
        }
        for (i, pos) in chain.iter().enumerate() {
            for later in &chain[i + 1..] {
                if let Some(n) = pos
                    .iter()
                    .find(|n| later.iter().any(|m| canonical_filter(m) == canonical_filter(n)))
                {
                    return Some(format!(
                        "filter {} repeated",
                        String::from_utf8_lossy(canonical_filter(n))
                    ));
                }
            }
        }
    }
    None
}

fn check(dict: &Dict, keys: &[&str], ctx: &Ctx) -> Option<String> {
    let max = ctx.thresholds().max_filter_chain;
    keys.iter()
        .flat_map(|k| dict.get_all(k))
        .find_map(|v| problem(&filter_chains(ctx, v), max))
}

impl Rule for FilterChain {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        let is_stream = loc.is_object()
            && ctx
                .objects()
                .get(loc.object)
                .is_some_and(|e| e.object.as_stream().is_some());
        if !is_stream {
            return;
        }
        if let Some(p) = check(dict, &["Filter"], ctx) {
            out.report(&META, Site::Object(loc.clone()), Some(p));
        }
    }

    fn check_content_op(&self, op: &ContentOp<'_>, loc: &OpLocation, ctx: &Ctx, out: &mut Findings) {
        let Some(img) = &op.inline_image else { return };
        if let Some(p) = check(&img.dict, &["Filter", "F"], ctx) {
            out.report(&META, loc, Some(format!("inline image: {p}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn details_with(src: &[u8], max: u32) -> Vec<Option<String>> {
        let t = Thresholds {
            max_filter_chain: max,
            ..Thresholds::default()
        };
        let ctx = Ctx::new(src, Limits::default(), t);
        run(&ctx, &[&FilterChain])
            .iter()
            .map(|f| f.detail.clone())
            .collect()
    }

    fn details(src: &[u8]) -> Vec<Option<String>> {
        details_with(src, 2)
    }

    fn stream(filter: &str) -> Vec<u8> {
        format!("1 0 obj << /Filter {filter} /Length 1 >> stream\nx\nendstream endobj\n3 0 obj /FlateDecode endobj\n4 0 obj [/AHx /A85 /Fl] endobj\n").into_bytes()
    }

    #[test]
    fn long_chains() {
        let three = vec![Some("3 filters (max 2)".to_string())];
        assert_eq!(details(&stream("[/A85 /AHx /Fl]")), three);
        assert_eq!(details(&stream("[/ASCII#38#35Decode /AHx /Fl]")), three);
        assert_eq!(details(&stream("4 0 R")), three);
        assert_eq!(details(&stream("[/A85 /AHx 3 0 R]")), three);
        // Threshold boundary and policy.
        assert!(details(&stream("[/A85 /Fl]")).is_empty());
        assert!(details_with(&stream("[/A85 /AHx /Fl]"), 3).is_empty());
        assert_eq!(
            details_with(&stream("[/A85 /Fl]"), 1),
            vec![Some("2 filters (max 1)".to_string())]
        );
    }

    #[test]
    fn repeated_filters() {
        let rep = vec![Some("filter FlateDecode repeated".to_string())];
        assert_eq!(details(&stream("[/FlateDecode /FlateDecode]")), rep);
        assert_eq!(details(&stream("[/Fl /FlateDecode]")), rep);
        assert_eq!(details(&stream("[3 0 R /Fl]")), rep);
        assert!(details(&stream("[/AHx /A85]")).is_empty());
    }

    #[test]
    fn only_stream_dictionaries_and_inline_images() {
        // A filter array on a plain dictionary does nothing.
        assert!(details(b"1 0 obj << /Filter [/Fl /Fl /Fl] >> endobj").is_empty());
        assert!(details(b"1 0 obj << /A << /Filter [/Fl /Fl /Fl] /Length 1 >> >> endobj").is_empty());
        let data = b"BI /W 1 /H 1 /CS /G /BPC 8 /F [/AHx /AHx] ID 00> EI";
        let src = [
            format!("1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length {} >> stream\n", data.len()).as_bytes(),
            data,
            b"\nendstream endobj",
        ]
        .concat();
        assert_eq!(
            details(&src),
            vec![Some("inline image: filter ASCIIHexDecode repeated".to_string())]
        );
    }
}
