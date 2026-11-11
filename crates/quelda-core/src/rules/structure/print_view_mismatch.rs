//! `STRUCT.PRINT_VIEW_MISMATCH`: content that prints but is hidden on
//! screen, so what is reviewed is not what is printed: an annotation with
//! the Print and NoView flags (ISO 32000-2 §12.5.3), or an optional content
//! group whose usage says print ON, view OFF (§8.11.4.4).

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::values;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct PrintViewMismatch;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.PRINT_VIEW_MISMATCH",
    category: Category::Structure,
    severity: Severity::Medium,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.2.0",
    message: "Content prints but is hidden on screen",
    description: "An annotation whose flags say print but do not show on screen (Print and \
        NoView set, Hidden not set, ISO 32000-2 §12.5.3), or an optional content group \
        (layer) whose usage dictionary says PrintState ON and ViewState OFF (§8.11.4.4). \
        What a person checks on screen is then not what the printer outputs. Some real \
        files use print-only layers (a \"COPY\" stamp), so balanced only warns.",
};

/// Annotation flags (ISO 32000-2 Table 167).
const HIDDEN: i64 = 1 << 1;
const PRINT: i64 = 1 << 2;
const NO_VIEW: i64 = 1 << 5;

/// The first print-but-not-view flags of `dict` (any value of a duplicate
/// `/F`), if it is an annotation (`/Type /Annot`, or `/Subtype` and `/Rect`
/// as annotations written without `/Type`).
fn print_only_flags(ctx: &Ctx, dict: &Dict) -> Option<i64> {
    let is_annot = values(ctx, dict, "Type").any(|v| v.is_name("Annot"))
        || (dict.contains_key("Rect")
            && values(ctx, dict, "Subtype").any(|v| v.as_name().is_some()));
    if !is_annot {
        return None;
    }
    values(ctx, dict, "F").find_map(|v| match v {
        PdfObject::Int(f) if f & PRINT != 0 && f & NO_VIEW != 0 && f & HIDDEN == 0 => Some(*f),
        _ => None,
    })
}

/// `/Usage /<category> /<state> /<want>` holds (any definition).
fn usage_state(ctx: &Ctx, usage: &Dict, category: &str, state: &str, want: &str) -> bool {
    values(ctx, usage, category).any(|c| match c {
        PdfObject::Dict(d) => values(ctx, d, state).any(|s| s.is_name(want)),
        _ => false,
    })
}

fn print_only_layer(ctx: &Ctx, dict: &Dict) -> bool {
    values(ctx, dict, "Usage").any(|u| match u {
        PdfObject::Dict(u) => {
            usage_state(ctx, u, "Print", "PrintState", "ON")
                && usage_state(ctx, u, "View", "ViewState", "OFF")
        }
        _ => false,
    })
}

impl Rule for PrintViewMismatch {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if let Some(f) = print_only_flags(ctx, dict) {
            out.report(
                &META,
                loc,
                Some(format!("annotation prints but is not shown (/F {f})")),
            );
        }
        if print_only_layer(ctx, dict) {
            out.report(
                &META,
                loc,
                Some("layer is ON for print, OFF for view".to_string()),
            );
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
        run(&ctx, &[&PrintViewMismatch])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn annotation_flags() {
        let src = b"1 0 obj << /Type /Annot /Subtype /Stamp /Rect [0 0 1 1] /F 36 >> endobj\n\
            2 0 obj << /Subtype /FreeText /Rect [0 0 1 1] /F 38 >> endobj\n\
            3 0 obj << /Subtype /Square /Rect [0 0 1 1] /F 4 >> endobj\n\
            4 0 obj << /Subtype /Square /Rect [0 0 1 1] /F 32 >> endobj\n\
            5 0 obj << /Subtype /Widget /Rect [0 0 1 1] /F 9 0 R >> endobj\n9 0 obj 100 endobj\n\
            6 0 obj << /Type /Filespec /F 36 >> endobj\n\
            7 0 obj << /S /Launch /F (a) >> endobj\n\
            8 0 obj << /Subtype /Square /Rect [0 0 1 1] /F 4 /F 36 >> endobj\n";
        assert_eq!(
            hits(src),
            vec![
                "1 0: annotation prints but is not shown (/F 36)",
                "5 0: annotation prints but is not shown (/F 100)",
                "8 0: annotation prints but is not shown (/F 36)",
            ]
        );
    }

    #[test]
    fn print_only_layers() {
        let src = b"1 0 obj << /Type /OCG /Name (x) /Usage << /Print << /PrintState /ON >> /View << /ViewState /OFF >> >> >> endobj\n\
            2 0 obj << /Type /OCG /Name (screen only) /Usage << /Print << /PrintState /OFF >> /View << /ViewState /ON >> >> >> endobj\n\
            3 0 obj << /Type /OCG /Name (print) /Usage << /Print << /PrintState /ON >> >> >> endobj\n\
            4 0 obj << /Type /OCG /Usage 5 0 R >> endobj\n\
            5 0 obj << /Print << /PrintState /ON >> /View << /ViewState /OFF >> >> endobj\n\
            6 0 obj << /Type /OCG /Name (watermark) /Usage << /Print << /PrintState /ON >> /View << /ViewState /ON >> >> >> endobj\n";
        assert_eq!(
            hits(src),
            vec![
                "1 0: layer is ON for print, OFF for view",
                "4 0: layer is ON for print, OFF for view",
            ]
        );
    }
}
