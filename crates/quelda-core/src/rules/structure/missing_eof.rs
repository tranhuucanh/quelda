//! `STRUCT.MISSING_EOF`: no `%%EOF` marker.

use crate::facts::Ctx;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct MissingEof;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.MISSING_EOF",
    category: Category::Structure,
    severity: Severity::Low,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "File has no %%EOF marker",
    description: "No `%%EOF` anywhere in the file (ISO 32000-2 §7.5.5): the file is \
        truncated or hand-crafted, and readers fall back to their own repair logic, \
        where they disagree with each other.",
};

impl Rule for MissingEof {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        if ctx.structure().eofs.is_empty() {
            out.report(&META, Site::Document, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn fires(src: &[u8]) -> bool {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&MissingEof]).fired(META.id)
    }

    #[test]
    fn detects_missing_marker() {
        assert!(fires(b"%PDF-1.7\n1 0 obj << >> endobj\n"));
        assert!(fires(b"%PDF-1.7\n%%E0F\n"));
        assert!(fires(b"%PDF-1.7\n%EOF\n"));
        assert!(fires(b""));
    }

    #[test]
    fn marker_anywhere_counts() {
        assert!(!fires(b"%PDF-1.7\n%%EOF"));
        assert!(!fires(b"%PDF-1.7\n%%EOF  \r\n"));
        assert!(!fires(b"%PDF-1.7\n%%EOF\nmore"));
    }
}
