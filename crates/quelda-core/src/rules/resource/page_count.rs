//! `RESOURCE.PAGE_COUNT`: too many pages, real or declared.

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::{num, values};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct PageCount;

static META: RuleMeta = RuleMeta {
    id: "RESOURCE.PAGE_COUNT",
    category: Category::Resource,
    severity: Severity::Medium,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Document has (or declares) too many pages",
    description: "The page tree (union of every revision) reaches more than \
        `thresholds.max_pages` (default 10000) distinct pages, or a page tree node \
        (/Type /Pages, or any dictionary with /Kids) declares a /Count above it. \
        Thumbnailing or rasterizing every page of such a file exhausts server resources; \
        readers also pre-allocate from /Count.",
};

fn is_tree_node(ctx: &Ctx, dict: &Dict) -> bool {
    dict.contains_key("Kids") || values(ctx, dict, "Type").any(|t| t.is_name("Pages"))
}

impl Rule for PageCount {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if !is_tree_node(ctx, dict) {
            return;
        }
        let max = ctx.thresholds().max_pages;
        let declared = values(ctx, dict, "Count")
            .filter_map(PdfObject::as_number)
            .fold(f64::NEG_INFINITY, f64::max);
        if declared > max as f64 {
            out.report(
                &META,
                loc,
                Some(format!("/Count {} (max {max})", num(declared))),
            );
        }
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let max = ctx.thresholds().max_pages;
        let n = ctx.page_tree().page_count;
        if n as u64 > max {
            out.report(&META, Site::Document, Some(format!("{n} pages (max {max})")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn details_with(src: &[u8], max: u64) -> Vec<Option<String>> {
        let t = Thresholds {
            max_pages: max,
            ..Thresholds::default()
        };
        let ctx = Ctx::new(src, Limits::default(), t);
        run(&ctx, &[&PageCount]).iter().map(|f| f.detail.clone()).collect()
    }

    fn tree(pages: usize, count: &str) -> Vec<u8> {
        let kids: Vec<String> = (0..pages).map(|i| format!("{} 0 R", 100 + i)).collect();
        let mut s = format!(
            "%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [{}] /Count {count} >> endobj\n9 0 obj 1000000 endobj\n",
            kids.join(" ")
        );
        for i in 0..pages {
            s.push_str(&format!("{} 0 obj << /Type /Page /Parent 2 0 R >> endobj\n", 100 + i));
        }
        s.into_bytes()
    }

    #[test]
    fn real_pages_boundary() {
        assert!(details_with(&tree(10, "10"), 10).is_empty());
        assert_eq!(
            details_with(&tree(11, "11"), 10),
            vec![
                Some("/Count 11 (max 10)".to_string()),
                Some("11 pages (max 10)".to_string())
            ]
        );
        // Lying /Count: the real pages still count.
        assert_eq!(
            details_with(&tree(11, "1"), 10),
            vec![Some("11 pages (max 10)".to_string())]
        );
    }

    #[test]
    fn declared_count() {
        assert_eq!(
            details_with(&tree(1, "1000000"), 10_000),
            vec![Some("/Count 1000000 (max 10000)".to_string())]
        );
        assert_eq!(details_with(&tree(1, "9 0 R"), 10_000).len(), 1);
        assert_eq!(details_with(&tree(1, "1 /C#6Funt 20000"), 10_000).len(), 1);
        assert_eq!(details_with(&tree(1, "10000"), 10_000).len(), 0);
        // An orphan /Pages node (union) and a node without /Type.
        let src = b"1 0 obj << /Type /Pages /Kids [] /Count 99999 >> endobj\n2 0 obj << /Kids [] /Count 99999 >> endobj";
        assert_eq!(details_with(src, 10_000).len(), 2);
    }

    #[test]
    fn near_misses() {
        // Outlines also have /Count.
        let src = b"1 0 obj << /Type /Outlines /Count 99999 >> endobj\n2 0 obj << /Count 99999 >> endobj";
        assert!(details_with(src, 10_000).is_empty());
        assert!(details_with(&tree(100, "100"), 10_000).is_empty());
    }
}
