//! `STRUCT.PAGE_TREE_CYCLE`: the page tree loops, or reaches a node twice.

use crate::facts::{Ctx, Location};
use crate::parser::ObjRef;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct PageTreeCycle;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.PAGE_TREE_CYCLE",
    category: Category::Structure,
    severity: Severity::High,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Page tree has a cycle or a repeated node",
    description: "`/Kids` edges form a cycle, or a page tree node is listed twice (twice in \
        one `/Kids`, or by two different parents). Readers that walk the tree naively loop \
        forever or render the same subtree many times (exponential page count from a few \
        objects). The tree is the union of every definition of every node, all revisions \
        (design §4.2), so a node moved to another parent by an incremental update also \
        counts.",
};

fn site(ctx: &Ctx, id: ObjRef) -> Site {
    ctx.document()
        .definition_indices(id)
        .next()
        .and_then(|i| Some(Location::of(i, ctx.objects().get(i)?)))
        .map_or(Site::Document, Site::Object)
}

impl Rule for PageTreeCycle {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let tree = ctx.page_tree();
        for &id in &tree.cycle_nodes {
            out.report(
                &META,
                site(ctx, id),
                Some(format!("page tree node {id} is on a /Kids cycle")),
            );
        }
        for &id in &tree.repeated_nodes {
            out.report(
                &META,
                site(ctx, id),
                Some(format!("page tree node {id} is listed more than once")),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn details(body: &str) -> Vec<String> {
        let src = format!("%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n{body}");
        let ctx = Ctx::new(src.as_bytes(), Limits::default(), Thresholds::default());
        run(&ctx, &[&PageTreeCycle])
            .iter()
            .filter_map(|f| f.detail.clone())
            .collect()
    }

    #[test]
    fn cycles() {
        assert_eq!(
            details(
                "2 0 obj << /Type /Pages /Kids [3 0 R 2 0 R] /Count 2 >> endobj\n\
                 3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n"
            ),
            vec!["page tree node 2 0 is on a /Kids cycle"]
        );
        let d = details(
            "2 0 obj << /Type /Pages /Kids [7 0 R] >> endobj\n\
             7 0 obj << /Type /Pages /Kids [2 0 R 3 0 R] >> endobj\n\
             3 0 obj << /Type /Page >> endobj\n",
        );
        assert_eq!(d, vec!["page tree node 2 0 is on a /Kids cycle"]);
    }

    #[test]
    fn repeated() {
        assert_eq!(
            details(
                "2 0 obj << /Type /Pages /Kids [3 0 R 3 0 R] /Count 2 >> endobj\n\
                 3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n"
            ),
            vec!["page tree node 3 0 is listed more than once"]
        );
        // Two parents.
        let d = details(
            "2 0 obj << /Type /Pages /Kids [7 0 R 8 0 R] >> endobj\n\
             7 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n\
             8 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n\
             3 0 obj << /Type /Page >> endobj\n",
        );
        assert_eq!(d, vec!["page tree node 3 0 is listed more than once"]);
    }

    #[test]
    fn valid_trees() {
        assert!(details(
            "2 0 obj << /Type /Pages /Kids [7 0 R 4 0 R] /Count 2 >> endobj\n\
             7 0 obj << /Type /Pages /Parent 2 0 R /Kids [3 0 R] /Count 1 >> endobj\n\
             3 0 obj << /Type /Page /Parent 7 0 R >> endobj\n\
             4 0 obj << /Type /Page /Parent 2 0 R >> endobj\n"
        )
        .is_empty());
        // The same node rewritten (an update adding a page): one parent id.
        assert!(details(
            "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n\
             3 0 obj << /Type /Page >> endobj\n\
             2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >> endobj\n\
             4 0 obj << /Type /Page >> endobj\n"
        )
        .is_empty());
    }

    #[test]
    fn page_moved_between_parents_across_revisions_counts() {
        // Union of definitions (design §4.2): old 7 lists 3, new 8 lists 3.
        let d = details(
            "2 0 obj << /Type /Pages /Kids [7 0 R 8 0 R] >> endobj\n\
             7 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n\
             8 0 obj << /Type /Pages /Kids [] >> endobj\n\
             3 0 obj << /Type /Page >> endobj\n\
             7 0 obj << /Type /Pages /Kids [] >> endobj\n\
             8 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n",
        );
        assert_eq!(d, vec!["page tree node 3 0 is listed more than once"]);
    }
}
