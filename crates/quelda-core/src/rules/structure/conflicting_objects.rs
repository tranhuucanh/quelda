//! `STRUCT.CONFLICTING_OBJECTS`: one object id defined twice, differently,
//! in the same revision.

use crate::facts::{Ctx, Location};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct ConflictingObjects;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.CONFLICTING_OBJECTS",
    category: Category::Structure,
    severity: Severity::Medium,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Same object defined twice with different content",
    description: "The same `N G obj` is defined at least twice in one revision with \
        different content. Which definition a reader uses depends on its xref handling or \
        repair logic, so two readers (or a reader and a scanner) can see different \
        documents. Redefinition through an incremental update, and byte-identical repeats, \
        do not count.",
};

impl Rule for ConflictingObjects {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        for g in &ctx.structure_facts().duplicates {
            if !g.conflict_in_revision {
                continue;
            }
            let site = g
                .entries
                .first()
                .and_then(|&i| Some(Location::of(i, ctx.objects().get(i)?)))
                .map_or(Site::Document, Site::Object);
            out.report(
                &META,
                site,
                Some(format!(
                    "object {} defined {} times with different content",
                    g.id,
                    g.entries.len()
                )),
            );
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
        run(&ctx, &[&ConflictingObjects])
            .iter()
            .map(|f| f.detail.clone())
            .collect()
    }

    #[test]
    fn conflict_in_one_revision() {
        let src = b"%PDF-1.7\n1 0 obj << /A 1 >> endobj\n1 0 obj << /A 2 >> endobj\n2 0 obj (x) endobj\n%%EOF\n";
        assert_eq!(
            details(src),
            vec![Some("object 1 0 defined 2 times with different content".into())]
        );
    }

    #[test]
    fn identical_repeat_does_not_count() {
        let src = b"%PDF-1.7\n1 0 obj << /A 1 >> endobj\n1 0 obj << /A 1 >> endobj\n%%EOF\n";
        assert!(details(src).is_empty());
    }

    #[test]
    fn incremental_redefinition_does_not_count() {
        // Revision 1: object 1 + xref; revision 2: object 1 again + xref.
        let mut src = b"%PDF-1.7\n".to_vec();
        let o1 = src.len();
        src.extend_from_slice(b"1 0 obj << /A 1 >> endobj\n");
        let x1 = src.len();
        src.extend_from_slice(format!("xref\n0 2\n0000000000 65535 f \n{o1:010} 00000 n \ntrailer << /Size 2 >>\nstartxref\n{x1}\n%%EOF\n").as_bytes());
        let o2 = src.len();
        src.extend_from_slice(b"1 0 obj << /A 2 >> endobj\n");
        let x2 = src.len();
        src.extend_from_slice(format!("xref\n0 2\n0000000000 65535 f \n{o2:010} 00000 n \ntrailer << /Size 2 /Prev {x1} >>\nstartxref\n{x2}\n%%EOF\n").as_bytes());
        assert!(details(&src).is_empty());
    }
}
