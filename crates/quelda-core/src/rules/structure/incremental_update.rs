//! `STRUCT.INCREMENTAL_UPDATE`: the file has more than one revision.

use crate::facts::Ctx;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct IncrementalUpdate;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.INCREMENTAL_UPDATE",
    category: Category::Structure,
    severity: Severity::Info,
    default_action: Action::Off,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "File has incremental updates",
    description: "More than one revision (xref section; a hybrid file's xref stream counts \
        with its table) — ISO 32000-2 §7.5.6. The first-page xref section of a linearized \
        file is not an update. Updates can change what a document shows after it was \
        signed or reviewed; the scan already covers every revision (union scan), so strict \
        only warns and balanced/permissive are off.",
};

/// Revisions that are updates of the original document: all but the
/// first-page section of a linearized file. That section comes first and its
/// trailer's `/Prev` points forward, at the main xref section.
fn revision_count(ctx: &Ctx) -> usize {
    let revs = ctx.revisions();
    let doc = ctx.document();
    let first_page_section = ctx.structure_facts().linearized
        && match (revs.first(), revs.get(1)) {
            (Some(a), Some(b)) => match (doc.sections.get(a.section), doc.sections.get(b.section)) {
                (Some(a), Some(b)) => a.prevs().contains(&b.offset),
                _ => false,
            },
            _ => false,
        };
    revs.len() - usize::from(first_page_section)
}

impl Rule for IncrementalUpdate {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let n = revision_count(ctx);
        if n > 1 {
            out.report(
                &META,
                Site::Document,
                Some(format!("{n} revisions")),
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
        run(&ctx, &[&IncrementalUpdate])
            .iter()
            .map(|f| f.detail.clone())
            .collect()
    }

    /// Appends `N 0 obj body endobj` and an xref table for it; returns the
    /// xref offset.
    fn section(src: &mut Vec<u8>, num: u32, body: &str, trailer: &str) -> usize {
        let o = src.len();
        src.extend_from_slice(format!("{num} 0 obj {body} endobj\n").as_bytes());
        let x = src.len();
        src.extend_from_slice(
            format!("xref\n{num} 1\n{o:010} 00000 n \ntrailer << /Size 9 {trailer} >>\nstartxref\n{x}\n%%EOF\n").as_bytes(),
        );
        x
    }

    #[test]
    fn counts_updates() {
        let mut src = b"%PDF-1.7\n".to_vec();
        let x1 = section(&mut src, 1, "<< /Type /Catalog >>", "");
        assert!(details(&src).is_empty());
        let x2 = section(&mut src, 2, "<< >>", &format!("/Prev {x1}"));
        assert_eq!(
            details(&src),
            vec![Some("2 revisions".into())]
        );
        section(&mut src, 3, "<< >>", &format!("/Prev {x2}"));
        assert_eq!(
            details(&src),
            vec![Some("3 revisions".into())]
        );
    }

    /// First-page section (with `/Prev` forward to the main section), then
    /// the main section.
    fn linearized(lin_dict: &str) -> (Vec<u8>, usize) {
        let mut src = b"%PDF-1.7\n".to_vec();
        let o1 = src.len();
        src.extend_from_slice(format!("1 0 obj << {lin_dict} >> endobj\n").as_bytes());
        // Placeholder /Prev, fixed below (10 digits).
        let x1 = src.len();
        src.extend_from_slice(format!("xref\n1 1\n{o1:010} 00000 n \ntrailer << /Size 3 /Prev PPPPPPPPPP >>\nstartxref\n0\n%%EOF\n").as_bytes());
        let o2 = src.len();
        src.extend_from_slice(b"2 0 obj << /Type /Catalog >> endobj\n");
        let x2 = src.len();
        src.extend_from_slice(format!("xref\n0 1\n0000000000 65535 f \n2 1\n{o2:010} 00000 n \ntrailer << /Size 3 >>\nstartxref\n{x1}\n%%EOF\n").as_bytes());
        let s = String::from_utf8(src).unwrap().replace("PPPPPPPPPP", &format!("{x2:010}"));
        (s.into_bytes(), x2)
    }

    #[test]
    fn linearized_first_page_section_is_not_an_update() {
        let (src, _) = linearized("/Linearized 1");
        assert!(details(&src).is_empty());
        // Without the linearization dictionary it is two revisions.
        let (src, _) = linearized("/NotLinearized 1");
        assert_eq!(details(&src).len(), 1);
        // A linearized file updated once.
        let (mut src, x2) = linearized("/Linearized 1");
        section(&mut src, 3, "<< >>", &format!("/Prev {x2}"));
        assert_eq!(
            details(&src),
            vec![Some("2 revisions".into())]
        );
    }
}
