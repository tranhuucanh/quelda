//! `STRUCT.XREF_MISMATCH`: the cross-reference data does not match the
//! objects in the file.

use crate::facts::{Ctx, Location};
use crate::parser::document::MismatchKind;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct XrefMismatch;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.XREF_MISMATCH",
    category: Category::Structure,
    severity: Severity::Medium,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Cross-reference data does not match the file",
    description: "An xref entry does not point at the object it lists; an object found by \
        scanning the file is listed by no xref section; there is no usable xref (none, \
        `startxref` not pointing at one, a `/Prev` loop); an xref section is damaged; or an \
        xref section is not reachable from `startxref` (a hidden revision). Readers then \
        repair the file, each in its own way: the classic way to show one reader something \
        other than what another reader (or a scanner) sees.",
};

fn kind(k: &MismatchKind) -> String {
    match k {
        MismatchKind::OutOfRange => "offset past the end of the file".into(),
        MismatchKind::NoObject => "no object at the offset".into(),
        MismatchKind::WrongId(id) => format!("object {id} at the offset"),
        MismatchKind::NoObjStm => "no such object stream".into(),
        MismatchKind::WrongMember => "no such object stream member".into(),
    }
}

impl Rule for XrefMismatch {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let doc = ctx.document();
        let facts = ctx.structure_facts();
        let at = |s: usize| doc.sections.get(s).map_or(0, |x| x.offset);
        if doc.sections.is_empty() {
            out.report(&META, Site::Document, Some("no xref section".into()));
        }
        if facts.startxref_invalid {
            let site = ctx
                .structure()
                .startxrefs
                .last()
                .map_or(Site::Document, |s| Site::Offset(s.offset));
            out.report(
                &META,
                site,
                Some("startxref does not point at an xref section".into()),
            );
        }
        if facts.prev_loop {
            out.report(&META, Site::Document, Some("/Prev chain loops".into()));
        }
        for r in ctx.revisions() {
            if !facts.chain.contains(&r.section) {
                out.report(
                    &META,
                    Site::Offset(at(r.section)),
                    Some("xref section not reachable from startxref".into()),
                );
            }
        }
        for s in &doc.sections {
            for p in &s.problems {
                out.report(
                    &META,
                    Site::Offset(s.offset),
                    Some(format!("damaged xref section: {p:?}")),
                );
            }
        }
        for m in &facts.xref_mismatches {
            out.report(
                &META,
                Site::Offset(at(m.section)),
                Some(format!("xref entry for object {}: {}", m.num, kind(&m.kind))),
            );
        }
        for &i in &facts.unlisted {
            if let Some(e) = ctx.objects().get(i) {
                out.report(
                    &META,
                    &Location::of(i, e),
                    Some(format!("object {} is listed by no xref section", e.id)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn details(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&XrefMismatch])
            .iter()
            .filter_map(|f| f.detail.clone())
            .collect()
    }

    /// A one-object file with a correct xref table (offsets computed).
    fn pdf(objects: &[&str], extra_trailer: &str) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (i, o) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj {o} endobj\n", i + 1).as_bytes());
        }
        let xref = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
        for o in offsets {
            out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!("trailer << /Size {} /Root 1 0 R {extra_trailer} >>\nstartxref\n{xref}\n%%EOF\n", objects.len() + 1).as_bytes(),
        );
        out
    }

    #[test]
    fn consistent_file() {
        assert!(details(&pdf(&["<< /Type /Catalog >>", "<< >>"], "")).is_empty());
    }

    #[test]
    fn wrong_offset_and_unlisted() {
        let mut src = pdf(&["<< /Type /Catalog >>"], "");
        // Shift every object by inserting bytes before it.
        src.splice(9..9, b"junk\n".iter().copied());
        let d = details(&src);
        assert!(d.contains(&"xref entry for object 1: no object at the offset".to_string()), "{d:?}");
        assert!(d.contains(&"startxref does not point at an xref section".to_string()), "{d:?}");

        let mut src = pdf(&["<< /Type /Catalog >>"], "");
        let at = src.windows(4).position(|w| w == b"xref").unwrap();
        src.splice(at..at, b"7 0 obj << /Hidden 1 >> endobj\n".iter().copied());
        // (startxref is now off too; only the object matters here.)
        let d = details(&src);
        assert!(d.contains(&"object 7 0 is listed by no xref section".to_string()), "{d:?}");
    }

    #[test]
    fn no_xref() {
        let d = details(b"%PDF-1.7\n1 0 obj << >> endobj\n%%EOF\n");
        assert!(d.contains(&"no xref section".to_string()), "{d:?}");
        assert!(d.contains(&"startxref does not point at an xref section".to_string()));
        assert!(d.contains(&"object 1 0 is listed by no xref section".to_string()));
    }

    #[test]
    fn prev_loop_and_unreachable_section() {
        // The trailer comes after the table: adding /Prev does not move it.
        let plain = pdf(&["<< /Type /Catalog >>"], "");
        let xref = plain.windows(5).position(|w| w == b"xref\n").unwrap();
        let src = pdf(&["<< /Type /Catalog >>"], &format!("/Prev {xref}"));
        let d = details(&src);
        assert_eq!(d, vec!["/Prev chain loops".to_string()]);

        // A second, complete xref table that startxref does not lead to.
        let mut src = plain.clone();
        let second = src.len();
        let first = xref;
        let tail = src[first..].to_vec();
        let tail = String::from_utf8(tail).unwrap();
        let (table, _) = tail.split_once("startxref").unwrap();
        src.extend_from_slice(table.as_bytes());
        src.extend_from_slice(format!("startxref\n{first}\n%%EOF\n").as_bytes());
        let d = details(&src);
        assert_eq!(d, vec!["xref section not reachable from startxref".to_string()], "second at {second}");
    }

    #[test]
    fn damaged_section() {
        let src = pdf(&["<< /Type /Catalog >>"], "");
        let s = String::from_utf8(src).unwrap().replace("0 2\n", "0 3\n");
        let d = details(s.as_bytes());
        assert!(d.iter().any(|x| x.starts_with("damaged xref section")), "{d:?}");
    }
}
