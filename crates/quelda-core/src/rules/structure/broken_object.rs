//! `STRUCT.BROKEN_OBJECT`: `N G obj` followed by a body that cannot be
//! parsed. Such an object is in no object list, so no other rule sees what
//! it holds; a lenient reader may still recover part of it.

use crate::facts::Ctx;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct BrokenObject;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.BROKEN_OBJECT",
    category: Category::Structure,
    severity: Severity::Medium,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.4.0",
    message: "Object cannot be parsed",
    description: "An object header (`N G obj`) whose body is not a valid object: cut \
        off in the middle (a truncated file), or damaged. quelda cannot inspect what \
        such an object holds (a script, an action), while a reader that repairs files \
        may still use part of it. A header that is only text inside another object (a \
        string, a comment, the data of a stream) is not counted.",
};

impl Rule for BrokenObject {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let broken = &ctx.structure_facts().broken_objects;
        for b in broken.iter().filter(|b| !b.enclosed) {
            out.report(
                &META,
                Site::Offset(b.offset),
                Some(format!("object {}: {:?}", b.id, b.error.kind)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&BrokenObject])
            .iter()
            .map(|f| f.detail.clone().unwrap_or_default())
            .collect()
    }

    #[test]
    fn truncated_and_damaged_objects() {
        // A script cut off inside its string (a truncated file).
        let cut = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n\
            7 0 obj << /S /JavaScript /JS (app.alert\\(1";
        assert_eq!(hits(cut).len(), 1, "{:?}", hits(cut));
        assert!(hits(cut)[0].starts_with("object 7 0: "));
        // A dictionary whose key has no value.
        let damaged = b"%PDF-1.4\n2 0 obj << /S /Launch /F >> endobj\n";
        assert_eq!(hits(damaged).len(), 1);
    }

    #[test]
    fn valid_objects_and_headers_inside_stream_data_do_not_fire() {
        assert!(hits(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n").is_empty());
        let data = b"text 9 0 obj << /S /JavaScript /JS (unterminated\n";
        let mut src = format!("%PDF-1.4\n3 0 obj << /Length {} >> stream\n", data.len()).into_bytes();
        src.extend_from_slice(data);
        src.extend_from_slice(b"\nendstream endobj\n");
        assert!(hits(&src).is_empty(), "{:?}", hits(&src));
    }

    #[test]
    fn headers_inside_strings_and_comments_do_not_fire() {
        let in_string = b"%PDF-1.4\n1 0 obj << /Type /Catalog /T (see 30 0 obj << /Bad >) >> endobj\n";
        assert!(hits(in_string).is_empty(), "{:?}", hits(in_string));
        let in_object_comment =
            b"%PDF-1.4\n1 0 obj << /Type /Catalog % 30 0 obj << /Bad >\n >> endobj\n";
        assert!(hits(in_object_comment).is_empty(), "{:?}", hits(in_object_comment));
        let comment_line = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n% was: 30 0 obj << /Bad >\n";
        assert!(hits(comment_line).is_empty(), "{:?}", hits(comment_line));
        // The same broken text on a line of its own is an object.
        let own_line = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n30 0 obj << /Bad >\n";
        assert_eq!(hits(own_line).len(), 1);
    }
}
