//! `STRUCT.MULTIPLE_HEADERS`: more than one `%PDF-` header line.

use crate::facts::Ctx;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct MultipleHeaders;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.MULTIPLE_HEADERS",
    category: Category::Structure,
    severity: Severity::Medium,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "File has more than one PDF header",
    description: "Two or more lines start with `%PDF-` outside stream data: concatenated \
        files, or a document built so that readers starting from the front and readers \
        starting from the back see different files. `%PDF-` inside a string or stream data \
        does not count; a single header at the wrong place is FILETYPE.NOT_PDF_HEADER.",
};

impl Rule for MultipleHeaders {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let lines = ctx.header_lines();
        if lines.len() < 2 {
            return;
        }
        for &at in &lines[1..] {
            out.report(
                &META,
                Site::Offset(at),
                Some(format!("{} %PDF- header lines", lines.len())),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn sites(src: &[u8]) -> Vec<Site> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&MultipleHeaders])
            .iter()
            .map(|f| f.site.clone())
            .collect()
    }

    #[test]
    fn second_header_line() {
        let src = b"%PDF-1.7\n1 0 obj << >> endobj\n%PDF-1.4\n2 0 obj << >> endobj\n%%EOF\n";
        let second = src.windows(8).rposition(|w| w == b"%PDF-1.4").unwrap();
        assert_eq!(sites(src), vec![Site::Offset(second)]);
        let src = b"%PDF-1.7\n%%EOF\n%PDF-1.7\n%%EOF\n  %PDF-2.0\n";
        assert_eq!(sites(src).len(), 2);
    }

    #[test]
    fn near_misses() {
        for src in [
            &b"%PDF-1.7\n1 0 obj << /Note (%PDF-1.4) >> endobj\n%%EOF\n"[..],
            b"%PDF-1.7\n1 0 obj << /Length 9 >> stream\n%PDF-1.4\nendstream endobj\n%%EOF\n",
            b"%PDF-1.7\n1 0 obj << >> endobj % %PDF-1.4\n%%EOF\n",
            b"junk %PDF-1.7\n",
        ] {
            assert!(sites(src).is_empty(), "{}", String::from_utf8_lossy(src));
        }
    }
}
