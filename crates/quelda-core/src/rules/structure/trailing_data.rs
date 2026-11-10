//! `STRUCT.TRAILING_DATA`: too many bytes after the last `%%EOF`.

use crate::facts::Ctx;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct TrailingData;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.TRAILING_DATA",
    category: Category::Structure,
    severity: Severity::Medium,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Data after the end of the PDF",
    description: "More than `thresholds.max_trailing_bytes` (default 1024) bytes follow the \
        last `%%EOF`. Appended data is how polyglot files (PDF + ZIP/HTML/PostScript…) and \
        smuggled payloads are built; small padding (line ends, a few hundred NUL bytes) is \
        normal and stays under the threshold.",
};

impl Rule for TrailingData {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let s = ctx.structure();
        let (Some(n), Some(&eof)) = (s.trailing_bytes, s.eofs.last()) else {
            return;
        };
        if n as u64 > ctx.thresholds().max_trailing_bytes {
            let at = eof + b"%%EOF".len();
            out.report(
                &META,
                Site::Offset(at),
                Some(format!("{n} bytes after the last %%EOF")),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn hits(src: &[u8], max: u64) -> Vec<(Site, Option<String>)> {
        let t = Thresholds {
            max_trailing_bytes: max,
            ..Thresholds::default()
        };
        let ctx = Ctx::new(src, Limits::default(), t);
        run(&ctx, &[&TrailingData])
            .iter()
            .map(|f| (f.site.clone(), f.detail.clone()))
            .collect()
    }

    fn pdf_then(tail: &[u8]) -> Vec<u8> {
        [&b"%PDF-1.7\n1 0 obj << >> endobj\n%%EOF"[..], tail].concat()
    }

    #[test]
    fn threshold_boundary() {
        let src = pdf_then(&[0; 1024]);
        assert!(hits(&src, 1024).is_empty(), "exactly the threshold is fine");
        let src = pdf_then(&[0; 1025]);
        let eof = src.windows(5).position(|w| w == b"%%EOF").unwrap();
        assert_eq!(
            hits(&src, 1024),
            vec![(
                Site::Offset(eof + 5),
                Some("1025 bytes after the last %%EOF".into())
            )]
        );
        // Threshold from policy.
        assert_eq!(hits(&pdf_then(b"\r\n"), 1).len(), 1);
        assert!(hits(&pdf_then(b"\r\n"), 2).is_empty());
    }

    #[test]
    fn only_after_the_last_eof() {
        let mut src = pdf_then(&[b'x'; 4000]);
        src.extend_from_slice(b"%%EOF\n");
        assert!(hits(&src, 1024).is_empty());
    }

    #[test]
    fn no_eof_is_not_trailing_data() {
        assert!(hits(&[b'x'; 5000], 0).is_empty());
    }
}
