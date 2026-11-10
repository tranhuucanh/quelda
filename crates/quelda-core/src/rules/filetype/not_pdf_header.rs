//! `FILETYPE.NOT_PDF_HEADER`: the file does not start with a PDF header.

use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct NotPdfHeader;

static META: RuleMeta = RuleMeta {
    id: "FILETYPE.NOT_PDF_HEADER",
    category: Category::Filetype,
    severity: Severity::Critical,
    default_action: Action::Block,
    locked: true,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "File does not start with a PDF header",
    description: "Byte 0 is not `%PDF-1.` or `%PDF-2.`. Readers that search for the header \
        further in (or sniff the content) may treat the file as another format, e.g. \
        PostScript run by Ghostscript.",
};

impl Rule for NotPdfHeader {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_file(&self, raw: &[u8], out: &mut Findings) {
        if raw.starts_with(b"%PDF-1.") || raw.starts_with(b"%PDF-2.") {
            return;
        }
        let head = &raw[..raw.len().min(8)];
        let detail = format!("file starts with {:?}", String::from_utf8_lossy(head));
        out.report(&META, Site::Offset(0), Some(detail));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fires(raw: &[u8]) -> bool {
        let mut f = Findings::new();
        NotPdfHeader.check_file(raw, &mut f);
        f.fired(META.id)
    }

    #[test]
    fn headers() {
        for ok in [&b"%PDF-1.7\n"[..], b"%PDF-1.0", b"%PDF-2.0\r%"] {
            assert!(!fires(ok), "{ok:?}");
        }
        for bad in [
            &b""[..],
            b"%PDF-",
            b"%PDF-3.0",
            b"%pdf-1.7",
            b" %PDF-1.7",
            b"\xEF\xBB\xBF%PDF-1.7",
            b"%!PS-Adobe-3.0",
        ] {
            assert!(fires(bad), "{bad:?}");
        }
    }

    #[test]
    fn detail_shows_start() {
        let mut f = Findings::new();
        NotPdfHeader.check_file(b"QUELDA-JUNK\n%PDF-1.7", &mut f);
        let x = f.iter().next().unwrap();
        assert_eq!(x.site, Site::Offset(0));
        assert_eq!(x.detail.as_deref(), Some("file starts with \"QUELDA-J\""));
    }
}
