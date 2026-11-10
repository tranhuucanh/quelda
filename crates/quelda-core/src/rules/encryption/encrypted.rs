//! `CRYPT.ENCRYPTED`: a trailer declares an encryption dictionary.

use crate::facts::Ctx;
use crate::parser::PdfObject;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct Encrypted;

static META: RuleMeta = RuleMeta {
    id: "CRYPT.ENCRYPTED",
    category: Category::Encryption,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "File is encrypted and cannot be fully inspected",
    description: "A trailer (classic `trailer` dictionary or cross-reference stream \
        dictionary, any revision) has an /Encrypt entry (ISO 32000-2 §7.6). Strings and \
        streams are encrypted; this engine does not decrypt them (v0.1), so their content \
        is not inspected.",
};

/// The security handler (`/Filter`) of an encryption dictionary, if known.
fn handler(ctx: &Ctx, value: &PdfObject) -> Option<String> {
    ctx.resolve(value).find_map(|o| {
        let name = o.as_dict()?.get("Filter")?.as_name()?;
        Some(String::from_utf8_lossy(name.as_bytes()).into_owned())
    })
}

impl Rule for Encrypted {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        for t in ctx.trailers() {
            let Some(value) = t
                .dict
                .get_all("Encrypt")
                .find(|v| !matches!(v, PdfObject::Null))
            else {
                continue;
            };
            let detail = match handler(ctx, value) {
                Some(h) => format!("/Encrypt with security handler /{h}"),
                None => "/Encrypt".to_string(),
            };
            out.report(&META, Site::Offset(t.offset), Some(detail));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn hits(src: &[u8]) -> Vec<(Site, Option<String>)> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&Encrypted])
            .iter()
            .map(|f| (f.site.clone(), f.detail.clone()))
            .collect()
    }

    #[test]
    fn trailer_encrypt() {
        let src = b"%PDF-1.7\n1 0 obj << /Filter /Standard /V 2 >> endobj\ntrailer << /Root 2 0 R /Encr#79pt 1 0 R >>\n%%EOF\n";
        let at = src.windows(7).position(|w| w == b"trailer").unwrap();
        assert_eq!(
            hits(src),
            vec![(
                Site::Offset(at),
                Some("/Encrypt with security handler /Standard".into())
            )]
        );
        // Direct dictionary, unknown handler.
        let src = b"%PDF-1.7\ntrailer << /Encrypt << /V 1 >> >>\n%%EOF\n";
        assert_eq!(hits(src)[0].1.as_deref(), Some("/Encrypt"));
    }

    #[test]
    fn not_encrypted() {
        for src in [
            &b"%PDF-1.7\ntrailer << /Root 1 0 R >>\n%%EOF\n"[..],
            b"%PDF-1.7\ntrailer << /Encrypt null >>\n%%EOF\n",
            b"%PDF-1.7\n1 0 obj << /Encrypt 2 0 R >> endobj\ntrailer << /Root 1 0 R /Note (/Encrypt) >>\n%%EOF\n",
        ] {
            assert!(hits(src).is_empty(), "{:?}", String::from_utf8_lossy(src));
        }
    }

    #[test]
    fn every_trailer_counts() {
        let src = b"%PDF-1.7\ntrailer << /Encrypt 9 0 R >>\n%%EOF\ntrailer << /Root 1 0 R >>\n%%EOF\ntrailer << /Encrypt 9 0 R >>\n%%EOF\n";
        assert_eq!(hits(src).len(), 2);
    }
}
