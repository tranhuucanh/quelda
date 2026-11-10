//! `FILETYPE.FOREIGN_MAGIC`: the file starts like another format (markup,
//! ImageMagick scripts, archives, images, executables).

use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct ForeignMagic;

static META: RuleMeta = RuleMeta {
    id: "FILETYPE.FOREIGN_MAGIC",
    category: Category::Filetype,
    severity: Severity::High,
    default_action: Action::Block,
    locked: true,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "File is another format disguised as PDF",
    description: "The file starts with the signature of another format: XML/SVG/HTML/MSL \
        markup, ImageMagick MVG, ZIP/GZIP/7z/RAR archives, OLE/RTF documents, PNG/JPEG/GIF/\
        TIFF/WebP images, or PE/ELF executables. Tools that sniff content (ImageMagick, \
        browsers) pick the real format, whatever the file is called.",
};

/// Binary signatures at byte 0.
const BINARY: &[(&[u8], &str)] = &[
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP"),
    (b"PK\x07\x08", "ZIP"),
    (b"\x1F\x8B", "GZIP"),
    (b"7z\xBC\xAF\x27\x1C", "7-Zip"),
    (b"Rar!\x1A\x07", "RAR"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE (MS Office)"),
    (b"\x89PNG\r\n\x1A\n", "PNG"),
    (b"\xFF\xD8\xFF", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"II*\0", "TIFF"),
    (b"MM\0*", "TIFF"),
    (b"MZ", "PE executable"),
    (b"\x7FELF", "ELF executable"),
];

/// Text signatures after an optional BOM and whitespace, ASCII
/// case-insensitive.
const TEXT: &[(&[u8], &str)] = &[
    (b"push graphic-context", "ImageMagick MVG"),
    (b"viewbox", "ImageMagick MVG"),
    (b"{\\rtf", "RTF"),
];

fn skip_bom_and_space(raw: &[u8]) -> &[u8] {
    let raw = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw);
    let n = raw
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0C' | b'\0'))
        .count();
    &raw[n..]
}

fn starts_with_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay[..needle.len()].eq_ignore_ascii_case(needle)
}

/// The format `raw` starts with, if it is a known non-PDF one.
fn detect(raw: &[u8]) -> Option<&'static str> {
    if let Some((_, what)) = BINARY.iter().find(|(m, _)| raw.starts_with(m)) {
        return Some(what);
    }
    if raw.len() >= 12 && raw.starts_with(b"RIFF") && &raw[8..12] == b"WEBP" {
        return Some("WebP");
    }
    let text = skip_bom_and_space(raw);
    if let Some((_, what)) = TEXT.iter().find(|(m, _)| starts_with_ci(text, m)) {
        return Some(what);
    }
    // `<?xml`, `<!DOCTYPE`, `<svg`, `<html`, `<image` (MSL)…: no PDF starts
    // with a tag.
    match text {
        [b'<', b'?' | b'!', ..] => Some("XML/HTML markup"),
        [b'<', c, ..] if c.is_ascii_alphabetic() => Some("XML/HTML/SVG markup"),
        _ => None,
    }
}

impl Rule for ForeignMagic {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_file(&self, raw: &[u8], out: &mut Findings) {
        if let Some(what) = detect(raw) {
            out.report(&META, Site::Offset(0), Some(format!("{what} signature")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        for (raw, want) in [
            (&b"<?xml version=\"1.0\"?><svg/>"[..], "XML/HTML markup"),
            (b"<svg xmlns=\"x\"/>", "XML/HTML/SVG markup"),
            (b"\xEF\xBB\xBF\n  <!DOCTYPE html>", "XML/HTML markup"),
            (b"<HTML><body>", "XML/HTML/SVG markup"),
            (b"<image size=\"1x1\">", "XML/HTML/SVG markup"),
            (b"push graphic-context\nviewbox 0 0 1 1", "ImageMagick MVG"),
            (b"\nVIEWBOX 0 0 1 1", "ImageMagick MVG"),
            (b"{\\rtf1\\ansi", "RTF"),
            (b"PK\x03\x04\x14\0", "ZIP"),
            (b"PK\x05\x06\0\0", "ZIP"),
            (b"\x1F\x8B\x08", "GZIP"),
            (b"\x89PNG\r\n\x1A\n\0", "PNG"),
            (b"\xFF\xD8\xFF\xE0", "JPEG"),
            (b"GIF89a\x01\0", "GIF"),
            (b"II*\0\x08\0", "TIFF"),
            (b"RIFF\0\0\0\0WEBPVP8 ", "WebP"),
            (b"MZ\x90\0", "PE executable"),
            (b"\x7FELF\x02", "ELF executable"),
            (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE (MS Office)"),
        ] {
            assert_eq!(detect(raw), Some(want), "{raw:?}");
        }
    }

    #[test]
    fn not_foreign() {
        for raw in [
            &b""[..],
            b"%PDF-1.7\n<svg>",
            b"%!PS-Adobe-3.0",
            b"\xC5\xD0\xD3\xC6",
            b"QUELDA-JUNK\n%PDF-1.7",
            b"quelda-test: plain text, not a PDF\n",
            b"< 1 2 >",
            b"<",
            b"RIFF\0\0\0\0WAVE",
            b"PK",
            b"  ZIP",
        ] {
            assert_eq!(detect(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn reports_at_offset_zero() {
        let mut f = Findings::new();
        ForeignMagic.check_file(b"<svg/>", &mut f);
        let x = f.iter().next().unwrap();
        assert_eq!(x.site, Site::Offset(0));
        assert_eq!(x.detail.as_deref(), Some("XML/HTML/SVG markup signature"));
        let mut f = Findings::new();
        ForeignMagic.check_file(b"%PDF-1.7\n", &mut f);
        assert!(f.is_empty());
    }
}
