//! `FILETYPE.POSTSCRIPT_MAGIC`: the file is PostScript / EPS, not PDF.

use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct PostscriptMagic;

static META: RuleMeta = RuleMeta {
    id: "FILETYPE.POSTSCRIPT_MAGIC",
    category: Category::Filetype,
    severity: Severity::Critical,
    default_action: Action::Block,
    locked: true,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "File is PostScript/EPS, not PDF",
    description: "The file starts with the PostScript magic `%!` (after an optional byte order \
        mark / whitespace), the DOS EPS binary header `C5 D0 D3 C6`, or a PJL job header \
        (UEL `ESC%-12345X`) followed by PostScript. Ghostscript and ImageMagick run such a \
        file as a PostScript program whatever its extension.",
};

/// PJL Universal Exit Language: starts a printer job, which may switch to
/// PostScript.
const UEL: &[u8] = b"\x1B%-12345X";
/// How far into a PJL job to look for the PostScript magic.
const PJL_WINDOW: usize = 4096;
const EPS_BINARY: &[u8] = &[0xC5, 0xD0, 0xD3, 0xC6];

/// `raw` without a leading UTF-8 byte order mark and ASCII whitespace.
fn skip_bom_and_space(raw: &[u8]) -> &[u8] {
    let raw = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw);
    let n = raw
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0C' | b'\0'))
        .count();
    &raw[n..]
}

/// What kind of PostScript `raw` starts with, if any.
fn detect(raw: &[u8]) -> Option<&'static str> {
    if raw.starts_with(EPS_BINARY) {
        return Some("DOS EPS binary header");
    }
    let start = skip_bom_and_space(raw);
    if start.starts_with(b"%!") {
        return Some(if start.len() == raw.len() {
            "PostScript magic `%!`"
        } else {
            "PostScript magic `%!` after BOM/whitespace"
        });
    }
    if start.starts_with(UEL) {
        let window = &start[..start.len().min(PJL_WINDOW)];
        if window.windows(2).any(|w| w == b"%!") {
            return Some("PJL job containing PostScript");
        }
    }
    None
}

impl Rule for PostscriptMagic {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_file(&self, raw: &[u8], out: &mut Findings) {
        if let Some(what) = detect(raw) {
            out.report(&META, Site::Offset(0), Some(what.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fires(raw: &[u8]) -> bool {
        let mut f = Findings::new();
        PostscriptMagic.check_file(raw, &mut f);
        f.fired(META.id)
    }

    #[test]
    fn postscript_starts() {
        for bad in [
            &b"%!PS-Adobe-3.0\nshowpage\n"[..],
            b"%!",
            b"%!\nshowpage",
            b"%!PS-Adobe-3.0 EPSF-3.0\n",
            b"\xC5\xD0\xD3\xC6\x1E\0\0\0",
            b"\xEF\xBB\xBF%!PS",
            b"  \r\n\t%!PS",
            b"\x1B%-12345X@PJL ENTER LANGUAGE=POSTSCRIPT\r\n%!PS-Adobe-3.0\n",
        ] {
            assert!(fires(bad), "{bad:?}");
        }
    }

    #[test]
    fn not_postscript() {
        for ok in [
            &b""[..],
            b"%PDF-1.7\n%!PS in a comment\n",
            b"%",
            b"!%",
            b"% !PS",
            b"\xC5\xD0\xD3",
            b"QUELDA %!PS",
            b"\x1B%-12345X@PJL ENTER LANGUAGE=PCL\r\n",
        ] {
            assert!(!fires(ok), "{ok:?}");
        }
        // PostScript past the PJL window is not looked for.
        let mut far = UEL.to_vec();
        far.extend(vec![b' '; PJL_WINDOW]);
        far.extend_from_slice(b"%!PS");
        assert!(!fires(&far));
    }

    #[test]
    fn detail_and_site() {
        let mut f = Findings::new();
        PostscriptMagic.check_file(b"\n%!PS", &mut f);
        let x = f.iter().next().unwrap();
        assert_eq!(x.site, Site::Offset(0));
        assert_eq!(
            x.detail.as_deref(),
            Some("PostScript magic `%!` after BOM/whitespace")
        );
        assert_eq!(detect(b"\xC5\xD0\xD3\xC6"), Some("DOS EPS binary header"));
    }

    #[test]
    fn skips_bom_and_whitespace_only() {
        assert_eq!(skip_bom_and_space(b"\xEF\xBB\xBF \n<x"), b"<x");
        assert_eq!(skip_bom_and_space(b"x "), b"x ");
        assert_eq!(skip_bom_and_space(b""), b"");
    }
}
