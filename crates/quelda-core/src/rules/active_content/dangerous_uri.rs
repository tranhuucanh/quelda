//! `ACTIVE.DANGEROUS_URI`: a URI action whose target runs code or reaches
//! the local machine or network shares, not a web page. `EXTERNAL.URI`
//! reports every link; this one only those that are never ordinary links.

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::values;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct DangerousUri;

static META: RuleMeta = RuleMeta {
    id: "ACTIVE.DANGEROUS_URI",
    category: Category::ActiveContent,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.3.0",
    message: "Link runs a script or opens a local file or network share",
    description: "A URI action (/S /URI, every definition) whose /URI is a script \
        (javascript:, vbscript:, data:), a local or network file (file:, smb:, a Windows \
        path such as C:\\ or \\\\server\\share), or a Windows protocol handler with a \
        history of exploits (ms-*: such as ms-msdt:, search-ms:, mhtml:, shell:, jar:). \
        Clicking one can run code in a web-based viewer, open a program, or send the \
        user's Windows credentials (NTLM hash) to another machine. Also a document \
        base URI (/URI << /Base … >> in the catalog) of these kinds, which turns every \
        relative link into one. Compared the way \
        browsers parse URLs: case-insensitive, tabs and line breaks removed, leading \
        spaces and control characters ignored, UTF-16 strings read. http, https, mailto, \
        ftp, tel and relative links are not reported.",
};

/// Schemes reported (lowercase), besides `ms-*` and one-letter drive names.
const SCHEMES: [&str; 13] = [
    "javascript",
    "vbscript",
    "livescript",
    "data",
    "file",
    "smb",
    "cifs",
    "mhtml",
    "jar",
    "search",
    "search-ms",
    "shell",
    "its",
];

/// `/URI` bytes as ASCII the way a browser reads them (`0xFF` for other
/// characters): UTF-16 decoded, tabs and line breaks removed, leading
/// spaces and control characters dropped, lowercase.
fn normalize(raw: &[u8]) -> Vec<u8> {
    let chars: Vec<u8> = match raw {
        [0xFE, 0xFF, rest @ ..] => rest
            .chunks(2)
            .map(|c| match c {
                [0, b] if b.is_ascii() => *b,
                _ => 0xFF,
            })
            .collect(),
        [0xFF, 0xFE, rest @ ..] => rest
            .chunks(2)
            .map(|c| match c {
                [b, 0] if b.is_ascii() => *b,
                _ => 0xFF,
            })
            .collect(),
        [0xEF, 0xBB, 0xBF, rest @ ..] => rest.to_vec(),
        _ => raw.to_vec(),
    };
    let chars: Vec<u8> = chars
        .into_iter()
        .filter(|b| !matches!(b, b'\t' | b'\n' | b'\r'))
        .skip_while(|&b| b <= b' ')
        .map(|b| b.to_ascii_lowercase())
        .collect();
    chars
}

/// Why `uri` is dangerous: its scheme, or the kind of path.
fn danger(uri: &[u8]) -> Option<String> {
    let u = normalize(uri);
    if u.starts_with(b"\\\\") || u.starts_with(b"\\/") || u.starts_with(b"/\\") {
        return Some("network share (UNC path)".to_string());
    }
    let colon = u.iter().position(|&b| b == b':')?;
    let scheme = &u[..colon];
    let valid = scheme.first().is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    if !valid {
        return None;
    }
    let s = String::from_utf8_lossy(scheme);
    if scheme.len() == 1 {
        Some(format!("Windows path ({s}:)"))
    } else if SCHEMES.contains(&s.as_ref()) || s.starts_with("ms-") {
        Some(format!("{s}: link"))
    } else {
        None
    }
}

/// `raw` shortened for the detail.
fn excerpt(raw: &[u8]) -> String {
    let s: String = String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control())
        .take(60)
        .collect();
    if raw.len() > 60 { format!("{s}…") } else { s }
}

impl Rule for DangerousUri {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        let is_action = values(ctx, dict, "S").any(|s| s.is_name("URI"));
        let found = values(ctx, dict, "URI")
            .find_map(|v| match v {
                PdfObject::String(raw) if is_action => {
                    danger(raw).map(|why| format!("{why}: {}", excerpt(raw)))
                }
                // The catalog's URI dictionary: relative links resolve against /Base.
                PdfObject::Dict(d) => values(ctx, d, "Base")
                    .filter_map(PdfObject::as_string)
                    .find_map(|raw| {
                        danger(raw).map(|why| format!("base URI, {why}: {}", excerpt(raw)))
                    }),
                _ => None,
            });
        if let Some(d) = found {
            out.report(&META, loc, Some(d));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    #[test]
    fn dangerous_and_ordinary_targets() {
        for (uri, want) in [
            (&b"javascript:app.alert(1)"[..], "javascript: link"),
            (b"  JaVa\tScRiPt:x", "javascript: link"),
            (b"\x01\x02 vbscript:x", "vbscript: link"),
            (b"data:text/html,<script>x</script>", "data: link"),
            (b"file:///C:/quelda-test.pdf", "file: link"),
            (b"FILE://attacker/share/a.pdf", "file: link"),
            (b"\\\\attacker\\share\\x", "network share (UNC path)"),
            (b"C:\\quelda-test.pdf", "Windows path (c:)"),
            (b"ms-msdt:quelda-test", "ms-msdt: link"),
            (b"search-ms:query=x", "search-ms: link"),
            (b"smb://host/share", "smb: link"),
            (b"\xFE\xFF\0j\0a\0v\0a\0s\0c\0r\0i\0p\0t\0:\0x", "javascript: link"),
        ] {
            assert_eq!(danger(uri).as_deref(), Some(want), "{}", String::from_utf8_lossy(uri));
        }
        for ok in [
            &b"https://example.com/a?b=javascript:x"[..],
            b"http://x",
            b"mailto:a@b.c",
            b"ftp://public.example.com/a.pdf",
            b"tel:+84123",
            b"doi:10.1000/x",
            b"page2.html",
            b"//cdn.example.com/x",
            b"#section",
            b"",
            b"1:2",
        ] {
            assert_eq!(danger(ok), None, "{}", String::from_utf8_lossy(ok));
        }
    }

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&DangerousUri])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn uri_actions_only() {
        let src = b"1 0 obj << /S /URI /URI (javascript:x) >> endobj\n\
            2 0 obj << /A << /S /URI /URI 3 0 R >> >> endobj\n3 0 obj (\\\\\\\\host\\\\s) endobj\n\
            4 0 obj << /S /URI /URI (https://example.com) >> endobj\n\
            5 0 obj << /Type /Annot /URI (javascript:x) >> endobj\n\
            6 0 obj << /Type /Catalog /URI << /Base (file:///share/) >> >> endobj\n\
            7 0 obj << /Type /Catalog /URI 8 0 R >> endobj\n8 0 obj << /Base (https://example.com/) >> endobj\n";
        assert_eq!(
            hits(src),
            vec![
                "1 0: javascript: link: javascript:x".to_string(),
                "2 0: network share (UNC path): \\\\host\\s".to_string(),
                "6 0: base URI, file: link: file:///share/".to_string(),
            ]
        );
    }
}
