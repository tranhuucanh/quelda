//! `STRUCT.NAME_TOO_LONG`: a name longer than 255 bytes, anywhere: dictionary keys and values,
//! arrays, top-level objects, operands and inline images of content streams
//! (not of speculative ones: binary data reads as long names).

use crate::facts::{ContentOp, Ctx, Location, OpLocation};
use crate::parser::{Name, PdfObject};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct NameTooLong;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.NAME_TOO_LONG",
    category: Category::Structure,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.2.0",
    message: "Name longer than 255 bytes",
    description: "A name (after #xx decoding) longer than 255 bytes. Long font and \
        resource names have overflowed fixed buffers in renderers (Ghostscript, 2025). \
        ISO 32000-1 Annex C.2 gives 127 bytes as the limit readers must handle, but real \
        producers exceed it: Word writes paragraph style names of up to about 250 bytes \
        as structure types, and form tools write long checkbox state names. No producer \
        is known to write names over 255 bytes.",
};

/// Twice the 127 bytes of ISO 32000-1 Annex C.2, Table C.1: real tagged
/// PDFs (Word style names as structure types) have names of 128 to 253
/// bytes, measured on 1,828 benign files (2026-11-12).
const MAX_NAME: usize = 255;

/// A long name for the finding: its length and its start, printable.
fn detail(n: &Name) -> String {
    let b = n.as_bytes();
    let head = b.get(..24).unwrap_or(b).escape_ascii().to_string();
    format!("name of {} bytes: /{head}…", b.len())
}

/// The first name longer than [`MAX_NAME`] in `root`, nested values
/// included. Iterative: nesting is bounded by the parser, not the stack.
fn long_name<'o>(root: &'o PdfObject) -> Option<&'o Name> {
    let mut stack = vec![root];
    while let Some(o) = stack.pop() {
        let dict = match o {
            PdfObject::Name(n) if n.as_bytes().len() > MAX_NAME => return Some(n),
            PdfObject::Array(items) => {
                stack.extend(items.iter().rev());
                continue;
            }
            PdfObject::Dict(d) => d,
            PdfObject::Stream(s) => &s.dict,
            _ => continue,
        };
        for (k, v) in dict.entries().iter().rev() {
            if k.as_bytes().len() > MAX_NAME {
                return Some(k);
            }
            stack.push(v);
        }
    }
    None
}

impl Rule for NameTooLong {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_content_op(&self, op: &ContentOp<'_>, loc: &OpLocation, _: &Ctx, out: &mut Findings) {
        // A stream with no content role (image data, fonts…) is tokenized
        // only in case it is drawn; its binary bytes read as long "names".
        if loc.speculative {
            return;
        }
        let inline = op.inline_image.as_ref().into_iter().flat_map(|i| {
            i.dict
                .entries()
                .iter()
                .flat_map(|(k, v)| [long_name(v), (k.as_bytes().len() > MAX_NAME).then_some(k)])
        });
        if let Some(n) = op.operands.iter().map(long_name).chain(inline).flatten().next() {
            out.report(&META, loc, Some(detail(n)));
        }
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        for (i, entry) in ctx.objects().iter().enumerate() {
            if let Some(n) = long_name(&entry.object) {
                out.report(&META, &Location::of(i, entry), Some(detail(n)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&NameTooLong])
            .iter()
            .map(|f| {
                let at = match &f.site {
                    Site::Object(l) => format!("{}", l.id),
                    Site::Op(o) => format!("op {}", o.stream.id),
                    other => format!("{other:?}"),
                };
                format!("{at}: {}", f.detail.clone().unwrap_or_default())
            })
            .collect()
    }

    fn name(n: usize) -> String {
        "A".repeat(n)
    }

    #[test]
    fn limit_is_255_decoded_bytes() {
        let ok = name(MAX_NAME);
        let long = name(MAX_NAME + 1);
        // 256 bytes once `#41` is decoded; 255 encoded `#41` decode to 255.
        let encoded = format!("#41{}", name(MAX_NAME));
        let src = format!(
            "1 0 obj << /BaseFont /{ok} >> endobj\n\
             2 0 obj << /BaseFont /{long} >> endobj\n\
             3 0 obj << /{long} 1 >> endobj\n\
             4 0 obj [1 [/x << /K /{long} >>]] endobj\n\
             5 0 obj /{encoded} endobj\n\
             6 0 obj << /N /{} >> endobj\n\
             7 0 obj ({long}) endobj\n",
            "#41".repeat(MAX_NAME)
        );
        let head = name(24);
        let d = |n| format!("name of {n} bytes: /{head}…");
        assert_eq!(
            hits(src.as_bytes()),
            vec![
                format!("2 0: {}", d(256)),
                format!("3 0: {}", d(256)),
                format!("4 0: {}", d(256)),
                format!("5 0: {}", d(256)),
            ]
        );
    }

    #[test]
    fn content_operands_and_inline_images() {
        let long = name(300);
        let data = format!(
            "BT /{long} 12 Tf ET q [/{long}] TJ BI /W 1 /H 1 /CS /{long} /BPC 8 ID x EI Q /Ok gs\n"
        );
        let src = format!(
            "1 0 obj << /Type /Page /Contents 2 0 R >> endobj\n2 0 obj << /Length {} >> stream\n{data}\nendstream endobj\n",
            data.len()
        );
        let found = hits(src.as_bytes());
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found.iter().all(|f| f.starts_with("op 2 0: name of 300 bytes")));
    }

    #[test]
    fn speculative_streams_are_skipped() {
        let data = format!("BT /{} 12 Tf ET\n", name(300));
        let src = format!(
            "1 0 obj << /Length {} >> stream\n{data}\nendstream endobj\n",
            data.len()
        );
        assert!(hits(src.as_bytes()).is_empty());
    }

    #[test]
    fn real_names_pass() {
        let src = b"1 0 obj << /Type /Font /Subtype /TrueType /BaseFont /ABCDEF+HiraginoKakuGothicProN-W3-90ms-RKSJ-H-Identity-H >> endobj\n\
            2 0 obj << /Length 18 >> stream\nBT /F1 9 Tf ET q Q\nendstream endobj\n";
        assert!(hits(src).is_empty());
    }
}
