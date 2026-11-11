//! `EXTERNAL.STREAM_FILE`: content that comes from a file outside the PDF:
//! a stream whose data is an external file (`/F`, `/FFilter`,
//! `/FDecodeParms` in the stream dictionary, ISO 32000-2 §7.3.8.2), or a
//! reference XObject (a Form XObject with `/Ref`, §8.10.4) that imports a
//! page of another PDF.

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::values;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct StreamFile;

static META: RuleMeta = RuleMeta {
    id: "EXTERNAL.STREAM_FILE",
    category: Category::External,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.2.0",
    message: "Content is read from a file outside the PDF",
    description: "A stream whose data lives in an external file (/F, /FFilter or \
        /FDecodeParms in the stream dictionary, ISO 32000-2 §7.3.8.2), or a reference \
        XObject (a Form XObject with /Ref, §8.10.4) that pulls in a page of another PDF. \
        A renderer that follows the reference reads a path or URL chosen by the file's \
        author (local files, network shares), and what is printed is not what was \
        checked. Images placed this way are not embedded; real print files embed them.",
};

/// Keys that only a stream dictionary has, naming an external file.
const FILE_KEYS: [&str; 3] = ["F", "FFilter", "FDecodeParms"];

/// The value is something other than `null`.
fn set(ctx: &Ctx, dict: &Dict, key: &str) -> bool {
    values(ctx, dict, key).any(|v| !matches!(v, PdfObject::Null))
}

impl Rule for StreamFile {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        let is_stream = loc.is_object()
            && ctx
                .objects()
                .get(loc.object)
                .is_some_and(|e| matches!(e.object, PdfObject::Stream(_)));
        // `/F` means "external file" only in a stream dictionary; the other
        // two keys exist nowhere else.
        let key = FILE_KEYS
            .iter()
            .filter(|&&k| is_stream || k != "F")
            .find(|k| set(ctx, dict, k));
        if let Some(key) = key {
            out.report(&META, loc, Some(format!("stream data from /{key}")));
        } else if set(ctx, dict, "Ref") && values(ctx, dict, "Subtype").any(|v| v.is_name("Form"))
        {
            out.report(&META, loc, Some("reference XObject (/Ref)".to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    fn details(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&StreamFile])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{} {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn external_streams() {
        let src = b"1 0 obj << /Length 0 /F (C:/hi-res/photo.tif) >> stream\n\nendstream endobj\n\
            2 0 obj << /Length 0 /F << /FS /URL /F (https://example.invalid/x) >> >> stream\n\nendstream endobj\n\
            3 0 obj << /Length 0 /FFilter /DCTDecode >> stream\n\nendstream endobj\n\
            4 0 obj << /A << /FDecodeParms << >> >> >> endobj\n\
            5 0 obj << /Length 0 /F 6 0 R >> stream\n\nendstream endobj\n\
            6 0 obj (photo.tif) endobj\n\
            7 0 obj << /Length 0 /F null >> stream\n\nendstream endobj\n\
            8 0 obj << /Length 0 /#46 (x) >> stream\n\nendstream endobj\n";
        assert_eq!(
            details(src),
            vec![
                "1 0 stream data from /F",
                "2 0 stream data from /F",
                "3 0 stream data from /FFilter",
                "4 0 stream data from /FDecodeParms",
                "5 0 stream data from /F",
                "8 0 stream data from /F",
            ]
        );
    }

    #[test]
    fn reference_xobject() {
        let src = b"1 0 obj << /Type /XObject /Subtype /Form /BBox [0 0 1 1] /Ref << /F (other.pdf) /Page 0 >> /Length 0 >> stream\n\nendstream endobj\n\
            2 0 obj << /Subtype /Form /Ref 3 0 R >> endobj\n3 0 obj << /F (x.pdf) /Page 1 >> endobj\n\
            4 0 obj << /Type /StructElem /S /P /Ref [5 0 R] >> endobj\n";
        assert_eq!(
            details(src),
            vec!["1 0 reference XObject (/Ref)", "2 0 reference XObject (/Ref)"]
        );
    }

    #[test]
    fn f_outside_a_stream_dict_is_not_reported() {
        // Annotation flags, file specifications, actions, a nested dict of
        // a stream, inline-image-like dicts: `/F` means something else.
        let src = b"1 0 obj << /Type /Annot /Subtype /Link /F 4 /Rect [0 0 1 1] >> endobj\n\
            2 0 obj << /Type /Filespec /F (a.txt) >> endobj\n\
            3 0 obj << /S /Launch /F (a.exe) >> endobj\n\
            4 0 obj << /Length 0 /DecodeParms << /F 1 >> >> stream\n\nendstream endobj\n\
            5 0 obj << /Length 0 /Filter /FlateDecode >> stream\n\nendstream endobj\n";
        assert!(details(src).is_empty(), "{:?}", details(src));
    }
}
