//! Rules that match a dictionary key/value. Each case is expanded into the
//! standard evasion variants: plain, name-encoded, in-objstm (Flate, LZW, and
//! a 3-filter chain), old-revision, nested-dict, and — for rules that match a
//! value — indirect-value (the value is an indirect object, ADR #19).

use super::{Doc, Fixture, LINK_TO_10, bad};
use crate::builder::{PdfBuilder, Xref};
use crate::filters::Filter;
use crate::names::encode_names_in;

pub(crate) const VARIANTS: &[&str] = &[
    "plain",
    "name-encoded",
    "in-objstm",
    "in-objstm-lzw",
    "in-objstm-filter-chain",
    "old-revision",
    "nested-dict",
];

/// Variant written only for cases with [`DictCase::indirect`].
pub(crate) const INDIRECT: &str = "indirect-value";

/// Object number of the indirect value in the `indirect-value` variant.
const INDIRECT_OBJ: u32 = 30;

/// ObjStm filters of the `in-objstm-filter-chain` variant (Flate → ASCIIHex →
/// ASCII85 when decoding).
const OBJSTM_CHAIN: [Filter; 3] = [Filter::Ascii85, Filter::AsciiHex, Filter::Flate];

/// `(rule, key, value)`: rules that match the value of `key`; their
/// `indirect-value` variant replaces `/key value` with `/key 30 0 R` and adds
/// `30 0 obj value endobj`.
const INDIRECT_VALUES: &[(&str, &str, &str)] = &[
    ("POSTSCRIPT.XOBJECT", "Subtype", "/PS"),
    ("POSTSCRIPT.TYPE4_FUNCTION", "FunctionType", "4"),
    ("ACTIVE.OPEN_ACTION", "OpenAction", "<< /S /Thread /D 0 >>"),
    ("ACTIVE.JAVASCRIPT", "S", "/JavaScript"),
    ("ACTIVE.LAUNCH", "S", "/Launch"),
    ("ACTIVE.OTHER_ACTIONS", "S", "/Named"),
    ("EMBED.EMBEDDED_FILE", "Type", "/EmbeddedFile"),
    ("EMBED.FILE_ATTACHMENT", "Subtype", "/FileAttachment"),
    ("EMBED.RICH_MEDIA", "Subtype", "/RichMedia"),
    ("EXTERNAL.URI", "S", "/URI"),
    ("EXTERNAL.REMOTE_GOTO", "S", "/GoToR"),
    ("EXTERNAL.SUBMIT_FORM", "S", "/SubmitForm"),
    ("EXTERNAL.IMPORT_DATA", "S", "/ImportData"),
    ("EXTERNAL.URL_FILESPEC", "FS", "/URL"),
    ("CODEC.JBIG2", "Filter", "/JBIG2Decode"),
    ("CODEC.JPX", "Filter", "/JPXDecode"),
    ("RESOURCE.IMAGE_DIMENSIONS", "Width", "100000"),
    ("RESOURCE.PAGE_SIZE", "MediaBox", "[0 0 100000 100000]"),
    (
        "CODEC.DECODE_PARAMS",
        "DecodeParms",
        "<< /Predictor 12 /Colors 3 /Columns 2147483647 >>",
    ),
    ("STRUCT.PRINT_VIEW_MISMATCH", "F", "36"),
];

/// Where a standalone payload object (number 10) is referenced from.
#[derive(Clone, Copy)]
pub(crate) enum Attach {
    /// Not referenced (only union scan sees it).
    Orphan,
    /// `/A` of a link annotation on the page.
    AnnotA,
    /// The payload is itself an annotation in the page's `/Annots`.
    PageAnnot,
    /// Page resource `/XObject << /Q1 10 0 R >>`.
    XObject,
}

pub(crate) enum Payload {
    /// Object 10: `dict`, plus stream data when `stream` is set.
    Obj {
        dict: String,
        stream: Option<Vec<u8>>,
        attach: Attach,
    },
    /// Entries inserted into the catalog dict (object 1).
    Catalog(String),
    /// Entries inserted into the page dict (object 3).
    Page(String),
}

pub(crate) struct DictCase {
    pub rule: &'static str,
    pub payload: Payload,
    /// Names rewritten by the `name-encoded` variant.
    pub names: &'static [&'static str],
    /// Helper objects the payload references (`(num, body)`), e.g. a FontFile stream.
    pub helpers: Vec<(u32, Vec<u8>)>,
    /// Other rules that the payload itself also triggers.
    pub also: &'static [&'static str],
    pub note: &'static str,
    /// `(key, value)` made indirect by the `indirect-value` variant.
    pub indirect: Option<(&'static str, &'static str)>,
}

fn obj(dict: &str, attach: Attach) -> Payload {
    Payload::Obj {
        dict: dict.to_string(),
        stream: None,
        attach,
    }
}

fn stream_obj(dict: &str, data: &[u8], attach: Attach) -> Payload {
    Payload::Obj {
        dict: dict.to_string(),
        stream: Some(data.to_vec()),
        attach,
    }
}

fn case(
    rule: &'static str,
    payload: Payload,
    names: &'static [&'static str],
    note: &'static str,
) -> DictCase {
    DictCase {
        rule,
        payload,
        names,
        helpers: Vec::new(),
        also: &[],
        note,
        indirect: INDIRECT_VALUES
            .iter()
            .find(|(r, _, _)| *r == rule)
            .map(|&(_, k, v)| (k, v)),
    }
}

fn helper_stream(dict: &str, data: &[u8]) -> Vec<u8> {
    crate::builder::raw_stream_body(dict, data)
}

pub(crate) fn cases() -> Vec<DictCase> {
    use Attach::*;
    let mut v = vec![
        case(
            "POSTSCRIPT.XOBJECT",
            stream_obj(
                "/Type /XObject /Subtype /PS",
                b"% quelda-test\nshowpage\n",
                XObject,
            ),
            &["PS"],
            "PostScript XObject (harmless `showpage`)",
        ),
        case(
            "POSTSCRIPT.TYPE4_FUNCTION",
            stream_obj(
                "/FunctionType 4 /Domain [0 1] /Range [0 1]",
                TYPE4_BAD,
                Orphan,
            ),
            &["FunctionType"],
            "Type 4 function whose program uses a string (outside the spec allowlist)",
        ),
        case(
            "ACTIVE.JAVASCRIPT",
            obj(
                "<< /S /JavaScript /JS (app.alert('quelda-test')) >>",
                AnnotA,
            ),
            &["JavaScript", "JS"],
            "JavaScript action on a link annotation",
        ),
        case(
            "ACTIVE.LAUNCH",
            obj("<< /S /Launch /F (quelda-test.txt) >>", AnnotA),
            &["Launch"],
            "Launch action (points at a harmless file name)",
        ),
        case(
            "ACTIVE.OPEN_ACTION",
            Payload::Catalog("/OpenAction << /S /Thread /D 0 >>".to_string()),
            &["OpenAction", "Thread"],
            "OpenAction running a (harmless) Thread action: not a plain GoTo",
        ),
        case(
            "ACTIVE.ADDITIONAL_ACTIONS",
            Payload::Page("/AA << /O << /S /GoTo /D [3 0 R /Fit] >> >>".to_string()),
            &["AA"],
            "Page additional-actions (harmless GoTo)",
        ),
        case(
            "ACTIVE.OTHER_ACTIONS",
            obj("<< /S /Named /N /NextPage >>", AnnotA),
            &["Named"],
            "Named action",
        ),
        case(
            "EMBED.EMBEDDED_FILE",
            stream_obj("/Type /EmbeddedFile", b"quelda-test\n", Orphan),
            &["EmbeddedFile"],
            "Embedded file stream",
        ),
        case(
            "EMBED.FILE_ATTACHMENT",
            obj(
                "<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] /FS << /Type /Filespec /F (quelda-test.txt) >> >>",
                PageAnnot,
            ),
            &["FileAttachment"],
            "File attachment annotation",
        ),
        case(
            "EMBED.RICH_MEDIA",
            obj(
                "<< /Type /Annot /Subtype /RichMedia /Rect [0 0 10 10] >>",
                PageAnnot,
            ),
            &["RichMedia"],
            "RichMedia annotation",
        ),
        case(
            "EMBED.PORTFOLIO",
            Payload::Catalog("/Collection << /Type /Collection /View /D >>".to_string()),
            &["Collection"],
            "PDF Portfolio (`/Collection` in the catalog)",
        ),
        case(
            "EXTERNAL.URI",
            obj(
                "<< /S /URI /URI (https://example.invalid/quelda-test) >>",
                AnnotA,
            ),
            &["URI"],
            "URI action to a reserved .invalid domain",
        ),
        case(
            "EXTERNAL.REMOTE_GOTO",
            obj("<< /S /GoToR /F (quelda-test.pdf) /D [0 /Fit] >>", AnnotA),
            &["GoToR"],
            "GoToR action",
        ),
        case(
            "EXTERNAL.SUBMIT_FORM",
            obj(
                "<< /S /SubmitForm /F (https://example.invalid/quelda-test) >>",
                AnnotA,
            ),
            &["SubmitForm"],
            "SubmitForm action",
        ),
        case(
            "EXTERNAL.IMPORT_DATA",
            obj("<< /S /ImportData /F (quelda-test.fdf) >>", AnnotA),
            &["ImportData"],
            "ImportData action",
        ),
        case(
            "EXTERNAL.URL_FILESPEC",
            obj(
                "<< /Type /Filespec /FS /URL /F (https://example.invalid/quelda-test) >>",
                Orphan,
            ),
            &["URL"],
            "URL file specification",
        ),
        case(
            "FORMS.ACROFORM",
            Payload::Catalog("/AcroForm << /Fields [] >>".to_string()),
            &["AcroForm"],
            "Empty AcroForm",
        ),
        case(
            "CODEC.JBIG2",
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 1 /Filter /JBIG2Decode",
                b"quelda-test jbig2 bytes (not decoded)",
                XObject,
            ),
            &["JBIG2Decode"],
            "Image declaring the JBIG2Decode filter (data is not real JBIG2)",
        ),
        case(
            "CODEC.JPX",
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 8 /Height 8 /Filter /JPXDecode",
                b"quelda-test jpx bytes (not decoded)",
                XObject,
            ),
            &["JPXDecode"],
            "Image declaring the JPXDecode filter (data is not real JPEG 2000)",
        ),
        case(
            "RESOURCE.IMAGE_DIMENSIONS",
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 100000 /Height 100000 /ColorSpace /DeviceGray /BitsPerComponent 8",
                &[0u8; 16],
                XObject,
            ),
            &["Width"],
            "Pixel bomb: declares 100000x100000 (1e10 px) with 16 bytes of data",
        ),
        case(
            "RESOURCE.PAGE_SIZE",
            Payload::Page("/MediaBox [0 0 100000 100000]".to_string()),
            &["MediaBox"],
            "Page bomb: 100000 pt square page (~35 m)",
        ),
        case(
            "EXTERNAL.OPI",
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /OPI << /2.0 << /Type /OPI /Version 2.0 /F (quelda-test.tif) /Inks /full_color >> >>",
                &[0u8],
                XObject,
            ),
            &["OPI"],
            "Image with OPI comments naming a (missing) high-resolution file",
        ),
        case(
            "CODEC.DECODE_PARAMS",
            stream_obj(
                "/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /DecodeParms << /Predictor 12 /Colors 3 /Columns 2147483647 >>",
                &[0u8],
                XObject,
            ),
            &["DecodeParms", "Columns"],
            "Image whose predictor parameters declare 2^31 columns (data not filtered)",
        ),
        case(
            "STRUCT.PRINT_VIEW_MISMATCH",
            obj(
                "<< /Type /Annot /Subtype /Stamp /Rect [0 0 10 10] /F 36 /Contents (quelda-test) >>",
                PageAnnot,
            ),
            &["Annot"],
            "Stamp annotation flagged Print + NoView: printed, not shown on screen",
        ),
    ];

    let mut xfa = case(
        "FORMS.XFA",
        Payload::Catalog("/AcroForm << /Fields [] /XFA 20 0 R >>".to_string()),
        &["XFA"],
        "AcroForm with an XFA stream",
    );
    xfa.helpers.push((20, helper_stream("", XFA_PLAIN)));
    xfa.also = &["FORMS.ACROFORM"];
    v.push(xfa);

    let mut type1 = case(
        "CODEC.TYPE1_FONT",
        obj(
            "<< /Type /FontDescriptor /FontName /QueldaTest /Flags 32 /FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 /FontFile 20 0 R >>",
            Orphan,
        ),
        &["FontFile"],
        "Font descriptor with an embedded Type 1 program (fake bytes)",
    );
    type1.helpers.push((
        20,
        helper_stream(
            "/Length1 40 /Length2 0 /Length3 0",
            b"%!PS-AdobeFont-1.0: QueldaTest\n% quelda-test\n",
        ),
    ));
    v.push(type1);
    v
}

/// A Type 4 program outside the allowlist (a string), harmless anyway.
pub(crate) const TYPE4_BAD: &[u8] = b"{ (quelda-test) pop }";

pub(crate) const XFA_PLAIN: &[u8] =
    b"<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><template xmlns=\"http://www.xfa.org/schema/xfa-template/3.3/\"/></xdp:xdp>";

/// Applies a payload to `doc` and returns the builder, ready for more objects.
/// `keep_stream: false` writes a stream payload as a bare dict (for ObjStm).
fn plain_builder(c: &DictCase, text: &str, mut doc: Doc, keep_stream: bool) -> PdfBuilder {
    match &c.payload {
        Payload::Obj { stream, attach, .. } => {
            match attach {
                Attach::Orphan => {}
                Attach::AnnotA => doc.annots.push(6),
                Attach::PageAnnot => doc.annots.push(10),
                Attach::XObject => doc.xobjects.push(("Q1", 10)),
            }
            let mut b = doc.builder();
            if matches!(attach, Attach::AnnotA) {
                b.object(6, LINK_TO_10);
            }
            match stream {
                Some(data) if keep_stream => b.stream_raw(10, text, data),
                _ => b.object(10, as_dict(text, false)),
            };
            b
        }
        Payload::Catalog(_) => {
            doc.catalog_extra = text.to_string();
            doc.builder()
        }
        Payload::Page(_) => {
            doc.page_extra = text.to_string();
            doc.builder()
        }
    }
}

fn payload_text(c: &DictCase) -> &str {
    match &c.payload {
        Payload::Obj { dict, .. } => dict,
        Payload::Catalog(e) | Payload::Page(e) => e,
    }
}

/// Payload as a direct dict (stream data dropped), for nesting and ObjStm.
fn as_dict(text: &str, is_entry: bool) -> String {
    let t = text.trim();
    if is_entry || t.starts_with("<<") {
        t.to_string()
    } else {
        format!("<< {t} >>")
    }
}

fn add_helpers(b: &mut PdfBuilder, c: &DictCase) {
    for (n, body) in &c.helpers {
        b.object(*n, body);
    }
}

/// Builds one variant; returns the bytes and the extra rules the variant itself triggers.
pub(crate) fn build_variant(c: &DictCase, variant: &str) -> (Vec<u8>, Vec<&'static str>) {
    let text = payload_text(c);
    let is_entry = matches!(c.payload, Payload::Catalog(_) | Payload::Page(_));
    match variant {
        "plain" | "name-encoded" => {
            let text = if variant == "name-encoded" {
                encode_names_in(text, c.names)
            } else {
                text.to_string()
            };
            let mut b = plain_builder(c, &text, Doc::new(), true);
            add_helpers(&mut b, c);
            (b.build(), vec![])
        }
        "in-objstm" | "in-objstm-lzw" | "in-objstm-filter-chain" => {
            let (filters, extra): (&[Filter], _) = match variant {
                "in-objstm" => (&[Filter::Flate], vec![]),
                "in-objstm-lzw" => (&[Filter::Lzw], vec![]),
                _ => (&OBJSTM_CHAIN, vec!["STRUCT.FILTER_CHAIN"]),
            };
            let mut doc = Doc::new();
            doc.version = "1.5";
            let mut b = plain_builder(c, text, doc, false);
            let member = match c.payload {
                Payload::Obj { .. } => 10,
                Payload::Catalog(_) => 1,
                Payload::Page(_) => 3,
            };
            b.objstm(9, &[member], filters).xref(Xref::Stream);
            add_helpers(&mut b, c);
            (b.build(), extra)
        }
        INDIRECT => {
            let Some((key, value)) = c.indirect else {
                panic!("{}: no indirect value", c.rule);
            };
            let from = format!("/{key} {value}");
            assert!(text.contains(&from), "{}: payload has no `{from}`", c.rule);
            let text = text.replacen(&from, &format!("/{key} {INDIRECT_OBJ} 0 R"), 1);
            let mut b = plain_builder(c, &text, Doc::new(), true);
            add_helpers(&mut b, c);
            b.object(INDIRECT_OBJ, value);
            (b.build(), vec![])
        }
        "old-revision" => {
            let mut b = plain_builder(c, text, Doc::new(), true);
            add_helpers(&mut b, c);
            b.revision();
            match &c.payload {
                Payload::Obj { .. } => {
                    b.object(10, "<< /Type /QueldaNeutralized >>");
                }
                Payload::Catalog(_) => {
                    b.object(1, Doc::new().catalog_body());
                }
                Payload::Page(_) => {
                    b.object(3, Doc::new().page_body());
                }
            }
            (b.build(), vec!["STRUCT.INCREMENTAL_UPDATE"])
        }
        "nested-dict" => {
            let mut doc = Doc::new();
            doc.page_extra = if is_entry {
                format!("/QueldaNest << /L2 << {} >> >>", text.trim())
            } else {
                format!("/QueldaNest << /L2 << /L3 {} >> >>", as_dict(text, false))
            };
            let mut b = doc.builder();
            add_helpers(&mut b, c);
            (b.build(), vec![])
        }
        other => panic!("unknown dict variant {other}"),
    }
}

pub(crate) fn all() -> Vec<Fixture> {
    let mut out = Vec::new();
    for c in cases() {
        let indirect = c.indirect.map(|_| INDIRECT);
        for &variant in VARIANTS.iter().chain(indirect.iter()) {
            let (bytes, extra) = build_variant(&c, variant);
            let mut also: Vec<&'static str> = c.also.to_vec();
            also.extend(extra);
            let note = format!("{} — variant `{variant}`", c.note);
            out.push(bad(c.rule, variant, bytes, &also, &note));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn launch() -> DictCase {
        cases()
            .into_iter()
            .find(|c| c.rule == "ACTIVE.LAUNCH")
            .unwrap()
    }

    #[test]
    fn plain_attaches_and_contains_payload() {
        let (pdf, extra) = build_variant(&launch(), "plain");
        assert!(extra.is_empty());
        assert!(contains(&pdf, b"/S /Launch"));
        assert!(contains(&pdf, b"/Annots [6 0 R]"));
        assert!(contains(&pdf, b"/A 10 0 R"));
    }

    #[test]
    fn name_encoded_hides_plain_name() {
        let (pdf, _) = build_variant(&launch(), "name-encoded");
        assert!(!contains(&pdf, b"/Launch"));
        assert!(contains(&pdf, b"/#4C#61#75#6E#63#68"));
    }

    #[test]
    fn objstm_variant_compresses_payload() {
        let (pdf, _) = build_variant(&launch(), "in-objstm");
        assert!(
            !contains(&pdf, b"/Launch"),
            "payload must only exist inside the Flate ObjStm"
        );
        assert!(contains(&pdf, b"/Type /ObjStm"));
        assert!(contains(&pdf, b"/Type /XRef"));
    }

    #[test]
    fn old_revision_neutralizes_in_update() {
        let (pdf, extra) = build_variant(&launch(), "old-revision");
        assert_eq!(extra, vec!["STRUCT.INCREMENTAL_UPDATE"]);
        assert!(contains(&pdf, b"/S /Launch"));
        assert!(contains(&pdf, b"/QueldaNeutralized"));
        assert_eq!(pdf.windows(5).filter(|w| w == b"%%EOF").count(), 2);
    }

    #[test]
    fn nested_dict_has_no_payload_object() {
        let (pdf, _) = build_variant(&launch(), "nested-dict");
        assert!(contains(&pdf, b"/QueldaNest << /L2 << /L3 << /S /Launch"));
        assert!(!contains(&pdf, b"10 0 obj"));
    }

    #[test]
    fn catalog_entry_variants() {
        let c = cases()
            .into_iter()
            .find(|c| c.rule == "ACTIVE.OPEN_ACTION")
            .unwrap();
        let (pdf, _) = build_variant(&c, "plain");
        assert!(contains(
            &pdf,
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Thread /D 0 >> >>"
        ));
        let (pdf, _) = build_variant(&c, "nested-dict");
        assert!(contains(
            &pdf,
            b"/QueldaNest << /L2 << /OpenAction << /S /Thread /D 0 >> >> >>"
        ));
        let (pdf, _) = build_variant(&c, INDIRECT);
        assert!(contains(&pdf, b"/OpenAction 30 0 R"));
        assert!(contains(&pdf, b"30 0 obj\n<< /S /Thread /D 0 >>\nendobj"));
        let (pdf, _) = build_variant(&c, "in-objstm");
        assert!(!contains(&pdf, b"/OpenAction"));
    }

    #[test]
    fn indirect_value_variant() {
        let (pdf, extra) = build_variant(&launch(), INDIRECT);
        assert!(extra.is_empty());
        assert!(contains(&pdf, b"/S 30 0 R"));
        assert!(contains(&pdf, b"30 0 obj\n/Launch\nendobj"));
        assert!(!contains(&pdf, b"/S /Launch"));
        let t4 = cases()
            .into_iter()
            .find(|c| c.rule == "POSTSCRIPT.TYPE4_FUNCTION")
            .unwrap();
        let (pdf, _) = build_variant(&t4, INDIRECT);
        assert!(contains(&pdf, b"/FunctionType 30 0 R"));
        // Every listed rule has a case, and key-only rules have none.
        for (rule, _, _) in INDIRECT_VALUES {
            assert!(cases().iter().any(|c| c.rule == *rule), "{rule}");
        }
        for c in cases() {
            if c.rule == "FORMS.ACROFORM" {
                assert!(c.indirect.is_none());
            }
        }
    }

    #[test]
    fn objstm_filter_variants() {
        let (pdf, extra) = build_variant(&launch(), "in-objstm-lzw");
        assert!(extra.is_empty());
        assert!(contains(&pdf, b"/LZWDecode"));
        assert!(!contains(&pdf, b"/Launch"));
        let (pdf, extra) = build_variant(&launch(), "in-objstm-filter-chain");
        assert_eq!(extra, vec!["STRUCT.FILTER_CHAIN"]);
        assert!(contains(&pdf, b"/ASCII85Decode"));
        assert!(!contains(&pdf, b"/Launch"));
    }

    #[test]
    fn every_case_builds_every_variant() {
        for c in cases() {
            for v in VARIANTS.iter().chain(c.indirect.map(|_| &INDIRECT)) {
                let (pdf, _) = build_variant(&c, v);
                assert!(pdf.starts_with(b"%PDF-1."), "{} {v}", c.rule);
            }
        }
    }
}
