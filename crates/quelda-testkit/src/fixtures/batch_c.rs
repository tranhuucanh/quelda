//! Rules added in 0.2.0 (ADR #40): fixtures the generic dict variants do not
//! cover (stream-only keys, content operands, `/DA` strings, layers) and
//! every new rule's near-miss `good/` files.

use super::{BASE_CONTENT, Doc, Fixture, bad, good};
use crate::builder::{PdfBuilder, Xref};
use crate::filters::Filter;

const INCR: &str = "STRUCT.INCREMENTAL_UPDATE";
const ACROFORM: &str = "FORMS.ACROFORM";
const IMAGE: &str =
    "/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8";

/// Base doc whose page draws image XObject 10 (`/Im0`), with `dict` extra
/// entries and `data` as its stream data.
fn image_builder(dict: &str, data: &[u8]) -> PdfBuilder {
    let mut d = Doc::new();
    d.xobjects.push(("Im0", 10));
    d.content = [BASE_CONTENT, b"q 10 0 0 10 72 72 cm /Im0 Do Q\n"].concat();
    let mut b = d.builder();
    b.stream_raw(10, &format!("{IMAGE} {dict}"), data);
    b
}

fn image(dict: &str, data: &[u8]) -> Vec<u8> {
    image_builder(dict, data).build()
}

/// Base doc + annotation 10 on the page.
fn annot(dict: &str) -> Vec<u8> {
    let mut d = Doc::new();
    d.annots.push(10);
    let mut b = d.builder();
    b.object(10, dict);
    b.build()
}

/// Base doc whose content is `data`.
fn content(data: &[u8]) -> Vec<u8> {
    let mut d = Doc::new();
    d.content = data.to_vec();
    d.build()
}

fn stream_file() -> Vec<Fixture> {
    const R: &str = "EXTERNAL.STREAM_FILE";
    let old_rev = {
        let mut b = image_builder("/F (quelda-test.tif)", b"");
        b.revision().stream_raw(10, IMAGE, &[0]);
        b.build()
    };
    let reference = {
        let mut d = Doc::new();
        d.xobjects.push(("Fx", 10));
        d.content = [BASE_CONTENT, b"/Fx Do\n"].concat();
        let mut b = d.builder();
        b.stream_raw(
            10,
            "/Type /XObject /Subtype /Form /BBox [0 0 10 10] /Ref << /F (quelda-test.pdf) /Page 0 >>",
            b"",
        );
        b.build()
    };
    vec![
        bad(
            R,
            "plain",
            image("/F (quelda-test.tif)", b""),
            &[],
            "Image whose data is an external file (`/F` path, as OPI/prepress tools wrote)",
        ),
        bad(
            R,
            "url-filespec",
            image(
                "/F << /FS /URL /F (https://example.invalid/quelda-test.tif) >>",
                b"",
            ),
            &["EXTERNAL.URL_FILESPEC"],
            "Image data fetched from a URL",
        ),
        bad(
            R,
            "ffilter",
            image("/FFilter /DCTDecode", &[0]),
            &[],
            "`/FFilter` (filter of external data) without `/F`",
        ),
        bad(
            R,
            "name-encoded",
            image("/#46 (quelda-test.tif)", b""),
            &[],
            "`/F` written as `/#46`",
        ),
        bad(
            R,
            "old-revision",
            old_rev,
            &[INCR],
            "External image only in the first revision",
        ),
        bad(
            R,
            "reference-xobject",
            reference,
            &[],
            "Reference XObject importing a page of another PDF",
        ),
        good(
            R,
            "embedded-image",
            image("", &[0]),
            &[],
            "Image with its data embedded",
        ),
        good(
            R,
            "annotation-flags",
            annot("<< /Type /Annot /Subtype /Square /Rect [0 0 10 10] /F 4 >>"),
            &[],
            "`/F` as annotation flags",
        ),
        good(
            R,
            "local-filespec",
            {
                let mut b = Doc::new().builder();
                b.object(10, "<< /Type /Filespec /F (quelda-test.txt) >>");
                b.build()
            },
            &[],
            "`/F` in a file specification (not a stream)",
        ),
    ]
}

fn opi() -> Vec<Fixture> {
    vec![good(
        "EXTERNAL.OPI",
        "opi-in-string",
        {
            let mut d = Doc::new();
            d.page_extra = "/QueldaNote (/OPI << /Type /OPI >>)".to_string();
            d.build()
        },
        &[],
        "`/OPI` only inside a string",
    )]
}

fn name_too_long() -> Vec<Fixture> {
    const R: &str = "STRUCT.NAME_TOO_LONG";
    let long = format!("QueldaTest{}", "X".repeat(190));
    let font = |name: &str| format!("<< /Type /Font /Subtype /Type1 /BaseFont /{name} >>");
    // Object 11: a second font, used only by union scan.
    let with_font = |name: &str| {
        let mut b = Doc::new().builder();
        b.object(11, font(name));
        b
    };
    let objstm = {
        let mut d = Doc::new();
        d.version = "1.5";
        let mut b = d.builder();
        b.object(11, font(&long))
            .objstm(9, &[11], &[Filter::Flate])
            .xref(Xref::Stream);
        b.build()
    };
    let old_rev = {
        let mut b = with_font(&long);
        b.revision().object(11, font("Helvetica"));
        b.build()
    };
    let operand = {
        let mut d = Doc::new();
        d.content = format!("BT /{long} 24 Tf 72 720 Td (quelda test) Tj ET\n").into_bytes();
        d.build()
    };
    vec![
        bad(
            R,
            "plain",
            with_font(&long).build(),
            &[],
            "Font /BaseFont of 200 bytes",
        ),
        bad(
            R,
            "name-encoded",
            with_font(&format!("QueldaTest{}", "#58".repeat(190))).build(),
            &[],
            "200 bytes once `#58` is decoded",
        ),
        bad(
            R,
            "in-objstm",
            objstm,
            &[],
            "Long font name inside an ObjStm",
        ),
        bad(
            R,
            "old-revision",
            old_rev,
            &[INCR],
            "Long font name only in the first revision",
        ),
        bad(
            R,
            "content-operand",
            operand,
            &[],
            "Long font resource name as a `Tf` operand",
        ),
        good(
            R,
            "127-bytes",
            with_font(&"Q".repeat(127)).build(),
            &[],
            "Name of exactly 127 bytes (the limit)",
        ),
        good(
            R,
            "subset-font-name",
            with_font("ABCDEF+HiraginoKakuGothicProN-W3-90ms-RKSJ-H-Identity-H").build(),
            &[],
            "Long but real CJK subset font name",
        ),
        good(
            R,
            "long-string",
            {
                let mut d = Doc::new();
                d.page_extra = format!("/QueldaNote ({long})");
                d.build()
            },
            &[],
            "200-byte string (strings have no such limit)",
        ),
    ]
}

fn decode_params() -> Vec<Fixture> {
    const R: &str = "CODEC.DECODE_PARAMS";
    let inline = |dp: &str| {
        content(
            format!("q 2 0 0 1 72 72 cm BI /W 2 /H 1 /BPC 8 /CS /G /DP << {dp} >> ID ab EI Q\n")
                .as_bytes(),
        )
    };
    vec![
        bad(
            R,
            "inline-image",
            inline("/Predictor 12 /Colors 0"),
            &[],
            "Inline image with `/Colors 0`",
        ),
        bad(
            R,
            "array-parms",
            image(
                "/Filter [/ASCIIHexDecode /FlateDecode] /DecodeParms [null << /Predictor 99 >>]",
                b"00>",
            ),
            &[],
            "Second filter's `/Predictor 99`",
        ),
        bad(
            R,
            "bits-per-component",
            image("/DecodeParms << /Predictor 2 /BitsPerComponent 3 >>", &[0]),
            &[],
            "TIFF predictor with 3 bits per component",
        ),
        good(
            R,
            "png-predictor",
            image(
                "/DecodeParms << /Predictor 15 /Colors 1 /BitsPerComponent 8 /Columns 1 >>",
                &[0],
            ),
            &[],
            "PNG predictor with real parameters",
        ),
        good(
            R,
            "ccitt",
            image(
                "/DecodeParms << /K -1 /Columns 1728 /Rows 2200 /BlackIs1 true >>",
                &[0],
            ),
            &[],
            "CCITT fax parameters",
        ),
        good(
            R,
            "inline-image",
            inline("/Predictor 1"),
            &[],
            "Inline image with a no-op predictor",
        ),
    ]
}

fn print_view_mismatch() -> Vec<Fixture> {
    const R: &str = "STRUCT.PRINT_VIEW_MISMATCH";
    let layer = |usage: &str| {
        let mut d = Doc::new();
        d.catalog_extra = "/OCProperties << /OCGs [10 0 R] /D << /Order [10 0 R] >> >>".to_string();
        d.page_extra = "/QueldaProps << /oc1 10 0 R >>".to_string();
        let mut b = d.builder();
        b.object(
            10,
            format!("<< /Type /OCG /Name (quelda-test) /Usage << {usage} >> >>"),
        );
        b.build()
    };
    vec![
        bad(
            R,
            "print-only-layer",
            layer("/Print << /PrintState /ON >> /View << /ViewState /OFF >>"),
            &[],
            "Layer ON when printed, OFF on screen",
        ),
        good(
            R,
            "print-flag",
            annot("<< /Type /Annot /Subtype /Stamp /Rect [0 0 10 10] /F 4 >>"),
            &[],
            "Annotation printed and shown (Print flag only)",
        ),
        good(
            R,
            "hidden-annotation",
            annot("<< /Type /Annot /Subtype /Stamp /Rect [0 0 10 10] /F 38 >>"),
            &[],
            "Hidden flag set: neither shown nor printed",
        ),
        good(
            R,
            "screen-only-layer",
            layer("/Print << /PrintState /OFF >> /View << /ViewState /ON >>"),
            &[],
            "Layer shown on screen, not printed (nothing printed is unseen)",
        ),
    ]
}

/// `POSTSCRIPT.CONTENT_OP` in `/DA` strings (0.2.0).
fn default_appearance() -> Vec<Fixture> {
    const R: &str = "POSTSCRIPT.CONTENT_OP";
    let form = |acroform_da: &str, field: &str| {
        let mut d = Doc::new();
        d.catalog_extra = format!("/AcroForm << /Fields [10 0 R] /DA {acroform_da} >>");
        d.annots.push(10);
        let mut b = d.builder();
        b.object(
            10,
            format!("<< /Type /Annot /Subtype /Widget /FT /Tx /T (q) /Rect [0 0 10 10] {field} >>"),
        );
        b
    };
    let indirect = {
        let mut b = form("(/Helv 0 Tf 0 g)", "/DA 20 0 R");
        b.object(20, "(/Helv 0 Tf 0 g (quelda-test) PS)");
        b.build()
    };
    vec![
        bad(
            R,
            "acroform-da",
            form("(/Helv 0 Tf 0 g (quelda-test) PS)", "").build(),
            &[ACROFORM],
            "`PS` in the AcroForm default appearance string",
        ),
        bad(
            R,
            "field-da",
            form("(/Helv 0 Tf 0 g)", "/DA (/Helv 12 Tf PS 0 g)").build(),
            &[ACROFORM],
            "`PS` in a text field's /DA",
        ),
        bad(
            R,
            "freetext-da",
            annot(
                "<< /Type /Annot /Subtype /FreeText /Rect [0 0 10 10] /Contents (q) /DA (0 g /Helv 9 Tf PS) >>",
            ),
            &[],
            "`PS` in a FreeText annotation's /DA",
        ),
        bad(
            R,
            "da-indirect",
            indirect,
            &[ACROFORM],
            "/DA string in an indirect object",
        ),
        good(
            R,
            "plain-da",
            form("(/Helv 0 Tf 0 g)", "/DA (/Helv 12 Tf 0 0 1 rg)").build(),
            &[ACROFORM],
            "Ordinary default appearance strings",
        ),
        good(
            R,
            "ps-in-da-text",
            form("(/Helv 0 Tf 0 g)", "/DA (/Helv 12 Tf 0 g) /V (PS)").build(),
            &[ACROFORM],
            "`PS` as a field value, not in /DA",
        ),
    ]
}

pub(crate) fn all() -> Vec<Fixture> {
    let mut out = Vec::new();
    out.extend(stream_file());
    out.extend(opi());
    out.extend(name_too_long());
    out.extend(decode_params());
    out.extend(print_view_mismatch());
    out.extend(default_appearance());
    out
}
