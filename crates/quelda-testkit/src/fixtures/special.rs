//! Fixtures that don't fit the generic dict variants: file-level, content-stream
//! and XML rules, rule-specific evasion variants, and every rule's near-miss
//! `good/` files.

use super::dict_cases::{TYPE4_BAD, XFA_PLAIN};
use super::filetype::{self, FOREIGN, NOT_PDF, POLYGLOT, PS_MAGIC};
use super::{BASE_CONTENT, Doc, Fixture, LINK_TO_10, bad, good};
use crate::builder::{PdfBuilder, Xref, raw_stream_body};
use crate::filters::{Filter, encode_chain, filter_entry};
use crate::names::{encode_names_in, name_encoded_all};

const INCR: &str = "STRUCT.INCREMENTAL_UPDATE";
const CHAIN: &str = "STRUCT.FILTER_CHAIN";
const ACROFORM: &str = "FORMS.ACROFORM";
const XFA: &str = "FORMS.XFA";
const CHAIN3: [Filter; 3] = [Filter::Ascii85, Filter::AsciiHex, Filter::Flate];

/// Base doc with an extra entry in the page dict (for near-miss strings/keys).
fn page_note(entry: &str) -> Vec<u8> {
    let mut d = Doc::new();
    d.page_extra = entry.to_string();
    d.build()
}

fn content(data: &[u8], filters: &[Filter]) -> Vec<u8> {
    let mut d = Doc::new();
    d.content = data.to_vec();
    d.content_filters = filters.to_vec();
    d.build()
}

/// Base doc + object 10, reached from a link annotation's `/A`.
fn action(dict: &str) -> Vec<u8> {
    let mut d = Doc::new();
    d.annots.push(6);
    let mut b = d.builder();
    b.object(6, LINK_TO_10).object(10, dict);
    b.build()
}

fn filetype_rules() -> Vec<Fixture> {
    let mut lower = Doc::new().build();
    lower[..5].copy_from_slice(b"%pdf-");
    let ps_then_pdf = {
        let mut v = filetype::ps_adobe();
        v.extend_from_slice(&Doc::new().build());
        v
    };
    vec![
        bad(
            NOT_PDF,
            "junk-before-header",
            filetype::with_prefix(b"QUELDA-JUNK\n"),
            &[],
            "Junk before %PDF-",
        ),
        bad(
            NOT_PDF,
            "header-after-1024",
            filetype::with_prefix(&b"QUELDA-JUNK ".repeat(100)),
            &[],
            "%PDF- only after 1200 bytes of junk (past the 1024-byte window many readers scan)",
        ),
        bad(
            NOT_PDF,
            "lowercase-header",
            lower,
            &[],
            "`%pdf-` is not a PDF header",
        ),
        bad(
            NOT_PDF,
            "no-header",
            b"quelda-test: plain text, not a PDF\n".to_vec(),
            &[],
            "Plain text",
        )
        .at_least(),
        good(
            NOT_PDF,
            "pdf-2.0",
            {
                let mut d = Doc::new();
                d.version = "2.0";
                d.build()
            },
            &[],
            "%PDF-2.0 at byte 0",
        ),
        good(
            NOT_PDF,
            "pdf-1.0",
            {
                let mut d = Doc::new();
                d.version = "1.0";
                d.build()
            },
            &[],
            "%PDF-1.0 at byte 0",
        ),
        bad(
            PS_MAGIC,
            "ps-adobe",
            filetype::ps_adobe(),
            &[NOT_PDF],
            "%!PS-Adobe-3.0",
        )
        .at_least(),
        bad(
            PS_MAGIC,
            "ps-minimal",
            b"%!\nshowpage\n".to_vec(),
            &[NOT_PDF],
            "Bare `%!`",
        )
        .at_least(),
        bad(
            PS_MAGIC,
            "eps-binary",
            filetype::eps_binary(),
            &[NOT_PDF],
            "EPS binary header",
        )
        .at_least(),
        bad(
            PS_MAGIC,
            "eps-ascii",
            filetype::eps_ascii(),
            &[NOT_PDF],
            "EPS text header",
        )
        .at_least(),
        bad(
            PS_MAGIC,
            "ps-then-pdf",
            ps_then_pdf,
            &[NOT_PDF],
            "PostScript followed by a full PDF: Ghostscript runs the PS part",
        )
        .at_least(),
        good(
            PS_MAGIC,
            "ps-text-in-content",
            content(b"BT /F1 12 Tf 72 720 Td (%!PS-Adobe-3.0) Tj ET\n", &[]),
            &[],
            "`%!PS` inside a content string",
        ),
        bad(FOREIGN, "svg", filetype::svg(), &[NOT_PDF], "SVG").at_least(),
        bad(
            FOREIGN,
            "mvg",
            filetype::mvg(),
            &[NOT_PDF],
            "ImageMagick MVG",
        )
        .at_least(),
        bad(
            FOREIGN,
            "msl",
            filetype::msl(),
            &[NOT_PDF],
            "ImageMagick MSL",
        )
        .at_least(),
        bad(FOREIGN, "html", filetype::html(), &[NOT_PDF], "HTML").at_least(),
        bad(FOREIGN, "zip", filetype::zip_one_file(), &[NOT_PDF], "ZIP").at_least(),
        bad(
            FOREIGN,
            "xml",
            b"<?xml version=\"1.0\"?>\n<quelda-test/>\n".to_vec(),
            &[NOT_PDF],
            "Generic XML",
        )
        .at_least(),
        good(
            FOREIGN,
            "svg-text-in-content",
            content(b"BT /F1 12 Tf 72 720 Td (<svg>) Tj ET\n", &[]),
            &[],
            "`<svg>` inside a content string",
        ),
        bad(
            POLYGLOT,
            "zip-appended",
            filetype::pdf_then(&filetype::zip_eocd()),
            &[],
            "Empty ZIP after %%EOF",
        ),
        bad(
            POLYGLOT,
            "zip-in-body",
            {
                let mut b = Doc::new().builder();
                b.raw(&filetype::zip_one_file()).raw(b"\n");
                b.build()
            },
            &[],
            "ZIP local header + central directory between PDF objects",
        ),
        bad(
            POLYGLOT,
            "html-in-body",
            {
                let mut b = Doc::new().builder();
                b.raw(b"<html><body><script>/* quelda-test */</script></body></html>\n");
                b.build()
            },
            &[],
            "HTML with <script> between PDF objects",
        ),
        good(
            POLYGLOT,
            "script-in-stream",
            content(b"BT /F1 12 Tf 72 720 Td (<script>) Tj ET\n", &[]),
            &[],
            "`<script>` inside a content stream",
        ),
    ]
}

const PS_OP: &[u8] = b"q (% quelda-test) PS Q\n";

fn content_op_rule() -> Vec<Fixture> {
    const R: &str = "POSTSCRIPT.CONTENT_OP";
    let ps_content = [BASE_CONTENT, PS_OP].concat();
    let form_dict = "/Type /XObject /Subtype /Form /BBox [0 0 10 10]";

    let form = {
        let mut d = Doc::new();
        d.xobjects.push(("Fx", 10));
        d.content = [BASE_CONTENT, b"/Fx Do\n"].concat();
        let mut b = d.builder();
        b.stream(10, form_dict, PS_OP, &[Filter::Flate]);
        b.build()
    };
    let appearance = {
        let mut d = Doc::new();
        d.annots.push(10);
        let mut b = d.builder();
        b.object(
            10,
            "<< /Type /Annot /Subtype /Square /Rect [0 0 10 10] /AP << /N 11 0 R >> >>",
        )
        .stream(11, form_dict, PS_OP, &[]);
        b.build()
    };
    let type3 = {
        let mut b = Doc::new().builder();
        b.object(
            10,
            "<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1 1] /FontMatrix [1 0 0 1 0 0] /CharProcs << /a 11 0 R >> /Encoding << /Type /Encoding /Differences [97 /a] >> /FirstChar 97 /LastChar 97 /Widths [1] >>",
        )
        .stream(11, "", &[b"1 0 0 0 1 1 d1\n".as_slice(), PS_OP].concat(), &[]);
        b.build()
    };
    let old_rev = {
        let mut d = Doc::new();
        d.content = ps_content.clone();
        let mut b = d.builder();
        b.revision().stream(4, "", BASE_CONTENT, &[]);
        b.build()
    };

    vec![
        bad(
            R,
            "plain",
            content(&ps_content, &[]),
            &[],
            "`PS` operator in page content",
        ),
        bad(
            R,
            "flate",
            content(&ps_content, &[Filter::Flate]),
            &[],
            "Flate-compressed page content",
        ),
        bad(
            R,
            "filter-chain",
            content(&ps_content, &CHAIN3),
            &[CHAIN],
            "Content through A85 → AHx → Flate",
        ),
        bad(
            R,
            "lzw",
            content(&ps_content, &[Filter::Lzw]),
            &[],
            "LZW-compressed page content",
        ),
        bad(
            R,
            "form-xobject",
            form,
            &[],
            "Inside a Flate Form XObject drawn with Do",
        ),
        bad(
            R,
            "appearance-stream",
            appearance,
            &[],
            "Inside an annotation appearance stream",
        ),
        bad(
            R,
            "type3-charproc",
            type3,
            &[],
            "Inside a Type 3 glyph procedure",
        ),
        bad(
            R,
            "old-revision",
            old_rev,
            &[INCR],
            "Only in the first revision's content",
        ),
        good(
            R,
            "inline-image-ps-bytes",
            content(
                b"q 2 0 0 1 72 72 cm BI /W 2 /H 1 /BPC 8 /CS /G ID PS EI Q\n",
                &[],
            ),
            &[],
            "Inline image whose data bytes are `PS`",
        ),
        good(
            R,
            "ps-text-string",
            content(b"BT /F1 12 Tf 72 720 Td (PS) Tj ET\n", &[]),
            &[],
            "`(PS) Tj`",
        ),
        good(
            R,
            "ps-name-operand",
            content(b"q /PS gs Q\n", &[]),
            &[],
            "`/PS` as a name operand of `gs`",
        ),
    ]
}

const XMP_DOCTYPE: &[u8] = b"<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n<!DOCTYPE x:xmpmeta [<!ENTITY quelda \"quelda-test\">]>\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"/></x:xmpmeta>\n<?xpacket end=\"w\"?>\n";
const XMP_CLEAN: &[u8] = b"<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"/></x:xmpmeta>\n<?xpacket end=\"w\"?>\n";
const XMP_ESCAPED: &[u8] = b"<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:title>&lt;!DOCTYPE quelda&gt;</dc:title></rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end=\"w\"?>\n";

fn metadata_doc(xmp: &[u8], filters: &[Filter]) -> PdfBuilder {
    let mut d = Doc::new();
    d.catalog_extra = "/Metadata 10 0 R".into();
    let mut b = d.builder();
    b.stream(10, "/Type /Metadata /Subtype /XML", xmp, filters);
    b
}

fn xml_rule() -> Vec<Fixture> {
    const R: &str = "XML.DOCTYPE";
    let old_rev = {
        let mut b = metadata_doc(XMP_DOCTYPE, &[]);
        b.revision()
            .stream(10, "/Type /Metadata /Subtype /XML", XMP_CLEAN, &[]);
        b.build()
    };
    let xfa = {
        let mut d = Doc::new();
        d.catalog_extra = "/AcroForm << /Fields [] /XFA 20 0 R >>".into();
        let mut b = d.builder();
        let data = b"<?xml version=\"1.0\"?>\n<!DOCTYPE xdp [<!ENTITY quelda \"quelda-test\">]>\n<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"/>\n";
        b.stream(20, "", data, &[]);
        b.build()
    };
    let entity_only =
        b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><!ENTITY quelda \"quelda-test\"></x:xmpmeta>\n";
    vec![
        bad(
            R,
            "plain",
            metadata_doc(XMP_DOCTYPE, &[]).build(),
            &[],
            "XMP metadata with DOCTYPE + ENTITY",
        ),
        bad(
            R,
            "flate",
            metadata_doc(XMP_DOCTYPE, &[Filter::Flate]).build(),
            &[],
            "Flate XMP",
        ),
        bad(
            R,
            "filter-chain",
            metadata_doc(XMP_DOCTYPE, &CHAIN3).build(),
            &[CHAIN],
            "XMP through 3 filters",
        ),
        bad(
            R,
            "lzw",
            metadata_doc(XMP_DOCTYPE, &[Filter::Lzw]).build(),
            &[],
            "LZW XMP",
        ),
        bad(
            R,
            "old-revision",
            old_rev,
            &[INCR],
            "DOCTYPE only in the first revision's XMP",
        ),
        bad(
            R,
            "in-xfa",
            xfa,
            &[ACROFORM, XFA],
            "DOCTYPE inside an XFA stream",
        ),
        bad(
            R,
            "entity-only",
            metadata_doc(entity_only, &[]).build(),
            &[],
            "<!ENTITY without DOCTYPE",
        ),
        good(
            R,
            "xmp-clean",
            metadata_doc(XMP_CLEAN, &[]).build(),
            &[],
            "Normal XMP packet",
        ),
        good(
            R,
            "xmp-escaped-doctype",
            metadata_doc(XMP_ESCAPED, &[]).build(),
            &[],
            "`&lt;!DOCTYPE` as escaped text",
        ),
    ]
}

fn utf16_hex(s: &str) -> String {
    let mut out = String::from("FEFF");
    for u in s.encode_utf16() {
        out.push_str(&format!("{u:04X}"));
    }
    out
}

fn javascript_rule() -> Vec<Fixture> {
    const R: &str = "ACTIVE.JAVASCRIPT";
    let js = b"app.alert('quelda-test');";
    let js_stream = {
        let mut d = Doc::new();
        d.annots.push(6);
        let mut b = d.builder();
        b.object(6, LINK_TO_10)
            .object(10, "<< /S /JavaScript /JS 11 0 R >>")
            .stream(11, "", js, &[Filter::Flate]);
        b.build()
    };
    let names_tree = {
        let mut d = Doc::new();
        d.catalog_extra = "/Names << /JavaScript << /Names [(quelda) 10 0 R] >> >>".into();
        let mut b = d.builder();
        b.object(10, "<< /S /JavaScript /JS (app.alert('quelda-test')) >>");
        b.build()
    };
    let widget_aa = {
        let mut d = Doc::new();
        d.annots.push(10);
        let mut b = d.builder();
        b.object(
            10,
            "<< /Type /Annot /Subtype /Widget /Rect [0 0 10 10] /AA << /K 11 0 R >> >>",
        )
        .object(11, "<< /S /JavaScript /JS (app.alert('quelda-test')) >>");
        b.build()
    };
    let open_action = {
        let mut d = Doc::new();
        d.catalog_extra = "/OpenAction 10 0 R".into();
        let mut b = d.builder();
        b.object(10, "<< /S /JavaScript /JS (app.alert('quelda-test')) >>");
        b.build()
    };
    vec![
        bad(R, "js-stream", js_stream, &[], "/JS is a Flate stream"),
        bad(
            R,
            "js-utf16",
            action(&format!(
                "<< /S /JavaScript /JS <{}> >>",
                utf16_hex("app.alert('quelda-test')")
            )),
            &[],
            "/JS as a UTF-16BE hex string with BOM",
        ),
        bad(
            R,
            "js-names-tree",
            names_tree,
            &[],
            "Document-level JavaScript name tree",
        ),
        bad(
            R,
            "js-annotation",
            widget_aa,
            &["ACTIVE.ADDITIONAL_ACTIONS"],
            "Widget /AA keystroke action",
        ),
        bad(
            R,
            "js-openaction",
            open_action,
            &["ACTIVE.OPEN_ACTION"],
            "OpenAction runs JavaScript",
        ),
        good(
            R,
            "js-in-string",
            page_note("/QueldaNote (/S /JavaScript /JS)"),
            &[],
            "Names only inside a string",
        ),
        good(
            R,
            "key-jsx",
            page_note("/JSX (quelda)"),
            &[],
            "Key /JSX is not /JS",
        ),
    ]
}

const XFA_SCRIPT: &[u8] = b"<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><template xmlns=\"http://www.xfa.org/schema/xfa-template/3.3/\"><subform><script contentType=\"application/x-javascript\">app.alert('quelda-test');</script></subform></template></xdp:xdp>";

fn acroform_doc(extra: &str, xfa: Option<&[u8]>) -> Vec<u8> {
    let mut d = Doc::new();
    d.catalog_extra = format!("/AcroForm << /Fields [] {extra} >>");
    let mut b = d.builder();
    if let Some(data) = xfa {
        b.stream(20, "", data, &[]);
    }
    b.build()
}

fn simple_rule_goods() -> Vec<Fixture> {
    vec![
        good(
            "POSTSCRIPT.XOBJECT",
            "form-xobject",
            {
                let mut d = Doc::new();
                d.xobjects.push(("Fx", 10));
                let mut b = d.builder();
                b.stream(
                    10,
                    "/Type /XObject /Subtype /Form /BBox [0 0 10 10]",
                    b"0 0 m 1 1 l S\n",
                    &[],
                );
                b.build()
            },
            &[],
            "Form XObject",
        ),
        good(
            "POSTSCRIPT.XOBJECT",
            "ps-in-string",
            page_note("/QueldaNote (/Subtype /PS)"),
            &[],
            "String",
        ),
        good(
            "POSTSCRIPT.TYPE4_FUNCTION",
            "function-type-2",
            {
                let mut b = Doc::new().builder();
                b.object(
                    10,
                    "<< /FunctionType 2 /Domain [0 1] /C0 [0] /C1 [1] /N 1 >>",
                );
                b.build()
            },
            &[],
            "Exponential (type 2) function",
        ),
        good(
            "ACTIVE.LAUNCH",
            "goto-action",
            action("<< /S /GoTo /D [3 0 R /Fit] >>"),
            &[],
            "GoTo action",
        ),
        good(
            "ACTIVE.LAUNCH",
            "launch-in-string",
            page_note("/QueldaNote (/S /Launch)"),
            &[],
            "String",
        ),
        good(
            "ACTIVE.OPEN_ACTION",
            "openaction-in-string",
            page_note("/QueldaNote (/OpenAction)"),
            &[],
            "String",
        ),
        good(
            "ACTIVE.ADDITIONAL_ACTIONS",
            "key-aax",
            page_note("/AAX << /O 1 >>"),
            &[],
            "Key /AAX is not /AA",
        ),
        good(
            "ACTIVE.OTHER_ACTIONS",
            "goto-action",
            action("<< /S /GoTo /D [3 0 R /Fit] >>"),
            &[],
            "GoTo action",
        ),
        good(
            "EMBED.EMBEDDED_FILE",
            "filespec-without-ef",
            {
                let mut b = Doc::new().builder();
                b.object(10, "<< /Type /Filespec /F (quelda-test.txt) >>");
                b.build()
            },
            &[],
            "File specification with no embedded stream",
        ),
        good(
            "EMBED.FILE_ATTACHMENT",
            "text-annotation",
            {
                let mut d = Doc::new();
                d.annots.push(10);
                let mut b = d.builder();
                b.object(
                    10,
                    "<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (quelda) >>",
                );
                b.build()
            },
            &[],
            "Text (sticky note) annotation",
        ),
        good(
            "EMBED.RICH_MEDIA",
            "link-annotation",
            {
                let mut d = Doc::new();
                d.annots.push(10);
                let mut b = d.builder();
                b.object(
                    10,
                    "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /Dest [3 0 R /Fit] >>",
                );
                b.build()
            },
            &[],
            "Plain link annotation",
        ),
        good(
            "EMBED.PORTFOLIO",
            "collection-in-string",
            page_note("/QueldaNote (/Collection)"),
            &[],
            "String",
        ),
        good(
            "EXTERNAL.URI",
            "goto-action",
            action("<< /S /GoTo /D [3 0 R /Fit] >>"),
            &[],
            "GoTo action",
        ),
        good(
            "EXTERNAL.REMOTE_GOTO",
            "goto-action",
            action("<< /S /GoTo /D [3 0 R /Fit] >>"),
            &[],
            "Local GoTo",
        ),
        good(
            "EXTERNAL.SUBMIT_FORM",
            "reset-form",
            action("<< /S /ResetForm >>"),
            &[],
            "ResetForm is not SubmitForm",
        ),
        good(
            "EXTERNAL.IMPORT_DATA",
            "import-in-string",
            page_note("/QueldaNote (/S /ImportData)"),
            &[],
            "String",
        ),
        good(
            "EXTERNAL.URL_FILESPEC",
            "local-filespec",
            {
                let mut b = Doc::new().builder();
                b.object(10, "<< /Type /Filespec /F (quelda-test.txt) >>");
                b.build()
            },
            &[],
            "File spec without /FS /URL",
        ),
        good(
            XFA,
            "acroform-without-xfa",
            acroform_doc("", None),
            &[ACROFORM],
            "AcroForm only",
        ),
        good(
            ACROFORM,
            "acroform-in-string",
            page_note("/QueldaNote (/AcroForm)"),
            &[],
            "String",
        ),
        good(
            "CODEC.JBIG2",
            "flate-image",
            {
                let mut d = Doc::new();
                d.xobjects.push(("Im1", 10));
                let mut b = d.builder();
                b.stream(
                    10,
                    "/Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceRGB /BitsPerComponent 8",
                    &super::benign::rgb_image(2, 2),
                    &[Filter::Flate],
                );
                b.build()
            },
            &[],
            "Flate image",
        ),
        good(
            "CODEC.JBIG2",
            "jbig2-in-string",
            page_note("/QueldaNote (/JBIG2Decode)"),
            &[],
            "String",
        ),
        good(
            "CODEC.JPX",
            "jpx-in-string",
            page_note("/QueldaNote (/JPXDecode)"),
            &[],
            "String",
        ),
        good(
            "CODEC.TYPE1_FONT",
            "fontfile2-truetype",
            {
                let mut b = Doc::new().builder();
                b.object(
                    10,
                    "<< /Type /FontDescriptor /FontName /QueldaTT /Flags 32 /FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 /FontFile2 20 0 R >>",
                )
                .stream(20, "", &super::rules_03::valid_truetype(), &[]);
                b.build()
            },
            &[],
            "TrueType program (/FontFile2) is not Type 1",
        ),
        good(
            "CODEC.TYPE1_FONT",
            "base14-no-fontfile",
            Doc::new().build(),
            &[],
            "Base-14 Type1 font, not embedded",
        ),
    ]
}

fn extra_rule_variants() -> Vec<Fixture> {
    let embedded_tree = {
        let mut d = Doc::new();
        d.catalog_extra =
            "/Names << /EmbeddedFiles << /Names [(quelda-test.txt) 11 0 R] >> >>".into();
        let mut b = d.builder();
        b.object(
            11,
            "<< /Type /Filespec /F (quelda-test.txt) /EF << /F 10 0 R >> >>",
        )
        .stream(10, "/Type /EmbeddedFile", b"quelda-test\n", &[]);
        b.build()
    };
    let rich = |subtype: &str| {
        let mut d = Doc::new();
        d.annots.push(10);
        let mut b = d.builder();
        b.object(
            10,
            format!("<< /Type /Annot /Subtype /{subtype} /Rect [0 0 10 10] >>"),
        );
        b.build()
    };
    let goto_e = action("<< /S /GoToE /T << /R /C /N (quelda-test) >> >>");
    // The value of `/S` is an indirect object (ADR #19: declarative rules
    // follow one level of references, every definition). The `bad` side is
    // the generic `indirect-value` variant (dict_cases).
    let indirect_s = |name: &str| {
        let mut d = Doc::new();
        d.annots.push(6);
        let mut b = d.builder();
        b.object(6, LINK_TO_10)
            .object(10, "<< /S 11 0 R /F (quelda-test.txt) >>")
            .object(11, format!("/{name}"));
        b.build()
    };
    vec![
        good(
            "ACTIVE.LAUNCH",
            "indirect-goto",
            indirect_s("GoTo"),
            &[],
            "GoTo action whose /S is an indirect name object",
        ),
        bad(
            "EMBED.EMBEDDED_FILE",
            "names-tree",
            embedded_tree,
            &[],
            "EmbeddedFiles name tree + filespec /EF",
        ),
        bad(
            "EMBED.RICH_MEDIA",
            "subtype-screen",
            rich("Screen"),
            &[],
            "Screen annotation",
        ),
        bad(
            "EMBED.RICH_MEDIA",
            "subtype-movie",
            rich("Movie"),
            &[],
            "Movie annotation",
        ),
        bad(
            "EMBED.RICH_MEDIA",
            "subtype-sound",
            rich("Sound"),
            &[],
            "Sound annotation",
        ),
        bad(
            "EMBED.RICH_MEDIA",
            "subtype-3d",
            rich("3D"),
            &[],
            "3D annotation",
        ),
        bad(
            "EXTERNAL.REMOTE_GOTO",
            "goto-e",
            goto_e,
            &[],
            "GoToE action",
        ),
        bad(
            XFA,
            "xfa-script",
            acroform_doc("/XFA 20 0 R", Some(XFA_SCRIPT)),
            &[ACROFORM],
            "XFA <script> JS",
        ),
        bad(
            XFA,
            "xfa-array",
            {
                let mut d = Doc::new();
                d.catalog_extra = "/AcroForm << /Fields [] /XFA [(template) 20 0 R] >>".into();
                let mut b = d.builder();
                b.stream(20, "", XFA_PLAIN, &[]);
                b.build()
            },
            &[ACROFORM],
            "XFA as an array of packets",
        ),
        bad(
            "CODEC.JBIG2",
            "filter-array",
            {
                let mut d = Doc::new();
                d.xobjects.push(("Im1", 10));
                let mut b = d.builder();
                b.stream_raw(
                    10,
                    "/Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 1 /Filter [/JBIG2Decode]",
                    b"quelda-test jbig2 bytes",
                );
                b.build()
            },
            &[],
            "/Filter given as a one-element array",
        ),
    ]
}

fn image_doc(dict: &str) -> Vec<u8> {
    let mut d = Doc::new();
    d.xobjects.push(("Im1", 10));
    let mut b = d.builder();
    b.stream_raw(
        10,
        &format!("/Type /XObject /Subtype /Image {dict}"),
        &[0u8; 16],
    );
    b.build()
}

fn resource_rules() -> Vec<Fixture> {
    const IMG: &str = "RESOURCE.IMAGE_DIMENSIONS";
    const SIZE: &str = "RESOURCE.PAGE_SIZE";
    const COUNT: &str = "RESOURCE.PAGE_COUNT";
    let page_with = |entry: &str| page_note(entry);
    let pages_with = |extra: &str| {
        let mut d = Doc::new();
        d.pages_extra = extra.to_string();
        d.build()
    };

    let mut inline = BASE_CONTENT.to_vec();
    inline.extend_from_slice(b"q BI /W 100000 /H 100000 /BPC 8 /CS /G ID ");
    inline.extend_from_slice(&[0u8; 16]);
    inline.extend_from_slice(b" EI Q\n");

    let declared_count = |encoded: bool| {
        let d = Doc::new();
        let mut pages = d.pages_body().replace("/Count 1", "/Count 1000000");
        if encoded {
            pages = encode_names_in(&pages, &["Count"]);
        }
        let mut b = PdfBuilder::new(d.version);
        b.object(1, d.catalog_body())
            .object(2, pages)
            .object(3, d.page_body())
            .stream(4, "", BASE_CONTENT, &[])
            .object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
        b.build()
    };

    let many_pages = |n: u32| {
        let first = 100;
        let mut d = Doc::new();
        d.version = "1.5";
        d.kids = (first..first + n)
            .map(|i| format!("{i} 0 R"))
            .collect::<Vec<_>>()
            .join(" ");
        d.count = u64::from(n);
        let mut b = PdfBuilder::new(d.version);
        b.object(1, d.catalog_body()).object(2, d.pages_body());
        for i in first..first + n {
            b.object(i, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>");
        }
        b.stream(4, "", BASE_CONTENT, &[]);
        let members: Vec<u32> = (first..first + n).collect();
        // ObjStm per 1000 pages keeps each stream a sane size.
        for (k, chunk) in members.chunks(1000).enumerate() {
            b.objstm(50 + k as u32, chunk, &[Filter::Flate]);
        }
        b.xref(Xref::Stream);
        b.build()
    };

    vec![
        bad(
            IMG,
            "inline-image",
            content(&inline, &[]),
            &[],
            "Inline image declaring /W 100000 /H 100000",
        ),
        bad(
            IMG,
            "negative-width",
            image_doc("/Width -1 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 8"),
            &[],
            "Width ≤ 0",
        ),
        bad(
            IMG,
            "zero-height",
            image_doc("/Width 8 /Height 0 /ColorSpace /DeviceGray /BitsPerComponent 8"),
            &[],
            "Height 0",
        ),
        bad(
            IMG,
            "non-numeric",
            image_doc("/Width /Huge /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 8"),
            &[],
            "Width is a name",
        ),
        good(
            IMG,
            "below-threshold",
            image_doc("/Width 30000 /Height 30000 /ColorSpace /DeviceGray /BitsPerComponent 8"),
            &[],
            "9e8 px: just under max_image_pixels (1e9)",
        ),
        good(
            IMG,
            "a0-photo",
            image_doc("/Width 14043 /Height 9933 /ColorSpace /DeviceRGB /BitsPerComponent 8"),
            &[],
            "A0 @300dpi photo",
        ),
        bad(
            SIZE,
            "userunit",
            page_with("/MediaBox [0 0 14400 14400] /UserUnit 10"),
            &[],
            "14400 pt × UserUnit 10",
        ),
        bad(
            SIZE,
            "cropbox",
            page_with("/CropBox [0 0 50000 50000]"),
            &[],
            "Huge CropBox",
        ),
        bad(
            SIZE,
            "degenerate",
            page_with("/MediaBox [0 0 0 0]"),
            &[],
            "Zero-area MediaBox",
        ),
        bad(
            SIZE,
            "inherited",
            pages_with("/MediaBox [0 0 100000 100000]"),
            &[],
            "Huge MediaBox on /Pages, inherited",
        ),
        good(
            SIZE,
            "a0",
            page_with("/MediaBox [0 0 2384 3370]"),
            &[],
            "A0 page",
        ),
        good(
            SIZE,
            "spec-max",
            page_with("/MediaBox [0 0 14400 14400]"),
            &[],
            "Largest page without UserUnit",
        ),
        good(
            SIZE,
            "banner",
            page_with("/MediaBox [0 0 28000 2000]"),
            &[],
            "~9.9 m banner, under 28800 pt",
        ),
        bad(
            COUNT,
            "declared-count",
            declared_count(false),
            &[],
            "/Count 1000000 on a one-page tree",
        ),
        bad(
            COUNT,
            "name-encoded",
            declared_count(true),
            &[],
            "/Count key #-encoded",
        ),
        bad(
            COUNT,
            "many-pages",
            many_pages(10_001),
            &[],
            "10001 real pages (packed in Flate ObjStms)",
        ),
        good(COUNT, "hundred-pages", many_pages(100), &[], "100 pages"),
    ]
}

fn structure_rules() -> Vec<Fixture> {
    const CYCLE: &str = "STRUCT.PAGE_TREE_CYCLE";
    const HEADERS: &str = "STRUCT.MULTIPLE_HEADERS";
    const TRAIL: &str = "STRUCT.TRAILING_DATA";
    const EOF: &str = "STRUCT.MISSING_EOF";
    const XREF: &str = "STRUCT.XREF_MISMATCH";
    const CONFLICT: &str = "STRUCT.CONFLICTING_OBJECTS";

    let kids = |kids: &str, count: u64| {
        let mut d = Doc::new();
        d.kids = kids.to_string();
        d.count = count;
        d.build()
    };
    let mutual = {
        let mut d = Doc::new();
        d.kids = "7 0 R".into();
        let mut b = d.builder();
        b.object(
            7,
            "<< /Type /Pages /Parent 2 0 R /Kids [2 0 R 3 0 R] /Count 1 >>",
        );
        b.build()
    };
    let two_level = {
        let mut d = Doc::new();
        d.kids = "7 0 R".into();
        d.page_parent = 7;
        let mut b = d.builder();
        b.object(7, "<< /Type /Pages /Parent 2 0 R /Kids [3 0 R] /Count 1 >>");
        b.build()
    };

    let with_raw = |raw: &[u8]| {
        let mut b = Doc::new().builder();
        b.raw(raw);
        b.build()
    };
    let concatenated = {
        let mut v = Doc::new().build();
        v.extend_from_slice(&Doc::new().build());
        v
    };

    let chain_named = {
        let data = encode_chain(&CHAIN3, BASE_CONTENT);
        let dict = encode_names_in(
            &filter_entry(&CHAIN3),
            &["ASCII85Decode", "ASCIIHexDecode", "FlateDecode"],
        );
        let d = Doc::new();
        let mut b = PdfBuilder::new(d.version);
        b.object(1, d.catalog_body())
            .object(2, d.pages_body())
            .object(3, d.page_body())
            .object(4, raw_stream_body(&dict, &data))
            .object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
        b.build()
    };

    let trailing = |tail: &[u8]| filetype::pdf_then(tail);
    let mut no_eof = Doc::new().builder();
    no_eof.omit_eof();
    let mut misspelled = Doc::new().builder();
    misspelled.omit_eof().trailing_bytes(b"%%E0F\n");

    let mut wrong = Doc::new().builder();
    wrong.wrong_offsets();
    let mut missing = Doc::new().builder();
    missing.unlisted_object(20, "<< /QueldaHidden 1 >>");
    let mut xs = Doc::new();
    xs.version = "1.5";
    let mut xref_stream = xs.builder();
    xref_stream.xref(Xref::Stream);

    let dup = |body: &str| {
        let mut b = Doc::new().builder();
        b.unlisted_object(5, body);
        b.build()
    };
    let mut overwrite = Doc::new().builder();
    overwrite
        .revision()
        .object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>");

    let revisions = |n: usize| {
        let mut b = Doc::new().builder();
        for i in 1..n {
            b.revision()
                .object(10, format!("<< /QueldaRevision {i} >>"));
        }
        b.build()
    };

    vec![
        bad(
            CYCLE,
            "kids-self",
            kids("3 0 R 2 0 R", 2),
            &[],
            "/Pages lists itself in /Kids",
        ),
        bad(
            CYCLE,
            "kids-duplicate",
            kids("3 0 R 3 0 R", 2),
            &[],
            "Same page twice in /Kids",
        ),
        bad(
            CYCLE,
            "mutual",
            mutual,
            &[],
            "Two /Pages nodes listing each other",
        ),
        good(
            CYCLE,
            "two-level",
            two_level,
            &[],
            "Valid Pages → Pages → Page tree",
        ),
        bad(
            HEADERS,
            "second-header",
            with_raw(b"%PDF-1.4\n"),
            &[],
            "Second %PDF- line between objects",
        ),
        bad(
            HEADERS,
            "concatenated",
            concatenated,
            &[],
            "Two complete PDFs back to back",
        )
        .at_least(),
        good(
            HEADERS,
            "header-in-stream",
            content(&[BASE_CONTENT, b"%PDF-1.4\n"].concat(), &[]),
            &[],
            "%PDF- line inside stream data",
        ),
        good(
            HEADERS,
            "header-in-string",
            page_note("/QueldaNote (%PDF-1.5)"),
            &[],
            "%PDF- inside a string",
        ),
        bad(
            CHAIN,
            "three-filters",
            content(BASE_CONTENT, &CHAIN3),
            &[],
            "A85 → AHx → Flate",
        ),
        bad(
            CHAIN,
            "repeated",
            content(BASE_CONTENT, &[Filter::Flate, Filter::Flate]),
            &[],
            "Flate twice",
        ),
        bad(
            CHAIN,
            "name-encoded",
            chain_named,
            &[],
            "Three filters with #-encoded names",
        ),
        good(
            CHAIN,
            "two-filters",
            content(BASE_CONTENT, &[Filter::Ascii85, Filter::Flate]),
            &[],
            "Common 2-filter chain",
        ),
        bad(
            TRAIL,
            "text-4kib",
            trailing(&b"quelda-test trailing data\n".repeat(160)),
            &[],
            "4 KiB of text after %%EOF",
        ),
        bad(
            TRAIL,
            "binary-2k",
            trailing(&[0xAB; 2000]),
            &[],
            "2000 binary bytes after %%EOF",
        ),
        good(TRAIL, "crlf", trailing(b"\r\n"), &[], "CRLF after %%EOF"),
        good(
            TRAIL,
            "zero-padding-512",
            trailing(&[0; 512]),
            &[],
            "512 NUL bytes: under max_trailing_bytes",
        ),
        bad(EOF, "omitted", no_eof.build(), &[], "No %%EOF"),
        bad(
            EOF,
            "misspelled",
            misspelled.build(),
            &[],
            "`%%E0F` (zero) instead of %%EOF",
        ),
        good(
            EOF,
            "eof-trailing-whitespace",
            trailing(b"  \r\n"),
            &[],
            "%%EOF then whitespace",
        ),
        bad(
            XREF,
            "wrong-offsets",
            wrong.build(),
            &[],
            "Offsets off by 3",
        ),
        bad(
            XREF,
            "missing-entry",
            missing.build(),
            &[],
            "Object 20 exists but no xref lists it",
        ),
        good(
            XREF,
            "xref-stream",
            xref_stream.build(),
            &[],
            "Correct xref stream",
        ),
        good(
            XREF,
            "xref-table",
            Doc::new().build(),
            &[],
            "Correct xref table",
        ),
        bad(
            CONFLICT,
            "duplicate-in-body",
            dup("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"),
            &[],
            "Object 5 defined twice in one revision with different content",
        ),
        good(
            CONFLICT,
            "identical-duplicate",
            dup("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
            &[],
            "Object 5 repeated byte-for-byte",
        ),
        good(
            CONFLICT,
            "incremental-overwrite",
            overwrite.build(),
            &[INCR],
            "Redefinition via a proper incremental update",
        ),
        bad(
            INCR,
            "two-revisions",
            revisions(2),
            &[],
            "One incremental update",
        ),
        bad(
            INCR,
            "three-revisions",
            revisions(3),
            &[],
            "Two incremental updates",
        ),
        good(
            INCR,
            "single-revision",
            Doc::new().build(),
            &[],
            "No update",
        ),
    ]
}

const ENCRYPT_DICT: &str = "<< /Filter /Standard /V 1 /R 2 /O <0000000000000000000000000000000000000000000000000000000000000000> /U <0000000000000000000000000000000000000000000000000000000000000000> /P -4 >>";
const FILE_ID: &str =
    "/ID [<51756C6461546573744964303030303030> <51756C6461546573744964303030303030>]";

fn crypt_rule() -> Vec<Fixture> {
    const R: &str = "CRYPT.ENCRYPTED";
    let enc = |trailer: &str, xref: Xref, version: &'static str| {
        let mut d = Doc::new();
        d.version = version;
        let mut b = d.builder();
        b.object(20, ENCRYPT_DICT)
            .xref(xref)
            .trailer(&format!("{trailer} {FILE_ID}"));
        b.build()
    };
    let old = {
        let mut b = Doc::new().builder();
        b.object(20, ENCRYPT_DICT)
            .trailer(&format!("/Encrypt 20 0 R {FILE_ID}"));
        b.revision().object(10, "<< /QueldaRev 2 >>");
        b.build()
    };
    vec![
        bad(
            R,
            "plain",
            enc("/Encrypt 20 0 R", Xref::Table, "1.7"),
            &[],
            "Standard security handler in the trailer",
        ),
        bad(
            R,
            "name-encoded",
            enc(
                &format!("{} 20 0 R", name_encoded_all("Encrypt")),
                Xref::Table,
                "1.7",
            ),
            &[],
            "Trailer key #-encoded",
        ),
        bad(
            R,
            "xref-stream",
            enc("/Encrypt 20 0 R", Xref::Stream, "1.5"),
            &[],
            "/Encrypt in the xref stream dict",
        ),
        bad(
            R,
            "old-revision",
            old,
            &[INCR],
            "/Encrypt only in the first trailer",
        ),
        good(
            R,
            "encrypt-in-string",
            page_note("/QueldaNote (/Encrypt)"),
            &[],
            "String",
        ),
        good(
            R,
            "encrypt-key-outside-trailer",
            page_note("/Encrypt << /QueldaNotATrailer true >>"),
            &[],
            "/Encrypt in a page dict is meaningless to readers",
        ),
    ]
}

/// Batch A (Step 9) evasion variants and near-misses not covered above.
fn batch_a_variants() -> Vec<Fixture> {
    const XOBJ: &str = "POSTSCRIPT.XOBJECT";
    const TYPE4: &str = "POSTSCRIPT.TYPE4_FUNCTION";
    const OTHER: &str = "ACTIVE.OTHER_ACTIONS";
    const CRYPT: &str = "CRYPT.ENCRYPTED";
    const EMBED: &str = "EMBED.EMBEDDED_FILE";
    let form = |dict: &str, extra: Option<(u32, &[u8])>| {
        let mut d = Doc::new();
        d.xobjects.push(("Fx", 10));
        d.content = [BASE_CONTENT, b"/Fx Do\n"].concat();
        let mut b = d.builder();
        b.stream(
            10,
            &format!("/Type /XObject /Subtype /Form /BBox [0 0 10 10] {dict}"),
            b"0 0 m 1 1 l S\n",
            &[],
        );
        if let Some((n, data)) = extra {
            b.stream(n, "", data, &[]);
        }
        b.build()
    };
    let ps_with = |prefix: &[u8]| [prefix, &filetype::ps_adobe()].concat();
    let pdf_with_raw = |raw: &[u8]| {
        let mut b = Doc::new().builder();
        b.raw(raw).raw(b"\n");
        b.build()
    };
    vec![
        bad(
            XOBJ,
            "subtype2-ps",
            form("/Subtype2 /PS", None),
            &[],
            "Form XObject marked /Subtype2 /PS (PostScript pass-through)",
        ),
        bad(
            XOBJ,
            "form-ps-key",
            form("/PS 11 0 R", Some((11, b"% quelda-test\nshowpage\n"))),
            &[],
            "Form XObject with an alternate /PS PostScript stream",
        ),
        good(
            XOBJ,
            "ps-resource-name",
            form("/Resources << /ExtGState << /PS 11 0 R >> >>", None),
            &[],
            "Form XObject whose ExtGState resource is named /PS",
        ),
        bad(
            TYPE4,
            "function-type-real",
            {
                let mut b = Doc::new().builder();
                b.stream(
                    10,
                    "/FunctionType 4.0 /Domain [0 1] /Range [0 1]",
                    TYPE4_BAD,
                    &[],
                );
                b.build()
            },
            &[],
            "/FunctionType written as the real 4.0",
        ),
        bad(
            OTHER,
            "s-hide",
            action("<< /S /Hide /T (quelda) >>"),
            &[],
            "Hide action",
        ),
        bad(
            OTHER,
            "s-set-ocg-state",
            action("<< /S /SetOCGState /State [/OFF] >>"),
            &[],
            "SetOCGState action",
        ),
        bad(
            OTHER,
            "s-rendition",
            action("<< /S /Rendition /OP 0 >>"),
            &[],
            "Rendition action (no script)",
        ),
        good(
            OTHER,
            "transparency-group",
            page_note("/Group << /S /Transparency /CS /DeviceRGB >>"),
            &[],
            "Page group /S /Transparency is not a Trans action",
        ),
        good(
            CRYPT,
            "encrypt-null",
            {
                let mut b = Doc::new().builder();
                b.trailer("/Encrypt null");
                b.build()
            },
            &[],
            "/Encrypt null in the trailer: not encrypted",
        ),
        bad(
            PS_MAGIC,
            "bom-before-ps",
            ps_with(b"\xEF\xBB\xBF"),
            &[NOT_PDF],
            "UTF-8 byte order mark before %!PS",
        )
        .at_least(),
        bad(
            PS_MAGIC,
            "whitespace-before-ps",
            ps_with(b"\r\n  \t\n"),
            &[NOT_PDF],
            "Whitespace before %!PS",
        )
        .at_least(),
        bad(
            PS_MAGIC,
            "pjl-wrapped",
            ps_with(
                b"\x1B%-12345X@PJL JOB NAME=\"quelda-test\"\r\n@PJL ENTER LANGUAGE=POSTSCRIPT\r\n",
            ),
            &[NOT_PDF],
            "PostScript inside a PJL printer job",
        )
        .at_least(),
        bad(
            FOREIGN,
            "svg-with-bom",
            [b"\xEF\xBB\xBF\n".as_slice(), &filetype::svg()].concat(),
            &[NOT_PDF],
            "SVG preceded by a byte order mark and a newline",
        )
        .at_least(),
        bad(
            FOREIGN,
            "png",
            b"\x89PNG\r\n\x1A\n\0\0\0\x0DIHDR quelda-test".to_vec(),
            &[NOT_PDF],
            "PNG signature (truncated image)",
        )
        .at_least(),
        bad(
            FOREIGN,
            "pe-executable",
            b"MZ quelda-test: not a real executable\n".to_vec(),
            &[NOT_PDF],
            "PE (`MZ`) signature",
        )
        .at_least(),
        bad(
            POLYGLOT,
            "svg-in-body",
            pdf_with_raw(b"<svg xmlns=\"http://www.w3.org/2000/svg\"><!-- quelda-test --></svg>"),
            &[],
            "SVG markup between PDF objects",
        ),
        bad(
            POLYGLOT,
            "zip-in-string",
            {
                let mut b = Doc::new().builder();
                b.object(
                    10,
                    [b"<< /QueldaNote (".as_slice(), b"PK\x03\x04", b") >>"].concat(),
                );
                b.build()
            },
            &[],
            "ZIP local file header inside a literal string (outside stream data)",
        ),
        good(
            POLYGLOT,
            "zip-in-embedded-file",
            {
                let mut b = Doc::new().builder();
                b.stream(10, "/Type /EmbeddedFile", &filetype::zip_one_file(), &[]);
                b.build()
            },
            &[EMBED],
            "Unfiltered ZIP inside an embedded file stream",
        ),
    ]
}

/// A linearized one-page file: linearization dictionary first, then the
/// first-page xref section whose trailer `/Prev` points forward at the main
/// section; the last `startxref` points at the first-page section (ISO
/// 32000-2 Annex F). `update`: plus one incremental update. Offsets are
/// computed; the hint values are not meaningful (nothing reads them).
fn linearized(update: bool) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    // Object offsets, indexed by number.
    let mut offsets = [0usize; 7];
    let obj = |out: &mut Vec<u8>, offsets: &mut [usize; 7], num: usize, body: &[u8]| {
        offsets[num] = out.len();
        out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    };
    obj(
        &mut out,
        &mut offsets,
        1,
        b"<< /Linearized 1 /L 0 /H [0 0] /O 4 /E 0 /N 1 /T 0 >>",
    );
    let first_xref = out.len();
    // `/Prev` placeholder: 10 digits, patched once the main section is written.
    let prev_at = {
        out.extend_from_slice(
            format!(
                "xref\n1 1\n{:010} 00000 n \ntrailer\n<< /Size 7 /Root 2 0 R /Prev ",
                offsets[1]
            )
            .as_bytes(),
        );
        let at = out.len();
        out.extend_from_slice(b"0000000000 >>\nstartxref\n0\n%%EOF\n");
        at
    };
    obj(
        &mut out,
        &mut offsets,
        2,
        b"<< /Type /Catalog /Pages 3 0 R >>",
    );
    obj(
        &mut out,
        &mut offsets,
        3,
        b"<< /Type /Pages /Kids [4 0 R] /Count 1 /MediaBox [0 0 595 842] >>",
    );
    obj(
        &mut out,
        &mut offsets,
        4,
        b"<< /Type /Page /Parent 3 0 R /Resources << /Font << /F1 6 0 R >> >> /Contents 5 0 R >>",
    );
    obj(
        &mut out,
        &mut offsets,
        5,
        &raw_stream_body("", BASE_CONTENT),
    );
    obj(
        &mut out,
        &mut offsets,
        6,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    );
    let main_xref = out.len();
    out.extend_from_slice(b"xref\n0 1\n0000000000 65535 f \n2 5\n");
    for o in &offsets[2..=6] {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size 7 /Root 2 0 R >>\nstartxref\n{first_xref}\n%%EOF\n").as_bytes(),
    );
    out[prev_at..prev_at + 10].copy_from_slice(format!("{main_xref:010}").as_bytes());
    if update {
        let at = out.len();
        out.extend_from_slice(b"7 0 obj\n<< /Title (quelda update) >>\nendobj\n");
        let x = out.len();
        out.extend_from_slice(
            format!(
                "xref\n7 1\n{at:010} 00000 n \ntrailer\n<< /Size 8 /Root 2 0 R /Info 7 0 R /Prev {first_xref} >>\nstartxref\n{x}\n%%EOF\n"
            )
            .as_bytes(),
        );
    }
    out
}

/// `pdf` plus a copy of its (first) xref table and trailer that no
/// `startxref` or `/Prev` leads to.
fn with_unreachable_section(pdf: Vec<u8>) -> Vec<u8> {
    let find = |needle: &[u8]| pdf.windows(needle.len()).position(|w| w == needle);
    let (Some(xref), Some(startxref)) = (find(b"\nxref\n"), find(b"startxref")) else {
        panic!("no xref table");
    };
    let mut out = pdf.clone();
    out.extend_from_slice(&pdf[xref + 1..startxref]);
    out.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref + 1).as_bytes());
    out
}

/// Batch B (Step 10) evasion variants and near-misses not covered above.
fn batch_b_variants() -> Vec<Fixture> {
    const EMBED: &str = "EMBED.EMBEDDED_FILE";
    const RICH: &str = "EMBED.RICH_MEDIA";
    const JBIG2: &str = "CODEC.JBIG2";
    const JPX: &str = "CODEC.JPX";
    const XML: &str = "XML.DOCTYPE";
    const IMG: &str = "RESOURCE.IMAGE_DIMENSIONS";
    const SIZE: &str = "RESOURCE.PAGE_SIZE";
    const COUNT: &str = "RESOURCE.PAGE_COUNT";
    const XREF: &str = "STRUCT.XREF_MISMATCH";
    const CYCLE: &str = "STRUCT.PAGE_TREE_CYCLE";

    let orphan = |objects: &[(u32, &str)]| {
        let mut b = Doc::new().builder();
        for (n, body) in objects {
            b.object(*n, body);
        }
        b.build()
    };
    let inline = |dict: &str| {
        let data = format!("q BI {dict} ID quelda-test EI Q\n");
        content(&[BASE_CONTENT, data.as_bytes()].concat(), &[])
    };
    let image_with = |dict: &str, extra: &[(u32, &str)]| {
        let mut d = Doc::new();
        d.xobjects.push(("Im1", 10));
        let mut b = d.builder();
        b.stream_raw(
            10,
            &format!(
                "/Type /XObject /Subtype /Image /ColorSpace /DeviceGray /BitsPerComponent 8 {dict}"
            ),
            b"quelda-test image bytes (not decoded)",
        );
        for (n, body) in extra {
            b.object(*n, body);
        }
        b.build()
    };
    let utf16be = |data: &[u8]| -> Vec<u8> {
        let mut v = vec![0xFE, 0xFF];
        v.extend(data.iter().flat_map(|&b| [0, b]));
        v
    };
    let page_tree_moved = {
        let mut d = Doc::new();
        d.kids = "7 0 R 8 0 R".into();
        d.page_parent = 7;
        let mut b = d.builder();
        b.object(7, "<< /Type /Pages /Parent 2 0 R /Kids [3 0 R] /Count 1 >>")
            .object(8, "<< /Type /Pages /Parent 2 0 R /Kids [] /Count 0 >>");
        let mut moved = d.clone();
        moved.page_parent = 8;
        b.revision()
            .object(7, "<< /Type /Pages /Parent 2 0 R /Kids [] /Count 0 >>")
            .object(8, "<< /Type /Pages /Parent 2 0 R /Kids [3 0 R] /Count 1 >>")
            .object(3, moved.page_body());
        b.build()
    };
    let count_with = |count: &str, extra: &[(u32, &str)], catalog: &str| {
        let mut d = Doc::new();
        d.catalog_extra = catalog.to_string();
        let pages = d
            .pages_body()
            .replace("/Count 1", &format!("/Count {count}"));
        let mut b = PdfBuilder::new(d.version);
        b.object(1, d.catalog_body())
            .object(2, pages)
            .object(3, d.page_body())
            .stream(4, "", BASE_CONTENT, &[])
            .object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
        for (n, body) in extra {
            b.object(*n, body);
        }
        b.build()
    };

    vec![
        bad(
            EMBED,
            "ef-without-type",
            {
                let mut b = Doc::new().builder();
                b.object(
                    11,
                    "<< /Type /Filespec /F (quelda-test.txt) /EF << /F 10 0 R >> >>",
                )
                .stream(10, "", b"quelda-test\n", &[]);
                b.build()
            },
            &[],
            "File spec /EF pointing at a stream without /Type /EmbeddedFile (optional)",
        ),
        good(
            EMBED,
            "ef-in-string",
            page_note("/QueldaNote (/EF << /F 10 0 R >>)"),
            &[],
            "String",
        ),
        bad(
            RICH,
            "subtype-u3d",
            {
                let mut b = Doc::new().builder();
                b.stream(10, "/Type /3D /Subtype /U3D", b"quelda-test u3d bytes", &[]);
                b.build()
            },
            &[],
            "3D artwork stream (U3D)",
        ),
        bad(
            RICH,
            "subtype-prc",
            {
                let mut b = Doc::new().builder();
                b.stream(10, "/Type /3D /Subtype /PRC", b"quelda-test prc bytes", &[]);
                b.build()
            },
            &[],
            "3D artwork stream (PRC)",
        ),
        bad(
            JBIG2,
            "filter-indirect-array",
            image_with(
                "/Width 8 /Height 8 /Filter 30 0 R",
                &[(30, "[/FlateDecode /JBIG2Decode]")],
            ),
            &[],
            "/Filter is a reference to an array",
        ),
        bad(
            JBIG2,
            "filter-array-indirect-element",
            image_with(
                "/Width 8 /Height 8 /Filter [/FlateDecode 30 0 R]",
                &[(30, "/JBIG2Decode")],
            ),
            &[],
            "/Filter array whose second element is a reference",
        ),
        bad(
            JBIG2,
            "inline-image",
            inline("/W 8 /H 8 /IM true /F /JBIG2Decode"),
            &[],
            "Inline image naming JBIG2Decode",
        ),
        good(
            JBIG2,
            "globals-without-filter",
            image_with(
                "/Width 8 /Height 8 /Filter /FlateDecode /DecodeParms << /JBIG2Globals 20 0 R >>",
                &[(20, "<< /QueldaNote (not a stream) >>")],
            ),
            &[],
            "/JBIG2Globals in /DecodeParms, but no JBIG2Decode filter",
        ),
        bad(
            JPX,
            "filter-array",
            image_with("/Width 8 /Height 8 /Filter [/JPXDecode]", &[]),
            &[],
            "/Filter given as a one-element array",
        ),
        bad(
            JPX,
            "inline-image",
            inline("/W 8 /H 8 /CS /G /BPC 8 /F /JPXDecode"),
            &[],
            "Inline image naming JPXDecode",
        ),
        bad(
            XML,
            "utf16",
            metadata_doc(&utf16be(XMP_DOCTYPE), &[]).build(),
            &[],
            "XMP packet in UTF-16BE (with BOM)",
        ),
        bad(
            XML,
            "lowercase",
            metadata_doc(&XMP_DOCTYPE.to_ascii_lowercase(), &[]).build(),
            &[],
            "<!doctype in lower case",
        ),
        bad(
            XML,
            "xfa-indirect-array",
            {
                let mut d = Doc::new();
                d.catalog_extra = "/AcroForm << /Fields [] /XFA 30 0 R >>".into();
                let mut b = d.builder();
                b.object(30, "[(template) 20 0 R]")
                    .stream(20, "", XMP_DOCTYPE, &[]);
                b.build()
            },
            &[ACROFORM, XFA],
            "/XFA is a reference to the packet array",
        ),
        good(
            XML,
            "doctype-in-content",
            content(
                &[
                    BASE_CONTENT,
                    b"BT /F1 12 Tf 72 700 Td (<!DOCTYPE quelda>) Tj ET\n",
                ]
                .concat(),
                &[],
            ),
            &[],
            "<!DOCTYPE as page text",
        ),
        good(
            XML,
            "embedded-html",
            {
                let mut b = Doc::new().builder();
                b.stream(
                    10,
                    "/Type /EmbeddedFile",
                    b"<!DOCTYPE quelda><p>quelda-test</p>\n",
                    &[],
                );
                b.build()
            },
            &[EMBED],
            "Attachment with a DOCTYPE: not parsed as XML by the reader",
        ),
        bad(
            CHAIN,
            "abbreviated-repeat",
            {
                let mut b = Doc::new().builder();
                b.stream_raw(
                    10,
                    "/Filter [/Fl /FlateDecode]",
                    &encode_chain(&[Filter::Flate, Filter::Flate], b"q Q\n"),
                );
                b.build()
            },
            &[],
            "/Fl and /FlateDecode are the same filter",
        ),
        bad(
            CHAIN,
            "indirect-array",
            {
                let mut b = Doc::new().builder();
                b.stream_raw(10, "/Filter 30 0 R", &encode_chain(&CHAIN3, b"q Q\n"))
                    .object(30, "[/ASCII85Decode /ASCIIHexDecode /FlateDecode]");
                b.build()
            },
            &[],
            "Three filters through a referenced array",
        ),
        bad(
            CHAIN,
            "inline-image",
            inline("/W 2 /H 1 /CS /G /BPC 8 /F [/AHx /AHx]"),
            &[],
            "Inline image with the same filter twice",
        ),
        good(
            CHAIN,
            "plain-dict",
            page_note("/QueldaNest << /Filter [/A85 /AHx /Fl] >>"),
            &[],
            "Filter array on a dictionary that is not a stream",
        ),
        bad(
            IMG,
            "abbreviated-keys",
            image_with("/W 100000 /H 100000", &[]),
            // A stream with /W is also read as a (broken) xref stream, as a
            // lenient reader at `startxref` would: one more revision.
            &[XREF, INCR],
            "Image XObject sized with /W /H (pdf.js reads them)",
        ),
        bad(
            IMG,
            "indirect-subtype",
            {
                let mut d = Doc::new();
                d.xobjects.push(("Im1", 10));
                let mut b = d.builder();
                b.stream_raw(
                    10,
                    "/Type /XObject /Subtype 30 0 R /Width 100000 /Height 100000 /ColorSpace /DeviceGray /BitsPerComponent 8",
                    &[0u8; 16],
                )
                .object(30, "/Image");
                b.build()
            },
            &[],
            "/Subtype /Image through a reference",
        ),
        good(
            IMG,
            "not-an-image",
            page_note("/QueldaNote << /Width 100000 /Height 100000 >>"),
            &[],
            "Width/Height on a dictionary that is not an image",
        ),
        bad(
            SIZE,
            "trimbox",
            page_note("/TrimBox [0 0 50000 50000]"),
            &[],
            "Huge TrimBox (Ghostscript -dUseTrimBox)",
        ),
        bad(
            SIZE,
            "array-element-indirect",
            {
                let mut d = Doc::new();
                d.page_extra = "/MediaBox [0 0 30 0 R 842]".into();
                let mut b = d.builder();
                b.object(30, "100000");
                b.build()
            },
            &[],
            "MediaBox element is a reference to 100000",
        ),
        good(
            SIZE,
            "form-bbox",
            {
                let mut d = Doc::new();
                d.xobjects.push(("Fx", 10));
                let mut b = d.builder();
                b.stream(
                    10,
                    "/Type /XObject /Subtype /Form /BBox [0 0 100000 100000]",
                    b"0 0 m 1 1 l S\n",
                    &[],
                );
                b.build()
            },
            &[],
            "Large Form XObject /BBox is not a page box",
        ),
        bad(
            COUNT,
            "indirect-value",
            count_with("30 0 R", &[(30, "1000000")], ""),
            &[],
            "/Count is a reference to 1000000",
        ),
        bad(
            COUNT,
            "orphan-pages-node",
            orphan(&[(7, "<< /Type /Pages /Kids [] /Count 1000000 >>")]),
            &[],
            "Unreferenced /Pages node declaring 1000000 pages (union)",
        ),
        good(
            COUNT,
            "outlines-count",
            count_with(
                "1",
                &[(7, "<< /Type /Outlines /Count 1000000 >>")],
                "/Outlines 7 0 R",
            ),
            &[],
            "Outline /Count is not a page count",
        ),
        good(
            INCR,
            "linearized",
            linearized(false),
            &[],
            "Linearized file: the first-page xref section is not an update",
        ),
        bad(
            INCR,
            "linearized-updated",
            linearized(true),
            &[],
            "Linearized file with one incremental update",
        ),
        bad(
            XREF,
            "unreachable-section",
            with_unreachable_section(Doc::new().build()),
            &[INCR],
            "A second xref section that no startxref or /Prev leads to",
        ),
        bad(
            CYCLE,
            "moved-across-revisions",
            page_tree_moved,
            &[INCR],
            "Page moved to another /Pages node by an update: union of revisions lists it twice",
        ),
    ]
}

pub(crate) fn all() -> Vec<Fixture> {
    let mut out = Vec::new();
    out.extend(batch_b_variants());
    out.extend(filetype_rules());
    out.extend(content_op_rule());
    out.extend(xml_rule());
    out.extend(javascript_rule());
    out.extend(simple_rule_goods());
    out.extend(extra_rule_variants());
    out.extend(resource_rules());
    out.extend(structure_rules());
    out.extend(crypt_rule());
    out.extend(batch_a_variants());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(hay: &[u8], needle: &[u8]) -> Vec<usize> {
        hay.windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle)
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn linearized_prev_points_forward_at_main_section() {
        let pdf = linearized(false);
        let xrefs = find(&pdf, b"\nxref\n");
        assert_eq!(xrefs.len(), 2);
        let (first, main) = (xrefs[0] + 1, xrefs[1] + 1);
        assert!(find(&pdf, format!("/Prev {main:010}").as_bytes()).len() == 1);
        // The last startxref points at the first-page section.
        assert!(pdf.ends_with(format!("startxref\n{first}\n%%EOF\n").as_bytes()));
        assert!(find(&pdf, b"/Linearized 1").len() == 1);
        let updated = linearized(true);
        assert!(updated.starts_with(&pdf));
        assert_eq!(find(&updated, b"\nxref\n").len(), 3);
        assert_eq!(find(&updated, format!("/Prev {first}").as_bytes()).len(), 1);
    }

    #[test]
    fn unreachable_section_is_a_copy_of_the_first() {
        let pdf = Doc::new().build();
        let out = with_unreachable_section(pdf.clone());
        assert!(out.starts_with(&pdf));
        let xrefs = find(&out, b"\nxref\n");
        assert_eq!(xrefs.len(), 2);
        assert!(out.ends_with(format!("startxref\n{}\n%%EOF\n", xrefs[0] + 1).as_bytes()));
    }

    #[test]
    fn utf16_hex_has_bom() {
        assert_eq!(utf16_hex("ab"), "FEFF00610062");
    }

    #[test]
    fn inline_image_ps_good_has_exact_bytes() {
        let f = content_op_rule()
            .into_iter()
            .find(|f| f.variant == "inline-image-ps-bytes")
            .unwrap();
        assert!(f.bytes.windows(9).any(|w| w == b"ID PS EI "));
    }
}
