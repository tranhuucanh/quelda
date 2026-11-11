//! Rules added in 0.3.0 (ADR #42): embedded fonts and ICC profiles built
//! byte by byte (valid ones, and ones with impossible offsets), and signed
//! files whose `/ByteRange` is computed over the file as written.

use super::{Doc, Fixture, bad, good};
use crate::builder::PdfBuilder;
use crate::filters::Filter;

const FONT: &str = "CODEC.FONT_MALFORMED";
const ICC: &str = "CODEC.ICC_MALFORMED";
const SIG: &str = "STRUCT.SIGNATURE_MODIFIED";
const INCR: &str = "STRUCT.INCREMENTAL_UPDATE";
const TYPE1: &str = "CODEC.TYPE1_FONT";

/// A minimal TrueType font: `head`, `maxp`, `loca` (short offsets) and
/// `glyf` of `glyf_len` zero bytes, tables padded to 4 bytes.
fn truetype(loca: &[u16], glyf_len: usize) -> Vec<u8> {
    let mut head = vec![0u8; 54];
    head[12..16].copy_from_slice(&0x5F0F_3CF5u32.to_be_bytes());
    head[18..20].copy_from_slice(&1000u16.to_be_bytes());
    let mut maxp = vec![0, 0, 0x50, 0];
    maxp.extend_from_slice(&((loca.len().max(1) - 1) as u16).to_be_bytes());
    let loca: Vec<u8> = loca.iter().flat_map(|o| o.to_be_bytes()).collect();
    let glyf = vec![0u8; glyf_len];
    let tables: [(&[u8; 4], &[u8]); 4] = [
        (b"glyf", &glyf),
        (b"head", &head),
        (b"loca", &loca),
        (b"maxp", &maxp),
    ];
    let mut out = vec![0, 1, 0, 0, 0, 4, 0, 64, 0, 2, 0, 0];
    let mut data = Vec::new();
    for (tag, body) in tables {
        let offset = 12 + 16 * tables.len() + data.len();
        out.extend_from_slice(tag);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(offset as u32).to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        data.extend_from_slice(body);
        while data.len() % 4 != 0 {
            data.push(0);
        }
    }
    out.extend(data);
    out
}

pub(super) fn valid_truetype() -> Vec<u8> {
    truetype(&[0, 2, 4], 8)
}

/// Sets the offset (`field` 8) or length (`field` 12) of table `index` of
/// a TrueType font.
fn table_field(mut font: Vec<u8>, index: usize, field: usize, value: u32) -> Vec<u8> {
    let at = 12 + 16 * index + field;
    font[at..at + 4].copy_from_slice(&value.to_be_bytes());
    font
}

/// A minimal CFF font: one name, a Top DICT with CharStrings (two empty
/// glyphs) and an empty Private DICT.
fn cff() -> Vec<u8> {
    let mut d = vec![1, 0, 4, 1];
    d.extend_from_slice(&[0, 1, 1, 1, 2, b'A']);
    let top = [28, 0, 26, 17, 139, 139, 18];
    d.extend_from_slice(&[0, 1, 1, 1, 1 + top.len() as u8]);
    d.extend_from_slice(&top);
    d.extend_from_slice(&[0, 0, 0, 0]);
    d.extend_from_slice(&[0, 2, 1, 1, 2, 3, 14, 14]);
    d
}

fn cff_with(at: usize, v: u8) -> Vec<u8> {
    let mut d = cff();
    d[at] = v;
    d
}

/// Base doc + TrueType font 10 (descriptor 11) whose program is stream
/// 12: `/FontFile2` (`key` `FontFile2`) or `/FontFile3` with `subtype`.
fn font_builder(key: &str, subtype: &str, program: &[u8], filters: &[Filter]) -> PdfBuilder {
    let mut b = Doc::new().builder();
    b.object(
        10,
        "<< /Type /Font /Subtype /TrueType /BaseFont /QueldaTest /FirstChar 32 /LastChar 32 /Widths [500] /FontDescriptor 11 0 R >>",
    )
    .object(
        11,
        format!(
            "<< /Type /FontDescriptor /FontName /QueldaTest /Flags 32 /FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 /{key} 12 0 R >>"
        ),
    )
    .stream(12, subtype, program, filters);
    b
}

fn font(key: &str, subtype: &str, program: &[u8]) -> Vec<u8> {
    font_builder(key, subtype, program, &[]).build()
}

fn font_malformed() -> Vec<Fixture> {
    let past_glyf = truetype(&[0, 2, 400], 8);
    let old_rev = {
        let mut b = font_builder("FontFile2", "", &past_glyf, &[]);
        b.revision().stream(12, "", &valid_truetype(), &[]);
        b.build()
    };
    vec![
        bad(
            FONT,
            "truetype-glyph-past-glyf",
            font("FontFile2", "", &past_glyf),
            &[],
            "TrueType `loca` gives glyph 2 an offset past the end of `glyf`",
        ),
        bad(
            FONT,
            "truetype-table-past-end",
            font(
                "FontFile2",
                "",
                &table_field(valid_truetype(), 0, 8, 0x7fff_0000),
            ),
            &[],
            "TrueType table directory: `glyf` starts 2 GB into a font of 140 bytes",
        ),
        bad(
            FONT,
            "truetype-length-wraps",
            font(
                "FontFile2",
                "",
                &table_field(valid_truetype(), 0, 12, u32::MAX),
            ),
            &[],
            "TrueType table length that wraps when added to its offset",
        ),
        bad(
            FONT,
            "truetype-head-short",
            font("FontFile2", "", &table_field(valid_truetype(), 1, 12, 20)),
            &[],
            "TrueType `head` table of 20 bytes (54 needed)",
        ),
        bad(
            FONT,
            "truetype-not-a-font",
            font("FontFile2", "", b"%!PS-AdobeFont-1.0: QueldaTest\n"),
            &[],
            "`/FontFile2` holding something that is not a TrueType font",
        ),
        bad(
            FONT,
            "truetype-flate",
            font_builder("FontFile2", "", &past_glyf, &[Filter::Flate]).build(),
            &[],
            "Malformed TrueType font, Flate-compressed",
        ),
        bad(
            FONT,
            "opentype-table-past-end",
            font(
                "FontFile3",
                "/Subtype /OpenType",
                &table_field(valid_truetype(), 2, 12, 4000),
            ),
            &[],
            "`/FontFile3 /OpenType` whose `loca` table runs past the font",
        ),
        bad(
            FONT,
            "cff-index-backwards",
            font("FontFile3", "/Subtype /Type1C", &cff_with(8, 0)),
            &[],
            "CFF Name INDEX offsets go backwards",
        ),
        bad(
            FONT,
            "cff-charstrings-past-end",
            font("FontFile3", "/Subtype /CIDFontType0C", &cff_with(16, 0x7f)),
            &[],
            "CFF Top DICT puts CharStrings 32 KB into a font of 34 bytes",
        ),
        bad(
            FONT,
            "cff-private-past-end",
            font("FontFile3", "/Subtype /Type1C", &cff_with(19, 200)),
            &[],
            "CFF Private DICT of 61 bytes in a font of 34 bytes",
        ),
        bad(
            FONT,
            "in-old-revision",
            old_rev,
            &[INCR],
            "Malformed font replaced by a valid one in an update: union scan sees both",
        ),
        good(
            FONT,
            "truetype",
            font("FontFile2", "", &valid_truetype()),
            &[],
            "Valid TrueType font",
        ),
        good(
            FONT,
            "truetype-flate",
            font_builder("FontFile2", "", &valid_truetype(), &[Filter::Flate]).build(),
            &[],
            "Valid TrueType font, Flate-compressed",
        ),
        good(
            FONT,
            "opentype",
            font("FontFile3", "/Subtype /OpenType", &valid_truetype()),
            &[],
            "Valid `/FontFile3 /OpenType` font",
        ),
        good(
            FONT,
            "cff",
            font("FontFile3", "/Subtype /Type1C", &cff()),
            &[],
            "Valid CFF font",
        ),
        good(
            FONT,
            "unpadded-last-table",
            {
                let mut f = truetype(&[0, 1, 3], 6);
                f.truncate(f.len() - 3);
                font("FontFile2", "", &f)
            },
            &[],
            "Last table without its padding to 4 bytes (some producers drop it)",
        ),
        good(
            FONT,
            "truncated-flate",
            {
                let mut b = Doc::new().builder();
                let z = Filter::Flate.encode(&past_glyf);
                b.object(
                    11,
                    "<< /Type /FontDescriptor /FontName /QueldaTest /FontFile2 12 0 R >>",
                )
                .stream_raw(12, "/Filter /FlateDecode", &z[..z.len() / 2]);
                b.build()
            },
            &[],
            "Font program whose Flate data is cut: not judged by its structure",
        ),
        good(
            FONT,
            "type1-program",
            font(
                "FontFile",
                "/Length1 9 /Length2 0 /Length3 0",
                b"not a font",
            ),
            &[TYPE1],
            "Type 1 programs (`/FontFile`) are `CODEC.TYPE1_FONT`'s, not checked here",
        ),
        good(
            FONT,
            "unreferenced-stream",
            {
                let mut b = Doc::new().builder();
                b.stream(12, "", &past_glyf, &[]);
                b.build()
            },
            &[],
            "Font-like bytes in a stream no font descriptor names",
        ),
    ]
}

/// A minimal ICC profile with one `desc` tag of 12 bytes.
fn profile() -> Vec<u8> {
    let mut d = vec![0u8; 156];
    d[0..4].copy_from_slice(&156u32.to_be_bytes());
    d[8..12].copy_from_slice(&[4, 0x30, 0, 0]);
    d[12..16].copy_from_slice(b"mntr");
    d[16..20].copy_from_slice(b"GRAY");
    d[20..24].copy_from_slice(b"XYZ ");
    d[36..40].copy_from_slice(b"acsp");
    d[128..132].copy_from_slice(&1u32.to_be_bytes());
    d[132..136].copy_from_slice(b"desc");
    d[136..140].copy_from_slice(&144u32.to_be_bytes());
    d[140..144].copy_from_slice(&12u32.to_be_bytes());
    d[144..148].copy_from_slice(b"mluc");
    d
}

fn profile_with(at: usize, v: &[u8]) -> Vec<u8> {
    let mut d = profile();
    d[at..at + v.len()].copy_from_slice(v);
    d
}

/// Base doc + object 10 naming stream 12 as an ICC profile (`holder`,
/// with `12 0 R` in it).
fn icc_builder(holder: &str, profile: &[u8], filters: &[Filter]) -> PdfBuilder {
    let mut b = Doc::new().builder();
    b.object(10, holder).stream(12, "/N 1", profile, filters);
    b
}

const COLOR_SPACE: &str = "<< /ColorSpace << /CS0 [/ICCBased 12 0 R] >> >>";

fn icc(profile: &[u8]) -> Vec<u8> {
    icc_builder(COLOR_SPACE, profile, &[]).build()
}

fn icc_malformed() -> Vec<Fixture> {
    let short = &profile()[..100];
    vec![
        bad(ICC, "short", icc(short), &[], "Profile of 100 bytes: shorter than its header"),
        bad(
            ICC,
            "no-acsp",
            icc(&profile_with(36, b"xxxx")),
            &[],
            "Profile without the `acsp` signature",
        ),
        bad(
            ICC,
            "tag-table-too-big",
            icc(&profile_with(128, &9u32.to_be_bytes())),
            &[],
            "Tag table of 9 tags in a profile with room for 2",
        ),
        bad(
            ICC,
            "tag-past-end",
            icc(&profile_with(136, &0xffff_fff0u32.to_be_bytes())),
            &[],
            "Tag `desc` at offset 4 GB in a profile of 156 bytes",
        ),
        bad(
            ICC,
            "tag-past-declared-size",
            icc(&profile_with(140, &300u32.to_be_bytes())),
            &[],
            "Tag ending past both the data and the size the header declares",
        ),
        bad(
            ICC,
            "output-intent",
            icc_builder(
                "<< /Type /OutputIntent /S /GTS_PDFX /OutputConditionIdentifier (Custom) /DestOutputProfile 12 0 R >>",
                short,
                &[],
            )
            .build(),
            &[],
            "Malformed profile as an output intent's `/DestOutputProfile`",
        ),
        bad(
            ICC,
            "indexed-base",
            icc_builder(
                "<< /ColorSpace << /CS0 [/Indexed [/ICCBased 12 0 R] 1 <00ff>] >> >>",
                short,
                &[],
            )
            .build(),
            &[],
            "Malformed profile as the base of an Indexed colour space",
        ),
        bad(
            ICC,
            "flate",
            icc_builder(COLOR_SPACE, short, &[Filter::Flate]).build(),
            &[],
            "Malformed profile, Flate-compressed",
        ),
        good(ICC, "valid", icc(&profile()), &[], "Valid profile"),
        good(
            ICC,
            "valid-flate",
            icc_builder(COLOR_SPACE, &profile(), &[Filter::Flate]).build(),
            &[],
            "Valid profile, Flate-compressed",
        ),
        good(
            ICC,
            "truncated",
            {
                let mut p = profile_with(140, &300u32.to_be_bytes());
                p[0..4].copy_from_slice(&444u32.to_be_bytes());
                icc(&p)
            },
            &[],
            "Truncated profile (as ABBYY FineReader embeds sRGB): its tags end within the \
             declared size, so they are not judged",
        ),
        good(
            ICC,
            "unreferenced-stream",
            {
                let mut b = Doc::new().builder();
                b.stream(12, "/N 1", short, &[]);
                b.build()
            },
            &[],
            "Profile-like bytes in a stream nothing names as a profile",
        ),
    ]
}

/// Placeholder `/ByteRange`, replaced by the real one (same width).
const BYTE_RANGE: &str = "[0000000000 0000000000 0000000000 0000000000]";

/// Signature value placeholder: a hex string of `SIG_HEX` digits.
const SIG_HEX: usize = 64;

/// `file` with its placeholder `/ByteRange` set so that the signature
/// covers bytes `0..end` except `/Contents <…>`; `first_end_shift` moves
/// the end of the first range (negative: something else is left out).
fn sign(mut file: Vec<u8>, end: usize, first_end_shift: isize) -> Vec<u8> {
    let find = |f: &[u8], what: &[u8]| f.windows(what.len()).position(|w| w == what);
    let Some(lt) = find(&file, b"/Contents <").map(|i| i + 10) else {
        return file;
    };
    let gt = lt + SIG_HEX + 1;
    let first = lt.saturating_add_signed(first_end_shift);
    let br = format!("[0 {first} {} {}]", gt + 1, end - gt - 1);
    if let Some(at) = find(&file, BYTE_RANGE.as_bytes()) {
        let padded = format!("{br:<width$}", width = BYTE_RANGE.len());
        file.splice(at..at + BYTE_RANGE.len(), padded.into_bytes());
    }
    file
}

/// Base doc + signature dictionary 10 (`/ByteRange` placeholder, or `br`).
fn signed_builder(br: &str) -> PdfBuilder {
    let mut b = Doc::new().builder();
    b.object(
        10,
        format!(
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /M (D:20261112000000Z) /ByteRange {br} /Contents <{}> >>",
            "0".repeat(SIG_HEX)
        ),
    );
    b
}

/// A signed file: the signature covers the whole file.
fn signed() -> Vec<u8> {
    let f = signed_builder(BYTE_RANGE).build();
    let end = f.len();
    sign(f, end, 0)
}

fn signature_modified() -> Vec<Fixture> {
    let updated = {
        let mut b = signed_builder(BYTE_RANGE);
        let first = b.build();
        let mut rotated = Doc::new();
        rotated.page_extra = "/Rotate 90".to_string();
        b.revision().object(3, rotated.page_body());
        sign(b.build(), first.len(), 0)
    };
    let appended = [
        signed(),
        b"% quelda test: appended after signing\n".to_vec(),
    ]
    .concat();
    vec![
        bad(
            SIG,
            "updated-after-signing",
            updated,
            &[INCR],
            "Incremental update after the signed revision changes the page",
        ),
        bad(
            SIG,
            "bytes-appended",
            appended,
            &[],
            "Bytes appended after the signed ranges (no new revision)",
        ),
        bad(
            SIG,
            "gap-not-signature",
            {
                let f = signed_builder(BYTE_RANGE).build();
                let end = f.len();
                sign(f, end, -10)
            },
            &[],
            "Signed ranges leave out `/Contents ` as well as the signature value",
        ),
        bad(
            SIG,
            "byte-range-odd",
            signed_builder("[0 10 20]").build(),
            &[],
            "`/ByteRange` of 3 numbers",
        ),
        bad(
            SIG,
            "byte-range-past-end",
            signed_builder("[0 10 20 99999999]").build(),
            &[],
            "`/ByteRange` ending past the end of the file",
        ),
        bad(
            SIG,
            "byte-range-overlap",
            signed_builder("[0 100 50 10]").build(),
            &[],
            "`/ByteRange` ranges that overlap",
        ),
        good(
            SIG,
            "intact",
            signed(),
            &[],
            "Signature covering the whole file",
        ),
        good(
            SIG,
            "trailing-whitespace",
            [signed(), b"\r\n\0\0 \n".to_vec()].concat(),
            &[],
            "Whitespace after the signed ranges is not a change",
        ),
        good(
            SIG,
            "unsigned-field",
            {
                let mut b = Doc::new().builder();
                b.object(10, "<< /FT /Sig /T (Signature1) /Rect [0 0 0 0] >>");
                b.build()
            },
            &[],
            "Empty signature field: no signature dictionary, no `/ByteRange`",
        ),
    ]
}

const XFA_SCRIPT: &str = "ACTIVE.XFA_SCRIPT";
const DANGEROUS_URI: &str = "ACTIVE.DANGEROUS_URI";
const XML_REF: &str = "XML.EXTERNAL_REFERENCE";
const DRAW_LOOP: &str = "RESOURCE.DRAW_RECURSION";
const FUNCTION_SIZE: &str = "RESOURCE.FUNCTION_SIZE";
const XFA: &str = "FORMS.XFA";
const ACROFORM: &str = "FORMS.ACROFORM";
const URI: &str = "EXTERNAL.URI";
const OPEN_ACTION: &str = "ACTIVE.OPEN_ACTION";

/// An XFA template with `inner` in a field.
fn template(inner: &str) -> String {
    format!(
        "<template xmlns=\"http://www.xfa.org/schema/xfa-template/3.3/\"><subform name=\"form1\"><field name=\"a\">{inner}</field></subform></template>"
    )
}

const ALERT: &str = "<event activity=\"initialize\"><script contentType=\"application/x-javascript\">app.alert(\"quelda-test\");</script></event>";

/// Base doc + an AcroForm (object 10) whose `/XFA` holds template stream 11
/// and datasets stream 12.
fn xfa_builder(tpl: &[u8], datasets: &[u8], filters: &[Filter]) -> PdfBuilder {
    let mut doc = Doc::new();
    doc.catalog_extra = "/AcroForm 10 0 R".to_string();
    let mut b = doc.builder();
    b.object(
        10,
        "<< /Fields [] /XFA [(template) 11 0 R (datasets) 12 0 R] >>",
    )
    .stream(11, "", tpl, filters)
    .stream(12, "", datasets, &[]);
    b
}

const DATASETS: &[u8] = b"<xfa:datasets xmlns:xfa=\"http://www.xfa.org/schema/xfa-data/1.0/\"><xfa:data><form1><a>1</a></form1></xfa:data></xfa:datasets>";

fn xfa(tpl: &str) -> Vec<u8> {
    xfa_builder(tpl.as_bytes(), DATASETS, &[]).build()
}

fn utf16be(s: &str) -> Vec<u8> {
    [0xFE, 0xFF]
        .into_iter()
        .chain(s.encode_utf16().flat_map(u16::to_be_bytes))
        .collect()
}

fn xfa_script() -> Vec<Fixture> {
    let forms = &[XFA, ACROFORM];
    vec![
        bad(XFA_SCRIPT, "javascript-event", xfa(&template(ALERT)), forms, "JavaScript run when the form initializes"),
        bad(
            XFA_SCRIPT,
            "formcalc",
            xfa(&template("<calculate><script>$.rawValue = 1</script></calculate>")),
            forms,
            "FormCalc calculation script (the default language)",
        ),
        bad(
            XFA_SCRIPT,
            "cdata",
            xfa(&template("<event activity=\"click\"><script contentType=\"application/x-javascript\"><![CDATA[app.alert(1)]]></script></event>")),
            forms,
            "Script inside a CDATA section",
        ),
        bad(
            XFA_SCRIPT,
            "prefixed-element",
            xfa(&template("<event><t:script xmlns:t=\"http://www.xfa.org/schema/xfa-template/3.3/\">app.alert(1)</t:script></event>")),
            forms,
            "Script element with a namespace prefix",
        ),
        bad(
            XFA_SCRIPT,
            "flate",
            xfa_builder(template(ALERT).as_bytes(), DATASETS, &[Filter::Flate]).build(),
            forms,
            "Template stream Flate-compressed",
        ),
        bad(
            XFA_SCRIPT,
            "utf16",
            xfa_builder(&utf16be(&template(ALERT)), DATASETS, &[]).build(),
            forms,
            "Template in UTF-16 (with a byte order mark)",
        ),
        bad(
            XFA_SCRIPT,
            "single-stream",
            {
                let mut doc = Doc::new();
                doc.catalog_extra = "/AcroForm << /Fields [] /XFA 11 0 R >>".to_string();
                let mut b = doc.builder();
                let xdp = format!("<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">{}</xdp:xdp>", template(ALERT));
                b.stream(11, "", xdp.as_bytes(), &[]);
                b.build()
            },
            forms,
            "Whole XDP as one stream (`/XFA 11 0 R`)",
        ),
        bad(
            XFA_SCRIPT,
            "string-packet",
            {
                let mut doc = Doc::new();
                doc.catalog_extra = format!(
                    "/AcroForm << /Fields [] /XFA [(template) {}] >>",
                    hex(template("<script>x = 1</script>").as_bytes())
                );
                doc.build()
            },
            forms,
            "Template written as a (hex) string in the `/XFA` array",
        ),
        good(
            XFA_SCRIPT,
            "empty-scripts",
            xfa(&template("<event activity=\"click\"><script contentType=\"application/x-javascript\"/></event><calculate><script>  </script></calculate>")),
            forms,
            "Empty `<script>` elements a form designer leaves in the template",
        ),
        good(
            XFA_SCRIPT,
            "static-form",
            xfa(&template("<ui><textEdit/></ui><caption><value><text>Name</text></value></caption>")),
            forms,
            "XFA form without scripts",
        ),
        good(
            XFA_SCRIPT,
            "escaped-in-data",
            xfa_builder(
                template("<ui><textEdit/></ui>").as_bytes(),
                b"<xfa:datasets><xfa:data><form1><a>&lt;script&gt;app.alert(1)&lt;/script&gt;</a></form1></xfa:data></xfa:datasets>",
                &[],
            )
            .build(),
            forms,
            "Form data containing the escaped text `<script>`",
        ),
        good(
            XFA_SCRIPT,
            "not-xfa",
            {
                let mut b = Doc::new().builder();
                b.stream(11, "", template(ALERT).as_bytes(), &[]);
                b.build()
            },
            &[],
            "A script-like XML stream nothing names as XFA",
        ),
    ]
}

/// `s` as a PDF hex string.
fn hex(s: &[u8]) -> String {
    let digits: String = s.iter().map(|b| format!("{b:02X}")).collect();
    format!("<{digits}>")
}

/// Base doc + a link annotation (object 10) to `uri` (a PDF string).
fn link(uri: &str) -> Vec<u8> {
    let mut doc = Doc::new();
    doc.annots = vec![10];
    let mut b = doc.builder();
    b.object(
        10,
        format!("<< /Type /Annot /Subtype /Link /Rect [72 700 300 720] /Border [0 0 0] /A << /S /URI /URI {uri} >> >>"),
    );
    b.build()
}

fn dangerous_uri() -> Vec<Fixture> {
    let uri = &[URI];
    let bad_link = |variant: &str, target: &[u8], what: &str| {
        bad(DANGEROUS_URI, variant, link(&hex(target)), uri, what)
    };
    let good_link = |variant: &str, target: &[u8], what: &str| {
        good(DANGEROUS_URI, variant, link(&hex(target)), uri, what)
    };
    vec![
        bad_link(
            "javascript",
            b"javascript:app.alert('quelda-test')",
            "`javascript:` link",
        ),
        bad_link(
            "javascript-obfuscated",
            b" \x01JaVa\tScRiPt:app.alert(1)",
            "`javascript:` with a leading control character, mixed case and a tab",
        ),
        bad_link(
            "vbscript",
            b"vbscript:msgbox(\"quelda-test\")",
            "`vbscript:` link",
        ),
        bad_link("data", b"data:text/plain,quelda-test", "`data:` URL"),
        bad_link("file", b"File:quelda-test.pdf", "`file:` link (any case)"),
        bad_link(
            "unc",
            b"\\\\example.invalid\\quelda-test\\x.pdf",
            "UNC path to a network share (NTLM leak)",
        ),
        bad_link(
            "windows-path",
            b"C:\\quelda-test\\x.pdf",
            "Local Windows path",
        ),
        bad_link(
            "ms-msdt",
            b"ms-msdt:quelda-test",
            "`ms-msdt:` protocol handler (Follina)",
        ),
        bad_link(
            "search-ms",
            b"search-ms:query=quelda-test",
            "`search-ms:` protocol handler",
        ),
        bad(
            DANGEROUS_URI,
            "utf16",
            link(&hex(&utf16be("javascript:app.alert(1)"))),
            uri,
            "`javascript:` link written in UTF-16",
        ),
        bad(
            DANGEROUS_URI,
            "indirect",
            {
                let mut doc = Doc::new();
                doc.annots = vec![10];
                let mut b = doc.builder();
                b.object(10, "<< /Type /Annot /Subtype /Link /Rect [72 700 300 720] /A << /S /URI /URI 11 0 R >> >>")
                    .object(11, "(javascript:app.alert\\(1\\))");
                b.build()
            },
            uri,
            "`/URI` value through an indirect reference",
        ),
        bad(
            DANGEROUS_URI,
            "open-action",
            {
                let mut doc = Doc::new();
                doc.catalog_extra =
                    "/OpenAction << /S /URI /URI (file:quelda-test.pdf) >>".to_string();
                doc.build()
            },
            &[URI, OPEN_ACTION],
            "`file:` URI action run when the document opens",
        ),
        good_link(
            "https",
            b"https://example.invalid/docs/a.pdf",
            "Ordinary web link",
        ),
        good_link(
            "mailto",
            b"mailto:quelda-test@example.invalid",
            "E-mail link",
        ),
        good_link("ftp", b"ftp:quelda-test", "FTP link"),
        good_link("tel", b"tel:+0000", "Phone link"),
        good_link("relative", b"chapter2.html#intro", "Relative link"),
        good_link(
            "javascript-in-query",
            b"https://example.invalid/?next=javascript:x",
            "`javascript:` inside the query of a web link",
        ),
    ]
}

/// Base doc + catalog `/Metadata 10 0 R`, an XMP stream.
fn xmp(packet: &[u8], filters: &[Filter]) -> Vec<u8> {
    let mut doc = Doc::new();
    doc.catalog_extra = "/Metadata 10 0 R".to_string();
    let mut b = doc.builder();
    b.stream(10, "/Type /Metadata /Subtype /XML", packet, filters);
    b.build()
}

const XMP_OPEN: &str = "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">";
const XMP_CLOSE: &str = "</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>";

fn xmp_with(inner: &str) -> String {
    format!("{XMP_OPEN}{inner}{XMP_CLOSE}")
}

fn xml_external_reference() -> Vec<Fixture> {
    let include = xmp_with(
        "<dc:title xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"quelda-test.txt\" parse=\"text\"/></dc:title>",
    );
    let stylesheet = format!(
        "<?xml-stylesheet type=\"text/xsl\" href=\"quelda-test.xsl\"?>{}",
        xmp_with("")
    );
    vec![
        bad(XML_REF, "xinclude", xmp(include.as_bytes(), &[]), &[], "XInclude of a file in XMP metadata"),
        bad(XML_REF, "xml-stylesheet", xmp(stylesheet.as_bytes(), &[]), &[], "Stylesheet instruction in XMP metadata"),
        bad(XML_REF, "flate", xmp(include.as_bytes(), &[Filter::Flate]), &[], "XInclude in Flate-compressed metadata"),
        bad(XML_REF, "utf16", xmp(&utf16be(&include), &[]), &[], "XInclude in UTF-16 metadata"),
        bad(
            XML_REF,
            "xfa-web-service",
            xfa_builder(
                b"<connectionSet xmlns=\"http://www.xfa.org/schema/xfa-connection-set/2.8/\"><wsdlConnection dataDescription=\"d\" name=\"svc\"><soapAddress>https://example.invalid/quelda-test</soapAddress></wsdlConnection></connectionSet>",
                DATASETS,
                &[],
            )
            .build(),
            &[XFA, ACROFORM],
            "XFA web service connection",
        ),
        good(XML_REF, "plain-xmp", xmp(xmp_with("<dc:format>application/pdf</dc:format>").as_bytes(), &[]), &[], "Ordinary XMP: namespace URIs only"),
        good(XML_REF, "include-without-namespace", xmp(xmp_with("<dc:title><include>chapter</include></dc:title>").as_bytes(), &[]), &[], "An element named `include` that is not XInclude"),
        good(
            XML_REF,
            "xfa-schema-connection",
            xfa_builder(b"<connectionSet><xsdConnection dataDescription=\"d\" name=\"s\"/></connectionSet>", DATASETS, &[]).build(),
            &[XFA, ACROFORM],
            "XFA schema connection (no web service)",
        ),
    ]
}

/// Base doc whose page draws `/Fm0` (object 10), plus `objects`.
fn drawing(objects: impl FnOnce(&mut PdfBuilder)) -> Vec<u8> {
    let mut doc = Doc::new();
    doc.xobjects = vec![("Fm0", 10)];
    doc.content = b"q /Fm0 Do Q\n".to_vec();
    let mut b = doc.builder();
    objects(&mut b);
    b.build()
}

const FORM: &str = "/Type /XObject /Subtype /Form /BBox [0 0 100 100]";

fn draw_recursion() -> Vec<Fixture> {
    let form = |res: &str| format!("{FORM} {res}");
    let type3 = "<< /Type /Font /Subtype /Type3 /FontMatrix [0.01 0 0 0.01 0 0] /FontBBox [0 0 100 100] \
        /Encoding << /Type /Encoding /Differences [65 /a /b] >> /CharProcs << /a 12 0 R /b 13 0 R >> \
        /FirstChar 65 /LastChar 66 /Widths [100 100] /Resources << /Font << /T3 11 0 R >> >> >>";
    vec![
        bad(
            DRAW_LOOP,
            "form-self",
            drawing(|b| {
                b.stream(
                    10,
                    &form("/Resources << /XObject << /X 10 0 R >> >>"),
                    b"/X Do",
                    &[],
                );
            }),
            &[],
            "Form XObject that draws itself",
        ),
        bad(
            DRAW_LOOP,
            "form-inherited",
            drawing(|b| {
                b.stream(10, FORM, b"/Fm0 Do", &[]);
            }),
            &[],
            "Form without resources that draws itself through the page's resources",
        ),
        bad(
            DRAW_LOOP,
            "form-chain",
            drawing(|b| {
                b.stream(
                    10,
                    &form("/Resources << /XObject << /B 11 0 R >> >>"),
                    b"q /B Do Q",
                    &[],
                )
                .stream(
                    11,
                    &form("/Resources << /XObject << /A 10 0 R >> >>"),
                    b"q /A Do Q",
                    &[],
                );
            }),
            &[],
            "Two forms that draw each other",
        ),
        bad(
            DRAW_LOOP,
            "flate",
            drawing(|b| {
                b.stream(
                    10,
                    &form("/Resources << /XObject << /X 10 0 R >> >>"),
                    b"q /X Do Q",
                    &[Filter::Flate],
                );
            }),
            &[],
            "Self-drawing form, Flate-compressed",
        ),
        bad(
            DRAW_LOOP,
            "pattern",
            drawing(|b| {
                b.stream(10, &form("/Resources 14 0 R"), b"/Pattern cs /P0 scn 0 0 100 100 re f", &[])
                    .object(14, "<< /Pattern << /P0 11 0 R >> >>")
                    .stream(11, "/Type /Pattern /PatternType 1 /PaintType 1 /TilingType 1 /BBox [0 0 10 10] /XStep 10 /YStep 10 /Resources 14 0 R", b"/Pattern cs /P0 scn 0 0 10 10 re f", &[]);
            }),
            &[],
            "Tiling pattern that paints with itself",
        ),
        bad(
            DRAW_LOOP,
            "soft-mask",
            drawing(|b| {
                b.stream(
                    10,
                    &form("/Group << /S /Transparency >> /Resources 14 0 R"),
                    b"/GS0 gs 0 0 100 100 re f",
                    &[],
                )
                .object(
                    14,
                    "<< /ExtGState << /GS0 << /SMask << /S /Luminosity /G 10 0 R >> >> >> >>",
                );
            }),
            &[],
            "Form whose soft mask is the form itself",
        ),
        bad(
            DRAW_LOOP,
            "type3-glyph",
            drawing(|b| {
                b.stream(
                    10,
                    &form("/Resources << /Font << /T3 11 0 R >> >>"),
                    b"BT /T3 12 Tf (B) Tj ET",
                    &[],
                )
                .object(11, type3)
                .stream(12, "", b"100 0 0 0 100 100 d1 BT /T3 1 Tf (A) Tj ET", &[])
                .stream(13, "", b"100 0 0 0 100 100 d1 0 0 100 100 re f", &[]);
            }),
            &[],
            "Type 3 glyph `a` that shows itself",
        ),
        good(
            DRAW_LOOP,
            "shared-resources",
            drawing(|b| {
                b.stream(10, &form("/Resources 14 0 R"), b"q /Fm1 Do Q", &[])
                    .object(14, "<< /XObject << /Fm0 10 0 R /Fm1 11 0 R >> >>")
                    .stream(11, &form("/Resources 14 0 R"), b"0 0 10 10 re f", &[]);
            }),
            &[],
            "Forms sharing a resource dictionary that lists them, without a loop",
        ),
        good(
            DRAW_LOOP,
            "nested-forms",
            drawing(|b| {
                b.stream(
                    10,
                    &form("/Resources << /XObject << /B 11 0 R >> >>"),
                    b"/B Do /B Do",
                    &[],
                )
                .stream(
                    11,
                    &form("/Resources << /XObject << /C 12 0 R >> >>"),
                    b"/C Do",
                    &[],
                )
                .stream(12, FORM, b"0 0 10 10 re f", &[]);
            }),
            &[],
            "Forms nested three deep, one drawn twice",
        ),
        good(
            DRAW_LOOP,
            "type3-other-glyph",
            drawing(|b| {
                b.stream(
                    10,
                    &form("/Resources << /Font << /T3 11 0 R >> >>"),
                    b"BT /T3 12 Tf (A) Tj ET",
                    &[],
                )
                .object(11, type3)
                .stream(12, "", b"100 0 0 0 100 100 d1 BT /T3 1 Tf (B) Tj ET", &[])
                .stream(13, "", b"100 0 0 0 100 100 d1 0 0 100 100 re f", &[]);
            }),
            &[],
            "Type 3 glyph built from another glyph of its font",
        ),
    ]
}

/// Base doc whose page draws a form shading with function stream 11
/// (dictionary `function`), plus `more` objects.
fn shading_with(function: &str, more: impl FnOnce(&mut PdfBuilder)) -> Vec<u8> {
    drawing(|b| {
        b.stream(
            10,
            &format!("{FORM} /Resources << /Shading << /Sh0 12 0 R >> >>"),
            b"/Sh0 sh",
            &[],
        )
        .object(
            12,
            "<< /ShadingType 2 /ColorSpace /DeviceRGB /Coords [0 0 100 0] /Function 11 0 R >>",
        )
        .stream(11, function, &[0u8; 96], &[]);
        more(b);
    })
}

fn shading(function: &str) -> Vec<u8> {
    shading_with(function, |_| {})
}

fn function_size() -> Vec<Fixture> {
    vec![
        bad(
            FUNCTION_SIZE,
            "huge-table",
            shading(
                "/FunctionType 0 /Domain [0 1 0 1] /Range [0 1 0 1 0 1] /Size [65536 65536] /BitsPerSample 16",
            ),
            &[],
            "2 inputs of 65536 samples, 3 outputs, 16 bits: 24 GiB declared",
        ),
        bad(
            FUNCTION_SIZE,
            "overflow",
            shading(
                "/FunctionType 0 /Domain [0 1 0 1 0 1 0 1] /Range [0 1] /Size [4294967295 4294967295 4294967295 4294967295] /BitsPerSample 32",
            ),
            &[],
            "Sizes whose product overflows 64 bits",
        ),
        bad(
            FUNCTION_SIZE,
            "indirect-size",
            shading_with(
                "/FunctionType 0 /Domain [0 1 0 1] /Range [0 1 0 1 0 1] /Size 15 0 R /BitsPerSample 8",
                |b| {
                    b.object(15, "[16384 16384]");
                },
            ),
            &[],
            "`/Size` through an indirect reference",
        ),
        good(
            FUNCTION_SIZE,
            "colour-lut",
            shading(
                "/FunctionType 0 /Domain [0 1 0 1 0 1] /Range [0 1 0 1 0 1 0 1] /Size [33 33 33] /BitsPerSample 16",
            ),
            &[],
            "33×33×33 colour lookup table, 4 outputs, 16 bits (287 KB)",
        ),
        good(
            FUNCTION_SIZE,
            "small",
            shading(
                "/FunctionType 0 /Domain [0 1] /Range [0 1 0 1 0 1] /Size [32] /BitsPerSample 8",
            ),
            &[],
            "32 samples",
        ),
    ]
}

pub(super) fn all() -> Vec<Fixture> {
    [
        font_malformed(),
        icc_malformed(),
        signature_modified(),
        xfa_script(),
        dangerous_uri(),
        xml_external_reference(),
        draw_recursion(),
        function_size(),
    ]
    .concat()
}
