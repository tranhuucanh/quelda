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

pub(super) fn all() -> Vec<Fixture> {
    [font_malformed(), icc_malformed(), signature_modified()].concat()
}
