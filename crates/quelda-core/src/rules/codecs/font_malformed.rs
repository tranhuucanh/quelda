//! `CODEC.FONT_MALFORMED`: an embedded font program whose structure no font
//! tool writes: tables or indexes that point outside the font's data. Font
//! parsers trust these offsets (FreeType, Ghostscript, Windows and printer
//! font engines have all had overflows from them).
//!
//! Checked: TrueType and OpenType (`/FontFile2`, `/FontFile3 /OpenType`)
//! and CFF (`/FontFile3 /Type1C`, `/CIDFontType0C`), every definition of
//! every font descriptor. Not checked: Type 1 programs (`/FontFile`,
//! reported by `CODEC.TYPE1_FONT`), font collections, CFF2, and programs
//! that do not decode completely (a truncated font is not judged by its
//! structure).

use std::collections::BTreeMap;

use crate::facts::visitor::visit_dicts;
use crate::facts::{Ctx, Location};
use crate::parser::PdfObject;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct FontMalformed;

static META: RuleMeta = RuleMeta {
    id: "CODEC.FONT_MALFORMED",
    category: Category::Codecs,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.3.0",
    message: "Embedded font is malformed",
    description: "An embedded TrueType, OpenType or CFF font program (/FontFile2, /FontFile3) \
        whose structure points outside its own data: a table directory or table that ends \
        past the font, a 'head' table too short, glyph offsets ('loca') past the glyph \
        data, a CFF header or INDEX with impossible sizes or offsets, CharStrings or \
        Private data past the font, or a /FontFile2 that is not a TrueType font at all. \
        Font parsers in renderers and printers trust these offsets, and malformed fonts \
        are a classic way to overflow them; font tools never write them. Type 1 programs \
        are reported by CODEC.TYPE1_FONT; programs that do not decode completely are not \
        judged.",
};

/// More tables than any real font has (they have about 10 to 30).
const MAX_TABLES: u16 = 1024;

/// Bytes a table may run past the data: the padding to 4 bytes that a
/// producer may have dropped from the last table.
const PAD: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// TrueType or OpenType (`sfnt` container).
    Sfnt,
    Cff,
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    let b = d.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn tag(t: [u8; 4]) -> String {
    t.escape_ascii().to_string()
}

/// A TrueType or OpenType font: `Err` says what is malformed.
fn check_sfnt(d: &[u8]) -> Result<(), String> {
    let len = d.len() as u64;
    let version = u32_at(d, 0).ok_or("shorter than a font header")?;
    match &version.to_be_bytes() {
        [0, 1, 0, 0] | b"true" | b"OTTO" | b"typ1" => {}
        b"ttcf" => return Ok(()),
        v => {
            return Err(format!(
                "not a TrueType or OpenType font (starts with {})",
                v.escape_ascii()
            ));
        }
    }
    let n = u16_at(d, 4).ok_or("shorter than a font header")?;
    if n == 0 || n > MAX_TABLES {
        return Err(format!("{n} tables"));
    }
    let dir_end = 12 + 16 * u64::from(n);
    if dir_end > len {
        return Err(format!(
            "table directory of {n} tables ends at {dir_end}, past the font ({len} bytes)"
        ));
    }
    let mut found: BTreeMap<[u8; 4], (usize, usize)> = BTreeMap::new();
    for i in 0..usize::from(n) {
        let at = 12 + 16 * i;
        let t = d.get(at..at + 4).ok_or("table directory cut")?;
        let t = [t[0], t[1], t[2], t[3]];
        let offset = u64::from(u32_at(d, at + 8).ok_or("table directory cut")?);
        let length = u64::from(u32_at(d, at + 12).ok_or("table directory cut")?);
        if offset + length > len + PAD || offset > len {
            return Err(format!(
                "table '{}' at {offset}, {length} bytes, ends past the font ({len} bytes)",
                tag(t)
            ));
        }
        let end = (offset + length).min(len);
        found.entry(t).or_insert((offset as usize, end as usize));
    }
    let get = |t: &[u8; 4]| found.get(t).map(|&(s, e)| &d[s..e]);
    if let Some(head) = get(b"head") {
        if head.len() < 54 {
            return Err(format!("'head' table of {} bytes (54 needed)", head.len()));
        }
    }
    if let (Some(head), Some(loca), Some(glyf)) = (get(b"head"), get(b"loca"), get(b"glyf")) {
        let long = u16_at(head, 50).is_some_and(|f| f != 0);
        let step = if long { 4 } else { 2 };
        let glyf_len = glyf.len() as u64;
        for i in 0..loca.len() / step {
            let at = i * step;
            let off = if long {
                u32_at(loca, at).map(u64::from)
            } else {
                u16_at(loca, at).map(|o| u64::from(o) * 2)
            };
            if let Some(off) = off.filter(|&o| o > glyf_len) {
                return Err(format!(
                    "glyph {i} at offset {off} of 'glyf', past its end ({glyf_len} bytes)"
                ));
            }
        }
    }
    Ok(())
}

/// The data ranges of the items of the CFF INDEX at `at`, and where the
/// INDEX ends.
fn cff_index(d: &[u8], at: usize, what: &str) -> Result<(Vec<(usize, usize)>, usize), String> {
    let cut = || format!("{what} INDEX at {at} past the font ({} bytes)", d.len());
    let count = usize::from(u16_at(d, at).ok_or_else(cut)?);
    if count == 0 {
        return Ok((Vec::new(), at + 2));
    }
    let off_size = usize::from(*d.get(at + 2).ok_or_else(cut)?);
    if !(1..=4).contains(&off_size) {
        return Err(format!("{what} INDEX offset size {off_size}"));
    }
    let offsets_at = at + 3;
    let base = offsets_at + (count + 1) * off_size - 1;
    let offset = |i: usize| -> Option<usize> {
        let b = d.get(offsets_at + i * off_size..offsets_at + (i + 1) * off_size)?;
        Some(b.iter().fold(0usize, |acc, &x| acc << 8 | usize::from(x)))
    };
    let mut items = Vec::with_capacity(count.min(4096));
    let mut prev = offset(0).ok_or_else(cut)?;
    if prev != 1 {
        return Err(format!("{what} INDEX first offset {prev} (must be 1)"));
    }
    for i in 1..=count {
        let o = offset(i).ok_or_else(cut)?;
        if o < prev {
            return Err(format!("{what} INDEX offsets go backwards ({prev} then {o})"));
        }
        items.push((base + prev, base + o));
        prev = o;
    }
    let end = base + prev;
    if end > d.len() {
        return Err(format!(
            "{what} INDEX data ends at {end}, past the font ({} bytes)",
            d.len()
        ));
    }
    Ok((items, end))
}

/// Operands of the operators of a CFF DICT that point into the font:
/// CharStrings (17) offset, Private (18) size and offset.
fn cff_top_dict(dict: &[u8]) -> Result<(Option<i64>, Option<(i64, i64)>), String> {
    let (mut charstrings, mut private) = (None, None);
    let mut operands: Vec<i64> = Vec::new();
    let mut i = 0;
    while let Some(&b) = dict.get(i) {
        i += 1;
        match b {
            0..=21 => {
                let op = if b == 12 {
                    i += 1;
                    1200 + u16::from(*dict.get(i - 1).unwrap_or(&0))
                } else {
                    u16::from(b)
                };
                match (op, operands.as_slice()) {
                    (17, [.., off]) => charstrings = Some(*off),
                    (18, [.., size, off]) => private = Some((*size, *off)),
                    _ => {}
                }
                operands.clear();
            }
            28 => {
                let v = dict.get(i..i + 2).ok_or("Top DICT cut")?;
                operands.push(i64::from(i16::from_be_bytes([v[0], v[1]])));
                i += 2;
            }
            29 => {
                let v = dict.get(i..i + 4).ok_or("Top DICT cut")?;
                operands.push(i64::from(i32::from_be_bytes([v[0], v[1], v[2], v[3]])));
                i += 4;
            }
            30 => {
                // A real: nibbles up to an 0xf nibble. Not an offset.
                while let Some(&n) = dict.get(i) {
                    i += 1;
                    if n & 0x0f == 0x0f || n >> 4 == 0x0f {
                        break;
                    }
                }
                operands.push(0);
            }
            32..=246 => operands.push(i64::from(b) - 139),
            247..=254 => {
                let w = i64::from(*dict.get(i).ok_or("Top DICT cut")?);
                i += 1;
                let v = if b <= 250 {
                    (i64::from(b) - 247) * 256 + w + 108
                } else {
                    -(i64::from(b) - 251) * 256 - w - 108
                };
                operands.push(v);
            }
            _ => return Err(format!("Top DICT reserved byte {b}")),
        }
        if operands.len() > 48 {
            return Err("Top DICT has more than 48 operands".to_string());
        }
    }
    Ok((charstrings, private))
}

/// A CFF font: `Err` says what is malformed.
fn check_cff(d: &[u8]) -> Result<(), String> {
    let (major, hdr_size, off_size) = match d {
        [major, _, hdr, off, ..] => (*major, usize::from(*hdr), *off),
        _ => return Err("shorter than a CFF header".to_string()),
    };
    if major == 2 {
        return Ok(());
    }
    if major != 1 {
        return Err(format!("CFF version {major}"));
    }
    if hdr_size < 4 || hdr_size > d.len() || !(1..=4).contains(&off_size) {
        return Err(format!(
            "CFF header size {hdr_size}, offset size {off_size}"
        ));
    }
    let (_, at) = cff_index(d, hdr_size, "Name")?;
    let (top, at) = cff_index(d, at, "Top DICT")?;
    let (_, at) = cff_index(d, at, "String")?;
    cff_index(d, at, "Global Subr")?;
    for &(s, e) in &top {
        let (charstrings, private) = cff_top_dict(&d[s..e])?;
        if let Some(off) = charstrings {
            let off = usize::try_from(off)
                .ok()
                .filter(|&o| o < d.len())
                .ok_or_else(|| format!("CharStrings at {off}, past the font ({} bytes)", d.len()))?;
            cff_index(d, off, "CharStrings")?;
        }
        if let Some((size, off)) = private {
            let end = off.checked_add(size);
            if size < 0 || off < 0 || end.is_none_or(|e| e > d.len() as i64) {
                return Err(format!(
                    "Private DICT at {off}, {size} bytes, past the font ({} bytes)",
                    d.len()
                ));
            }
        }
    }
    Ok(())
}

/// Font program streams (object index → format), from every `/FontFile2`
/// and `/FontFile3` of every dictionary, every definition.
fn font_programs(ctx: &Ctx) -> BTreeMap<usize, Format> {
    let doc = ctx.document();
    let mut out = BTreeMap::new();
    visit_dicts(ctx.objects(), |dict, _| {
        for (key, v) in dict.entries() {
            let three = key == "FontFile3";
            if !(three || key == "FontFile2") {
                continue;
            }
            let Some(r) = v.as_reference() else { continue };
            for i in doc.definition_indices(r) {
                let Some(stream) = doc.objects[i].object.as_stream() else {
                    continue;
                };
                let format = if !three {
                    Some(Format::Sfnt)
                } else {
                    stream.dict.get_all("Subtype").find_map(|s| match s {
                        PdfObject::Name(n) if n == "OpenType" => Some(Format::Sfnt),
                        PdfObject::Name(n) if n == "Type1C" || n == "CIDFontType0C" => {
                            Some(Format::Cff)
                        }
                        _ => None,
                    })
                };
                if let Some(f) = format {
                    out.entry(i).or_insert(f);
                }
            }
        }
    });
    out
}

impl Rule for FontMalformed {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        for (i, format) in font_programs(ctx) {
            let Some(data) = ctx.decode_opaque(i) else { continue };
            let (name, result) = match format {
                Format::Sfnt => ("TrueType/OpenType", check_sfnt(&data)),
                Format::Cff => ("CFF", check_cff(&data)),
            };
            if let Err(why) = result {
                let entry = &ctx.objects()[i];
                out.report(&META, &Location::of(i, entry), Some(format!("{name}: {why}")));
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    /// A minimal TrueType font: `head`, `maxp`, `loca` (short offsets),
    /// `glyf` of `glyf_len` zero bytes.
    pub(crate) fn truetype(loca: &[u16], glyf_len: usize) -> Vec<u8> {
        let mut head = vec![0u8; 54];
        head[12..16].copy_from_slice(&0x5F0F_3CF5u32.to_be_bytes());
        head[18..20].copy_from_slice(&1000u16.to_be_bytes());
        let mut maxp = vec![0, 0, 0x50, 0];
        maxp.extend_from_slice(&((loca.len().max(1) - 1) as u16).to_be_bytes());
        let loca: Vec<u8> = loca.iter().flat_map(|o| o.to_be_bytes()).collect();
        let glyf = vec![0u8; glyf_len];
        let tables: [(&[u8; 4], &[u8]); 4] =
            [(b"glyf", &glyf), (b"head", &head), (b"loca", &loca), (b"maxp", &maxp)];
        let mut out = vec![0, 1, 0, 0, 0, 4, 0, 64, 0, 2, 0, 0];
        let mut data = Vec::new();
        let mut offset = 12 + 16 * tables.len();
        for (t, body) in tables {
            out.extend_from_slice(t);
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&(offset as u32).to_be_bytes());
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            data.extend_from_slice(body);
            while data.len() % 4 != 0 {
                data.push(0);
            }
            offset = 12 + 16 * tables.len() + data.len();
        }
        out.extend(data);
        out
    }

    /// A minimal CFF font: one name, a Top DICT with CharStrings (two
    /// empty glyphs) and Private.
    pub(crate) fn cff() -> Vec<u8> {
        let mut d = vec![1, 0, 4, 1];
        // Name INDEX: "A".
        d.extend_from_slice(&[0, 1, 1, 1, 2, b'A']);
        // Top DICT INDEX: CharStrings at 26 (operand 28 x x), Private 0 at 0.
        let top = [28, 0, 26, 17, 139, 139, 18];
        d.extend_from_slice(&[0, 1, 1, 1, 1 + top.len() as u8]);
        d.extend_from_slice(&top);
        // String INDEX and Global Subr INDEX: empty.
        d.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(d.len(), 26);
        // CharStrings INDEX: two glyphs, `endchar` each.
        d.extend_from_slice(&[0, 2, 1, 1, 2, 3, 14, 14]);
        d
    }

    #[test]
    fn valid_fonts_pass() {
        assert_eq!(check_sfnt(&truetype(&[0, 2, 4], 8)), Ok(()));
        assert_eq!(check_cff(&cff()), Ok(()));
        // Collections and CFF2 are not checked.
        assert_eq!(check_sfnt(b"ttcf\0\x01\0\0"), Ok(()));
        assert_eq!(check_cff(&[2, 0, 5, 0, 0]), Ok(()));
        // The last table may lack its padding.
        let mut f = truetype(&[0, 1, 3], 6);
        f.truncate(f.len() - 3);
        assert_eq!(check_sfnt(&f), Ok(()));
    }

    #[test]
    fn sfnt_defects() {
        let err = |d: &[u8]| check_sfnt(d).unwrap_err();
        assert_eq!(err(b"\0\x01"), "shorter than a font header");
        assert!(err(b"%!PS-AdobeFont-1.0").starts_with("not a TrueType or OpenType font"));
        assert_eq!(err(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "0 tables");
        assert!(err(&[0, 1, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0]).starts_with("table directory of 9"));
        // A table offset far past the data.
        let mut f = truetype(&[0, 2, 4], 8);
        f[12 + 8..12 + 12].copy_from_slice(&0x7fff_0000u32.to_be_bytes());
        assert!(err(&f).starts_with("table 'glyf' at 2147418112"), "{}", err(&f));
        // A table length that wraps when added to its offset.
        let mut f = truetype(&[0, 2, 4], 8);
        f[12 + 12..12 + 16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(err(&f).starts_with("table 'glyf'"));
        // A short `head`.
        let mut f = truetype(&[0, 2, 4], 8);
        f[12 + 16 + 12..12 + 16 + 16].copy_from_slice(&20u32.to_be_bytes());
        assert_eq!(err(&f), "'head' table of 20 bytes (54 needed)");
        // A glyph past the end of `glyf`.
        assert_eq!(
            err(&truetype(&[0, 2, 400], 8)),
            "glyph 2 at offset 800 of 'glyf', past its end (8 bytes)"
        );
    }

    #[test]
    fn cff_defects() {
        let err = |d: &[u8]| check_cff(d).unwrap_err();
        let base = cff();
        assert_eq!(err(&base[..3]), "shorter than a CFF header");
        let with = |at: usize, v: u8| {
            let mut d = base.clone();
            d[at] = v;
            d
        };
        assert_eq!(err(&with(0, 7)), "CFF version 7");
        assert_eq!(err(&with(3, 9)), "CFF header size 4, offset size 9");
        // Name INDEX: offset size 0, first offset 2, offsets backwards.
        assert_eq!(err(&with(6, 0)), "Name INDEX offset size 0");
        assert_eq!(err(&with(7, 2)), "Name INDEX first offset 2 (must be 1)");
        assert_eq!(err(&with(8, 0)), "Name INDEX offsets go backwards (1 then 0)");
        // Name INDEX data past the font.
        assert!(err(&with(8, 200)).starts_with("Name INDEX data ends at"));
        // CharStrings and Private past the font.
        assert!(err(&with(16, 0x7f)).starts_with("CharStrings at 32538"));
        assert!(err(&with(19, 200)).starts_with("Private DICT at 0, 61 bytes"));
        // CharStrings INDEX itself broken.
        assert_eq!(err(&with(28, 5)), "CharStrings INDEX offset size 5");
        // Reserved byte in the Top DICT.
        assert_eq!(err(&with(15, 255)), "Top DICT reserved byte 255");
    }

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&FontMalformed])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    fn stream(num: u32, dict: &str, data: &[u8]) -> Vec<u8> {
        let mut v = format!("{num} 0 obj << {dict} /Length {} >> stream\n", data.len()).into_bytes();
        v.extend_from_slice(data);
        v.extend_from_slice(b"\nendstream endobj\n");
        v
    }

    #[test]
    fn found_through_font_descriptors() {
        let bad_tt = truetype(&[0, 2, 400], 8);
        let src = [
            b"1 0 obj << /Type /FontDescriptor /FontFile2 2 0 R /FontFile3 3 0 R >> endobj\n".to_vec(),
            stream(2, "", &bad_tt),
            stream(3, "/Subtype /Type1C", &cff()[..20]),
            b"4 0 obj << /FontFile2 5 0 R /FontFile3 6 0 R /FontFile 7 0 R >> endobj\n".to_vec(),
            stream(5, "", &truetype(&[0, 2, 4], 8)),
            stream(6, "/Subtype /OpenType", &bad_tt),
            // Type 1, and a font stream not referenced as a font: not checked.
            stream(7, "", b"garbage"),
            stream(8, "", &bad_tt),
            // A second descriptor of the same stream: reported once.
            b"9 0 obj << /FontFile2 2 0 R >> endobj\n".to_vec(),
        ]
        .concat();
        assert_eq!(
            hits(&src),
            vec![
                "2 0: TrueType/OpenType: glyph 2 at offset 800 of 'glyf', past its end (8 bytes)",
                "3 0: CFF: Top DICT INDEX data ends at 22, past the font (20 bytes)",
                "6 0: TrueType/OpenType: glyph 2 at offset 800 of 'glyf', past its end (8 bytes)",
            ]
        );
    }

    #[test]
    fn compressed_and_truncated_programs() {
        let bad = truetype(&[0, 2, 400], 8);
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&bad, 6);
        let src = [
            b"1 0 obj << /FontFile2 2 0 R /FontFile3 3 0 R >> endobj\n".to_vec(),
            stream(2, "/Filter /FlateDecode", &z),
            // Truncated Flate data: not judged.
            stream(3, "/Subtype /OpenType /Filter /FlateDecode", &z[..z.len() / 2]),
        ]
        .concat();
        assert_eq!(hits(&src).len(), 1);
    }
}
