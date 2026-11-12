//! `CODEC.ICC_MALFORMED`: an embedded ICC colour profile whose structure no
//! colour tool writes: no `acsp` signature, a tag table that does not fit,
//! or tags that point outside the profile. Colour engines (Little CMS in
//! Ghostscript and pdf tools, vendor engines in printers) trust these
//! offsets.
//!
//! Checked: every stream named by `[/ICCBased s]` (colour spaces, any
//! depth) or `/DestOutputProfile` (output intents), every definition.
//! Profiles that do not decode completely are not judged, nor are tags of
//! a truncated profile that end within its declared size: real producers
//! (ABBYY FineReader) embed only the first part of a profile.

use std::collections::BTreeSet;

use crate::facts::{Ctx, Location};
use crate::parser::{Document, ObjRef, PdfObject};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct IccMalformed;

static META: RuleMeta = RuleMeta {
    id: "CODEC.ICC_MALFORMED",
    category: Category::Codecs,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.3.0",
    message: "Embedded ICC colour profile is malformed",
    description: "An ICC profile (a stream of an /ICCBased colour space or an output \
        intent's /DestOutputProfile) whose structure is impossible (ICC.1:2010 §7): \
        shorter than its header, without the 'acsp' signature, with a tag table that does \
        not fit in the profile or has more than 1024 tags, or with a tag that ends past \
        both the profile's data and the size its header declares (a truncated profile, as \
        some OCR tools embed, is not judged by its tags). Colour engines in renderers and printers read tags at the offsets \
        the profile gives, and malformed profiles have overflowed them; colour tools never \
        write them. Profiles that do not decode completely are not judged.",
};

/// Header (128 bytes) and tag count.
const HEADER: usize = 132;

/// More tags than any real profile has (they have about 10 to 40).
const MAX_TAGS: u32 = 1024;

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// An ICC profile: `Err` says what is malformed.
fn check(d: &[u8]) -> Result<(), String> {
    let len = d.len() as u64;
    if d.len() < HEADER {
        return Err(format!("{len} bytes, shorter than an ICC header"));
    }
    if d.get(36..40) != Some(b"acsp") {
        return Err("no 'acsp' signature".to_string());
    }
    let declared = u64::from(u32_at(d, 0).unwrap_or(0));
    let count = u32_at(d, 128).unwrap_or(0);
    let table_end = HEADER as u64 + 12 * u64::from(count);
    if count > MAX_TAGS || table_end > len {
        return Err(format!(
            "tag table of {count} tags ends at {table_end}, past the profile ({len} bytes)"
        ));
    }
    for i in 0..count as usize {
        let at = HEADER + 12 * i;
        let (Some(offset), Some(size)) = (u32_at(d, at + 4), u32_at(d, at + 8)) else {
            break;
        };
        let end = u64::from(offset) + u64::from(size);
        if end > len && end > declared {
            let sig = d.get(at..at + 4).unwrap_or_default().escape_ascii();
            return Err(format!(
                "tag '{sig}' at {offset}, {size} bytes, ends past the profile ({len} bytes)"
            ));
        }
    }
    Ok(())
}

/// Object indices of every definition of `r` that is a stream.
fn streams(doc: &Document, r: ObjRef, out: &mut BTreeSet<usize>) {
    out.extend(
        doc.definition_indices(r)
            .filter(|&i| doc.objects[i].object.as_stream().is_some()),
    );
}

/// ICC profile streams: `[/ICCBased s]` arrays and `/DestOutputProfile`
/// values anywhere in any object. Iterative: nesting is bounded by the
/// parser, not the stack.
fn profiles(ctx: &Ctx) -> BTreeSet<usize> {
    let doc = ctx.document();
    let mut out = BTreeSet::new();
    for entry in ctx.objects() {
        let mut stack = vec![&entry.object];
        while let Some(o) = stack.pop() {
            let dict = match o {
                PdfObject::Array(items) => {
                    if let [first, second, ..] = items.as_slice() {
                        if first.is_name("ICCBased") {
                            if let Some(r) = second.as_reference() {
                                streams(doc, r, &mut out);
                            }
                        }
                    }
                    stack.extend(items.iter());
                    continue;
                }
                PdfObject::Dict(d) => d,
                PdfObject::Stream(s) => &s.dict,
                _ => continue,
            };
            for (k, v) in dict.entries() {
                if k == "DestOutputProfile" {
                    if let Some(r) = v.as_reference() {
                        streams(doc, r, &mut out);
                    }
                }
                stack.push(v);
            }
        }
    }
    out
}

impl Rule for IccMalformed {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        for i in profiles(ctx) {
            let Some(data) = ctx.decode_opaque(i) else { continue };
            if let Err(why) = check(&data) {
                let entry = &ctx.objects()[i];
                out.report(&META, &Location::of(i, entry), Some(why));
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    /// A minimal ICC profile with one `desc` tag of 12 bytes.
    pub(crate) fn profile() -> Vec<u8> {
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

    #[test]
    fn defects() {
        assert_eq!(check(&profile()), Ok(()));
        let err = |d: &[u8]| check(d).unwrap_err();
        assert_eq!(err(&profile()[..100]), "100 bytes, shorter than an ICC header");
        let with = |at: usize, v: &[u8]| {
            let mut d = profile();
            d[at..at + v.len()].copy_from_slice(v);
            d
        };
        assert_eq!(err(&with(36, b"xxxx")), "no 'acsp' signature");
        assert_eq!(
            err(&with(128, &9u32.to_be_bytes())),
            "tag table of 9 tags ends at 240, past the profile (156 bytes)"
        );
        assert!(err(&with(128, &u32::MAX.to_be_bytes())).starts_with("tag table of 4294967295"));
        assert_eq!(
            err(&with(136, &0xffff_fff0u32.to_be_bytes())),
            "tag 'desc' at 4294967280, 12 bytes, ends past the profile (156 bytes)"
        );
        assert_eq!(
            err(&with(140, &13u32.to_be_bytes())),
            "tag 'desc' at 144, 13 bytes, ends past the profile (156 bytes)"
        );
        // Truncated (ABBYY FineReader embeds the first 1200 bytes of sRGB):
        // tags within the declared size are not judged, tags past it are.
        let mut cut = with(140, &300u32.to_be_bytes());
        cut[0..4].copy_from_slice(&444u32.to_be_bytes());
        assert_eq!(check(&cut), Ok(()));
        cut[0..4].copy_from_slice(&443u32.to_be_bytes());
        assert_eq!(
            err(&cut),
            "tag 'desc' at 144, 300 bytes, ends past the profile (156 bytes)"
        );
    }

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&IccMalformed])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    fn stream(num: u32, data: &[u8]) -> Vec<u8> {
        let mut v = format!("{num} 0 obj << /N 1 /Length {} >> stream\n", data.len()).into_bytes();
        v.extend_from_slice(data);
        v.extend_from_slice(b"\nendstream endobj\n");
        v
    }

    #[test]
    fn found_in_colour_spaces_and_output_intents() {
        let bad = &profile()[..100];
        let src = [
            // A page colour space, nested in an Indexed space, an output intent.
            b"1 0 obj << /ColorSpace << /CS0 [/ICCBased 2 0 R] /CS1 [/Indexed [/ICCBased 3 0 R] 1 <00>] >> >> endobj\n".to_vec(),
            stream(2, bad),
            stream(3, bad),
            b"4 0 obj << /Type /OutputIntent /S /GTS_PDFX /DestOutputProfile 5 0 R >> endobj\n".to_vec(),
            stream(5, bad),
            // Valid, and a stream nothing names as a profile.
            b"6 0 obj [/ICCBased 7 0 R] endobj\n".to_vec(),
            stream(7, &profile()),
            stream(8, bad),
            // Named twice: reported once.
            b"9 0 obj [/ICCBased 2 0 R] endobj\n".to_vec(),
        ]
        .concat();
        let d = "100 bytes, shorter than an ICC header";
        assert_eq!(
            hits(&src),
            vec![format!("2 0: {d}"), format!("3 0: {d}"), format!("5 0: {d}")]
        );
    }
}
