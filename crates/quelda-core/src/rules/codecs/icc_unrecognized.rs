//! `CODEC.ICC_UNRECOGNIZED`: a stream used as an ICC colour profile whose
//! data is not one (no `acsp` signature at byte 36). Real producers embed
//! such streams (byte-swapped or damaged profiles; measured on real files,
//! 2026-11-12): a colour engine rejects the profile at its signature and the
//! reader falls back to the alternate colour space, so the structure of the
//! data is not judged (`CODEC.ICC_MALFORMED` judges real profiles).
//!
//! Checked on the same streams as `CODEC.ICC_MALFORMED`.

use super::icc_malformed::{lacks_signature, profiles};
use crate::facts::{Ctx, Location};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct IccUnrecognized;

static META: RuleMeta = RuleMeta {
    id: "CODEC.ICC_UNRECOGNIZED",
    category: Category::Codecs,
    severity: Severity::Low,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.4.0",
    message: "Embedded colour profile is not an ICC profile",
    description: "A stream used as an ICC profile (an /ICCBased colour space or an output \
        intent's /DestOutputProfile) that is long enough for an ICC header but has no \
        'acsp' signature: byte-swapped, damaged or unrelated data. Colour engines reject \
        such data at the signature and readers fall back to the alternate colour space; \
        some real producers write it. Profiles that do carry the signature are checked \
        by CODEC.ICC_MALFORMED. Profiles that do not decode completely are not judged.",
};

impl Rule for IccUnrecognized {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        for i in profiles(ctx) {
            let Some(data) = ctx.decode_opaque(i) else { continue };
            if lacks_signature(&data) {
                let entry = &ctx.objects()[i];
                out.report(
                    &META,
                    &Location::of(i, entry),
                    Some("no 'acsp' signature".to_string()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use super::super::icc_malformed::tests::profile;
    use crate::rules::{Site, run};

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&IccUnrecognized])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    fn stream(num: u32, data: &[u8]) -> Vec<u8> {
        let mut v = format!("{num} 0 obj << /N 3 /Length {} >> stream\n", data.len()).into_bytes();
        v.extend_from_slice(data);
        v.extend_from_slice(b"\nendstream endobj\n");
        v
    }

    #[test]
    fn only_profile_streams_without_the_signature() {
        let mut swapped = profile();
        swapped[36..40].copy_from_slice(b"caps");
        let src = [
            b"1 0 obj << /ColorSpace << /A [/ICCBased 2 0 R] /B [/ICCBased 3 0 R] /C [/ICCBased 4 0 R] >> >> endobj\n".to_vec(),
            stream(2, &swapped),
            // A valid profile, and one too short to have a signature
            // (CODEC.ICC_MALFORMED's).
            stream(3, &profile()),
            stream(4, &profile()[..100]),
            // Not named as a profile.
            stream(5, &swapped),
        ]
        .concat();
        assert_eq!(hits(&src), vec!["2 0: no 'acsp' signature"]);
    }
}
