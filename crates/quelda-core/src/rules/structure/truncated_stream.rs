//! `STRUCT.TRUNCATED_STREAM`: compressed stream data ends before its end
//! marker (ADR #26).

use crate::facts::{Ctx, Location};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct TruncatedStream;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.TRUNCATED_STREAM",
    category: Category::Structure,
    severity: Severity::Low,
    default_action: Action::Warn,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Compressed stream data is truncated",
    description: "A FlateDecode stream (content, XML, object or xref stream, or a stream \
        of unknown role) runs out of data before the final deflate block. Common in files \
        from careless producers; readers render everything decoded up to that point, and \
        quelda inspects exactly those bytes. Corrupt (not merely truncated) data in a \
        stream that must be inspected is an `ENGINE.UNDECODABLE` error instead.",
};

impl Rule for TruncatedStream {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        for (i, filter) in ctx.truncated_streams() {
            let Some(entry) = ctx.objects().get(i) else {
                continue;
            };
            out.report(
                &META,
                &Location::of(i, entry),
                Some(format!("{} data ends early", filter.name())),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;
    use miniz_oxide::deflate::compress_to_vec_zlib;

    fn details(src: &[u8]) -> Vec<(u32, Option<String>)> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        let f = run(&ctx, &[&TruncatedStream]);
        f.iter()
            .map(|f| match &f.site {
                crate::rules::Site::Object(l) => (l.id.num, f.detail.clone()),
                _ => (0, f.detail.clone()),
            })
            .collect()
    }

    fn stream(num: u32, dict: &str, data: &[u8]) -> Vec<u8> {
        [
            format!("{num} 0 obj << {dict} /Length {} >> stream\n", data.len()).as_bytes(),
            data,
            b"\nendstream endobj\n",
        ]
        .concat()
    }

    fn content() -> Vec<u8> {
        (0..300)
            .flat_map(|i| format!("q 1 0 0 1 {i} {} cm Q ", i % 7).into_bytes())
            .collect()
    }

    #[test]
    fn reports_truncated_content_and_unknown_streams() {
        let z = compress_to_vec_zlib(&content(), 6);
        let cut = &z[..z.len() / 2];
        let src = [
            &b"1 0 obj << /Contents 2 0 R >> endobj\n"[..],
            &stream(2, "/Filter /FlateDecode", cut),
            &stream(3, "/Filter /FlateDecode", cut),
            &stream(4, "/Filter /FlateDecode", &z),
            // Images are never decoded: not reported.
            &stream(5, "/Subtype /Image /Filter /FlateDecode", cut),
        ]
        .concat();
        let detail = Some("FlateDecode data ends early".to_string());
        assert_eq!(details(&src), vec![(2, detail.clone()), (3, detail)]);
    }

    #[test]
    fn corrupt_and_complete_are_not_reported() {
        let z = compress_to_vec_zlib(&content(), 6);
        let src = [
            &stream(2, "/Filter /FlateDecode", &z)[..],
            &stream(3, "/Filter /FlateDecode", b"\x78\x9c\xff\xff"),
            &stream(4, "", b"q Q"),
        ]
        .concat();
        assert!(details(&src).is_empty());
    }
}
