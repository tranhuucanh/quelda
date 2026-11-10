//! `FILETYPE.POLYGLOT`: another format's structures embedded in the PDF
//! outside stream data (ZIP records, HTML/SVG script markup).

use std::ops::Range;

use crate::facts::Ctx;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct Polyglot;

static META: RuleMeta = RuleMeta {
    id: "FILETYPE.POLYGLOT",
    category: Category::Filetype,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "File is also valid as another format (polyglot)",
    description: "The file has a `%PDF-` header and, outside every stream's data, contains ZIP records (local file \
        header, central directory, end of central directory) or HTML/SVG markup (`<script`, \
        `<html`, `<svg`): the same bytes open as a PDF in a reader and as an archive / web \
        page in other tools. The same bytes inside stream data (compressed data, embedded \
        files, content strings) do not count.",
};

/// Sorted, merged byte ranges of every top-level stream's raw data.
fn stream_ranges(ctx: &Ctx) -> Vec<Range<usize>> {
    let mut v: Vec<Range<usize>> = ctx
        .objects()
        .iter()
        .filter(|e| e.is_top_level())
        .filter_map(|e| e.object.as_stream().map(|s| s.data.clone()))
        .filter(|r| !r.is_empty())
        .collect();
    v.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(v.len());
    for r in v {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    merged
}

/// `pos` is inside one of the sorted, disjoint `ranges`.
fn inside(ranges: &[Range<usize>], pos: usize) -> bool {
    let i = ranges.partition_point(|r| r.end <= pos);
    ranges.get(i).is_some_and(|r| r.contains(&pos))
}

impl Rule for Polyglot {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        // No `%PDF-` anywhere: the file is simply another format
        // (`FILETYPE.NOT_PDF_HEADER` / `FOREIGN_MAGIC`), not a polyglot.
        if ctx.structure().header.is_none() {
            return;
        }
        let ranges = stream_ranges(ctx);
        for sig in ctx.signatures() {
            if !inside(&ranges, sig.offset) {
                let what = sig.kind.describe().to_string();
                out.report(&META, Site::Offset(sig.offset), Some(what));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn hits(src: &[u8]) -> Vec<(usize, String)> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&Polyglot])
            .iter()
            .map(|f| match f.site {
                Site::Offset(o) => (o, f.detail.clone().unwrap_or_default()),
                ref other => panic!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn inside_ranges() {
        let r = [2..4, 10..11];
        let got: Vec<usize> = (0..12).filter(|&p| inside(&r, p)).collect();
        assert_eq!(got, vec![2, 3, 10]);
        assert!(!inside(&[], 0));
    }

    #[test]
    fn signatures_outside_streams() {
        let src = b"%PDF-1.7\n1 0 obj << /Length 9 >> stream\nPK\x03\x04<svg>\nendstream endobj\nPK\x05\x06\n<SCRIPT>x</script>\n<Html>\n%%EOF\n";
        let eocd = src.windows(4).position(|w| w == b"PK\x05\x06").unwrap();
        let script = src.windows(7).position(|w| w == b"<SCRIPT").unwrap();
        let html = src.windows(5).position(|w| w == b"<Html").unwrap();
        assert_eq!(
            hits(src),
            vec![
                (eocd, "ZIP end of central directory".to_string()),
                (script, "HTML <script>".to_string()),
                (html, "HTML document".to_string()),
            ]
        );
    }

    #[test]
    fn near_misses() {
        // Signature bytes only in stream data, partial signatures, `<scrip`
        // at the end of the file.
        let src = b"%PDF-1.7\n1 0 obj << /Length 18 >> stream\nPK\x01\x02 <script> <svg\nendstream endobj\n2 0 obj << /A (PK\x03) /B (<scrip) >> endobj\nPK\x05 <scrip";
        assert!(hits(src).is_empty(), "{:?}", hits(src));
    }

    #[test]
    fn needs_a_pdf_header_somewhere() {
        assert!(hits(b"<html><script></script></html>\nPK\x05\x06").is_empty());
        let src = b"PK\x03\x04 quelda\n%PDF-1.7\n%%EOF\n";
        assert_eq!(hits(src), vec![(0, "ZIP local file header".to_string())]);
    }

    #[test]
    fn overlapping_stream_ranges_merge() {
        let src = b"%PDF-1.7\n1 0 obj << /Length 30 >> stream\nAAAA 2 0 obj << /Length 4 >> stream\nPK\x03\x04\nendstream endobj\nendstream endobj\n";
        assert!(hits(src).is_empty(), "{:?}", hits(src));
    }
}
