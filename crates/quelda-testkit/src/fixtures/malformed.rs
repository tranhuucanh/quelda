//! Broken files and resource bombs. The engine must never crash or hang on
//! them; bombs and uninspectable content must end in `ERROR` (fail-closed).

use super::{Doc, Fixture, Kind, group};
use crate::builder::{PdfBuilder, Xref, raw_stream_body};
use crate::filters::{Filter, flate_zeros};

/// Decoded size of the double-Flate bomb: just over 1 GiB.
pub(crate) const BOMB_BYTES: u64 = (1 << 30) + (1 << 20);
/// Decoded size of the single-layer bomb (deflate caps out near 1032:1).
pub(crate) const SINGLE_BOMB_BYTES: u64 = 256 << 20;

fn mal(name: &str, bytes: Vec<u8>, fires: &[&'static str], note: &str) -> Fixture {
    group(Kind::Malformed, name, bytes, fires, note)
}

/// Page content that inflates to `BOMB_BYTES` zeros through `[/FlateDecode /FlateDecode]`.
pub(crate) fn flate_bomb() -> Vec<u8> {
    let inner = flate_zeros(BOMB_BYTES);
    let outer = Filter::Flate.encode(&inner);
    with_content_body(raw_stream_body(
        "/Filter [/FlateDecode /FlateDecode]",
        &outer,
    ))
}

fn flate_bomb_single() -> Vec<u8> {
    with_content_body(raw_stream_body(
        "/Filter /FlateDecode",
        &flate_zeros(SINGLE_BOMB_BYTES),
    ))
}

/// The base document with object 4 (page content) replaced by `body`.
fn with_content_body(body: Vec<u8>) -> Vec<u8> {
    let d = Doc::new();
    let mut b = PdfBuilder::new(d.version);
    b.object(1, d.catalog_body())
        .object(2, d.pages_body())
        .object(3, d.page_body())
        .object(4, body)
        .object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    b.build()
}

pub(crate) fn all() -> Vec<Fixture> {
    let mut out = Vec::new();

    let mut b = Doc::new().builder();
    b.xref(Xref::None);
    out.push(
        mal(
            "no-xref",
            b.build(),
            &["STRUCT.XREF_MISMATCH"],
            "No xref, no trailer, no startxref: objects only found by linear scan",
        )
        .at_least(),
    );

    let mut b = Doc::new().builder();
    b.wrong_offsets();
    out.push(
        mal(
            "xref-wrong-offsets",
            b.build(),
            &["STRUCT.XREF_MISMATCH"],
            "Every xref offset is off by 3 bytes",
        )
        .at_least(),
    );

    let full = Doc::new().build();
    let cut = full[..full.len() * 3 / 5].to_vec();
    out.push(
        mal(
            "truncated",
            cut,
            &["STRUCT.MISSING_EOF"],
            "File cut at 60%: no xref, no trailer, no %%EOF",
        )
        .at_least(),
    );

    let mut b = Doc::new().builder();
    b.omit_eof();
    out.push(mal(
        "missing-eof",
        b.build(),
        &["STRUCT.MISSING_EOF"],
        "Valid file without the final %%EOF",
    ));

    let mut b = Doc::new().builder();
    b.revision().object(10, "<< /QueldaRev 2 >>").prev_loop();
    out.push(
        mal(
            "prev-loop",
            b.build(),
            &["STRUCT.XREF_MISMATCH"],
            "Second trailer's /Prev points at its own xref: must not loop forever",
        )
        .at_least(),
    );

    let depth = 10_000;
    let mut d = Doc::new();
    d.page_extra = format!(
        "/QueldaNest {}{}",
        "<< /A ".repeat(depth),
        ">> ".repeat(depth)
    );
    out.push(
        mal(
            "deep-nesting",
            d.build(),
            &[],
            "Dict nested 10000 levels in the page: LIMIT.NESTING_DEPTH, no stack overflow",
        )
        .at_least()
        .error("LIMIT"),
    );

    out.push(
        mal(
            "flate-bomb",
            flate_bomb(),
            &["STRUCT.FILTER_CHAIN"],
            "Page content [/FlateDecode /FlateDecode] inflating to >1 GiB of zeros: decode budget → ERROR",
        )
        .at_least()
        .error("LIMIT"),
    );

    out.push(
        mal(
            "flate-bomb-single",
            flate_bomb_single(),
            &[],
            "Page content, single Flate layer inflating to 256 MiB (~1000:1): ratio/budget limit → ERROR",
        )
        .at_least()
        .error("LIMIT"),
    );

    let mut d = Doc::new();
    d.version = "1.5";
    let mut b = d.builder();
    b.object(10, "<< /QueldaHidden (inside an undecodable ObjStm) >>")
        .objstm(9, &[10], &[Filter::Declared("QueldaUnknownDecode")])
        .xref(Xref::Stream);
    out.push(
        mal(
            "objstm-unknown-filter",
            b.build(),
            &[],
            "ObjStm with an unknown filter: its objects cannot be inspected → ERROR (fail-closed)",
        )
        .at_least()
        .error("ENGINE"),
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_nesting_is_balanced() {
        let f = all()
            .into_iter()
            .find(|f| f.variant == "deep-nesting")
            .unwrap();
        let opens = f.bytes.windows(2).filter(|w| w == b"<<").count();
        let closes = f.bytes.windows(2).filter(|w| w == b">>").count();
        assert_eq!(opens, closes);
        assert!(opens > 10_000);
    }

    #[test]
    fn truncated_has_no_eof() {
        let f = all()
            .into_iter()
            .find(|f| f.variant == "truncated")
            .unwrap();
        assert!(!f.bytes.windows(5).any(|w| w == b"%%EOF"));
    }
}
