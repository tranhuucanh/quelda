//! Stream decoding on the testkit fixtures.

mod common;

use common::{fixture, fixtures, object, parse_all};
use quelda_core::filters::{DecodeOutcome, FilterKind, decode_stream};
use quelda_core::limits::{Budget, Limits};
use quelda_core::parser::{Name, PdfObject};
use quelda_testkit::fixtures::Kind;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn is_image(o: &PdfObject) -> bool {
    o.as_dict()
        .and_then(|d| d.get("Subtype"))
        .is_some_and(|s| s.is_name("Image"))
}

/// Decodes every top-level stream of a fixture, except images: the engine
/// never decodes image data (design §4.4), and large real images exceed the
/// per-stream budget by design.
fn decode_all(pdf: &[u8]) -> Vec<(u32, DecodeOutcome)> {
    decode_streams(pdf, false)
}

fn decode_streams(pdf: &[u8], images: bool) -> Vec<(u32, DecodeOutcome)> {
    let mut budget = Budget::new(&Limits::default());
    parse_all(pdf)
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|o| match &o.object {
            PdfObject::Stream(s) if images || !is_image(&o.object) => {
                Some((o.id.num, decode_stream(pdf, s, &mut budget)))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn large_image_would_exceed_stream_budget() {
    let f = fixture("benign/a0-large-image.pdf");
    let img = parse_all(&f.bytes)
        .into_iter()
        .filter_map(Result::ok)
        .find(|o| is_image(&o.object))
        .unwrap();
    let s = img.object.as_stream().unwrap();
    let out = decode_stream(&f.bytes, s, &mut Budget::new(&Limits::default()));
    assert_eq!(
        out,
        DecodeOutcome::Limit(quelda_core::error::IssueCode::LimitStreamDecodedBytes)
    );
}

#[test]
fn benign_streams_decode_completely() {
    let mut decoded = 0;
    for f in fixtures().iter().filter(|f| f.kind == Kind::Benign) {
        for (num, outcome) in decode_all(&f.bytes) {
            match outcome {
                DecodeOutcome::Complete(_) => decoded += 1,
                other => panic!("{} object {num}: {other:?}", f.path),
            }
        }
    }
    assert!(decoded >= 15, "{decoded}");
}

#[test]
fn two_filter_content_decodes_to_text() {
    let f = fixture("benign/content-two-filters.pdf");
    let content = object(&f.bytes, 4);
    let s = content.object.as_stream().unwrap();
    assert_eq!(
        s.dict
            .get("Filter")
            .and_then(PdfObject::as_array)
            .map(<[_]>::len),
        Some(2)
    );
    let out = decode_stream(&f.bytes, s, &mut Budget::new(&Limits::default()));
    assert!(out.data().unwrap().starts_with(b"BT /F1 24 Tf"), "{out:?}");
}

#[test]
fn encoded_payloads_are_revealed() {
    for (rule, marker) in [
        ("POSTSCRIPT.CONTENT_OP", &b" PS"[..]),
        ("XML.DOCTYPE", &b"<!DOCTYPE"[..]),
    ] {
        for variant in ["flate", "filter-chain", "lzw"] {
            let f = fixture(&format!("rules/{rule}/bad/{variant}.pdf"));
            assert!(
                !contains(&f.bytes, marker),
                "{rule}/{variant}: marker visible raw"
            );
            let found = decode_all(&f.bytes)
                .iter()
                .any(|(_, o)| matches!(o, DecodeOutcome::Complete(d) if contains(d, marker)));
            assert!(found, "{rule}/{variant}: marker not found after decoding");
        }
    }
}

#[test]
fn objstm_with_unknown_filter_is_unknown() {
    let f = fixture("malformed/objstm-unknown-filter.pdf");
    let outcome = decode_all(&f.bytes)
        .into_iter()
        .find(|(num, _)| *num == 9)
        .map(|(_, o)| o);
    assert_eq!(
        outcome,
        Some(DecodeOutcome::Unknown(Name::from("QueldaUnknownDecode")))
    );
}

#[test]
fn codec_fixtures_are_not_inspected() {
    for (path, kind) in [
        ("rules/CODEC.JBIG2/bad/plain.pdf", FilterKind::Jbig2),
        ("rules/CODEC.JPX/bad/plain.pdf", FilterKind::Jpx),
    ] {
        let f = fixture(path);
        let outcomes: Vec<_> = decode_streams(&f.bytes, true)
            .into_iter()
            .map(|(_, o)| o)
            .collect();
        assert!(
            outcomes.contains(&DecodeOutcome::NotInspected(kind)),
            "{path}: {outcomes:?}"
        );
    }
}

/// No panic on any stream of any fixture (bombs are covered in `filters_bomb`).
#[test]
fn every_fixture_stream_decodes_without_panic() {
    let mut streams = 0;
    for f in fixtures().iter().filter(|f| !f.path.contains("bomb")) {
        streams += decode_all(&f.bytes).len();
    }
    assert!(streams > 300, "{streams}");
}
