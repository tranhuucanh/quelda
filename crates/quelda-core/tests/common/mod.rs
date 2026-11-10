//! Helpers shared by integration tests: in-memory testkit fixtures and a
//! parser-independent way to find top-level objects.

#![allow(dead_code)] // each test binary uses a subset

use std::sync::OnceLock;

use quelda_core::limits::Limits;
use quelda_core::parser::{IndirectObject, ParseError, parse_indirect_object};
use quelda_testkit::fixtures::Fixture;

pub fn fixtures() -> &'static [Fixture] {
    static ALL: OnceLock<Vec<Fixture>> = OnceLock::new();
    ALL.get_or_init(quelda_testkit::fixtures::all)
}

pub fn fixture(path: &str) -> &'static Fixture {
    fixtures()
        .iter()
        .find(|f| f.path == path)
        .unwrap_or_else(|| panic!("no fixture {path}"))
}

/// Offsets of `<digits> <digits> obj` at the start of a line.
pub fn object_offsets(pdf: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    for i in 0..pdf.len() {
        if i > 0 && !matches!(pdf[i - 1], b'\n' | b'\r') {
            continue;
        }
        let mut j = i;
        for _ in 0..2 {
            let d = pdf[j..].iter().take_while(|b| b.is_ascii_digit()).count();
            if d == 0 || pdf.get(j + d) != Some(&b' ') {
                j = usize::MAX;
                break;
            }
            j += d + 1;
        }
        if j != usize::MAX && pdf[j..].starts_with(b"obj") {
            out.push(i);
        }
    }
    out
}

/// Every top-level object of `pdf`, parsed at its offset.
pub fn parse_all(pdf: &[u8]) -> Vec<Result<IndirectObject, ParseError>> {
    object_offsets(pdf)
        .into_iter()
        .map(|off| parse_indirect_object(pdf, off, &Limits::default()))
        .collect()
}

/// The top-level object `num` (first definition) of `pdf`.
pub fn object(pdf: &[u8], num: u32) -> IndirectObject {
    parse_all(pdf)
        .into_iter()
        .filter_map(Result::ok)
        .find(|o| o.id.num == num)
        .unwrap_or_else(|| panic!("no object {num}"))
}
