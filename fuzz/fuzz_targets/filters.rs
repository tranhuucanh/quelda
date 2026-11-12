//! Stream filters. The first 4 bytes pick the `/Filter` chain and its
//! `/DecodeParms`; the rest is the raw stream data.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quelda_core::filters;
use quelda_core::limits::{Budget, Limits};
use quelda_core::parser::{Dict, Name, PdfObject};

const FILTERS: [&[u8]; 8] = [
    b"FlateDecode",
    b"LZWDecode",
    b"ASCIIHexDecode",
    b"ASCII85Decode",
    b"RunLengthDecode",
    b"Fl",
    b"DCTDecode",
    b"Unknown",
];

const PREDICTORS: [i64; 8] = [1, 2, 10, 11, 12, 14, 15, 0];

fn name(b: &[u8]) -> PdfObject {
    PdfObject::Name(Name::from_slice(b))
}

fn parms(sel: u8, cols: u8) -> PdfObject {
    if sel & 0x80 == 0 {
        return PdfObject::Null;
    }
    PdfObject::Dict(Dict::new(vec![
        (
            Name::from_slice(b"Predictor"),
            PdfObject::Int(PREDICTORS[usize::from(sel & 7)]),
        ),
        (
            Name::from_slice(b"Colors"),
            PdfObject::Int(i64::from((sel >> 3) & 3) + 1),
        ),
        (
            Name::from_slice(b"BitsPerComponent"),
            PdfObject::Int([1, 2, 4, 8, 16, 3][usize::from(sel >> 5 & 3)]),
        ),
        (
            Name::from_slice(b"Columns"),
            PdfObject::Int(i64::from(cols)),
        ),
        (
            Name::from_slice(b"EarlyChange"),
            PdfObject::Int(i64::from(sel & 0x40 != 0)),
        ),
    ]))
}

fuzz_target!(|data: &[u8]| {
    let [a, b, c, d, raw @ ..] = data else {
        return;
    };
    let len = usize::from(a % 3) + 1;
    let sels = [*b, *c, *d];
    let chain: Vec<PdfObject> = sels[..len]
        .iter()
        .map(|s| name(FILTERS[usize::from(s % 8)]))
        .collect();
    let parm: Vec<PdfObject> = sels[..len].iter().map(|s| parms(*s, *a)).collect();
    let (filter, parms) = if len == 1 {
        (chain[0].clone(), parm[0].clone())
    } else {
        (PdfObject::Array(chain), PdfObject::Array(parm))
    };

    let limits = Limits::default();
    let mut budget = Budget::new(&limits);
    let _ = filters::decode(raw, Some(&filter), Some(&parms), &mut budget);
});
