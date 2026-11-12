//! File structure: raw keyword scan, xref/trailer chain, object index.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quelda_core::limits::{Budget, Limits};
use quelda_core::parser::Document;
use quelda_core::parser::raw_scan::RawScan;

fuzz_target!(|data: &[u8]| {
    let _ = RawScan::scan(data);

    let limits = Limits::default();
    let mut budget = Budget::new(&limits);
    let _ = Document::parse(data, &limits, &mut budget);
});
