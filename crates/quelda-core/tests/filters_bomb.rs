//! Flate bombs stop at the decode budget, early, without allocating much
//! more than the budget. Peak heap is measured with a counting allocator;
//! everything runs in one test so measurements do not overlap.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{fixture, object};
use quelda_core::error::IssueCode;
use quelda_core::filters::{DecodeOutcome, decode_stream};
use quelda_core::limits::{Budget, Limits};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Decodes the page content (object 4) of `path`; returns the outcome,
/// heap growth at peak, and time taken.
fn decode_content(path: &str, limits: &Limits) -> (DecodeOutcome, usize, Duration) {
    let f = fixture(path);
    let content = object(&f.bytes, 4);
    let stream = content.object.as_stream().unwrap();
    let mut budget = Budget::new(limits);
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let start = Instant::now();
    let outcome = decode_stream(&f.bytes, stream, &mut budget);
    let elapsed = start.elapsed();
    let peak = PEAK.load(Ordering::SeqCst) - base;
    eprintln!("{path}: {outcome:?}, peak {} KiB, {elapsed:?}", peak / 1024);
    assert_eq!(budget.used(), 0, "{path}: limit hit but bytes charged");
    (outcome, peak, elapsed)
}

const MB: usize = 1 << 20;

#[test]
fn bombs_stop_at_budget() {
    common::fixtures(); // generate fixtures before measuring

    // > 1 GiB through two Flate layers: the ratio limit stops it within a
    // few MiB of output.
    let f = fixture("malformed/flate-bomb.pdf");
    assert!(f.bytes.len() < MB);
    let (out, peak, took) = decode_content("malformed/flate-bomb.pdf", &Limits::default());
    assert_eq!(out, DecodeOutcome::Limit(IssueCode::LimitCompressionRatio));
    assert!(peak < 16 * MB, "peak {peak}");
    assert!(took < Duration::from_secs(5), "{took:?}");

    // Single layer, 256 MiB at ~1000:1 (under the ratio limit): stopped by the
    // per-stream limit. Peak stays within 1.5× the limit (Vec growth).
    let limits = Limits {
        max_decoded_bytes_per_stream: 8 * MB as u64,
        ..Limits::default()
    };
    let (out, peak, _) = decode_content("malformed/flate-bomb-single.pdf", &limits);
    assert_eq!(
        out,
        DecodeOutcome::Limit(IssueCode::LimitStreamDecodedBytes)
    );
    assert!(peak <= 8 * MB * 3 / 2 + MB, "peak {peak}");

    // Default limits: still a LIMIT issue, peak bounded by the 128 MiB limit.
    let (out, peak, _) = decode_content("malformed/flate-bomb-single.pdf", &Limits::default());
    assert_eq!(
        out,
        DecodeOutcome::Limit(IssueCode::LimitStreamDecodedBytes)
    );
    assert!(peak <= 128 * MB * 3 / 2 + MB, "peak {peak}");

    // Total budget smaller than the stream: LIMIT.DECODED_BYTES.
    let limits = Limits {
        max_decoded_bytes_total: 4 * MB as u64,
        ..Limits::default()
    };
    let (out, peak, _) = decode_content("malformed/flate-bomb-single.pdf", &limits);
    assert_eq!(out, DecodeOutcome::Limit(IssueCode::LimitDecodedBytes));
    assert!(peak <= 4 * MB * 3 / 2 + MB, "peak {peak}");
}
