//! Engine limits (design §4.5): guardrails, not rules. Exceeding one is an
//! engine issue (`LIMIT.*` → `ERROR`). Only the limits the engine enforces so
//! far are here; the rest arrive with the steps that use them. Detection
//! [`Thresholds`] live here too: both come from the policy.
//!
//! Default values are provisional until measured on real files (Q6, Step 13).

use crate::error::IssueCode;

/// Absolute ceiling for nesting depth, whatever the policy says. Parsed
/// objects are dropped, compared and visited recursively; this keeps those
/// recursions far below the smallest stack we run on (1 MiB on wasm32).
pub const HARD_MAX_NESTING_DEPTH: u32 = 512;

/// Default for [`Limits::max_nesting_depth`]. Real files nest direct objects a
/// handful of levels deep (deeper structures use indirect references).
pub const DEFAULT_MAX_NESTING_DEPTH: u32 = 128;

pub const DEFAULT_MAX_DECODED_BYTES_PER_STREAM: u64 = 128 << 20;
pub const DEFAULT_MAX_DECODED_BYTES_TOTAL: u64 = 512 << 20;
pub const DEFAULT_MAX_COMPRESSION_RATIO: u32 = 1000;
/// Large real documents have a few hundred thousand objects.
pub const DEFAULT_MAX_OBJECTS: u64 = 1_000_000;
/// Signed forms reach tens of incremental updates, not thousands.
pub const DEFAULT_MAX_REVISIONS: u32 = 1000;

/// The compression ratio limit only applies once a stream decodes to more
/// than this: small streams (XMP padding, tiny content) legitimately reach
/// high ratios and cost nothing.
pub const RATIO_MIN_OUTPUT: u64 = 1 << 20;

/// Limits configured by policy (`limits` object).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of arrays/dictionaries open at once while parsing one
    /// object. Clamped to [`HARD_MAX_NESTING_DEPTH`].
    pub max_nesting_depth: u32,
    /// Decoded size of one stream (also caps each filter stage).
    pub max_decoded_bytes_per_stream: u64,
    /// Decoded size of all streams together.
    pub max_decoded_bytes_total: u64,
    /// Decoded size / raw size of one stream (above [`RATIO_MIN_OUTPUT`]).
    pub max_compression_ratio: u32,
    /// Object definitions in the union set (every revision, linear scan,
    /// object streams).
    pub max_objects: u64,
    /// Cross-reference sections (one per revision; a hybrid file's xref
    /// stream counts with its table).
    pub max_revisions: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
            max_decoded_bytes_per_stream: DEFAULT_MAX_DECODED_BYTES_PER_STREAM,
            max_decoded_bytes_total: DEFAULT_MAX_DECODED_BYTES_TOTAL,
            max_compression_ratio: DEFAULT_MAX_COMPRESSION_RATIO,
            max_objects: DEFAULT_MAX_OBJECTS,
            max_revisions: DEFAULT_MAX_REVISIONS,
        }
    }
}

impl Limits {
    /// Nesting depth actually enforced.
    pub fn nesting_depth(&self) -> usize {
        self.max_nesting_depth.min(HARD_MAX_NESTING_DEPTH) as usize
    }
}

/// Detection thresholds configured by policy (`thresholds` object, design
/// §4.5). Unlike [`Limits`], exceeding one is a rule finding, not an engine
/// issue; rules read them through `Ctx::thresholds`.
#[derive(Clone, Debug, PartialEq)]
pub struct Thresholds {
    /// Width × height of one image (`RESOURCE.IMAGE_DIMENSIONS`).
    pub max_image_pixels: u64,
    /// Longest side of a page box × `UserUnit`, in points (`RESOURCE.PAGE_SIZE`).
    pub max_page_side_pt: f64,
    /// Pages in the page tree (`RESOURCE.PAGE_COUNT`).
    pub max_pages: u64,
    /// Filters on one stream (`STRUCT.FILTER_CHAIN`).
    pub max_filter_chain: u32,
    /// Bytes after the last `%%EOF` (`STRUCT.TRAILING_DATA`).
    pub max_trailing_bytes: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            max_image_pixels: 1_000_000_000,
            max_page_side_pt: 28_800.0,
            max_pages: 10_000,
            max_filter_chain: 2,
            max_trailing_bytes: 1024,
        }
    }
}

/// Decode budget for one scan: tracks decoded bytes across streams.
#[derive(Clone, Debug)]
pub struct Budget {
    per_stream: u64,
    total: u64,
    ratio: u64,
    used: u64,
}

/// Output cap for one decode step and the issue reported when it is hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap {
    pub bytes: u64,
    pub code: IssueCode,
}

impl Budget {
    pub fn new(limits: &Limits) -> Self {
        Budget {
            per_stream: limits.max_decoded_bytes_per_stream,
            total: limits.max_decoded_bytes_total,
            ratio: u64::from(limits.max_compression_ratio),
            used: 0,
        }
    }

    /// Decoded bytes charged so far.
    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn remaining(&self) -> u64 {
        self.total.saturating_sub(self.used)
    }

    /// The tightest cap for output decoded from `raw_len` input bytes.
    pub fn cap_for(&self, raw_len: u64) -> Cap {
        let ratio_cap = raw_len.saturating_mul(self.ratio).max(RATIO_MIN_OUTPUT);
        let mut cap = Cap {
            bytes: self.per_stream,
            code: IssueCode::LimitStreamDecodedBytes,
        };
        if self.remaining() < cap.bytes {
            cap = Cap {
                bytes: self.remaining(),
                code: IssueCode::LimitDecodedBytes,
            };
        }
        if ratio_cap < cap.bytes {
            cap = Cap {
                bytes: ratio_cap,
                code: IssueCode::LimitCompressionRatio,
            };
        }
        cap
    }

    /// Records `n` decoded bytes.
    pub fn charge(&mut self, n: u64) {
        self.used = self.used.saturating_add(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_thresholds() {
        let t = Thresholds::default();
        assert_eq!(t.max_image_pixels, 1_000_000_000);
        assert_eq!(t.max_page_side_pt, 28_800.0);
        assert_eq!(t.max_pages, 10_000);
        assert_eq!(t.max_filter_chain, 2);
        assert_eq!(t.max_trailing_bytes, 1024);
    }

    #[test]
    fn default_depth() {
        assert_eq!(Limits::default().nesting_depth(), 128);
    }

    #[test]
    fn depth_is_clamped_to_hard_max() {
        let l = Limits {
            max_nesting_depth: u32::MAX,
            ..Limits::default()
        };
        assert_eq!(l.nesting_depth(), HARD_MAX_NESTING_DEPTH as usize);
        let l = Limits {
            max_nesting_depth: 3,
            ..Limits::default()
        };
        assert_eq!(l.nesting_depth(), 3);
    }

    fn budget(per_stream: u64, total: u64, ratio: u32) -> Budget {
        Budget::new(&Limits {
            max_decoded_bytes_per_stream: per_stream,
            max_decoded_bytes_total: total,
            max_compression_ratio: ratio,
            ..Limits::default()
        })
    }

    #[test]
    fn cap_picks_tightest_limit() {
        let mb = 1 << 20;
        let b = budget(100 * mb, 1000 * mb, 10);
        // Ratio: 20 MiB raw × 10 = 200 MiB > per-stream.
        assert_eq!(
            b.cap_for(20 * mb),
            Cap {
                bytes: 100 * mb,
                code: IssueCode::LimitStreamDecodedBytes
            }
        );
        // Ratio: 2 MiB raw × 10 = 20 MiB.
        assert_eq!(
            b.cap_for(2 * mb),
            Cap {
                bytes: 20 * mb,
                code: IssueCode::LimitCompressionRatio
            }
        );
        // Ratio floor: tiny input may still decode to RATIO_MIN_OUTPUT.
        assert_eq!(b.cap_for(1).bytes, RATIO_MIN_OUTPUT);
        assert_eq!(b.cap_for(0).bytes, RATIO_MIN_OUTPUT);
    }

    #[test]
    fn cap_shrinks_with_total_budget() {
        let mb = 1 << 20;
        let mut b = budget(100 * mb, 150 * mb, 1000);
        assert_eq!(b.cap_for(mb).code, IssueCode::LimitStreamDecodedBytes);
        b.charge(120 * mb);
        assert_eq!(b.used(), 120 * mb);
        assert_eq!(b.remaining(), 30 * mb);
        assert_eq!(
            b.cap_for(mb),
            Cap {
                bytes: 30 * mb,
                code: IssueCode::LimitDecodedBytes
            }
        );
        b.charge(u64::MAX);
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn huge_ratio_does_not_overflow() {
        let b = budget(u64::MAX, u64::MAX, u32::MAX);
        assert_eq!(b.cap_for(u64::MAX).bytes, u64::MAX);
    }
}
