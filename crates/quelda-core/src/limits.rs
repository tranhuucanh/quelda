//! Engine limits (design §4.5): guardrails, not rules. Exceeding one is an
//! engine issue (`LIMIT.*` → `ERROR`). Only the limits the engine enforces so
//! far are here; decode budgets arrive with stream decoding (Step 4).

/// Absolute ceiling for nesting depth, whatever the policy says. Parsed
/// objects are dropped, compared and visited recursively; this keeps those
/// recursions far below the smallest stack we run on (1 MiB on wasm32).
pub const HARD_MAX_NESTING_DEPTH: u32 = 512;

/// Default for [`Limits::max_nesting_depth`]. Real files nest direct objects a
/// handful of levels deep (deeper structures use indirect references).
pub const DEFAULT_MAX_NESTING_DEPTH: u32 = 128;

/// Limits configured by policy (`limits` object).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of arrays/dictionaries open at once while parsing one
    /// object. Clamped to [`HARD_MAX_NESTING_DEPTH`].
    pub max_nesting_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
        }
    }
}

impl Limits {
    /// Nesting depth actually enforced.
    pub fn nesting_depth(&self) -> usize {
        self.max_nesting_depth.min(HARD_MAX_NESTING_DEPTH) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_depth() {
        assert_eq!(Limits::default().nesting_depth(), 128);
    }

    #[test]
    fn depth_is_clamped_to_hard_max() {
        let l = Limits {
            max_nesting_depth: u32::MAX,
        };
        assert_eq!(l.nesting_depth(), HARD_MAX_NESTING_DEPTH as usize);
        let l = Limits {
            max_nesting_depth: 3,
        };
        assert_eq!(l.nesting_depth(), 3);
    }
}
