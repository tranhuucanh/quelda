//! quelda scan engine: one PDF + policy in, verdict out.
//!
//! Layers (design §4): parser → facts → rules → policy. Only the public API
//! skeleton exists so far; see the implementation plan for what comes next.

#![forbid(unsafe_code)]
// Input must never be able to crash the engine (design: fail-closed, no panics).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Engine version, reported in every verdict as `engine_version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the engine version.
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_package_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }
}
