//! quelda scan engine: one PDF + policy in, verdict out.
//!
//! Layers (design §4): parser → facts → rules → policy. So far: the lexer,
//! object model and union object set (`parser`, `parser::Document`), stream
//! decoding (`filters`), the facts layer rules read (`facts::Ctx`), the rule
//! framework and registry (`rules`), engine issues, limits and thresholds.

#![forbid(unsafe_code)]
// Input must never be able to crash the engine (design: fail-closed, no panics).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod error;
pub mod facts;
pub mod filters;
pub mod limits;
pub mod parser;
pub mod rules;

/// Engine version, reported in every verdict as `engine_version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the engine version.
pub fn version() -> &'static str {
    VERSION
}

/// Every rule the engine knows, sorted by ID (for settings screens).
pub fn list_rules() -> Vec<rules::RuleInfo> {
    rules::registry::list()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_package_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }

    #[test]
    fn list_rules_is_the_registry() {
        let ids: Vec<_> = list_rules().iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), rules::registry::all().len());
        assert!(ids.contains(&"ACTIVE.LAUNCH"));
    }
}
