//! Dev-only test kit: `PdfBuilder` and the fixture generator.
//! Payloads are always harmless; never put a real exploit here.

pub mod builder;
pub mod conformance;
pub mod filters;
pub mod fixtures;
pub mod manifest;
pub mod names;
pub mod rules;

pub use builder::{PdfBuilder, Xref};
pub use filters::Filter;

/// Returns the testkit version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_package_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
