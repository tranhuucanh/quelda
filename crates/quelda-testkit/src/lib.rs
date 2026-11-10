//! Dev-only test kit: `PdfBuilder` and the fixture generator (Step 2).
//! Payloads are always harmless; never put a real exploit here.

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
