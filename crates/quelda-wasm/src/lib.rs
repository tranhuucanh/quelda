//! WebAssembly binding for quelda. Thin wrapper around `quelda_core::scan_json`;
//! no logic lives here. The wasm-bindgen exports arrive in Step 11.

/// Returns the engine version.
pub fn version() -> &'static str {
    quelda_core::version()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_core() {
        assert_eq!(version(), quelda_core::VERSION);
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
