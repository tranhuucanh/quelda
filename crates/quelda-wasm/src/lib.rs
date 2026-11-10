//! WebAssembly binding for quelda (design §8.2). A thin wrapper: every export
//! forwards to `quelda_core`; no logic lives here.
//!
//! JS API (wasm-bindgen, `--target web`):
//! - `scan(bytes: Uint8Array, policy_json: string): string` — verdict JSON
//!   (`schemas/verdict.schema.json`). A malformed policy gives an `ERROR`
//!   verdict, never an exception.
//! - `list_rules(): string` — JSON array of rule metadata.
//! - `version(): string` — engine version.
//!
//! `stats.duration_ms` is always 0 here (wasm32-unknown-unknown has no clock
//! in std); the JS side measures wall time (`performance.now`).

use wasm_bindgen::prelude::wasm_bindgen;

/// Scans one PDF under a JSON policy; returns the verdict as JSON.
#[wasm_bindgen]
pub fn scan(bytes: &[u8], policy_json: &str) -> String {
    quelda_core::scan_json(bytes, policy_json)
}

/// Every rule the engine knows, sorted by ID, as a JSON array.
#[wasm_bindgen]
pub fn list_rules() -> String {
    quelda_core::list_rules_json()
}

/// Engine version.
#[wasm_bindgen]
pub fn version() -> String {
    quelda_core::version().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_core() {
        assert_eq!(version(), quelda_core::VERSION);
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn scan_forwards_to_scan_json() {
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n";
        for policy in ["{}", r#"{"preset":"strict"}"#, "not json", "[]"] {
            assert_eq!(scan(pdf, policy), quelda_core::scan_json(pdf, policy));
        }
        let v: serde_json::Value = serde_json::from_str(&scan(pdf, "not json")).unwrap();
        assert_eq!(v["status"], "ERROR");
        assert_eq!(v["errors"][0]["code"], "POLICY.INVALID");
        let v: serde_json::Value = serde_json::from_str(&scan(b"", "{}")).unwrap();
        assert_eq!(v["valid"], false);
    }

    #[test]
    fn list_rules_forwards_to_core() {
        assert_eq!(list_rules(), quelda_core::list_rules_json());
        let v: serde_json::Value = serde_json::from_str(&list_rules()).unwrap();
        assert_eq!(
            v.as_array().map(Vec::len),
            Some(quelda_core::list_rules().len())
        );
    }
}
