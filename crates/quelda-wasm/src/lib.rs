//! WebAssembly binding for quelda (design §8.2). A thin wrapper: every export
//! forwards to `quelda_core`; no logic lives here.
//!
//! JS API (wasm-bindgen, `--target web`):
//! - `scan(bytes: Uint8Array, policy_json: string): string` — verdict JSON
//!   (`schemas/verdict.schema.json`). A malformed policy gives an `ERROR`
//!   verdict, never an exception.
//! - `scan_source(reader, policy_json: string): string` — the same, reading
//!   the file on demand (plan Step 16 Phase B): `reader` is
//!   `{ size: number, readInto(offset: number, into: Uint8Array): void }`,
//!   which must fill `into` with the bytes at `offset` synchronously (e.g.
//!   `FileReaderSync` over `blob.slice`) or throw. Only the regions the
//!   engine needs are read, a block at a time; a throw or a bad `size`
//!   makes the verdict `ERROR` (`ENGINE.READ`).
//! - `list_rules(): string` — JSON array of rule metadata.
//! - `version(): string` — engine version.
//!
//! `stats.duration_ms` is always 0 here (wasm32-unknown-unknown has no clock
//! in std); the JS side measures wall time (`performance.now`).

use quelda_core::{ReadError, Source};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    /// `{ size, readInto(offset, into) }` (see the module docs).
    pub type Reader;

    #[wasm_bindgen(method, getter)]
    fn size(this: &Reader) -> JsValue;

    #[wasm_bindgen(method, catch, js_name = readInto)]
    fn read_into(this: &Reader, offset: f64, into: &mut [u8]) -> Result<(), JsValue>;
}

/// A [`Reader`] as a [`Source`].
struct JsSource<'r> {
    reader: &'r Reader,
    len: u64,
}

impl Source for JsSource<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        // Offsets are below `size`, an exact JS number (≤ 2^53).
        self.reader
            .read_into(offset as f64, buf)
            .map_err(|e| ReadError(e.as_string().unwrap_or_else(|| format!("{e:?}"))))
    }
}

/// `size` as a byte count (a non-negative integer JS number).
fn source_len(size: &JsValue) -> Option<u64> {
    let n = size.as_f64()?;
    (n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= 9_007_199_254_740_992.0)
        .then_some(n as u64)
}

/// Scans one PDF read through `reader` on demand; returns the verdict as JSON.
#[wasm_bindgen]
pub fn scan_source(reader: &Reader, policy_json: &str) -> String {
    let Some(len) = source_len(&reader.size()) else {
        return quelda_core::read_error_json("reader size is not a byte count", policy_json);
    };
    quelda_core::scan_source_json(&JsSource { reader, len }, policy_json)
}

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

    /// Parses a verdict and drops `stats.duration_ms` (wall time differs between runs).
    fn without_duration(verdict: &str) -> serde_json::Value {
        let mut v: serde_json::Value = serde_json::from_str(verdict).unwrap();
        if let Some(stats) = v.get_mut("stats").and_then(|s| s.as_object_mut()) {
            stats.remove("duration_ms");
        }
        v
    }

    #[test]
    fn scan_forwards_to_scan_json() {
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n";
        for policy in ["{}", r#"{"preset":"strict"}"#, "not json", "[]"] {
            assert_eq!(
                without_duration(&scan(pdf, policy)),
                without_duration(&quelda_core::scan_json(pdf, policy))
            );
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
