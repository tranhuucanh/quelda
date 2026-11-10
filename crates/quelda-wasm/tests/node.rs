//! wasm-bindgen-test on Node (plan Step 11): the wasm32 build gives the same
//! verdicts as the native Rust lib (`stats.duration_ms` aside).
//!
//! Needs `tests/wasm/golden.json` from the native lib:
//!   cargo run -p quelda-testkit --bin gen-fixtures
//!   cargo run -p quelda-wasm --example wasm_golden
//! Run: `wasm-pack test --node crates/quelda-wasm` or
//!   CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!     cargo test -p quelda-wasm --target wasm32-unknown-unknown
//! (scripts/wasm-test.sh does all of it.)
#![cfg(target_arch = "wasm32")]

use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen(module = "node:fs")]
extern "C" {
    #[wasm_bindgen(js_name = readFileSync, catch)]
    fn read_file_sync(path: &str) -> Result<Vec<u8>, JsValue>;
}

const TESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/");

fn read(rel: &str) -> Vec<u8> {
    read_file_sync(&format!("{TESTS}{rel}")).unwrap_or_else(|e| {
        panic!(
            "cannot read tests/{rel} ({e:?}): run `cargo run -p quelda-testkit --bin gen-fixtures` \
             and `cargo run -p quelda-wasm --example wasm_golden` first"
        )
    })
}

fn golden() -> Value {
    serde_json::from_slice(&read("wasm/golden.json")).expect("golden.json is JSON")
}

/// Verdict JSON → value without the wall-clock field.
fn comparable(verdict: &str) -> Value {
    let mut v: Value = serde_json::from_str(verdict).expect("verdict is JSON");
    let stats = v["stats"].as_object_mut().expect("verdict has stats");
    assert!(
        stats.remove("duration_ms").is_some(),
        "stats.duration_ms missing"
    );
    v
}

#[wasm_bindgen_test]
fn verdicts_match_native_lib() {
    let golden = golden();
    let cases = golden["cases"].as_array().expect("cases");
    let mut statuses = std::collections::BTreeMap::<String, usize>::new();
    for case in cases {
        let file = case["file"].as_str().expect("file");
        let policy = case["policy"].as_str().expect("policy");
        let native = case["verdict"].as_str().expect("verdict");
        let bytes = read(&format!("fixtures/{file}"));
        let wasm = quelda_wasm::scan(&bytes, policy);
        let (w, n) = (comparable(&wasm), comparable(native));
        assert_eq!(
            w, n,
            "{file} under {policy}: wasm verdict differs from native"
        );
        *statuses
            .entry(w["status"].as_str().unwrap_or("?").to_string())
            .or_default() += 1;
    }
    // All three outcomes are exercised (fixtures × 4 policies + conformance).
    assert!(cases.len() > 1000, "only {} golden cases", cases.len());
    for s in ["PASS", "REJECT", "ERROR"] {
        assert!(
            statuses.get(s).copied().unwrap_or(0) > 0,
            "no {s} case: {statuses:?}"
        );
    }
}

#[wasm_bindgen_test]
fn list_rules_and_version_match_native_lib() {
    let golden = golden();
    assert_eq!(
        quelda_wasm::list_rules(),
        golden["list_rules"].as_str().expect("list_rules")
    );
    assert_eq!(
        quelda_wasm::version(),
        golden["version"].as_str().expect("version")
    );
}

#[wasm_bindgen_test]
fn duration_ms_is_zero_on_wasm32() {
    let v: Value = serde_json::from_str(&quelda_wasm::scan(b"%PDF-1.7\n%%EOF\n", "{}")).unwrap();
    assert_eq!(v["stats"]["duration_ms"], 0);
}

#[wasm_bindgen_test]
fn bad_policy_is_an_error_verdict_not_a_trap() {
    for policy in [
        "",
        "{",
        "[]",
        r#"{"preset":"nope"}"#,
        r#"{"rules":{"NO.SUCH":"off"}}"#,
    ] {
        let v: Value = serde_json::from_str(&quelda_wasm::scan(b"%PDF-1.7\n", policy)).unwrap();
        assert_eq!(v["status"], "ERROR", "{policy}");
        assert_eq!(v["valid"], false);
        assert_eq!(v["errors"][0]["code"], "POLICY.INVALID");
    }
}
