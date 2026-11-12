//! The whole engine, as every binding calls it: bytes + policy JSON in,
//! verdict JSON out. The verdict must be valid JSON, and an `ERROR` must
//! never be `valid`.
#![no_main]

use libfuzzer_sys::fuzz_target;

const POLICIES: [&str; 3] = [
    r#"{"preset":"strict"}"#,
    r#"{"preset":"balanced"}"#,
    r#"{"preset":"permissive"}"#,
];

fuzz_target!(|data: &[u8]| {
    let policy = POLICIES[data.len() % 3];
    let out = quelda_core::scan_json(data, policy);
    let v: serde_json::Value = serde_json::from_str(&out).expect("verdict is JSON");
    let valid = v["valid"].as_bool().expect("verdict has `valid`");
    if v["status"] == "ERROR" {
        assert!(!valid, "ERROR verdict marked valid");
    }
});
