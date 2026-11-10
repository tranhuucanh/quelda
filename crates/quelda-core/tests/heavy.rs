//! The heavy benchmark files (plan Step 16, `quelda_testkit::heavy`), at
//! their tiny test sizes, are well-formed for the engine: every one is
//! scanned without an engine or limit error, so the bench measures real work.

use quelda_testkit::heavy;
use serde_json::Value;

#[test]
fn small_heavy_files_scan_without_errors() {
    for h in heavy::small_catalog() {
        let pdf = heavy::build(h.kind);
        let v: Value = serde_json::from_str(&quelda_core::scan_json(&pdf, "{}")).unwrap();
        assert_ne!(v["status"], "ERROR", "{}: {}", h.name, v["errors"]);
    }
}
