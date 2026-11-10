//! Writes `tests/wasm/golden.json`: native (Rust lib) verdicts that the WASM
//! build must reproduce exactly, `stats.duration_ms` aside (plan Step 11).
//!
//! Cases: every fixture of `tests/fixtures/manifest.json` × {`{}`, strict,
//! balanced, permissive} + every `tests/conformance/*.json` case, plus
//! `list_rules()` and `version()`. Read by `tests/node.rs` (wasm-bindgen-test)
//! and `scripts/wasm-smoke.mjs` (the built npm artifact).
//!
//! Run after gen-fixtures: `cargo run -p quelda-wasm --example wasm_golden`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};

const PRESET_POLICIES: [&str; 4] = [
    "{}",
    r#"{"preset":"strict"}"#,
    r#"{"preset":"balanced"}"#,
    r#"{"preset":"permissive"}"#,
];

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests")
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// (fixture path relative to `tests/fixtures`, policy JSON) pairs.
fn cases(tests: &Path) -> Result<Vec<(String, String)>, String> {
    let manifest = read_json(&tests.join("fixtures/manifest.json"))?;
    let files = manifest["files"]
        .as_object()
        .ok_or("manifest.json: no `files` object")?;
    let mut out = Vec::new();
    for file in files.keys() {
        for p in PRESET_POLICIES {
            out.push((file.clone(), p.to_string()));
        }
    }
    let mut conf: Vec<PathBuf> = fs::read_dir(tests.join("conformance"))
        .map_err(|e| format!("tests/conformance: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    conf.sort();
    for path in conf {
        let case = read_json(&path)?;
        let file = case["file"]
            .as_str()
            .ok_or_else(|| format!("{}: no `file`", path.display()))?;
        let policy = match (&case["policy"], &case["policy_raw"]) {
            (Value::Null, Value::String(raw)) => raw.clone(),
            (p, Value::Null) if !p.is_null() => p.to_string(),
            _ => return Err(format!("{}: need `policy` or `policy_raw`", path.display())),
        };
        out.push((file.to_string(), policy));
    }
    Ok(out)
}

fn run() -> Result<String, String> {
    let tests = tests_dir();
    if !tests.join("fixtures/manifest.json").is_file() {
        return Err(
            "tests/fixtures not found: run `cargo run -p quelda-testkit --bin gen-fixtures` first"
                .into(),
        );
    }
    let mut out = Vec::new();
    for (file, policy) in cases(&tests)? {
        let path = tests.join("fixtures").join(&file);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let verdict = quelda_core::scan_json(&bytes, &policy);
        out.push(json!({ "file": file, "policy": policy, "verdict": verdict }));
    }
    let golden = json!({
        "version": quelda_core::version(),
        "list_rules": quelda_core::list_rules_json(),
        "cases": out,
    });
    let dir = tests.join("wasm");
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join("golden.json");
    fs::write(&path, golden.to_string()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!("wrote {} cases to {}", out.len(), path.display()))
}

fn main() -> ExitCode {
    match run() {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("wasm_golden: {e}");
            ExitCode::FAILURE
        }
    }
}
