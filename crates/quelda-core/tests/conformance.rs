//! Conformance runner for the Rust lib (design §9.3): `tests/conformance/*.json`
//! and every fixture of `tests/fixtures/manifest.json` × preset, through the
//! public JSON API (`scan_json`), as a binding would call it.
//!
//! Expectations are written for the whole v0.1 rule set (design §5.7), and
//! the engine registers all of it: every case runs, none is skipped, and the
//! expected rule lists are compared as they are.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use quelda_core::{list_rules, scan_json};
use serde_json::Value;

fn tests_dir(sub: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests")
        .join(sub);
    assert!(
        dir.is_dir(),
        "{} not found: run `cargo run -p quelda-testkit --bin gen-fixtures` first",
        dir.display()
    );
    dir
}

/// The registry is exactly the rule set the expectations are written for.
#[test]
fn registry_is_the_whole_rule_set() {
    let registered: BTreeSet<&str> = list_rules().iter().map(|r| r.id).collect();
    let spec: BTreeSet<&str> = quelda_testkit::rules::RULES.iter().map(|r| r.id).collect();
    assert_eq!(registered, spec);
    assert_eq!(registered.len(), 56);
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| {
                    x.get("rule_id")
                        .unwrap_or(x)
                        .as_str()
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn error_codes(verdict: &Value) -> Vec<String> {
    verdict["errors"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| e["code"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Compares one verdict with an expectation; returns problems.
fn check(
    what: &str,
    verdict: &Value,
    status: &str,
    error: Option<&str>,
    violations: &[String],
    warnings: &[String],
    exact: bool,
) -> Vec<String> {
    let mut p = Vec::new();
    let codes = error_codes(verdict);
    if verdict["valid"].as_bool() != Some(verdict["status"] == "PASS") {
        p.push(format!("{what}: valid does not match status"));
    }
    if let Some(prefix) = error {
        if verdict["status"] != "ERROR" || !codes.iter().any(|c| c.starts_with(prefix)) {
            p.push(format!(
                "{what}: want ERROR {prefix}, got {} {codes:?}",
                verdict["status"]
            ));
        }
        return p;
    }
    if !codes.is_empty() {
        p.push(format!("{what}: unexpected errors {codes:?}"));
        return p;
    }
    let status = if status == "ERROR" {
        status
    } else if violations.is_empty() {
        "PASS"
    } else {
        "REJECT"
    };
    if verdict["status"] != status {
        p.push(format!("{what}: want {status}, got {}", verdict["status"]));
    }
    for (key, want) in [("violations", violations), ("warnings", warnings)] {
        let got = ids(&verdict[key]);
        let ok = if exact {
            got == want
        } else {
            want.iter().all(|w| got.contains(w))
        };
        if !ok {
            p.push(format!("{what}: {key} want {want:?}, got {got:?}"));
        }
    }
    p
}

#[test]
fn conformance_cases() {
    let dir = tests_dir("conformance");
    let fixtures = tests_dir("fixtures");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    assert!(files.len() >= 20, "only {} cases", files.len());
    let mut problems = Vec::new();
    let mut ran = 0;
    for path in &files {
        let case: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap_or("?");
        let policy = match case.get("policy_raw") {
            Some(raw) => raw.as_str().unwrap_or_default().to_string(),
            None => case["policy"].to_string(),
        };
        let input = fs::read(fixtures.join(case["file"].as_str().unwrap()))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let verdict: Value = serde_json::from_str(&scan_json(&input, &policy)).unwrap();
        let exp = &case["expected"];
        problems.extend(check(
            name,
            &verdict,
            exp["status"].as_str().unwrap_or_default(),
            exp["error"].as_str(),
            &ids(&exp["violations"]),
            &ids(&exp["warnings"]),
            true,
        ));
        ran += 1;
    }
    // No skip mechanism: every case file ran.
    assert_eq!(ran, files.len());
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn manifest_every_fixture_every_preset() {
    let dir = tests_dir("fixtures");
    let manifest: Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let mut problems = Vec::new();
    let mut n = 0;
    for (path, f) in manifest["files"].as_object().unwrap() {
        let input = fs::read(dir.join(path)).unwrap();
        let exact = f["match"] == "exact";
        for preset in ["strict", "balanced", "permissive"] {
            let policy = format!(r#"{{"preset":"{preset}"}}"#);
            let verdict: Value = serde_json::from_str(&scan_json(&input, &policy)).unwrap();
            let exp = &f["expected"][preset];
            problems.extend(check(
                &format!("{path} [{preset}]"),
                &verdict,
                exp["status"].as_str().unwrap_or_default(),
                f["engine_error"].as_str(),
                &ids(&exp["violations"]),
                &ids(&exp["warnings"]),
                exact,
            ));
            n += 1;
        }
    }
    assert!(n >= 3 * 250, "{n}");
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
