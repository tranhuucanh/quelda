//! Conformance cases (design §9.3): `tests/conformance/<name>.json` =
//! `{ file, policy, expected }`, run against every binding (Rust lib now;
//! WASM and CLI later) so they all give the same verdict.
//!
//! `expected` is the verdict with the **whole** v0.1 rule set (design §5.7).
//! A runner for an engine that has only some rules keeps the expected rule
//! IDs it has registered and recomputes `PASS`/`REJECT` from those. `ERROR`
//! cases list the error code prefix and do not check rule IDs (what fires
//! after an engine issue is not specified).

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// One case.
#[derive(Clone, Debug)]
pub struct Case {
    pub name: &'static str,
    pub description: &'static str,
    /// Path under `tests/fixtures/`.
    pub file: &'static str,
    /// Raw JSON (may be invalid on purpose).
    pub policy: &'static str,
    pub status: &'static str,
    pub violations: &'static [&'static str],
    pub warnings: &'static [&'static str],
    /// Prefix of an expected error code (`ERROR` cases).
    pub error: Option<&'static str>,
}

const fn case(
    name: &'static str,
    description: &'static str,
    file: &'static str,
    policy: &'static str,
    status: &'static str,
    violations: &'static [&'static str],
    warnings: &'static [&'static str],
) -> Case {
    Case {
        name,
        description,
        file,
        policy,
        status,
        violations,
        warnings,
        error: None,
    }
}

const fn error(
    name: &'static str,
    description: &'static str,
    file: &'static str,
    policy: &'static str,
    error: &'static str,
) -> Case {
    Case {
        name,
        description,
        file,
        policy,
        status: "ERROR",
        violations: &[],
        warnings: &[],
        error: Some(error),
    }
}

const LAUNCH: &str = "rules/ACTIVE.LAUNCH/bad/plain.pdf";
const URI: &str = "benign/link-uri.pdf";
const MINIMAL: &str = "benign/minimal.pdf";
const L: &[&str] = &["ACTIVE.LAUNCH"];
const U: &[&str] = &["EXTERNAL.URI"];

/// The cases. Files are `exact` fixtures (their `fires` is complete), so
/// the expected rule lists are complete too.
pub const CASES: &[Case] = &[
    case(
        "minimal-default",
        "{} is balanced",
        MINIMAL,
        "{}",
        "PASS",
        &[],
        &[],
    ),
    case(
        "minimal-strict",
        "clean file passes strict",
        MINIMAL,
        r#"{"preset":"strict"}"#,
        "PASS",
        &[],
        &[],
    ),
    case(
        "launch-default",
        "locked rule blocks",
        LAUNCH,
        "{}",
        "REJECT",
        L,
        &[],
    ),
    case(
        "launch-rule-off",
        "a rule override cannot lower a locked rule",
        LAUNCH,
        r#"{"rules":{"ACTIVE.LAUNCH":"off"}}"#,
        "REJECT",
        L,
        &[],
    ),
    case(
        "launch-permissive-category-off",
        "neither can preset nor category",
        LAUNCH,
        r#"{"preset":"permissive","categories":{"active_content":"off"}}"#,
        "REJECT",
        L,
        &[],
    ),
    case(
        "launch-unlocked-off",
        "unsafe_allow_unlock lets the policy turn it off",
        LAUNCH,
        r#"{"rules":{"ACTIVE.LAUNCH":"off"},"unsafe_allow_unlock":true}"#,
        "PASS",
        &[],
        &[],
    ),
    case(
        "launch-unlocked-warn",
        "unlocked rule override to warn",
        LAUNCH,
        r#"{"rules":{"ACTIVE.LAUNCH":"warn"},"unsafe_allow_unlock":true}"#,
        "PASS",
        &[],
        L,
    ),
    case(
        "launch-unlocked-permissive",
        "unlocked: permissive preset warns on active content",
        LAUNCH,
        r#"{"preset":"permissive","unsafe_allow_unlock":true}"#,
        "PASS",
        &[],
        L,
    ),
    case(
        "launch-unlocked-category-off-rule-block",
        "rule override beats category override",
        LAUNCH,
        r#"{"categories":{"active_content":"off"},"rules":{"ACTIVE.LAUNCH":"block"},"unsafe_allow_unlock":true}"#,
        "REJECT",
        L,
        &[],
    ),
    case(
        "uri-balanced",
        "URI warns in balanced",
        URI,
        "{}",
        "PASS",
        &[],
        U,
    ),
    case(
        "uri-strict",
        "URI blocks in strict",
        URI,
        r#"{"preset":"strict"}"#,
        "REJECT",
        U,
        &[],
    ),
    case(
        "uri-permissive",
        "URI is off in permissive",
        URI,
        r#"{"preset":"permissive"}"#,
        "PASS",
        &[],
        &[],
    ),
    case(
        "uri-strict-category-warn",
        "category override beats preset",
        URI,
        r#"{"preset":"strict","categories":{"external":"warn"}}"#,
        "PASS",
        &[],
        U,
    ),
    case(
        "uri-rule-block",
        "rule override beats preset",
        URI,
        r#"{"rules":{"EXTERNAL.URI":"block"}}"#,
        "REJECT",
        U,
        &[],
    ),
    // Thresholds (design §4.5): the policy moves what RESOURCE.* and
    // STRUCT.FILTER_CHAIN / STRUCT.TRAILING_DATA detect.
    case(
        "a0-image-strict",
        "A0 page with an A0 @300dpi image passes strict (under every default threshold)",
        "benign/a0-large-image.pdf",
        r#"{"preset":"strict"}"#,
        "PASS",
        &[],
        &[],
    ),
    case(
        "image-threshold-raised",
        "1e10 px image passes once max_image_pixels allows it",
        "rules/RESOURCE.IMAGE_DIMENSIONS/bad/plain.pdf",
        r#"{"thresholds":{"max_image_pixels":10000000000}}"#,
        "PASS",
        &[],
        &[],
    ),
    case(
        "image-threshold-lowered",
        "a small image is rejected once max_image_pixels is below its size",
        "benign/image-rgb-flate.pdf",
        r#"{"thresholds":{"max_image_pixels":255}}"#,
        "REJECT",
        &["RESOURCE.IMAGE_DIMENSIONS"],
        &[],
    ),
    case(
        "page-size-threshold-lowered",
        "A4 is rejected once max_page_side_pt is below 842",
        MINIMAL,
        r#"{"thresholds":{"max_page_side_pt":800}}"#,
        "REJECT",
        &["RESOURCE.PAGE_SIZE"],
        &[],
    ),
    case(
        "page-size-threshold-raised",
        "a 100000 pt page passes once max_page_side_pt allows it",
        "rules/RESOURCE.PAGE_SIZE/bad/plain.pdf",
        r#"{"thresholds":{"max_page_side_pt":100000}}"#,
        "PASS",
        &[],
        &[],
    ),
    case(
        "page-count-threshold-lowered",
        "three pages are rejected once max_pages is 2",
        "benign/multipage-text.pdf",
        r#"{"thresholds":{"max_pages":2}}"#,
        "REJECT",
        &["RESOURCE.PAGE_COUNT"],
        &[],
    ),
    case(
        "filter-chain-threshold-raised",
        "three filters pass strict once max_filter_chain is 3",
        "rules/STRUCT.FILTER_CHAIN/bad/three-filters.pdf",
        r#"{"preset":"strict","thresholds":{"max_filter_chain":3}}"#,
        "PASS",
        &[],
        &[],
    ),
    case(
        "filter-chain-threshold-lowered",
        "the common two-filter chain warns (balanced) once max_filter_chain is 1",
        "benign/content-two-filters.pdf",
        r#"{"thresholds":{"max_filter_chain":1}}"#,
        "PASS",
        &[],
        &["STRUCT.FILTER_CHAIN"],
    ),
    case(
        "trailing-threshold-lowered",
        "512 NUL bytes after %%EOF are rejected in strict once max_trailing_bytes is 100",
        "rules/STRUCT.TRAILING_DATA/good/zero-padding-512.pdf",
        r#"{"preset":"strict","thresholds":{"max_trailing_bytes":100}}"#,
        "REJECT",
        &["STRUCT.TRAILING_DATA"],
        &[],
    ),
    case(
        "incremental-strict",
        "preset rule override: incremental update warns in strict",
        "benign/incremental-update.pdf",
        r#"{"preset":"strict"}"#,
        "PASS",
        &[],
        &["STRUCT.INCREMENTAL_UPDATE"],
    ),
    case(
        "incremental-balanced",
        "and is off in balanced",
        "benign/incremental-update.pdf",
        "{}",
        "PASS",
        &[],
        &[],
    ),
    case(
        "junk-header-filetype-off",
        "locked filetype rule",
        "rules/FILETYPE.NOT_PDF_HEADER/bad/junk-before-header.pdf",
        r#"{"categories":{"filetype":"off"}}"#,
        "REJECT",
        &["FILETYPE.NOT_PDF_HEADER"],
        &[],
    ),
    case(
        "javascript-permissive",
        "permissive only warns on JavaScript",
        "rules/ACTIVE.JAVASCRIPT/bad/plain.pdf",
        r#"{"preset":"permissive"}"#,
        "PASS",
        &[],
        &["ACTIVE.JAVASCRIPT"],
    ),
    case(
        "javascript-rule-off",
        "an unlocked rule can be turned off",
        "rules/ACTIVE.JAVASCRIPT/bad/plain.pdf",
        r#"{"rules":{"ACTIVE.JAVASCRIPT":"off"}}"#,
        "PASS",
        &[],
        &[],
    ),
    case(
        "other-actions-balanced",
        "per-rule preset value: other actions warn in balanced",
        "rules/ACTIVE.OTHER_ACTIONS/bad/plain.pdf",
        "{}",
        "PASS",
        &[],
        &["ACTIVE.OTHER_ACTIONS"],
    ),
    case(
        "other-actions-strict",
        "and block in strict",
        "rules/ACTIVE.OTHER_ACTIONS/bad/plain.pdf",
        r#"{"preset":"strict"}"#,
        "REJECT",
        &["ACTIVE.OTHER_ACTIONS"],
        &[],
    ),
    case(
        "postscript-xobject-category-off",
        "locked PostScript rule ignores a category override",
        "rules/POSTSCRIPT.XOBJECT/bad/plain.pdf",
        r#"{"preset":"permissive","categories":{"postscript":"off"}}"#,
        "REJECT",
        &["POSTSCRIPT.XOBJECT"],
        &[],
    ),
    case(
        "type4-category-warn",
        "unlocked PostScript rule follows a category override",
        "rules/POSTSCRIPT.TYPE4_FUNCTION/bad/plain.pdf",
        r#"{"categories":{"postscript":"warn"}}"#,
        "PASS",
        &[],
        &["POSTSCRIPT.TYPE4_FUNCTION"],
    ),
    case(
        "encrypted-default",
        "encrypted files are rejected by default",
        "rules/CRYPT.ENCRYPTED/bad/plain.pdf",
        "{}",
        "REJECT",
        &["CRYPT.ENCRYPTED"],
        &[],
    ),
    case(
        "encrypted-category-warn",
        "encryption can be downgraded to a warning",
        "rules/CRYPT.ENCRYPTED/bad/plain.pdf",
        r#"{"categories":{"encryption":"warn"}}"#,
        "PASS",
        &[],
        &["CRYPT.ENCRYPTED"],
    ),
    error(
        "bomb-strict",
        "decompression bomb is an engine error",
        "malformed/flate-bomb.pdf",
        r#"{"preset":"strict"}"#,
        "LIMIT",
    ),
    error(
        "bomb-permissive",
        "in every preset",
        "malformed/flate-bomb.pdf",
        r#"{"preset":"permissive","categories":{"structure":"off"}}"#,
        "LIMIT",
    ),
    error(
        "file-too-large",
        "max_file_bytes",
        MINIMAL,
        r#"{"limits":{"max_file_bytes":100}}"#,
        "LIMIT.FILE_BYTES",
    ),
    error(
        "policy-unknown-preset",
        "invalid policy value",
        MINIMAL,
        r#"{"preset":"paranoid"}"#,
        "POLICY.INVALID",
    ),
    error(
        "policy-unknown-field",
        "unknown policy field",
        MINIMAL,
        r#"{"rule":{"ACTIVE.LAUNCH":"off"}}"#,
        "POLICY.INVALID",
    ),
    error(
        "policy-unknown-rule",
        "unknown rule ID",
        MINIMAL,
        r#"{"rules":{"ACTIVE.LAUNCHH":"off"}}"#,
        "POLICY.INVALID",
    ),
    error(
        "policy-not-json",
        "policy is not JSON",
        MINIMAL,
        "{preset: strict}",
        "POLICY.INVALID",
    ),
];

/// A case as JSON. A policy that is not valid JSON is kept as a string
/// (`policy_raw`); otherwise `policy` is the parsed object.
pub fn case_json(c: &Case) -> Value {
    let mut expected = json!({ "status": c.status });
    match c.error {
        Some(e) => expected["error"] = json!(e),
        None => {
            expected["violations"] = json!(c.violations);
            expected["warnings"] = json!(c.warnings);
        }
    }
    let mut v = json!({
        "name": c.name,
        "description": c.description,
        "file": c.file,
        "expected": expected,
    });
    match serde_json::from_str::<Value>(c.policy) {
        Ok(p) => v["policy"] = p,
        Err(_) => v["policy_raw"] = json!(c.policy),
    }
    v
}

/// `name.json` → pretty JSON, for every case.
pub fn files() -> BTreeMap<String, Vec<u8>> {
    CASES
        .iter()
        .map(|c| {
            let mut s = serde_json::to_string_pretty(&case_json(c)).unwrap_or_default();
            s.push('\n');
            (format!("{}.json", c.name), s.into_bytes())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use crate::rules::{self, Preset};

    #[test]
    fn names_unique_and_files_exist() {
        let all = fixtures::all();
        let mut names: Vec<_> = CASES.iter().map(|c| c.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CASES.len());
        for c in CASES {
            let f = all
                .iter()
                .find(|f| f.path == c.file)
                .unwrap_or_else(|| panic!("{}: no fixture {}", c.name, c.file));
            if c.error.is_none() {
                assert!(f.exact, "{}: {} is not exact", c.name, c.file);
                assert!(f.engine_error.is_none(), "{}", c.name);
            }
            // `fires` is computed with the default thresholds.
            let default_thresholds = !c.policy.contains("\"thresholds\"");
            for id in c.violations.iter().chain(c.warnings) {
                assert!(rules::rule(id).is_some(), "{}: {id}", c.name);
                if default_thresholds {
                    assert!(f.fires.contains(id), "{}: {id} does not fire", c.name);
                }
            }
            let status_ok = match c.status {
                "PASS" => c.violations.is_empty(),
                "REJECT" => !c.violations.is_empty(),
                "ERROR" => c.error.is_some(),
                _ => false,
            };
            assert!(status_ok, "{}", c.name);
        }
    }

    /// Cases whose policy is only a preset agree with the manifest.
    #[test]
    fn preset_only_cases_match_manifest() {
        let all = fixtures::all();
        let mut checked = 0;
        for c in CASES.iter().filter(|c| c.error.is_none()) {
            let p: Value = serde_json::from_str(c.policy).unwrap();
            let obj = p.as_object().unwrap();
            if obj.keys().any(|k| k != "preset") {
                continue;
            }
            let preset = Preset::ALL
                .into_iter()
                .find(|x| p["preset"].as_str().unwrap_or("balanced") == x.key())
                .unwrap();
            let f = all.iter().find(|f| f.path == c.file).unwrap();
            let e = rules::expected(&f.fires, false, preset);
            assert_eq!(e.status, c.status, "{}", c.name);
            assert_eq!(e.violations, c.violations, "{}", c.name);
            assert_eq!(e.warnings, c.warnings, "{}", c.name);
            checked += 1;
        }
        assert!(checked >= 8, "{checked}");
    }

    #[test]
    fn json_shape() {
        let files = files();
        assert_eq!(files.len(), CASES.len());
        let v: Value = serde_json::from_slice(&files["uri-balanced.json"]).unwrap();
        assert_eq!(v["file"], URI);
        assert_eq!(v["policy"], json!({}));
        assert_eq!(v["expected"]["warnings"], json!(["EXTERNAL.URI"]));
        let v: Value = serde_json::from_slice(&files["policy-not-json.json"]).unwrap();
        assert_eq!(v["policy_raw"], "{preset: strict}");
        assert!(v.get("policy").is_none());
        assert_eq!(v["expected"]["error"], "POLICY.INVALID");
        assert!(v["expected"].get("violations").is_none());
    }
}
