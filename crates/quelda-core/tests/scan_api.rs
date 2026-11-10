//! Public API end to end (design §7, §8.1): `scan`, `scan_json`, and the JSON
//! schemas in `schemas/` (validated with the `jsonschema` dev-dependency).

mod common;

use std::path::Path;
use std::sync::OnceLock;

use jsonschema::Validator;
use quelda_core::verdict::Status;
use quelda_core::{Policy, scan, scan_json};
use serde_json::{Value, json};

fn schema(name: &str) -> &'static Validator {
    static POLICY: OnceLock<Validator> = OnceLock::new();
    static VERDICT: OnceLock<Validator> = OnceLock::new();
    let cell = if name == "policy" { &POLICY } else { &VERDICT };
    cell.get_or_init(|| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas")
            .join(format!("{name}.schema.json"));
        let s: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        jsonschema::draft202012::new(&s).unwrap_or_else(|e| panic!("{name} schema: {e}"))
    })
}

fn schema_errors(name: &str, v: &Value) -> Vec<String> {
    schema(name)
        .iter_errors(v)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect()
}

const PRESETS: [&str; 3] = ["strict", "balanced", "permissive"];

#[test]
fn engine_issue_is_error_in_every_preset() {
    let bomb = &common::fixture("malformed/flate-bomb.pdf").bytes;
    for preset in PRESETS {
        for extra in ["", r#","categories":{"structure":"off","codecs":"off"}"#] {
            let policy = Policy::from_json(&format!(r#"{{"preset":"{preset}"{extra}}}"#)).unwrap();
            let v = scan(bomb, &policy);
            assert_eq!(v.status, Status::Error, "{preset}{extra}");
            assert!(!v.valid);
            assert!(
                v.errors.iter().any(|e| e.code.starts_with("LIMIT.")),
                "{:?}",
                v.errors
            );
        }
    }
}

#[test]
fn real_verdicts_match_schema() {
    let policies = [
        r#"{"preset":"strict"}"#.to_string(),
        "{}".into(),
        r#"{"preset":"permissive","unsafe_allow_unlock":true,"rules":{"ACTIVE.LAUNCH":"warn"}}"#
            .into(),
        r#"{"stop_on_first":true}"#.into(),
    ];
    let mut checked = 0;
    let mut statuses = std::collections::BTreeSet::new();
    for f in common::fixtures() {
        for p in &policies {
            let v: Value = serde_json::from_str(&scan_json(&f.bytes, p)).unwrap();
            let errs = schema_errors("verdict", &v);
            assert!(errs.is_empty(), "{} {p}: {errs:?}\n{v:#}", f.path);
            statuses.insert(v["status"].as_str().unwrap().to_string());
            checked += 1;
        }
    }
    // Error verdicts made before scanning.
    for p in [
        "[]",
        r#"{"preset":"x"}"#,
        r#"{"limits":{"max_file_bytes":1}}"#,
    ] {
        let v: Value = serde_json::from_str(&scan_json(b"%PDF-1.7\n", p)).unwrap();
        let errs = schema_errors("verdict", &v);
        assert!(errs.is_empty(), "{p}: {errs:?}");
        checked += 1;
    }
    assert!(checked > 1000);
    assert_eq!(statuses.len(), 3, "{statuses:?}");
}

#[test]
fn schema_rejects_inconsistent_verdicts() {
    let good: Value = serde_json::from_str(&scan_json(b"%PDF-1.7\n%%EOF\n", "{}")).unwrap();
    assert!(schema_errors("verdict", &good).is_empty());
    let mut bad = good.clone();
    bad["valid"] = json!(false);
    assert!(
        !schema_errors("verdict", &bad).is_empty(),
        "PASS but invalid"
    );
    let mut bad = good.clone();
    bad["status"] = json!("REJECT");
    bad["valid"] = json!(false);
    assert!(
        !schema_errors("verdict", &bad).is_empty(),
        "REJECT without violations"
    );
    let mut bad = good.clone();
    bad["extra"] = json!(1);
    assert!(!schema_errors("verdict", &bad).is_empty());
    let mut bad = good;
    bad["policy"]["digest"] = json!("md5:x");
    assert!(!schema_errors("verdict", &bad).is_empty());
}

/// Every sample policy validates with the schema and parses in the engine;
/// every invalid one fails both (except what only the engine can know).
#[test]
fn policies_schema_and_engine_agree() {
    let valid = [
        json!({}),
        json!({"preset": "strict"}),
        json!({
            "preset": "balanced",
            "categories": {"external": "warn", "codecs": "off"},
            "rules": {"ACTIVE.OPEN_ACTION": "off", "CODEC.JBIG2": "block"},
            "limits": {"max_file_bytes": 104857600, "max_objects": 10, "max_nesting_depth": 64,
                       "max_decoded_bytes_total": 1, "max_decoded_bytes_per_stream": 1,
                       "max_compression_ratio": 10, "max_revisions": 3},
            "thresholds": {"max_image_pixels": 1000000000, "max_page_side_pt": 14400.0,
                           "max_pages": 10000, "max_filter_chain": 2, "max_trailing_bytes": 0},
            "stop_on_first": false,
            "unsafe_allow_unlock": false
        }),
    ];
    for p in &valid {
        let errs = schema_errors("policy", p);
        assert!(errs.is_empty(), "{p}: {errs:?}");
        assert!(Policy::from_json(&p.to_string()).is_ok(), "{p}");
    }
    let invalid = [
        json!([]),
        json!(null),
        json!({"preset": "paranoid"}),
        json!({"preset": null}),
        json!({"rule": {}}),
        json!({"categories": {"activecontent": "off"}}),
        json!({"categories": {"external": "disable"}}),
        json!({"rules": {"active.launch": "off"}}),
        json!({"limits": {"max_file_bytes": -1}}),
        json!({"limits": {"max_file_bytes": 1.5}}),
        json!({"limits": {"max_pages": 1}}),
        json!({"limits": []}),
        json!({"thresholds": {"max_page_side_pt": -1}}),
        json!({"thresholds": {"max_pages": "1"}}),
        json!({"stop_on_first": 1}),
    ];
    for p in &invalid {
        assert!(!schema_errors("policy", p).is_empty(), "schema accepts {p}");
        let engine = Policy::from_json(&p.to_string()).and_then(|pol| {
            pol.validate(quelda_core::rules::registry::all())
                .map(|()| pol)
        });
        assert!(engine.is_err(), "engine accepts {p}");
    }
    // Only the engine knows which rule IDs exist.
    let unknown = json!({"rules": {"ACTIVE.NOPE": "off"}});
    assert!(schema_errors("policy", &unknown).is_empty());
    let v: Value = serde_json::from_str(&scan_json(b"%PDF-1.7\n", &unknown.to_string())).unwrap();
    assert_eq!(v["errors"][0]["code"], "POLICY.INVALID");
}

#[test]
fn stop_on_first_on_a_real_file() {
    // Two blocking rules: junk before the header + a Launch action.
    let mut input = b"junk\n".to_vec();
    input.extend_from_slice(&common::fixture("rules/ACTIVE.LAUNCH/bad/plain.pdf").bytes);
    let full = scan(&input, &Policy::default());
    let ids: Vec<_> = full.violations.iter().map(|v| v.rule_id).collect();
    assert_eq!(ids, ["ACTIVE.LAUNCH", "FILETYPE.NOT_PDF_HEADER"]);
    let first = scan(
        &input,
        &Policy::from_json(r#"{"stop_on_first":true}"#).unwrap(),
    );
    assert_eq!(first.status, Status::Reject);
    assert_eq!(first.violations.len(), 1);
    // check_file runs before the traversal: the header rule is the first.
    assert_eq!(first.violations[0].rule_id, "FILETYPE.NOT_PDF_HEADER");
    assert!(first.policy.stop_on_first);
}

#[test]
fn verdict_reports_policy_and_stats() {
    let f = &common::fixture("rules/ACTIVE.LAUNCH/bad/in-objstm.pdf").bytes;
    let policy = r#"{"rules":{"ACTIVE.LAUNCH":"off"},"preset":"strict"}"#;
    let v: Value = serde_json::from_str(&scan_json(f, policy)).unwrap();
    assert_eq!(v["policy"]["preset"], "strict");
    assert_eq!(v["policy"]["unsafe_allow_unlock"], false);
    let reordered = r#"{"preset":"strict","rules":{"ACTIVE.LAUNCH":"off"}}"#;
    let w: Value = serde_json::from_str(&scan_json(f, reordered)).unwrap();
    assert_eq!(v["policy"]["digest"], w["policy"]["digest"]);
    assert_eq!(v["stats"]["bytes"], f.len());
    assert!(v["stats"]["objects"].as_u64().unwrap() > 3);
    assert!(
        v["stats"]["decoded_bytes"].as_u64().unwrap() > 0,
        "ObjStm decoded"
    );
    assert_eq!(v["stats"]["revisions"], 1);
    // Locked rule still blocks; its location points into the object stream.
    let launch = &v["violations"][0];
    assert_eq!(launch["rule_id"], "ACTIVE.LAUNCH");
    let loc = &launch["locations"][0];
    assert!(
        loc["source"].as_str().unwrap().starts_with("objstm:"),
        "{loc}"
    );
    assert!(loc["object"].is_string() && loc["offset"].is_u64(), "{loc}");
}
