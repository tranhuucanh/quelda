//! Rule set v0.1, batch A (Step 9): `FILETYPE.*`, `POSTSCRIPT.*`, `ACTIVE.*`,
//! `CRYPT.ENCRYPTED` (design §5.7). The fixture harness (`rule_fixtures`) and
//! the conformance runner check every fixture; this file checks what is
//! specific to the batch.

mod common;

use quelda_core::facts::Ctx;
use quelda_core::limits::{Limits, Thresholds};
use quelda_core::rules::{Rule, Severity, registry, run};
use quelda_core::verdict::Status;
use quelda_core::{Policy, scan};
use quelda_testkit::fixtures::Kind;

/// `(id, severity, locked)` of design §5.7.
const BATCH_A: &[(&str, Severity, bool)] = &[
    ("FILETYPE.NOT_PDF_HEADER", Severity::Critical, true),
    ("FILETYPE.POSTSCRIPT_MAGIC", Severity::Critical, true),
    ("FILETYPE.FOREIGN_MAGIC", Severity::High, true),
    ("FILETYPE.POLYGLOT", Severity::High, false),
    ("POSTSCRIPT.XOBJECT", Severity::Critical, true),
    ("POSTSCRIPT.CONTENT_OP", Severity::Critical, true),
    ("POSTSCRIPT.TYPE4_FUNCTION", Severity::Medium, false),
    ("ACTIVE.JAVASCRIPT", Severity::High, false),
    ("ACTIVE.LAUNCH", Severity::Critical, true),
    ("ACTIVE.OPEN_ACTION", Severity::Medium, false),
    ("ACTIVE.ADDITIONAL_ACTIONS", Severity::Medium, false),
    ("ACTIVE.OTHER_ACTIONS", Severity::Low, false),
    ("CRYPT.ENCRYPTED", Severity::High, false),
];

const PS_MAGIC: &str = "FILETYPE.POSTSCRIPT_MAGIC";

fn batch_a_rules() -> Vec<&'static dyn Rule> {
    BATCH_A
        .iter()
        .map(|(id, _, _)| registry::get(id).unwrap_or_else(|| panic!("{id} not registered")))
        .collect()
}

#[test]
fn batch_a_registered_as_designed() {
    for &(id, severity, locked) in BATCH_A {
        let m = registry::get(id)
            .unwrap_or_else(|| panic!("{id} not registered"))
            .meta();
        assert_eq!(m.severity, severity, "{id}: severity");
        assert_eq!(m.locked, locked, "{id}: locked");
        assert_eq!(m.since, "0.1.0", "{id}");
    }
}

/// Variant names of the in-memory `bad/` fixtures of `rule`.
fn bad_variants(rule: &str) -> Vec<&'static str> {
    common::fixtures()
        .iter()
        .filter(|f| f.kind == Kind::Bad && f.rule == Some(rule))
        .map(|f| f.variant.as_str())
        .collect()
}

/// Design §5.7: required evasion variants per rule (those that apply).
#[test]
fn required_variants_exist() {
    const DICT: &[&str] = &[
        "plain",
        "name-encoded",
        "in-objstm",
        "in-objstm-lzw",
        "in-objstm-filter-chain",
        "old-revision",
        "nested-dict",
    ];
    let mut required: Vec<(&str, Vec<&str>)> = Vec::new();
    for id in [
        "POSTSCRIPT.XOBJECT",
        "POSTSCRIPT.TYPE4_FUNCTION",
        "ACTIVE.JAVASCRIPT",
        "ACTIVE.LAUNCH",
        "ACTIVE.OTHER_ACTIONS",
    ] {
        required.push((id, [DICT, &["indirect-value"]].concat()));
    }
    for id in ["ACTIVE.OPEN_ACTION", "ACTIVE.ADDITIONAL_ACTIONS"] {
        required.push((id, DICT.to_vec()));
    }
    required.push((
        "ACTIVE.JAVASCRIPT",
        vec![
            "js-stream",
            "js-utf16",
            "js-names-tree",
            "js-annotation",
            "js-openaction",
        ],
    ));
    required.push(("POSTSCRIPT.XOBJECT", vec!["subtype2-ps", "form-ps-key"]));
    required.push((
        "POSTSCRIPT.CONTENT_OP",
        vec![
            "plain",
            "flate",
            "filter-chain",
            "lzw",
            "old-revision",
            "form-xobject",
            "appearance-stream",
            "type3-charproc",
        ],
    ));
    required.push((
        "FILETYPE.NOT_PDF_HEADER",
        vec!["junk-before-header", "header-after-1024"],
    ));
    required.push((
        PS_MAGIC,
        vec![
            "ps-adobe",
            "eps-ascii",
            "eps-binary",
            "ps-then-pdf",
            "bom-before-ps",
            "whitespace-before-ps",
            "pjl-wrapped",
        ],
    ));
    required.push((
        "CRYPT.ENCRYPTED",
        vec!["plain", "name-encoded", "xref-stream", "old-revision"],
    ));
    let mut missing = Vec::new();
    for (id, variants) in required {
        let have = bad_variants(id);
        for v in variants {
            if !have.contains(&v) {
                missing.push(format!("{id}/bad/{v}"));
            }
        }
    }
    assert!(missing.is_empty(), "{missing:?}");
}

/// PS/EPS renamed to `.pdf` is rejected by `FILETYPE.POSTSCRIPT_MAGIC` in
/// every preset, even when the policy tries to turn it off (locked).
#[test]
fn postscript_rejected_in_every_preset_even_when_turned_off() {
    let files: Vec<_> = common::fixtures()
        .iter()
        .filter(|f| {
            f.path.starts_with("filetype/ps-")
                || f.path.starts_with("filetype/eps-")
                || (f.kind == Kind::Bad && f.rule == Some(PS_MAGIC))
        })
        .collect();
    assert!(files.len() >= 10, "{}", files.len());
    let mut checked = 0;
    for preset in ["strict", "balanced", "permissive"] {
        for extra in [
            "",
            r#","categories":{"filetype":"off"}"#,
            r#","rules":{"FILETYPE.POSTSCRIPT_MAGIC":"off"}"#,
            r#","rules":{"FILETYPE.POSTSCRIPT_MAGIC":"warn"},"categories":{"filetype":"warn"}"#,
        ] {
            let policy = Policy::from_json(&format!(r#"{{"preset":"{preset}"{extra}}}"#))
                .unwrap_or_else(|e| panic!("{preset}{extra}: {e:?}"));
            for f in &files {
                let v = scan(&f.bytes, &policy);
                assert_eq!(v.status, Status::Reject, "{} {preset}{extra}", f.path);
                assert!(!v.valid);
                assert!(
                    v.violations.iter().any(|x| x.rule_id == PS_MAGIC),
                    "{} {preset}{extra}: {:?}",
                    f.path,
                    v.violations.iter().map(|x| x.rule_id).collect::<Vec<_>>()
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 120);
    // Only `unsafe_allow_unlock` lowers it (the file is still rejected: it
    // has no PDF header either).
    let policy = Policy::from_json(
        r#"{"rules":{"FILETYPE.POSTSCRIPT_MAGIC":"off"},"unsafe_allow_unlock":true}"#,
    )
    .unwrap();
    let v = scan(&common::fixture("filetype/ps-renamed.pdf").bytes, &policy);
    assert!(v.violations.iter().all(|x| x.rule_id != PS_MAGIC));
    assert_eq!(v.status, Status::Reject);
}

/// No benign file triggers a batch A rule, unless its manifest entry says so.
#[test]
fn benign_files_trigger_no_batch_a_rule() {
    let rules = batch_a_rules();
    let mut n = 0;
    for f in common::fixtures().iter().filter(|f| f.kind == Kind::Benign) {
        let ctx = Ctx::new(&f.bytes, Limits::default(), Thresholds::default());
        let found = run(&ctx, &rules);
        let expected: Vec<_> = f
            .fires
            .iter()
            .filter(|id| BATCH_A.iter().any(|(b, _, _)| b == *id))
            .copied()
            .collect();
        assert_eq!(found.rule_ids(), expected, "{}", f.path);
        n += 1;
    }
    assert!(n >= 10, "{n}");
}

/// Findings point at the right place and say what matched.
#[test]
fn findings_carry_site_and_detail() {
    use quelda_core::rules::Site;
    let rules = batch_a_rules();
    let scan_one = |path: &str, id: &str| {
        let f = common::fixture(path);
        let ctx = Ctx::new(&f.bytes, Limits::default(), Thresholds::default());
        let found = run(&ctx, &rules);
        found
            .iter()
            .find(|x| x.rule.id == id)
            .cloned()
            .unwrap_or_else(|| panic!("{path}: {id} did not fire"))
    };
    let x = scan_one("rules/CRYPT.ENCRYPTED/bad/plain.pdf", "CRYPT.ENCRYPTED");
    assert_eq!(
        x.detail.as_deref(),
        Some("/Encrypt with security handler /Standard")
    );
    assert!(matches!(x.site, Site::Offset(o) if o > 0));
    let x = scan_one(
        "rules/FILETYPE.POLYGLOT/bad/zip-appended.pdf",
        "FILETYPE.POLYGLOT",
    );
    assert_eq!(x.detail.as_deref(), Some("ZIP end of central directory"));
    let x = scan_one("filetype/svg.pdf", "FILETYPE.FOREIGN_MAGIC");
    assert_eq!(x.detail.as_deref(), Some("XML/HTML markup signature"));
    let x = scan_one(
        "rules/POSTSCRIPT.CONTENT_OP/bad/plain.pdf",
        "POSTSCRIPT.CONTENT_OP",
    );
    assert!(matches!(x.site, Site::Op(ref o) if !o.speculative));
}
