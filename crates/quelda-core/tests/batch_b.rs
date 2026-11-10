//! Rule set v0.1, batch B (Step 10): `EMBED.*`, `EXTERNAL.*`, `FORMS.*`,
//! `XML.DOCTYPE`, `STRUCT.*`, `CODEC.*`, `RESOURCE.*` (design §5.7). The
//! fixture harness (`rule_fixtures`) and the conformance runner check every
//! fixture; this file checks what is specific to the batch.

mod common;

use quelda_core::facts::Ctx;
use quelda_core::limits::{Limits, Thresholds};
use quelda_core::rules::{Action, Rule, Severity, Site, Stage, registry, run};
use quelda_core::verdict::Status;
use quelda_core::{Policy, scan};
use quelda_testkit::fixtures::Kind;

/// `(id, severity, default_action)` of design §5.7 / §6.2. No batch B rule
/// is locked.
const BATCH_B: &[(&str, Severity, Action)] = &[
    ("EMBED.EMBEDDED_FILE", Severity::High, Action::Block),
    ("EMBED.FILE_ATTACHMENT", Severity::High, Action::Block),
    ("EMBED.RICH_MEDIA", Severity::High, Action::Block),
    ("EMBED.PORTFOLIO", Severity::High, Action::Block),
    ("EXTERNAL.URI", Severity::Low, Action::Warn),
    ("EXTERNAL.REMOTE_GOTO", Severity::Medium, Action::Warn),
    ("EXTERNAL.SUBMIT_FORM", Severity::Medium, Action::Warn),
    ("EXTERNAL.IMPORT_DATA", Severity::Medium, Action::Warn),
    ("EXTERNAL.URL_FILESPEC", Severity::Medium, Action::Warn),
    ("FORMS.XFA", Severity::High, Action::Warn),
    ("FORMS.ACROFORM", Severity::Low, Action::Warn),
    ("XML.DOCTYPE", Severity::High, Action::Block),
    ("STRUCT.TRAILING_DATA", Severity::Medium, Action::Warn),
    ("STRUCT.MISSING_EOF", Severity::Low, Action::Warn),
    ("STRUCT.XREF_MISMATCH", Severity::Medium, Action::Warn),
    ("STRUCT.CONFLICTING_OBJECTS", Severity::Medium, Action::Warn),
    ("STRUCT.INCREMENTAL_UPDATE", Severity::Info, Action::Off),
    ("STRUCT.MULTIPLE_HEADERS", Severity::Medium, Action::Warn),
    ("STRUCT.PAGE_TREE_CYCLE", Severity::High, Action::Warn),
    ("STRUCT.FILTER_CHAIN", Severity::Medium, Action::Warn),
    ("RESOURCE.IMAGE_DIMENSIONS", Severity::High, Action::Block),
    ("RESOURCE.PAGE_SIZE", Severity::Medium, Action::Block),
    ("RESOURCE.PAGE_COUNT", Severity::Medium, Action::Block),
    ("CODEC.JBIG2", Severity::Medium, Action::Warn),
    ("CODEC.JPX", Severity::Low, Action::Warn),
    ("CODEC.TYPE1_FONT", Severity::Low, Action::Off),
];

const RESOURCE: &[&str] = &[
    "RESOURCE.IMAGE_DIMENSIONS",
    "RESOURCE.PAGE_SIZE",
    "RESOURCE.PAGE_COUNT",
];

fn rule(id: &str) -> &'static dyn Rule {
    registry::get(id).unwrap_or_else(|| panic!("{id} not registered"))
}

fn batch_b_rules() -> Vec<&'static dyn Rule> {
    BATCH_B.iter().map(|(id, _, _)| rule(id)).collect()
}

fn policy(json: &str) -> Policy {
    Policy::from_json(json).unwrap_or_else(|e| panic!("{json}: {e:?}"))
}

fn ids(v: &[quelda_core::verdict::Violation]) -> Vec<&str> {
    v.iter().map(|x| x.rule_id).collect()
}

#[test]
fn batch_b_registered_as_designed() {
    for &(id, severity, action) in BATCH_B {
        let m = rule(id).meta();
        assert_eq!(m.severity, severity, "{id}: severity");
        assert_eq!(m.default_action, action, "{id}: default_action");
        assert!(!m.locked, "{id}: locked");
        assert_eq!(m.stage, Stage::Stable, "{id}: stage");
        assert_eq!(m.since, "0.1.0", "{id}");
        assert!(!m.message.is_empty() && m.description.len() > 40, "{id}");
    }
    // With batch A (13 rules): the whole v0.1 rule set.
    assert_eq!(BATCH_B.len(), 26);
    assert_eq!(registry::list().len(), 40);
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
/// Rules matching a name/number value need `indirect-value` (ADR #19).
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
        "EMBED.EMBEDDED_FILE",
        "EMBED.FILE_ATTACHMENT",
        "EMBED.RICH_MEDIA",
        "EXTERNAL.URI",
        "EXTERNAL.REMOTE_GOTO",
        "EXTERNAL.SUBMIT_FORM",
        "EXTERNAL.IMPORT_DATA",
        "EXTERNAL.URL_FILESPEC",
        "CODEC.JBIG2",
        "CODEC.JPX",
        "RESOURCE.IMAGE_DIMENSIONS",
        "RESOURCE.PAGE_SIZE",
    ] {
        required.push((id, [DICT, &["indirect-value"]].concat()));
    }
    for id in [
        "EMBED.PORTFOLIO",
        "FORMS.XFA",
        "FORMS.ACROFORM",
        "CODEC.TYPE1_FONT",
    ] {
        required.push((id, DICT.to_vec()));
    }
    required.extend([
        ("EMBED.EMBEDDED_FILE", vec!["names-tree", "ef-without-type"]),
        (
            "EMBED.RICH_MEDIA",
            vec![
                "subtype-screen",
                "subtype-movie",
                "subtype-sound",
                "subtype-3d",
                "subtype-u3d",
                "subtype-prc",
            ],
        ),
        ("EXTERNAL.REMOTE_GOTO", vec!["goto-e"]),
        ("FORMS.XFA", vec!["xfa-script", "xfa-array"]),
        (
            "XML.DOCTYPE",
            vec![
                "plain",
                "flate",
                "filter-chain",
                "lzw",
                "old-revision",
                "in-xfa",
                "entity-only",
                "utf16",
                "lowercase",
                "xfa-indirect-array",
            ],
        ),
        (
            "CODEC.JBIG2",
            vec![
                "filter-array",
                "filter-indirect-array",
                "filter-array-indirect-element",
                "inline-image",
            ],
        ),
        ("CODEC.JPX", vec!["filter-array", "inline-image"]),
        (
            "RESOURCE.IMAGE_DIMENSIONS",
            vec![
                "inline-image",
                "negative-width",
                "zero-height",
                "non-numeric",
                "abbreviated-keys",
                "indirect-subtype",
            ],
        ),
        (
            "RESOURCE.PAGE_SIZE",
            vec![
                "userunit",
                "cropbox",
                "trimbox",
                "degenerate",
                "inherited",
                "array-element-indirect",
            ],
        ),
        (
            "RESOURCE.PAGE_COUNT",
            vec![
                "declared-count",
                "name-encoded",
                "many-pages",
                "indirect-value",
                "orphan-pages-node",
            ],
        ),
        (
            "STRUCT.FILTER_CHAIN",
            vec![
                "three-filters",
                "repeated",
                "name-encoded",
                "abbreviated-repeat",
                "indirect-array",
                "inline-image",
            ],
        ),
        (
            "STRUCT.PAGE_TREE_CYCLE",
            vec![
                "kids-self",
                "kids-duplicate",
                "mutual",
                "moved-across-revisions",
            ],
        ),
        (
            "STRUCT.XREF_MISMATCH",
            vec!["wrong-offsets", "missing-entry", "unreachable-section"],
        ),
        (
            "STRUCT.INCREMENTAL_UPDATE",
            vec!["two-revisions", "three-revisions", "linearized-updated"],
        ),
    ]);
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

/// An ordinary hyperlink: warning (valid) in balanced, rejected in strict,
/// nothing in permissive (ADR #21).
#[test]
fn benign_link_uri_per_preset() {
    let f = common::fixture("benign/link-uri.pdf");
    let v = scan(&f.bytes, &policy(r#"{"preset":"balanced"}"#));
    assert_eq!(v.status, Status::Pass);
    assert!(v.valid);
    assert!(v.violations.is_empty());
    assert_eq!(ids(&v.warnings), vec!["EXTERNAL.URI"]);
    let v = scan(&f.bytes, &Policy::default());
    assert_eq!(
        (v.status, ids(&v.warnings)),
        (Status::Pass, vec!["EXTERNAL.URI"])
    );
    let v = scan(&f.bytes, &policy(r#"{"preset":"strict"}"#));
    assert_eq!(v.status, Status::Reject);
    assert!(!v.valid);
    assert_eq!(ids(&v.violations), vec!["EXTERNAL.URI"]);
    let v = scan(&f.bytes, &policy(r#"{"preset":"permissive"}"#));
    assert_eq!(v.status, Status::Pass);
    assert!(v.warnings.is_empty() && v.violations.is_empty());
}

/// Benign A0 files (page and A0 @300dpi image) hit no `RESOURCE.*` rule in
/// any preset; no benign file does.
#[test]
fn benign_files_hit_no_resource_rule() {
    let a0 = common::fixture("benign/a0-large-image.pdf");
    assert!(a0.note.contains("A0"));
    let mut n = 0;
    for f in common::fixtures().iter().filter(|f| f.kind == Kind::Benign) {
        for preset in ["strict", "balanced", "permissive"] {
            let v = scan(&f.bytes, &policy(&format!(r#"{{"preset":"{preset}"}}"#)));
            let hits: Vec<_> = ids(&v.violations)
                .into_iter()
                .chain(ids(&v.warnings))
                .filter(|id| RESOURCE.contains(id))
                .collect();
            assert!(hits.is_empty(), "{} [{preset}]: {hits:?}", f.path);
            n += 1;
        }
    }
    assert!(n >= 30, "{n}");
    let v = scan(&a0.bytes, &policy(r#"{"preset":"strict"}"#));
    assert_eq!(v.status, Status::Pass, "{:?}", ids(&v.violations));
}

/// No benign file triggers a batch B rule, unless its manifest entry says so.
#[test]
fn benign_files_trigger_no_batch_b_rule() {
    let rules = batch_b_rules();
    let mut n = 0;
    for f in common::fixtures().iter().filter(|f| f.kind == Kind::Benign) {
        let ctx = Ctx::new(&f.bytes, Limits::default(), Thresholds::default());
        let found = run(&ctx, &rules);
        let expected: Vec<_> = f
            .fires
            .iter()
            .filter(|id| BATCH_B.iter().any(|(b, _, _)| b == *id))
            .copied()
            .collect();
        assert_eq!(found.rule_ids(), expected, "{}", f.path);
        n += 1;
    }
    assert!(n >= 10, "{n}");
}

/// `(file, threshold policy, rule)`: the rule fires with the default
/// thresholds and not with the policy's, or the other way round.
#[test]
fn thresholds_change_resource_and_structure_results() {
    let cases: &[(&str, &str, &str, bool)] = &[
        // (file, thresholds, rule, fires with these thresholds)
        (
            "rules/RESOURCE.IMAGE_DIMENSIONS/bad/plain.pdf",
            r#"{"max_image_pixels":10000000000}"#,
            "RESOURCE.IMAGE_DIMENSIONS",
            false,
        ),
        (
            "rules/RESOURCE.IMAGE_DIMENSIONS/good/below-threshold.pdf",
            r#"{"max_image_pixels":899999999}"#,
            "RESOURCE.IMAGE_DIMENSIONS",
            true,
        ),
        (
            "rules/RESOURCE.PAGE_SIZE/bad/plain.pdf",
            r#"{"max_page_side_pt":100000}"#,
            "RESOURCE.PAGE_SIZE",
            false,
        ),
        (
            "rules/RESOURCE.PAGE_SIZE/good/banner.pdf",
            r#"{"max_page_side_pt":27999}"#,
            "RESOURCE.PAGE_SIZE",
            true,
        ),
        (
            "rules/RESOURCE.PAGE_COUNT/bad/many-pages.pdf",
            r#"{"max_pages":10001}"#,
            "RESOURCE.PAGE_COUNT",
            false,
        ),
        (
            "rules/RESOURCE.PAGE_COUNT/good/hundred-pages.pdf",
            r#"{"max_pages":99}"#,
            "RESOURCE.PAGE_COUNT",
            true,
        ),
        (
            "rules/STRUCT.FILTER_CHAIN/bad/three-filters.pdf",
            r#"{"max_filter_chain":3}"#,
            "STRUCT.FILTER_CHAIN",
            false,
        ),
        (
            "rules/STRUCT.FILTER_CHAIN/good/two-filters.pdf",
            r#"{"max_filter_chain":1}"#,
            "STRUCT.FILTER_CHAIN",
            true,
        ),
        (
            "rules/STRUCT.TRAILING_DATA/good/zero-padding-512.pdf",
            r#"{"max_trailing_bytes":511}"#,
            "STRUCT.TRAILING_DATA",
            true,
        ),
        (
            "rules/STRUCT.TRAILING_DATA/bad/binary-2k.pdf",
            r#"{"max_trailing_bytes":2001}"#,
            "STRUCT.TRAILING_DATA",
            false,
        ),
    ];
    let reported = |v: &quelda_core::Verdict, id: &str| {
        ids(&v.violations).contains(&id) || ids(&v.warnings).contains(&id)
    };
    for &(file, thresholds, id, fires) in cases {
        let f = common::fixture(file);
        let base = scan(&f.bytes, &policy(r#"{"preset":"strict"}"#));
        assert_eq!(reported(&base, id), !fires, "{file}: default thresholds");
        let p = policy(&format!(
            r#"{{"preset":"strict","thresholds":{thresholds}}}"#
        ));
        let v = scan(&f.bytes, &p);
        assert_eq!(reported(&v, id), fires, "{file}: {thresholds}");
        // Strict blocks both categories: the status follows.
        if fires {
            assert_eq!(v.status, Status::Reject, "{file}");
        }
    }
}

fn first(path: &str, id: &str) -> quelda_core::rules::Finding {
    let f = common::fixture(path);
    let ctx = Ctx::new(&f.bytes, Limits::default(), Thresholds::default());
    run(&ctx, &[rule(id)])
        .iter()
        .next()
        .cloned()
        .unwrap_or_else(|| panic!("{path}: {id} did not fire"))
}

/// Findings point at the right place and say what matched.
#[test]
fn findings_carry_site_and_detail() {
    let x = first(
        "rules/RESOURCE.IMAGE_DIMENSIONS/bad/plain.pdf",
        "RESOURCE.IMAGE_DIMENSIONS",
    );
    assert_eq!(
        x.detail.as_deref(),
        Some("100000 x 100000 pixels (max 1000000000)")
    );
    assert!(matches!(x.site, Site::Object(ref l) if l.id.num == 10));
    let x = first(
        "rules/RESOURCE.IMAGE_DIMENSIONS/bad/inline-image.pdf",
        "RESOURCE.IMAGE_DIMENSIONS",
    );
    assert!(matches!(x.site, Site::Op(ref o) if !o.speculative));
    let x = first(
        "rules/RESOURCE.PAGE_SIZE/bad/userunit.pdf",
        "RESOURCE.PAGE_SIZE",
    );
    assert_eq!(
        x.detail.as_deref(),
        Some("MediaBox 144000 x 144000 pt (max side 28800)")
    );
    let x = first(
        "rules/RESOURCE.PAGE_COUNT/bad/many-pages.pdf",
        "RESOURCE.PAGE_COUNT",
    );
    assert_eq!(x.detail.as_deref(), Some("/Count 10001 (max 10000)"));
    let x = first("rules/XML.DOCTYPE/bad/utf16.pdf", "XML.DOCTYPE");
    assert_eq!(
        x.detail.as_deref(),
        Some("<!DOCTYPE in XML stream (UTF-16)")
    );
    let x = first(
        "rules/XML.DOCTYPE/bad/xfa-indirect-array.pdf",
        "XML.DOCTYPE",
    );
    // The XML role follows the indirect array (ADR #26).
    assert_eq!(x.detail.as_deref(), Some("<!DOCTYPE in XML stream (UTF-8)"));
    let x = first("rules/CODEC.JBIG2/bad/inline-image.pdf", "CODEC.JBIG2");
    assert_eq!(x.detail.as_deref(), Some("inline image JBIG2Decode"));
    let x = first(
        "rules/STRUCT.FILTER_CHAIN/bad/repeated.pdf",
        "STRUCT.FILTER_CHAIN",
    );
    assert_eq!(x.detail.as_deref(), Some("filter FlateDecode repeated"));
    let x = first(
        "rules/STRUCT.TRAILING_DATA/bad/binary-2k.pdf",
        "STRUCT.TRAILING_DATA",
    );
    assert_eq!(x.detail.as_deref(), Some("2001 bytes after the last %%EOF"));
    assert!(matches!(x.site, Site::Offset(o) if o > 0));
    let x = first(
        "rules/STRUCT.PAGE_TREE_CYCLE/bad/kids-self.pdf",
        "STRUCT.PAGE_TREE_CYCLE",
    );
    assert_eq!(
        x.detail.as_deref(),
        Some("page tree node 2 0 is on a /Kids cycle")
    );
    let x = first(
        "rules/STRUCT.XREF_MISMATCH/bad/missing-entry.pdf",
        "STRUCT.XREF_MISMATCH",
    );
    assert_eq!(
        x.detail.as_deref(),
        Some("object 20 0 is listed by no xref section")
    );
    let x = first(
        "rules/STRUCT.INCREMENTAL_UPDATE/bad/linearized-updated.pdf",
        "STRUCT.INCREMENTAL_UPDATE",
    );
    assert_eq!(x.detail.as_deref(), Some("2 revisions"));
}

/// Default-off rules (`STRUCT.INCREMENTAL_UPDATE`, `CODEC.TYPE1_FONT`) warn
/// in strict only; a policy can still turn them on in balanced.
#[test]
fn default_off_rules() {
    for (file, id) in [
        (
            "rules/STRUCT.INCREMENTAL_UPDATE/bad/two-revisions.pdf",
            "STRUCT.INCREMENTAL_UPDATE",
        ),
        ("rules/CODEC.TYPE1_FONT/bad/plain.pdf", "CODEC.TYPE1_FONT"),
    ] {
        let bytes = &common::fixture(file).bytes;
        let v = scan(bytes, &policy(r#"{"preset":"strict"}"#));
        assert_eq!(ids(&v.warnings), vec![id], "{file}");
        for preset in ["balanced", "permissive"] {
            let v = scan(bytes, &policy(&format!(r#"{{"preset":"{preset}"}}"#)));
            assert!(!ids(&v.warnings).contains(&id), "{file} {preset}");
        }
        let v = scan(
            bytes,
            &policy(&format!(r#"{{"rules":{{"{id}":"block"}}}}"#)),
        );
        assert_eq!(v.status, Status::Reject, "{file}");
    }
}
