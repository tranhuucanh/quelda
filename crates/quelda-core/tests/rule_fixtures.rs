//! Rule fixture harness (design §9.2): for every rule in the registry,
//! `tests/fixtures/rules/<ID>/bad/*.pdf` must fire it and `good/*.pdf` must
//! not. A rule without both directories (each with ≥ 1 file) fails.
//!
//! Plus the manifest view (in-memory testkit fixtures): every fixture that
//! lists a registered rule in `fires` fires it, and an `exact` fixture fires
//! no registered rule it does not list.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use quelda_core::facts::Ctx;
use quelda_core::limits::{Limits, Thresholds};
use quelda_core::rules::{
    Action, Category, Findings, Rule, RuleMeta, Severity, Stage, registry, run,
};

fn fixtures_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    assert!(
        root.join("manifest.json").is_file(),
        "{} not found: run `cargo run -p quelda-testkit --bin gen-fixtures` first",
        root.display()
    );
    root
}

fn scan(bytes: &[u8], rules: &[&dyn Rule]) -> Findings {
    let ctx = Ctx::new(bytes, Limits::default(), Thresholds::default());
    run(&ctx, rules)
}

fn pdfs(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|e| e == "pdf"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Checks one rule against its fixture directories; returns the number of
/// files checked, or every problem found.
fn check_rule(rule: &dyn Rule, root: &Path) -> Result<usize, Vec<String>> {
    let id = rule.meta().id;
    let mut problems = Vec::new();
    let mut checked = 0;
    for (kind, must_fire) in [("bad", true), ("good", false)] {
        let dir = root.join("rules").join(id).join(kind);
        let files = pdfs(&dir);
        if files.is_empty() {
            problems.push(format!(
                "{id}: missing fixtures: {} has no .pdf (every rule needs bad/ and good/)",
                dir.display()
            ));
        }
        for f in files {
            let bytes = fs::read(&f).unwrap_or_default();
            let fired = scan(&bytes, &[rule]).fired(id);
            checked += 1;
            if fired != must_fire {
                problems.push(format!(
                    "{id}: {kind}/{}: {}",
                    f.file_name().unwrap_or_default().to_string_lossy(),
                    if must_fire { "did not fire" } else { "fired" }
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(checked)
    } else {
        Err(problems)
    }
}

#[test]
fn every_rule_passes_its_fixtures() {
    let root = fixtures_root();
    let mut problems = Vec::new();
    for rule in registry::all() {
        match check_rule(*rule, &root) {
            Ok(n) => assert!(n >= 2, "{}", rule.meta().id),
            Err(p) => problems.extend(p),
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn sample_rules_cover_required_variants() {
    let root = fixtures_root();
    let variants = |id: &str| -> Vec<String> {
        pdfs(&root.join("rules").join(id).join("bad"))
            .iter()
            .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .collect()
    };
    let launch = variants("ACTIVE.LAUNCH");
    for v in [
        "plain",
        "name-encoded",
        "in-objstm",
        "old-revision",
        "nested-dict",
        "indirect-value",
    ] {
        assert!(launch.iter().any(|x| x == v), "ACTIVE.LAUNCH/bad/{v}");
    }
    let header = variants("FILETYPE.NOT_PDF_HEADER");
    for v in ["junk-before-header", "header-after-1024"] {
        assert!(
            header.iter().any(|x| x == v),
            "FILETYPE.NOT_PDF_HEADER/bad/{v}"
        );
    }
}

/// Every fixture, every registered rule, against the manifest's `fires`.
#[test]
fn registered_rules_match_manifest() {
    let rules = registry::all();
    let mut problems = Vec::new();
    for f in common::fixtures() {
        let found = scan(&f.bytes, rules);
        for r in rules {
            let id = r.meta().id;
            let expected = f.fires.contains(&id);
            let fired = found.fired(id);
            if expected && !fired {
                problems.push(format!("{}: {id} did not fire", f.path));
            } else if fired && !expected && f.exact {
                problems.push(format!("{}: {id} fired (not in exact `fires`)", f.path));
            }
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

/// The harness itself: a rule with no fixture directory fails.
#[test]
fn harness_fails_without_fixtures() {
    static META: RuleMeta = RuleMeta {
        id: "ACTIVE.QUELDA_NO_FIXTURES",
        category: Category::ActiveContent,
        severity: Severity::Low,
        default_action: Action::Warn,
        locked: false,
        stage: Stage::Preview,
        since: "0.1.0",
        message: "test",
        description: "test",
    };
    struct NoFixtures;
    impl Rule for NoFixtures {
        fn meta(&self) -> &'static RuleMeta {
            &META
        }
    }
    let problems = check_rule(&NoFixtures, &fixtures_root()).unwrap_err();
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(problems[0].contains("ACTIVE.QUELDA_NO_FIXTURES: missing fixtures"));
    assert!(problems[0].contains("bad"));
    assert!(problems[1].contains("good"));
}

/// The harness itself: a rule that never fires fails on bad/, one that
/// always fires fails on good/.
#[test]
fn harness_catches_wrong_rules() {
    static META: RuleMeta = RuleMeta {
        id: "ACTIVE.LAUNCH",
        category: Category::ActiveContent,
        severity: Severity::Critical,
        default_action: Action::Block,
        locked: true,
        stage: Stage::Stable,
        since: "0.1.0",
        message: "test",
        description: "test",
    };
    struct Never;
    impl Rule for Never {
        fn meta(&self) -> &'static RuleMeta {
            &META
        }
    }
    struct Always;
    impl Rule for Always {
        fn meta(&self) -> &'static RuleMeta {
            &META
        }
        fn check_file(&self, _: &[u8], out: &mut Findings) {
            out.report(&META, quelda_core::rules::Site::Document, None);
        }
    }
    let root = fixtures_root();
    let never = check_rule(&Never, &root).unwrap_err();
    assert!(never.iter().all(|p| p.contains(": bad/")), "{never:?}");
    assert!(
        never
            .iter()
            .any(|p| p.contains("bad/plain.pdf: did not fire")),
        "{never:?}"
    );
    let always = check_rule(&Always, &root).unwrap_err();
    assert!(
        always
            .iter()
            .all(|p| p.contains("good/") && p.ends_with("fired")),
        "{always:?}"
    );
}
