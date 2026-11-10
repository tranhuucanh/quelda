//! quelda scan engine: one PDF + policy in, verdict out.
//!
//! Layers (design §4): parser (`parser`, `filters`) → facts (`facts::Ctx`)
//! → rules (`rules`) → policy (`policy`) → [`Verdict`].
//!
//! Public API (design §8.1): [`scan`], [`scan_json`] (the contract every
//! binding wraps; schemas in `schemas/`), [`list_rules`]; [`scan_source`],
//! [`scan_source_json`] read the input on demand ([`Source`]) instead of
//! holding it all in memory, with the same verdict.

#![forbid(unsafe_code)]
// Input must never be able to crash the engine (design: fail-closed, no panics).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod error;
pub mod facts;
pub mod filters;
pub mod limits;
pub mod parser;
pub mod policy;
pub mod rules;
pub mod source;
pub mod verdict;

#[cfg(test)]
mod differential;

use error::IssueCode;
use facts::Ctx;
use parser::input::{Input, Tuning};
pub use policy::Policy;
use rules::{Action, Findings, Rule};
pub use source::{ReadError, Source};
pub use verdict::Verdict;
use verdict::{PolicyInfo, Stats};

/// Engine version, reported in every verdict as `engine_version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the engine version.
pub fn version() -> &'static str {
    VERSION
}

/// Every rule the engine knows, sorted by ID (for settings screens).
pub fn list_rules() -> Vec<rules::RuleInfo> {
    rules::registry::list()
}

/// [`list_rules`] as a JSON array (the contract bindings expose): one object
/// per rule with `id`, `category`, `severity`, `default_action`, `locked`,
/// `stage`, `since`, `message`, `description`.
pub fn list_rules_json() -> String {
    // Unreachable for these types; still never panic.
    serde_json::to_string(&list_rules()).unwrap_or_else(|_| "[]".to_string())
}

/// Scans one file under `policy`. Never panics; anything the engine cannot
/// inspect makes the verdict `ERROR` (`valid: false`).
pub fn scan(input: &[u8], policy: &Policy) -> Verdict {
    scan_with(
        Ok(Input::slice(input)),
        input.len() as u64,
        policy,
        rules::registry::all(),
    )
}

/// [`scan`] with the policy as JSON, verdict as JSON. A policy that does not
/// parse gives an `ERROR` verdict with `POLICY.INVALID`.
pub fn scan_json(input: &[u8], policy_json: &str) -> String {
    match Policy::from_json(policy_json) {
        Ok(policy) => scan(input, &policy),
        Err(e) => invalid_policy(e, input.len() as u64),
    }
    .to_json()
}

/// [`scan`] reading `source` on demand: one pass in blocks, then only the
/// regions to parse or decode (opaque stream data is never read again).
/// Memory does not grow with the file, except for data that must be
/// decoded. Same verdict as [`scan`] on the same bytes; a read error makes
/// it `ERROR` (`ENGINE.READ`).
pub fn scan_source(source: &dyn Source, policy: &Policy) -> Verdict {
    scan_source_tuned(source, policy, Tuning::DEFAULT)
}

/// [`scan_source`] with the policy as JSON, verdict as JSON.
pub fn scan_source_json(source: &dyn Source, policy_json: &str) -> String {
    match Policy::from_json(policy_json) {
        Ok(policy) => scan_source(source, &policy),
        Err(e) => invalid_policy(e, source.len()),
    }
    .to_json()
}

/// The verdict for a source that cannot be read at all (bindings: e.g. a
/// JS reader without a valid `size`): `ERROR` with `ENGINE.READ`.
pub fn read_error_json(message: &str, policy_json: &str) -> String {
    match Policy::from_json(policy_json) {
        Ok(policy) => scan_with(Err(message.to_string()), 0, &policy, rules::registry::all()),
        Err(e) => invalid_policy(e, 0),
    }
    .to_json()
}

fn scan_source_tuned(source: &dyn Source, policy: &Policy, tuning: Tuning) -> Verdict {
    let input = Input::source(source, tuning);
    scan_with(input, source.len(), policy, rules::registry::all())
}

fn invalid_policy(e: policy::PolicyError, bytes: u64) -> Verdict {
    Verdict::error(
        &verdict::issue(IssueCode::PolicyInvalid, e.0),
        PolicyInfo::unknown(),
        bytes,
    )
}

/// [`scan`] over a given rule set (tests inject probe rules). `input` is
/// `Err` when the source cannot be addressed here.
fn scan_with(
    input: Result<Input<'_>, String>,
    bytes: u64,
    policy: &Policy,
    all: &[&'static dyn Rule],
) -> Verdict {
    let clock = Clock::start();
    if let Err(e) = policy.validate(all) {
        let issue = verdict::issue(IssueCode::PolicyInvalid, e.0);
        return Verdict::error(&issue, PolicyInfo::of(policy), bytes);
    }
    let limits = policy.limits();
    if bytes > limits.max_file_bytes {
        let issue = verdict::issue(
            IssueCode::LimitFileBytes,
            format!(
                "input is {bytes} bytes, more than max_file_bytes ({})",
                limits.max_file_bytes
            ),
        );
        return Verdict::error(&issue, PolicyInfo::of(policy), bytes);
    }

    let input = match input {
        Ok(i) => i,
        Err(msg) => {
            let issue = verdict::issue(IssueCode::EngineRead, msg);
            return Verdict::error(&issue, PolicyInfo::of(policy), bytes);
        }
    };
    let ctx = Ctx::from_input(input, limits, policy.thresholds());
    let resolved = policy::resolve_all(all, policy);
    // Rules resolved to `off` do not run (design §6.5).
    let active: Vec<&dyn Rule> = resolved
        .iter()
        .filter(|(_, a)| *a != Action::Off)
        .map(|(r, _)| *r)
        .collect();
    let out = if policy.stop_on_first() {
        let blocking = resolved
            .iter()
            .filter(|(_, a)| *a == Action::Block)
            .map(|(r, _)| r.meta().id)
            .collect();
        Findings::stopping_on(blocking)
    } else {
        Findings::new()
    };
    let findings = rules::run_into(&ctx, &active, out);
    let stats = Stats {
        bytes,
        objects: ctx.objects().len() as u64,
        revisions: ctx.revisions().len() as u64,
        decoded_bytes: ctx.decoded_bytes(),
        duration_ms: clock.elapsed_ms(),
    };
    Verdict::new(&findings, &ctx.issues(), ctx.objects(), policy, stats)
}

/// Wall clock for `stats.duration_ms`; wasm32-unknown-unknown has none
/// (`Instant::now` panics there), so it reports 0.
struct Clock {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    start: std::time::Instant,
}

impl Clock {
    fn start() -> Clock {
        Clock {
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            start: std::time::Instant::now(),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_package_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }

    use crate::facts::Location;
    use crate::parser::Dict;
    use crate::rules::{Category, RuleMeta, Severity, Stage};
    use crate::verdict::Status;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MINIMAL: &[u8] = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n%%EOF\n";

    /// Counts calls; reports once per dictionary.
    struct Probe {
        meta: &'static RuleMeta,
        calls: AtomicUsize,
    }

    impl Rule for Probe {
        fn meta(&self) -> &'static RuleMeta {
            self.meta
        }
        fn check_file(&self, _: &[u8], _: &mut Findings) {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
        fn check_dict(&self, _: &Dict, loc: &Location, _: &Ctx, out: &mut Findings) {
            self.calls.fetch_add(1, Ordering::Relaxed);
            out.report(self.meta, loc, None);
        }
        fn check_document(&self, _: &Ctx, _: &mut Findings) {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    const fn meta(id: &'static str, category: Category) -> RuleMeta {
        RuleMeta {
            id,
            category,
            severity: Severity::High,
            default_action: Action::Block,
            locked: false,
            stage: Stage::Stable,
            since: "0.1.0",
            message: "probe",
            description: "probe",
        }
    }

    static A: RuleMeta = meta("ACTIVE.QUELDA_A", Category::ActiveContent);
    static B: RuleMeta = meta("EMBED.QUELDA_B", Category::Embedded);
    static W: RuleMeta = meta("EXTERNAL.QUELDA_W", Category::External);

    fn probe(meta: &'static RuleMeta) -> &'static Probe {
        Box::leak(Box::new(Probe {
            meta,
            calls: AtomicUsize::new(0),
        }))
    }

    fn policy(json: &str) -> Policy {
        Policy::from_json(json).unwrap()
    }

    #[test]
    fn off_rules_are_not_called() {
        let (a, b) = (probe(&A), probe(&B));
        let rules: [&'static dyn Rule; 2] = [a, b];
        let v = scan_with(
            Ok(Input::slice(MINIMAL)),
            MINIMAL.len() as u64,
            &policy(r#"{"rules": {"ACTIVE.QUELDA_A": "off"}}"#),
            &rules,
        );
        assert_eq!(a.calls.load(Ordering::Relaxed), 0);
        assert!(b.calls.load(Ordering::Relaxed) > 0);
        assert_eq!(v.status, Status::Reject);
        let ids: Vec<_> = v.violations.iter().map(|v| v.rule_id).collect();
        assert_eq!(ids, ["EMBED.QUELDA_B"]);
        // Category off works the same way.
        let a = probe(&A);
        let rules: [&'static dyn Rule; 1] = [a];
        let v = scan_with(
            Ok(Input::slice(MINIMAL)),
            MINIMAL.len() as u64,
            &policy(r#"{"categories": {"active_content": "off"}}"#),
            &rules,
        );
        assert_eq!(a.calls.load(Ordering::Relaxed), 0);
        assert_eq!((v.status, v.valid), (Status::Pass, true));
    }

    #[test]
    fn stop_on_first_stops_after_first_block() {
        let (w, a, b) = (probe(&W), probe(&A), probe(&B));
        let rules: [&'static dyn Rule; 3] = [w, a, b];
        let full = scan_with(
            Ok(Input::slice(MINIMAL)),
            MINIMAL.len() as u64,
            &Policy::default(),
            &rules,
        );
        assert_eq!(full.violations.len(), 2);
        assert_eq!(full.violations[0].count, 2);
        assert_eq!(full.warnings.len(), 1);

        let (w, a, b) = (probe(&W), probe(&A), probe(&B));
        let rules: [&'static dyn Rule; 3] = [w, a, b];
        let v = scan_with(
            Ok(Input::slice(MINIMAL)),
            MINIMAL.len() as u64,
            &policy(r#"{"stop_on_first": true}"#),
            &rules,
        );
        assert_eq!(v.status, Status::Reject);
        assert!(v.policy.stop_on_first);
        let ids: Vec<_> = v.violations.iter().map(|v| v.rule_id).collect();
        assert_eq!(ids, ["ACTIVE.QUELDA_A"]);
        assert_eq!(v.violations[0].count, 1);
        // The warn rule ran before A on the first dict, B never reported.
        assert_eq!(v.warnings.len(), 1);
        assert_eq!(b.calls.load(Ordering::Relaxed), 1, "check_file only");
        // A warning alone does not stop the scan.
        let w = probe(&W);
        let rules: [&'static dyn Rule; 1] = [w];
        let v = scan_with(
            Ok(Input::slice(MINIMAL)),
            MINIMAL.len() as u64,
            &policy(r#"{"stop_on_first": true}"#),
            &rules,
        );
        assert_eq!(v.warnings[0].count, 2);
        assert_eq!(v.status, Status::Pass);
    }

    #[test]
    fn invalid_policy_json_is_an_error_verdict() {
        for bad in [
            "",
            "{",
            "[]",
            r#"{"preset": "x"}"#,
            r#"{"rules": {"NOPE.X": "off"}}"#,
        ] {
            let json: serde_json::Value = serde_json::from_str(&scan_json(MINIMAL, bad)).unwrap();
            assert_eq!(json["status"], "ERROR", "{bad}");
            assert_eq!(json["valid"], false);
            assert_eq!(json["errors"][0]["code"], "POLICY.INVALID");
            assert_eq!(json["stats"]["bytes"], MINIMAL.len());
        }
        // Parses but names an unknown rule: the policy info is known.
        let v = scan(MINIMAL, &policy(r#"{"rules": {"NOPE.X": "off"}}"#));
        assert_eq!(v.errors[0].code, "POLICY.INVALID");
        assert!(v.policy.digest.is_some());
    }

    #[test]
    fn file_too_large_is_not_parsed() {
        let v = scan(MINIMAL, &policy(r#"{"limits": {"max_file_bytes": 10}}"#));
        assert_eq!((v.status, v.valid), (Status::Error, false));
        assert_eq!(v.errors[0].code, "LIMIT.FILE_BYTES");
        assert_eq!(v.stats.objects, 0);
        let max = MINIMAL.len().to_string();
        let v = scan(
            MINIMAL,
            &policy(&format!(r#"{{"limits": {{"max_file_bytes": {max}}}}}"#)),
        );
        assert_eq!(v.status, Status::Pass);
    }

    #[test]
    fn scan_json_round_trip() {
        let json: serde_json::Value = serde_json::from_str(&scan_json(MINIMAL, "{}")).unwrap();
        assert_eq!(json["status"], "PASS");
        assert_eq!(json["valid"], true);
        assert_eq!(json["stats"]["objects"], 2);
        assert_eq!(json["policy"]["preset"], "balanced");
        assert_eq!(json["policy"]["digest"], Policy::default().digest());
        let v = scan(b"%!PS-Adobe-3.0\nshowpage\n", &Policy::default());
        assert_eq!(v.status, Status::Reject);
        assert!(
            v.violations
                .iter()
                .any(|v| v.rule_id == "FILETYPE.NOT_PDF_HEADER")
        );
    }

    #[test]
    fn list_rules_is_the_registry() {
        let ids: Vec<_> = list_rules().iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), rules::registry::all().len());
        assert!(ids.contains(&"ACTIVE.LAUNCH"));
    }

    #[test]
    fn list_rules_json_matches_list_rules() {
        let json: serde_json::Value = serde_json::from_str(&list_rules_json()).unwrap();
        let arr = json.as_array().unwrap();
        let rules = list_rules();
        assert_eq!(arr.len(), rules.len());
        for (j, r) in arr.iter().zip(&rules) {
            assert_eq!(j["id"], r.id);
            assert_eq!(j["category"], r.category.key());
            assert_eq!(j["severity"], r.severity.key());
            assert_eq!(j["default_action"], r.default_action.key());
            assert_eq!(j["locked"], r.locked);
            assert_eq!(j["stage"], r.stage.key());
            assert_eq!(j["since"], r.since);
            assert_eq!(j["message"], r.message);
            assert_eq!(j["description"], r.description);
            assert_eq!(j.as_object().unwrap().len(), 9);
        }
    }
}
