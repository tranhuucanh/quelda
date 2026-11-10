//! Verdict (design §7): the JSON contract every binding returns.
//!
//! `status` is `ERROR` when the engine could not inspect everything (engine
//! issue, invalid policy), else `REJECT` when a finding resolves to `block`,
//! else `PASS`; `valid` is `status == PASS`. Findings are grouped per rule
//! (sorted by ID) with the total count and up to
//! [`MAX_FINDINGS_PER_RULE`](crate::rules::MAX_FINDINGS_PER_RULE) locations.
//! Schema: `schemas/verdict.schema.json`.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::error::{EngineIssue, IssueCode};
use crate::facts::{Location, PathSeg};
use crate::parser::document::{Location as Source, ObjectEntry};
use crate::policy::{Policy, Preset, resolve};
use crate::rules::{Action, Category, Findings, Severity, Site};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Pass,
    Reject,
    Error,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Verdict {
    pub valid: bool,
    pub status: Status,
    /// Rules that fired with action `block`.
    pub violations: Vec<Violation>,
    /// Rules that fired with action `warn` (do not make the file invalid).
    pub warnings: Vec<Violation>,
    /// Engine issues and policy errors; any makes the status `ERROR`.
    pub errors: Vec<VerdictError>,
    pub engine_version: &'static str,
    pub policy: PolicyInfo,
    pub stats: Stats,
}

/// One rule that fired.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Violation {
    pub rule_id: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub action: Action,
    pub message: &'static str,
    /// Every hit, including those beyond the kept locations.
    pub count: u64,
    /// Where (document-level findings have none).
    pub locations: Vec<VerdictLocation>,
}

/// Where a finding is. Every field is optional.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct VerdictLocation {
    /// `"N G"` of the object holding the dictionary (or content stream).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Byte offset in the file: of the object, of its object stream when it
    /// is in one, or of the finding itself (file-level rules).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// `"file"` or `"objstm:N"` (member of object stream `N`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// From the object to the nested dictionary, e.g. `/AA/O`, `/Annots[2]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Offset of a content operator in the decoded stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_offset: Option<u64>,
    /// Extra context from the rule (e.g. the value that matched).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerdictError {
    /// `LIMIT.*`, `ENGINE.*` or `POLICY.INVALID`.
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// The policy the verdict was made with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyInfo {
    /// `null` when the policy could not be parsed.
    pub preset: Option<Preset>,
    /// `sha256:…` of the canonical policy; `null` when it could not be parsed.
    pub digest: Option<String>,
    pub unsafe_allow_unlock: bool,
    pub stop_on_first: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub bytes: u64,
    /// Object definitions in the union set.
    pub objects: u64,
    pub revisions: u64,
    pub decoded_bytes: u64,
    /// Wall time of the scan; `0` where the platform has no clock
    /// (wasm32-unknown-unknown).
    pub duration_ms: u64,
}

impl PolicyInfo {
    pub fn of(policy: &Policy) -> PolicyInfo {
        PolicyInfo {
            preset: Some(policy.preset()),
            digest: Some(policy.digest()),
            unsafe_allow_unlock: policy.unsafe_allow_unlock(),
            stop_on_first: policy.stop_on_first(),
        }
    }

    /// For a policy that could not be parsed.
    pub fn unknown() -> PolicyInfo {
        PolicyInfo {
            preset: None,
            digest: None,
            unsafe_allow_unlock: false,
            stop_on_first: false,
        }
    }
}

impl Verdict {
    /// The verdict of a scan: findings of the rules that ran (none `off`)
    /// mapped through `policy`, and every engine issue.
    pub fn new(
        findings: &Findings,
        issues: &[EngineIssue],
        objects: &[ObjectEntry],
        policy: &Policy,
        stats: Stats,
    ) -> Verdict {
        let mut by_rule: BTreeMap<&'static str, Violation> = BTreeMap::new();
        for f in findings.iter() {
            let m = f.rule;
            let v = by_rule.entry(m.id).or_insert_with(|| Violation {
                rule_id: m.id,
                category: m.category,
                severity: m.severity,
                action: resolve(m, policy),
                message: m.message,
                count: findings.count(m.id),
                locations: Vec::new(),
            });
            if let Some(mut loc) = location(&f.site, objects) {
                loc.detail.clone_from(&f.detail);
                v.locations.push(loc);
            }
        }
        let (mut violations, mut warnings) = (Vec::new(), Vec::new());
        for v in by_rule.into_values() {
            match v.action {
                Action::Block => violations.push(v),
                Action::Warn => warnings.push(v),
                Action::Off => {}
            }
        }
        let errors = issues.iter().map(VerdictError::from).collect();
        Verdict::assemble(violations, warnings, errors, PolicyInfo::of(policy), stats)
    }

    /// A verdict that stops before scanning (invalid policy, file too large).
    pub fn error(issue: &EngineIssue, policy: PolicyInfo, bytes: u64) -> Verdict {
        Verdict::assemble(
            Vec::new(),
            Vec::new(),
            vec![VerdictError::from(issue)],
            policy,
            Stats {
                bytes,
                ..Stats::default()
            },
        )
    }

    fn assemble(
        violations: Vec<Violation>,
        warnings: Vec<Violation>,
        errors: Vec<VerdictError>,
        policy: PolicyInfo,
        stats: Stats,
    ) -> Verdict {
        let status = if !errors.is_empty() {
            Status::Error
        } else if !violations.is_empty() {
            Status::Reject
        } else {
            Status::Pass
        };
        Verdict {
            valid: status == Status::Pass,
            status,
            violations,
            warnings,
            errors,
            engine_version: crate::VERSION,
            policy,
            stats,
        }
    }

    /// The verdict as JSON (the contract of `scan_json`).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            // Unreachable for these types; still never panic and never PASS.
            format!(
                "{{\"valid\":false,\"status\":\"ERROR\",\"violations\":[],\"warnings\":[],\"errors\":[{{\"code\":\"ENGINE.PARSE\",\"message\":{:?}}}],\"engine_version\":{:?},\"policy\":{{\"preset\":null,\"digest\":null,\"unsafe_allow_unlock\":false,\"stop_on_first\":false}},\"stats\":{{\"bytes\":0,\"objects\":0,\"revisions\":0,\"decoded_bytes\":0,\"duration_ms\":0}}}}",
                format!("verdict serialization failed: {e}"),
                crate::VERSION
            )
        })
    }
}

impl From<&EngineIssue> for VerdictError {
    fn from(i: &EngineIssue) -> VerdictError {
        VerdictError {
            code: i.code.as_str(),
            message: i.message.clone(),
            offset: i.offset.map(|o| o as u64),
        }
    }
}

/// Convenience for the error verdicts built by `scan`.
pub(crate) fn issue(code: IssueCode, message: String) -> EngineIssue {
    EngineIssue::new(code, None, message)
}

fn location(site: &Site, objects: &[ObjectEntry]) -> Option<VerdictLocation> {
    match site {
        Site::Offset(o) => Some(VerdictLocation {
            offset: Some(*o as u64),
            source: Some("file".into()),
            ..VerdictLocation::default()
        }),
        Site::Object(loc) => Some(object_location(loc, objects)),
        Site::Op(op) => Some(VerdictLocation {
            op_offset: Some(op.offset as u64),
            ..object_location(&op.stream, objects)
        }),
        Site::Document => None,
    }
}

fn object_location(loc: &Location, objects: &[ObjectEntry]) -> VerdictLocation {
    let (offset, source) = match loc.source {
        Source::File { offset } => (Some(offset as u64), "file".to_string()),
        Source::ObjStm { container, .. } => match objects.get(container) {
            Some(c) => {
                let offset = match c.location {
                    Source::File { offset } => Some(offset as u64),
                    Source::ObjStm { .. } => None,
                };
                (offset, format!("objstm:{}", c.id.num))
            }
            None => (None, "objstm".to_string()),
        },
    };
    VerdictLocation {
        object: Some(format!("{} {}", loc.id.num, loc.id.generation)),
        offset,
        source: Some(source),
        path: (!loc.path.is_empty()).then(|| path(&loc.path)),
        ..VerdictLocation::default()
    }
}

/// `/Key` per key (bytes outside printable ASCII and PDF delimiters as
/// `#xx`), `[i]` per array index.
fn path(segs: &[PathSeg]) -> String {
    let mut s = String::new();
    for seg in segs {
        match seg {
            PathSeg::Key(name) => {
                s.push('/');
                for &b in name.as_bytes() {
                    if b.is_ascii_graphic() && !b"#/()<>[]{}%".contains(&b) {
                        s.push(char::from(b));
                    } else {
                        s.push_str(&format!("#{b:02x}"));
                    }
                }
            }
            PathSeg::Index(i) => s.push_str(&format!("[{i}]")),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::OpLocation;
    use crate::parser::{Name, ObjRef, PdfObject};
    use crate::rules::{RuleMeta, Stage};

    static BLOCK: RuleMeta = RuleMeta {
        id: "ACTIVE.LAUNCH",
        category: Category::ActiveContent,
        severity: Severity::Critical,
        default_action: Action::Block,
        locked: true,
        stage: Stage::Stable,
        since: "0.1.0",
        message: "launch",
        description: "d",
    };
    static WARN: RuleMeta = RuleMeta {
        id: "EXTERNAL.URI",
        category: Category::External,
        severity: Severity::Low,
        default_action: Action::Warn,
        locked: false,
        ..BLOCK
    };

    fn entry(num: u32, location: Source) -> ObjectEntry {
        ObjectEntry {
            id: ObjRef::new(num, 0),
            location,
            object: PdfObject::Null,
            revision: None,
            has_endobj: true,
            linear: true,
            listed_in: Vec::new(),
        }
    }

    fn objects() -> Vec<ObjectEntry> {
        vec![
            entry(7, Source::File { offset: 100 }),
            entry(
                12,
                Source::ObjStm {
                    container: 0,
                    index: 3,
                    offset: 40,
                },
            ),
        ]
    }

    fn loc(object: usize, objs: &[ObjectEntry], path: Vec<PathSeg>) -> Location {
        Location {
            path,
            ..Location::of(object, &objs[object])
        }
    }

    #[test]
    fn status_from_findings_and_issues() {
        let objs = objects();
        let p = Policy::default();
        let empty = Verdict::new(&Findings::new(), &[], &objs, &p, Stats::default());
        assert_eq!((empty.status, empty.valid), (Status::Pass, true));

        let mut f = Findings::new();
        f.report(&WARN, Site::Document, None);
        let v = Verdict::new(&f, &[], &objs, &p, Stats::default());
        assert_eq!((v.status, v.valid), (Status::Pass, true));
        assert_eq!(v.warnings[0].rule_id, "EXTERNAL.URI");
        assert!(v.warnings[0].locations.is_empty());

        f.report(&BLOCK, Site::Offset(5), None);
        let v = Verdict::new(&f, &[], &objs, &p, Stats::default());
        assert_eq!((v.status, v.valid), (Status::Reject, false));
        assert_eq!(v.violations.len(), 1);

        let issue = EngineIssue::new(IssueCode::LimitDecodedBytes, Some(9), "too much");
        let v = Verdict::new(&f, &[issue], &objs, &p, Stats::default());
        assert_eq!((v.status, v.valid), (Status::Error, false));
        assert_eq!(
            v.errors,
            vec![VerdictError {
                code: "LIMIT.DECODED_BYTES",
                message: "too much".into(),
                offset: Some(9)
            }]
        );
        // Findings are still reported alongside the error.
        assert_eq!(v.violations.len(), 1);
    }

    #[test]
    fn action_comes_from_policy() {
        let objs = objects();
        let mut f = Findings::new();
        f.report(&WARN, Site::Document, None);
        let strict = Policy {
            preset: Some(Preset::Strict),
            ..Policy::default()
        };
        let v = Verdict::new(&f, &[], &objs, &strict, Stats::default());
        assert_eq!(v.status, Status::Reject);
        assert_eq!(v.violations[0].action, Action::Block);
        assert!(v.warnings.is_empty());
    }

    #[test]
    fn grouped_per_rule_sorted_with_count_and_locations() {
        let objs = objects();
        let mut f = Findings::new();
        for i in 0..100 {
            f.report(&BLOCK, Site::Offset(i), None);
        }
        f.report(
            &WARN,
            &loc(
                1,
                &objs,
                vec![PathSeg::Key(Name::from("AA")), PathSeg::Index(2)],
            ),
            Some("x".into()),
        );
        let strict = Policy {
            preset: Some(Preset::Strict),
            ..Policy::default()
        };
        let v = Verdict::new(&f, &[], &objs, &strict, Stats::default());
        let ids: Vec<_> = v.violations.iter().map(|v| v.rule_id).collect();
        assert_eq!(ids, ["ACTIVE.LAUNCH", "EXTERNAL.URI"]);
        assert_eq!(v.violations[0].count, 100);
        assert_eq!(
            v.violations[0].locations.len(),
            crate::rules::MAX_FINDINGS_PER_RULE
        );
        assert_eq!(
            v.violations[1].locations,
            vec![VerdictLocation {
                object: Some("12 0".into()),
                offset: Some(100),
                source: Some("objstm:7".into()),
                path: Some("/AA[2]".into()),
                detail: Some("x".into()),
                op_offset: None,
            }]
        );
    }

    #[test]
    fn locations() {
        let objs = objects();
        assert_eq!(
            location(&Site::Offset(3), &objs),
            Some(VerdictLocation {
                offset: Some(3),
                source: Some("file".into()),
                ..VerdictLocation::default()
            })
        );
        assert_eq!(location(&Site::Document, &objs), None);
        let op = OpLocation {
            stream: loc(0, &objs, Vec::new()),
            offset: 17,
            speculative: false,
        };
        assert_eq!(
            location(&Site::Op(op), &objs),
            Some(VerdictLocation {
                object: Some("7 0".into()),
                offset: Some(100),
                source: Some("file".into()),
                op_offset: Some(17),
                ..VerdictLocation::default()
            })
        );
        // Container that is itself in an object stream: no file offset.
        let mut nested = objects();
        nested[0].location = Source::ObjStm {
            container: 1,
            index: 0,
            offset: 0,
        };
        let l = object_location(&loc(1, &nested, Vec::new()), &nested);
        assert_eq!((l.offset, l.source.as_deref()), (None, Some("objstm:7")));
    }

    #[test]
    fn path_escapes_odd_name_bytes() {
        let segs = vec![
            PathSeg::Key(Name::new(b"A B#/\xff".to_vec())),
            PathSeg::Index(0),
            PathSeg::Key(Name::from("JS")),
        ];
        assert_eq!(path(&segs), "/A#20B#23#2f#ff[0]/JS");
    }

    #[test]
    fn error_verdict() {
        let i = issue(IssueCode::PolicyInvalid, "invalid policy: x".into());
        let v = Verdict::error(&i, PolicyInfo::unknown(), 10);
        assert_eq!((v.status, v.valid), (Status::Error, false));
        assert_eq!(v.errors[0].code, "POLICY.INVALID");
        assert_eq!(v.stats.bytes, 10);
        let json: serde_json::Value = serde_json::from_str(&v.to_json()).unwrap();
        assert_eq!(json["policy"]["digest"], serde_json::Value::Null);
        assert_eq!(json["status"], "ERROR");
        assert_eq!(json["valid"], false);
        assert!(json["errors"][0].get("offset").is_none());
    }

    #[test]
    fn json_shape() {
        let objs = objects();
        let mut f = Findings::new();
        f.report(&BLOCK, &loc(0, &objs, Vec::new()), None);
        let v = Verdict::new(
            &f,
            &[],
            &objs,
            &Policy::default(),
            Stats {
                bytes: 1,
                objects: 2,
                revisions: 3,
                decoded_bytes: 4,
                duration_ms: 5,
            },
        );
        let json: serde_json::Value = serde_json::from_str(&v.to_json()).unwrap();
        let keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        let mut want = vec![
            "valid",
            "status",
            "violations",
            "warnings",
            "errors",
            "engine_version",
            "policy",
            "stats",
        ];
        want.sort_unstable();
        let mut keys = keys;
        keys.sort();
        assert_eq!(keys, want);
        assert_eq!(json["status"], "REJECT");
        let viol = &json["violations"][0];
        assert_eq!(viol["rule_id"], "ACTIVE.LAUNCH");
        assert_eq!(viol["category"], "active_content");
        assert_eq!(viol["severity"], "critical");
        assert_eq!(viol["action"], "block");
        assert_eq!(viol["count"], 1);
        assert_eq!(
            viol["locations"][0],
            serde_json::json!({"object": "7 0", "offset": 100, "source": "file"})
        );
        assert_eq!(json["policy"]["preset"], "balanced");
        assert_eq!(json["stats"]["duration_ms"], 5);
        assert_eq!(json["engine_version"], crate::VERSION);
    }
}
