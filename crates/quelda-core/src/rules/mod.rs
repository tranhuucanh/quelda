//! Rules (design §5): detect only. A rule reads [`Ctx`] and reports
//! [`Finding`]s; it never parses bytes, never reads the policy and never
//! decides block/warn.
//!
//! Two kinds, one interface: declarative rules (`rules/*.toml`, generated into
//! [`declarative::DeclRule`]s) and code rules (one file per rule in
//! `src/rules/<category>/`, discovered by `build.rs`, ADR #19). See
//! `docs/ADDING_A_RULE.md`.

#[cfg(test)]
#[path = "../../build_support/rules_codegen.rs"]
mod codegen;
pub mod declarative;
pub mod meta;
pub mod registry;

use std::collections::HashMap;

use crate::facts::{ContentOp, Ctx, Location, OpLocation, Visitor};
use crate::parser::Dict;
pub use meta::{Action, Category, RuleInfo, RuleMeta, Severity, Stage};

/// A rule. The engine traverses the scan data once and calls the hooks of
/// every active rule; a rule overrides only the hooks it needs.
pub trait Rule: Sync {
    fn meta(&self) -> &'static RuleMeta;

    /// L0: the raw input bytes (header, magic, polyglots).
    fn check_file(&self, _raw: &[u8], _out: &mut Findings) {}

    /// Every dictionary in the union set: top-level, nested, stream
    /// dictionaries, object stream members, every revision.
    fn check_dict(&self, _dict: &Dict, _loc: &Location, _ctx: &Ctx, _out: &mut Findings) {}

    /// Every operator of every content stream (known and speculative).
    fn check_content_op(
        &self,
        _op: &ContentOp<'_>,
        _loc: &OpLocation,
        _ctx: &Ctx,
        _out: &mut Findings,
    ) {
    }

    /// After the traversal: whole-document checks (counts, revisions,
    /// relations between objects).
    fn check_document(&self, _ctx: &Ctx, _out: &mut Findings) {}
}

/// Where a finding is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Site {
    /// A byte offset in the input.
    Offset(usize),
    /// A dictionary (or the object it belongs to).
    Object(Location),
    /// A content operator.
    Op(OpLocation),
    /// The document as a whole.
    Document,
}

impl From<&Location> for Site {
    fn from(l: &Location) -> Site {
        Site::Object(l.clone())
    }
}

impl From<&OpLocation> for Site {
    fn from(l: &OpLocation) -> Site {
        Site::Op(l.clone())
    }
}

/// One detection.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub rule: &'static RuleMeta,
    pub site: Site,
    /// Extra context (e.g. the value that matched), if any.
    pub detail: Option<String>,
}

/// Locations kept per rule; further hits are only counted (ADR #19).
pub const MAX_FINDINGS_PER_RULE: usize = 64;

/// What rules report during one scan.
#[derive(Debug, Default)]
pub struct Findings {
    items: Vec<Finding>,
    /// Hits per rule ID, including the ones not kept.
    counts: HashMap<&'static str, u64>,
}

impl Findings {
    pub fn new() -> Findings {
        Findings::default()
    }

    /// Records that `rule` detected something at `site`. The rule does not
    /// choose an action or status (policy does).
    pub fn report(
        &mut self,
        rule: &'static RuleMeta,
        site: impl Into<Site>,
        detail: Option<String>,
    ) {
        let n = self.counts.entry(rule.id).or_insert(0);
        *n += 1;
        if *n <= MAX_FINDINGS_PER_RULE as u64 {
            self.items.push(Finding {
                rule,
                site: site.into(),
                detail,
            });
        }
    }

    /// Kept findings, in report order.
    pub fn iter(&self) -> impl Iterator<Item = &Finding> {
        self.items.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Kept findings (at most [`MAX_FINDINGS_PER_RULE`] per rule).
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Total hits of rule `id` (kept or not).
    pub fn count(&self, id: &str) -> u64 {
        self.counts.get(id).copied().unwrap_or(0)
    }

    pub fn fired(&self, id: &str) -> bool {
        self.count(id) > 0
    }

    /// IDs of the rules that fired, sorted.
    pub fn rule_ids(&self) -> Vec<&'static str> {
        let mut v: Vec<_> = self.counts.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

/// Dispatches the single traversal to every rule.
struct Dispatch<'r, 'c, 'a> {
    rules: &'r [&'r dyn Rule],
    ctx: &'c Ctx<'a>,
    out: Findings,
}

impl Visitor for Dispatch<'_, '_, '_> {
    fn dict(&mut self, dict: &Dict, loc: &Location) {
        for r in self.rules {
            r.check_dict(dict, loc, self.ctx, &mut self.out);
        }
    }

    fn content_op(&mut self, op: &ContentOp<'_>, loc: &OpLocation) {
        for r in self.rules {
            r.check_content_op(op, loc, self.ctx, &mut self.out);
        }
    }
}

/// Runs `rules` over one scan: `check_file`, then one traversal
/// (`check_dict`, `check_content_op`), then `check_document`. Which rules
/// run is the caller's choice (policy: rules with action `off` are left out).
pub fn run(ctx: &Ctx, rules: &[&dyn Rule]) -> Findings {
    let mut d = Dispatch {
        rules,
        ctx,
        out: Findings::new(),
    };
    for r in rules {
        r.check_file(ctx.raw(), &mut d.out);
    }
    ctx.walk(&mut d);
    for r in rules {
        r.check_document(ctx, &mut d.out);
    }
    d.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static META: RuleMeta = RuleMeta {
        id: "STRUCT.QUELDA_TEST",
        category: Category::Structure,
        severity: Severity::Info,
        default_action: Action::Warn,
        locked: false,
        stage: Stage::Preview,
        since: "0.1.0",
        message: "test",
        description: "test",
    };

    /// Counts hook calls; reports one finding per hook.
    #[derive(Default)]
    struct Probe {
        file: AtomicUsize,
        dicts: AtomicUsize,
        ops: AtomicUsize,
        document: AtomicUsize,
    }

    impl Rule for Probe {
        fn meta(&self) -> &'static RuleMeta {
            &META
        }
        fn check_file(&self, raw: &[u8], out: &mut Findings) {
            self.file.fetch_add(1, Ordering::Relaxed);
            out.report(&META, Site::Offset(raw.len()), Some("file".into()));
        }
        fn check_dict(&self, _: &Dict, loc: &Location, _: &Ctx, out: &mut Findings) {
            self.dicts.fetch_add(1, Ordering::Relaxed);
            out.report(&META, loc, None);
        }
        fn check_content_op(
            &self,
            _: &ContentOp<'_>,
            loc: &OpLocation,
            _: &Ctx,
            out: &mut Findings,
        ) {
            self.ops.fetch_add(1, Ordering::Relaxed);
            out.report(&META, loc, None);
        }
        fn check_document(&self, _: &Ctx, out: &mut Findings) {
            self.document.fetch_add(1, Ordering::Relaxed);
            out.report(&META, Site::Document, None);
        }
    }

    /// Implements no hook.
    struct Silent;
    impl Rule for Silent {
        fn meta(&self) -> &'static RuleMeta {
            &META
        }
    }

    const SRC: &[u8] = b"1 0 obj << /Contents 2 0 R /A << >> >> endobj\n2 0 obj << /Length 6 >> stream\nq 1 w\nendstream endobj";

    #[test]
    fn hooks_called_in_order() {
        let ctx = Ctx::new(SRC, Limits::default(), Thresholds::default());
        let p = Probe::default();
        let f = run(&ctx, &[&p, &Silent]);
        assert_eq!(p.file.load(Ordering::Relaxed), 1);
        assert_eq!(p.dicts.load(Ordering::Relaxed), 3);
        assert_eq!(p.ops.load(Ordering::Relaxed), 2);
        assert_eq!(p.document.load(Ordering::Relaxed), 1);
        let sites: Vec<_> = f
            .iter()
            .map(|f| match &f.site {
                Site::Offset(_) => "file",
                Site::Object(_) => "dict",
                Site::Op(_) => "op",
                Site::Document => "doc",
            })
            .collect();
        assert_eq!(sites, ["file", "dict", "dict", "dict", "op", "op", "doc"]);
        assert_eq!(f.iter().next().unwrap().detail.as_deref(), Some("file"));
        assert_eq!(f.count("STRUCT.QUELDA_TEST"), 7);
        assert_eq!(f.rule_ids(), vec!["STRUCT.QUELDA_TEST"]);
    }

    #[test]
    fn no_rules_no_findings() {
        let ctx = Ctx::new(SRC, Limits::default(), Thresholds::default());
        let f = run(&ctx, &[]);
        assert!(f.is_empty());
        assert!(!f.fired("STRUCT.QUELDA_TEST"));
        assert!(run(&ctx, &[&Silent]).is_empty());
    }

    #[test]
    fn findings_capped_per_rule_but_counted() {
        static OTHER: RuleMeta = RuleMeta {
            id: "STRUCT.QUELDA_OTHER",
            ..META
        };
        let mut f = Findings::new();
        for i in 0..1000 {
            f.report(&META, Site::Offset(i), None);
        }
        f.report(&OTHER, Site::Document, None);
        assert_eq!(f.len(), MAX_FINDINGS_PER_RULE + 1);
        assert_eq!(f.count(META.id), 1000);
        assert_eq!(f.count(OTHER.id), 1);
        assert_eq!(f.count("X.Y"), 0);
        assert_eq!(
            f.rule_ids(),
            vec!["STRUCT.QUELDA_OTHER", "STRUCT.QUELDA_TEST"]
        );
        let kept: Vec<_> = f
            .iter()
            .filter(|x| x.rule.id == META.id)
            .map(|x| x.site.clone())
            .collect();
        assert_eq!(kept.last(), Some(&Site::Offset(MAX_FINDINGS_PER_RULE - 1)));
    }
}
