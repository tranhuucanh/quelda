//! Rules (design §5): detect only. A rule reads [`Ctx`] and reports
//! [`Finding`]s; it never parses bytes, never reads the policy and never
//! decides block/warn.
//!
//! Two kinds, one interface: declarative rules (`rules/*.toml`, generated into
//! [`declarative::DeclRule`]s) and code rules (one file per rule in
//! `src/rules/<category>/`, discovered by `build.rs`, ADR #19). See
//! `CONTRIBUTING.md`.

#[cfg(test)]
#[path = "../../build_support/rules_codegen.rs"]
mod codegen;
pub mod declarative;
pub mod meta;
pub mod registry;
pub(crate) mod values;

use std::collections::HashMap;

use crate::facts::{ContentOp, Ctx, Location, OpLocation, Visitor};
use crate::parser::Dict;
pub use meta::{Action, Category, RuleInfo, RuleMeta, Severity, Stage};

/// A rule. The engine traverses the scan data once and calls the hooks of
/// every active rule; a rule overrides only the hooks it needs.
pub trait Rule: Sync {
    fn meta(&self) -> &'static RuleMeta;

    /// L0: the start of the raw input (header, magic): at least its leading
    /// BOM/whitespace plus [`crate::facts::ctx::HEAD_TAIL`] bytes, the whole
    /// file when it is in memory (see [`Ctx::file_head`]). Facts about the
    /// rest of the file come from `Ctx` (e.g. `Ctx::signatures`).
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

    /// The hooks the engine calls; the others are skipped (they are the
    /// default no-ops). Code rules get this from `build.rs` ([`Hooked`]).
    fn hooks(&self) -> Hooks {
        Hooks::ALL
    }
}

/// Which [`Rule`] hooks a rule implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hooks {
    pub file: bool,
    pub dict: bool,
    pub content_op: bool,
    pub document: bool,
}

impl Hooks {
    pub const ALL: Hooks = Hooks {
        file: true,
        dict: true,
        content_op: true,
        document: true,
    };
}

/// A code rule with the hooks its file defines (generated registry).
pub struct Hooked {
    pub rule: &'static dyn Rule,
    pub hooks: Hooks,
}

impl Rule for Hooked {
    fn meta(&self) -> &'static RuleMeta {
        self.rule.meta()
    }
    fn check_file(&self, raw: &[u8], out: &mut Findings) {
        self.rule.check_file(raw, out);
    }
    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        self.rule.check_dict(dict, loc, ctx, out);
    }
    fn check_content_op(
        &self,
        op: &ContentOp<'_>,
        loc: &OpLocation,
        ctx: &Ctx,
        out: &mut Findings,
    ) {
        self.rule.check_content_op(op, loc, ctx, out);
    }
    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        self.rule.check_document(ctx, out);
    }
    fn hooks(&self) -> Hooks {
        self.hooks
    }
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
    /// A report from one of these rules stops the scan (`stop_on_first`).
    stop_on: Vec<&'static str>,
    stopped: bool,
}

impl Findings {
    pub fn new() -> Findings {
        Findings::default()
    }

    /// Findings that ask the engine to stop at the first report of any rule
    /// in `ids` (policy `stop_on_first`: the rules whose action is `block`).
    pub fn stopping_on(ids: Vec<&'static str>) -> Findings {
        Findings {
            stop_on: ids,
            ..Findings::default()
        }
    }

    /// A stop rule has reported: [`run_into`] calls no more hooks.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// Records that `rule` detected something at `site`. The rule does not
    /// choose an action or status (policy does).
    pub fn report(
        &mut self,
        rule: &'static RuleMeta,
        site: impl Into<Site>,
        detail: Option<String>,
    ) {
        if self.stop_on.contains(&rule.id) {
            self.stopped = true;
        }
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

/// Dispatches the single traversal to the rules implementing each hook.
struct Dispatch<'r, 'c, 'a> {
    dict_rules: Vec<&'r dyn Rule>,
    op_rules: Vec<&'r dyn Rule>,
    ctx: &'c Ctx<'a>,
    out: Findings,
}

impl Visitor for Dispatch<'_, '_, '_> {
    fn dict(&mut self, dict: &Dict, loc: &Location) {
        for r in &self.dict_rules {
            if self.out.stopped() {
                return;
            }
            r.check_dict(dict, loc, self.ctx, &mut self.out);
        }
    }

    fn content_op(&mut self, op: &ContentOp<'_>, loc: &OpLocation) {
        for r in &self.op_rules {
            if self.out.stopped() {
                return;
            }
            r.check_content_op(op, loc, self.ctx, &mut self.out);
        }
    }

    fn done(&self) -> bool {
        self.out.stopped()
    }
}

/// Runs `rules` over one scan: `check_file`, then one traversal
/// (`check_dict`, `check_content_op`), then `check_document`. Which rules
/// run is the caller's choice (policy: rules with action `off` are left out).
pub fn run(ctx: &Ctx, rules: &[&dyn Rule]) -> Findings {
    run_into(ctx, rules, Findings::new())
}

/// [`run`] into `out`; stops calling hooks once [`Findings::stopped`].
pub fn run_into(ctx: &Ctx, rules: &[&dyn Rule], out: Findings) -> Findings {
    let with = |hook: fn(Hooks) -> bool| -> Vec<&dyn Rule> {
        rules.iter().copied().filter(|r| hook(r.hooks())).collect()
    };
    let mut d = Dispatch {
        dict_rules: with(|h| h.dict),
        op_rules: with(|h| h.content_op),
        ctx,
        out,
    };
    for r in with(|h| h.file) {
        if d.out.stopped() {
            return d.out;
        }
        r.check_file(ctx.file_head(), &mut d.out);
    }
    ctx.walk(&mut d);
    for r in with(|h| h.document) {
        if d.out.stopped() {
            return d.out;
        }
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
    fn stops_at_first_report_of_a_stop_rule() {
        static STOP: RuleMeta = RuleMeta {
            id: "STRUCT.QUELDA_STOP",
            ..META
        };
        /// Reports `STOP` on the second dictionary it sees.
        #[derive(Default)]
        struct Second(AtomicUsize);
        impl Rule for Second {
            fn meta(&self) -> &'static RuleMeta {
                &STOP
            }
            fn check_dict(&self, _: &Dict, loc: &Location, _: &Ctx, out: &mut Findings) {
                if self.0.fetch_add(1, Ordering::Relaxed) == 1 {
                    out.report(&STOP, loc, None);
                }
            }
        }
        let ctx = Ctx::new(SRC, Limits::default(), Thresholds::default());
        let (p, s) = (Probe::default(), Second::default());
        let f = run_into(&ctx, &[&s, &p], Findings::stopping_on(vec![STOP.id]));
        assert!(f.stopped());
        assert_eq!(f.count(STOP.id), 1);
        // Probe saw the file and the first dict only: not the dict where
        // STOP fired, no ops, no document.
        assert_eq!(p.file.load(Ordering::Relaxed), 1);
        assert_eq!(p.dicts.load(Ordering::Relaxed), 1);
        assert_eq!(p.ops.load(Ordering::Relaxed), 0);
        assert_eq!(p.document.load(Ordering::Relaxed), 0);
        assert_eq!(s.0.load(Ordering::Relaxed), 2);

        // A report by a non-stop rule does not stop; stop in check_file
        // skips everything after.
        let p = Probe::default();
        let f = run_into(&ctx, &[&p], Findings::stopping_on(vec![STOP.id]));
        assert!(!f.stopped());
        assert_eq!(p.document.load(Ordering::Relaxed), 1);
        let (p, q) = (Probe::default(), Probe::default());
        let f = run_into(&ctx, &[&p, &q], Findings::stopping_on(vec![META.id]));
        assert!(f.stopped());
        assert_eq!(f.count(META.id), 1);
        assert_eq!(q.file.load(Ordering::Relaxed), 0);
        assert_eq!(p.dicts.load(Ordering::Relaxed), 0);
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
