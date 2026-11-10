//! `ACTIVE.OPEN_ACTION`: the document runs an action, other than going to a
//! page, when it is opened (ADR #26).

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::values;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct OpenAction;

static META: RuleMeta = RuleMeta {
    id: "ACTIVE.OPEN_ACTION",
    category: Category::ActiveContent,
    severity: Severity::Medium,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "Document runs an action when opened",
    description: "A dictionary's /OpenAction (ISO 32000-2 §7.7.2) is an action performed \
        automatically when the document is opened: an action dictionary whose /S is not \
        GoTo, or any action with a /Next chain, or a value that is not a destination array \
        or an action dictionary (unresolved reference included). Every definition of an \
        indirect value counts. A destination array or a plain GoTo action only opens the \
        document at a page and is not reported; dangerous actions (JavaScript, Launch, \
        URI, SubmitForm…) are also reported by their own rules wherever they are.",
};

/// What makes one (resolved) `/OpenAction` value worth reporting.
fn problem(ctx: &Ctx, value: &PdfObject) -> Option<String> {
    match value {
        PdfObject::Null | PdfObject::Array(_) => None,
        PdfObject::Dict(d) => action_problem(ctx, d),
        other => Some(format!("value is a {}", other.type_name())),
    }
}

fn action_problem(ctx: &Ctx, d: &Dict) -> Option<String> {
    if d.contains_key("Next") {
        return Some("action with /Next".to_string());
    }
    let mut kinds = values(ctx, d, "S").peekable();
    if kinds.peek().is_none() {
        return Some("action without /S".to_string());
    }
    kinds.find(|s| !s.is_name("GoTo")).map(|s| match s.as_name() {
        Some(n) => format!("action /S /{}", String::from_utf8_lossy(n.as_bytes())),
        None => format!("action /S is a {}", s.type_name()),
    })
}

impl Rule for OpenAction {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        for raw in dict.get_all("OpenAction") {
            let found = match raw.as_reference() {
                Some(r) if ctx.resolve(raw).next().is_none() => {
                    Some(format!("unresolved reference {} {} R", r.num, r.generation))
                }
                _ => ctx.resolve(raw).find_map(|v| problem(ctx, v)),
            };
            if let Some(detail) = found {
                out.report(&META, loc, Some(detail));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn details(src: &str) -> Vec<Option<String>> {
        let ctx = Ctx::new(src.as_bytes(), Limits::default(), Thresholds::default());
        run(&ctx, &[&OpenAction])
            .iter()
            .map(|f| f.detail.clone())
            .collect()
    }

    fn detail(src: &str) -> Option<String> {
        let d = details(src);
        assert!(d.len() <= 1, "{d:?}");
        d.into_iter().next().flatten()
    }

    #[test]
    fn destinations_and_goto_are_not_reported() {
        for src in [
            "1 0 obj << /OpenAction [3 0 R /Fit] >> endobj",
            "1 0 obj << /OpenAction [3 0 R /FitH -32768] >> endobj",
            "1 0 obj << /OpenAction << /S /GoTo /D [4 0 R /FitH 0] >> >> endobj",
            "1 0 obj << /OpenAction << /S /G#6fTo /D (chapter1) >> >> endobj",
            "1 0 obj << /OpenAction 5 0 R >> endobj\n5 0 obj [3 0 R /XYZ 0 792 0] endobj",
            "1 0 obj << /OpenAction 5 0 R >> endobj\n5 0 obj << /S /GoTo /D [3 0 R /Fit] >> endobj",
            "1 0 obj << /OpenAction << /S 6 0 R /D [3 0 R /Fit] >> >> endobj\n6 0 obj /GoTo endobj",
            "1 0 obj << /OpenAction null >> endobj",
            "1 0 obj << /Type /Catalog >> endobj",
        ] {
            assert!(details(src).is_empty(), "{src}");
        }
    }

    #[test]
    fn other_actions_are_reported() {
        let cases = [
            (
                "1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj",
                "action /S /JavaScript",
            ),
            (
                "1 0 obj << /OpenAction << /S /Thread /D 0 >> >> endobj",
                "action /S /Thread",
            ),
            // Name encoded: decoded by the parser.
            (
                "1 0 obj << /Open#41ction << /S /#4Camp#68 >> >> endobj",
                "action /S /Lamph",
            ),
            (
                "1 0 obj << /OpenAction 5 0 R >> endobj\n5 0 obj << /S /Launch /F (x) >> endobj",
                "action /S /Launch",
            ),
            (
                "1 0 obj << /OpenAction << /S /GoTo /D [3 0 R /Fit] /Next << /S /JavaScript /JS (x) >> >> >> endobj",
                "action with /Next",
            ),
            (
                "1 0 obj << /OpenAction << /S /GoTo /D [3 0 R /Fit] /Next 7 0 R >> >> endobj",
                "action with /Next",
            ),
            (
                "1 0 obj << /OpenAction << /D [3 0 R /Fit] >> >> endobj",
                "action without /S",
            ),
            (
                "1 0 obj << /OpenAction << /S (GoTo) >> >> endobj",
                "action /S is a string",
            ),
            (
                "1 0 obj << /OpenAction << /S 6 0 R >> >> endobj\n6 0 obj /GoTo endobj\n6 0 obj /URI endobj",
                "action /S /URI",
            ),
            (
                "1 0 obj << /OpenAction 9 0 R >> endobj",
                "unresolved reference 9 0 R",
            ),
            (
                "1 0 obj << /OpenAction 5 0 R >> endobj\n5 0 obj 6 0 R endobj",
                "value is a reference",
            ),
            (
                "1 0 obj << /OpenAction (dest) >> endobj",
                "value is a string",
            ),
            (
                "1 0 obj << /OpenAction /Named >> endobj",
                "value is a name",
            ),
            // Union: any definition, any duplicate key.
            (
                "1 0 obj << /OpenAction 5 0 R >> endobj\n5 0 obj [3 0 R /Fit] endobj\n5 0 obj << /S /Named /N /Print >> endobj",
                "action /S /Named",
            ),
            (
                "1 0 obj << /OpenAction [3 0 R /Fit] /OpenAction << /S /Hide >> >> endobj",
                "action /S /Hide",
            ),
            // Nested dictionary.
            (
                "1 0 obj << /Q << /OpenAction << /S /SubmitForm >> >> >> endobj",
                "action /S /SubmitForm",
            ),
        ];
        for (src, expected) in cases {
            assert_eq!(detail(src).as_deref(), Some(expected), "{src}");
        }
    }
}
