//! Declarative rules (design §5.4): `rules/*.toml`, turned into static
//! [`DeclRule`]s by `build.rs`. A new match kind = a variant here + parsing and
//! codegen in `build_support/rules_codegen.rs`.

use super::meta::RuleMeta;
use super::{Findings, Hooks, Rule};
use crate::facts::{ContentOp, Ctx, Location, OpLocation};
use crate::parser::{Dict, PdfObject};

/// What a declarative rule looks for.
#[derive(Clone, Copy, Debug)]
pub enum Match {
    /// Any dictionary in the union set (`check_dict`).
    Dict(DictMatch),
    /// A content stream operator (`check_content_op`).
    ContentOp(&'static str),
}

/// A condition on one dictionary. Duplicate keys: any value may match. A
/// value that is an indirect reference matches through any definition of the
/// referenced object (one level, ADR #19).
#[derive(Clone, Copy, Debug)]
pub enum DictMatch {
    /// The key is present.
    Key(&'static str),
    /// The key's value is a dictionary or a stream, or a reference no object
    /// defines (unknown: counted, fail-closed). An array, name, number or
    /// string value does not match.
    IsDict(&'static str),
    /// The key's value is this name.
    Name {
        key: &'static str,
        name: &'static str,
    },
    /// The key's value is one of these names.
    NameIn {
        key: &'static str,
        names: &'static [&'static str],
    },
    /// The key's value is this number (`4` and `4.0` alike).
    Int { key: &'static str, value: i64 },
    /// Every condition holds on the same dictionary.
    All(&'static [DictMatch]),
    /// At least one condition holds.
    Any(&'static [DictMatch]),
}

impl DictMatch {
    pub fn matches(&self, dict: &Dict, ctx: &Ctx) -> bool {
        let any_value = |key: &str, pred: &dyn Fn(&PdfObject) -> bool| {
            dict.get_all(key).any(|v| ctx.resolve(v).any(pred))
        };
        match *self {
            DictMatch::Key(key) => dict.contains_key(key),
            DictMatch::IsDict(key) => dict.get_all(key).any(|v| {
                let mut defined = false;
                let is_dict = ctx.resolve(v).any(|o| {
                    defined = true;
                    matches!(o, PdfObject::Dict(_) | PdfObject::Stream(_))
                });
                is_dict || !defined
            }),
            DictMatch::Name { key, name } => any_value(key, &|o| o.is_name(name)),
            DictMatch::NameIn { key, names } => {
                any_value(key, &|o| names.iter().any(|n| o.is_name(n)))
            }
            DictMatch::Int { key, value } => {
                // Exact for any i64 a PDF integer can hold; reals compare
                // as numbers.
                any_value(key, &|o| match o {
                    PdfObject::Int(i) => *i == value,
                    other => other.as_number() == Some(value as f64),
                })
            }
            DictMatch::All(all) => all.iter().all(|m| m.matches(dict, ctx)),
            DictMatch::Any(any) => any.iter().any(|m| m.matches(dict, ctx)),
        }
    }
}

/// A rule defined in TOML.
#[derive(Debug)]
pub struct DeclRule {
    pub meta: &'static RuleMeta,
    pub matcher: Match,
}

impl Rule for DeclRule {
    fn meta(&self) -> &'static RuleMeta {
        self.meta
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if matches!(&self.matcher, Match::Dict(m) if m.matches(dict, ctx)) {
            out.report(self.meta, loc, None);
        }
    }

    fn check_content_op(&self, op: &ContentOp<'_>, loc: &OpLocation, _: &Ctx, out: &mut Findings) {
        if matches!(self.matcher, Match::ContentOp(operator) if op.is(operator)) {
            out.report(self.meta, loc, None);
        }
    }

    fn hooks(&self) -> Hooks {
        let op = matches!(self.matcher, Match::ContentOp(_));
        Hooks {
            file: false,
            dict: !op,
            content_op: op,
            document: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::meta::{Action, Category, Severity, Stage};
    use crate::rules::{Site, run};

    static META: RuleMeta = RuleMeta {
        id: "ACTIVE.QUELDA_TEST",
        category: Category::ActiveContent,
        severity: Severity::High,
        default_action: Action::Block,
        locked: false,
        stage: Stage::Stable,
        since: "0.1.0",
        message: "test",
        description: "test",
    };

    /// Objects (top-level and nested) whose dicts the matcher fires on.
    fn hits(m: Match, src: &[u8]) -> Vec<String> {
        let rule = DeclRule {
            meta: &META,
            matcher: m,
        };
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        let f = run(&ctx, &[&rule]);
        f.iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{} {}", l.id, l.path.len()),
                Site::Op(o) => format!("op {} @{}", o.stream.id, o.offset),
                other => format!("{other:?}"),
            })
            .collect()
    }

    fn dict(m: DictMatch, src: &[u8]) -> Vec<String> {
        hits(Match::Dict(m), src)
    }

    #[test]
    fn key() {
        let src = b"1 0 obj << /JS (x) >> endobj\n2 0 obj << /A << /JS 3 0 R >> >> endobj\n3 0 obj << /JSX 1 >> endobj\n4 0 obj (/JS) endobj";
        assert_eq!(dict(DictMatch::Key("JS"), src), vec!["1 0 0", "2 0 1"]);
    }

    #[test]
    fn is_dict() {
        // 1: direct dict; 2: reference to a dict; 3: array of names (usage
        // rights); 4: reference to an array; 5: reference nothing defines;
        // 6: duplicate key, one value a dict; 7: name.
        let src = b"1 0 obj << /EF << /F 9 0 R >> >> endobj\n\
            2 0 obj << /EF 8 0 R >> endobj\n\
            3 0 obj << /EF [/Create /Delete] >> endobj\n\
            4 0 obj << /EF 7 0 R >> endobj\n\
            5 0 obj << /EF 99 0 R >> endobj\n\
            6 0 obj << /EF [/Create] /EF << >> >> endobj\n\
            10 0 obj << /EF /Create >> endobj\n\
            7 0 obj [/Create] endobj\n\
            8 0 obj << /F 9 0 R >> endobj";
        assert_eq!(
            dict(DictMatch::IsDict("EF"), src),
            vec!["1 0 0", "2 0 0", "5 0 0", "6 0 0"]
        );
    }

    #[test]
    fn name() {
        let m = DictMatch::Name {
            key: "S",
            name: "Launch",
        };
        let src = b"1 0 obj << /S /Launch >> endobj\n\
            2 0 obj << /S /L#61unch >> endobj\n\
            3 0 obj << /S (Launch) >> endobj\n\
            4 0 obj << /S /LaunchX >> endobj\n\
            5 0 obj << /T /Launch >> endobj\n\
            6 0 obj << /S /GoTo /S /Launch >> endobj\n\
            7 0 obj << /S 20 0 R >> endobj\n\
            8 0 obj << /S 21 0 R >> endobj\n\
            9 0 obj << /S [/Launch] >> endobj\n\
            20 0 obj /Launch endobj\n\
            21 0 obj /GoTo endobj\n\
            21 0 obj /Launch endobj\n\
            22 0 obj << /S 22 0 R >> endobj";
        assert_eq!(
            dict(m, src),
            vec!["1 0 0", "2 0 0", "6 0 0", "7 0 0", "8 0 0"]
        );
    }

    #[test]
    fn indirect_is_one_level() {
        let m = DictMatch::Name {
            key: "S",
            name: "Launch",
        };
        let src = b"1 0 obj << /S 2 0 R >> endobj\n2 0 obj 3 0 R endobj\n3 0 obj /Launch endobj\n4 0 obj << /S 9 0 R >> endobj";
        assert!(dict(m, src).is_empty());
    }

    #[test]
    fn name_in() {
        let m = DictMatch::NameIn {
            key: "Subtype",
            names: &["RichMedia", "Movie"],
        };
        let src = b"1 0 obj << /Subtype /Movie >> endobj\n2 0 obj << /Subtype /Link >> endobj\n3 0 obj << /Subtype /Rich#4Dedia >> endobj";
        assert_eq!(dict(m, src), vec!["1 0 0", "3 0 0"]);
    }

    #[test]
    fn int() {
        let m = DictMatch::Int {
            key: "FunctionType",
            value: 4,
        };
        let src = b"1 0 obj << /FunctionType 4 >> endobj\n2 0 obj << /FunctionType 2 >> endobj\n\
            3 0 obj << /FunctionType 4.0 >> endobj\n4 0 obj << /FunctionType (4) >> endobj\n\
            5 0 obj << /FunctionType 6 0 R >> endobj\n6 0 obj 4 endobj";
        assert_eq!(dict(m, src), vec!["1 0 0", "3 0 0", "5 0 0"]);
    }

    #[test]
    fn all() {
        static ALL: [DictMatch; 2] = [
            DictMatch::Name {
                key: "Type",
                name: "EmbeddedFile",
            },
            DictMatch::Key("Length"),
        ];
        let src = b"1 0 obj << /Type /EmbeddedFile /Length 0 >> stream\n\nendstream endobj\n\
            2 0 obj << /Type /EmbeddedFile >> endobj\n3 0 obj << /Length 1 /A << /Type /EmbeddedFile >> >> endobj";
        assert_eq!(dict(DictMatch::All(&ALL), src), vec!["1 0 0"]);
    }

    #[test]
    fn any() {
        static ANY: [DictMatch; 2] = [
            DictMatch::Key("JS"),
            DictMatch::Name {
                key: "S",
                name: "JavaScript",
            },
        ];
        static NESTED: [DictMatch; 2] = [DictMatch::Any(&ANY), DictMatch::Key("Next")];
        let src = b"1 0 obj << /JS (x) >> endobj\n\
            2 0 obj << /S /JavaScript >> endobj\n\
            3 0 obj << /S /Java#53cript /JS (x) >> endobj\n\
            4 0 obj << /S /GoTo /JSX 1 >> endobj\n\
            5 0 obj << /S 6 0 R /Next 1 >> endobj\n\
            6 0 obj /JavaScript endobj";
        assert_eq!(
            dict(DictMatch::Any(&ANY), src),
            vec!["1 0 0", "2 0 0", "3 0 0", "5 0 0"]
        );
        assert_eq!(dict(DictMatch::All(&NESTED), src), vec!["5 0 0"]);
    }

    #[test]
    fn content_op() {
        let src = b"1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length 22 >> stream\nq (PS) Tj /PS gs PS Q\nendstream endobj";
        let at = src.windows(5).position(|w| w == b"PS Q\n").unwrap();
        let data = src.windows(7).position(|w| w == b"stream\n").unwrap() + 7;
        assert_eq!(
            hits(Match::ContentOp("PS"), src),
            vec![format!("op 2 0 @{}", at - data)]
        );
        // A dict matcher never sees content ops and vice versa.
        assert!(hits(Match::Dict(DictMatch::Key("PS")), src).is_empty());
        assert!(hits(Match::ContentOp("Contents"), src).is_empty());
    }
}
