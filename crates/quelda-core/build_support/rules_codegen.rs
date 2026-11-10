//! Rule codegen (design §5.4, §5.5), shared by `build.rs` and the crate's unit
//! tests: parse + validate declarative rules (`rules/*.toml`), discover code
//! rules (`src/rules/<category>/*.rs`), and emit the static registry.
//!
//! Pure functions over strings: every error names the file and rule so a bad
//! rule is a build error that says where to look.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// `(category key, rule ID prefix, Rust variant)` — must match
/// `rules::meta::Category` (checked by a unit test).
pub const CATEGORIES: &[(&str, &str, &str)] = &[
    ("filetype", "FILETYPE", "Filetype"),
    ("postscript", "POSTSCRIPT", "Postscript"),
    ("active_content", "ACTIVE", "ActiveContent"),
    ("embedded", "EMBED", "Embedded"),
    ("external", "EXTERNAL", "External"),
    ("forms", "FORMS", "Forms"),
    ("xml", "XML", "Xml"),
    ("structure", "STRUCT", "Structure"),
    ("encryption", "CRYPT", "Encryption"),
    ("codecs", "CODEC", "Codecs"),
    ("resource", "RESOURCE", "Resource"),
];

const SEVERITIES: &[(&str, &str)] = &[
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
];
const ACTIONS: &[(&str, &str)] = &[("block", "Block"), ("warn", "Warn"), ("off", "Off")];
const STAGES: &[(&str, &str)] = &[("preview", "Preview"), ("stable", "Stable")];

const RULE_KEYS: &[&str] = &[
    "id",
    "category",
    "severity",
    "default_action",
    "locked",
    "stage",
    "since",
    "message",
    "description",
    "match",
];

/// One declarative rule, validated field by field.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleSpec {
    /// The `.toml` file it came from (for messages).
    pub file: String,
    pub id: String,
    pub category: String,
    pub severity: String,
    pub default_action: String,
    pub locked: bool,
    pub stage: String,
    pub since: String,
    pub message: String,
    pub description: String,
    pub matcher: MatchSpec,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MatchSpec {
    Dict(DictSpec),
    ContentOp(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DictSpec {
    Key(String),
    Name { key: String, name: String },
    NameIn { key: String, names: Vec<String> },
    Int { key: String, value: i64 },
    All(Vec<DictSpec>),
    Any(Vec<DictSpec>),
}

/// `^[A-Z0-9]+\.[A-Z0-9_]+$` (design §5.5).
pub fn is_valid_id(id: &str) -> bool {
    let Some((prefix, name)) = id.split_once('.') else {
        return false;
    };
    !prefix.is_empty()
        && !name.is_empty()
        && prefix
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn lookup<'a>(table: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn category_variant(key: &str) -> Option<&'static str> {
    CATEGORIES.iter().find(|c| c.0 == key).map(|c| c.2)
}

fn category_prefix(key: &str) -> Option<&'static str> {
    CATEGORIES.iter().find(|c| c.0 == key).map(|c| c.1)
}

fn keys(list: &[(&str, &str)]) -> String {
    list.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", ")
}

/// Parses one `rules/<category>.toml`. Errors are prefixed with `file` and,
/// once known, the rule ID.
pub fn parse_file(file: &str, text: &str) -> Result<Vec<RuleSpec>, Vec<String>> {
    let table: toml::Table = text
        .parse()
        .map_err(|e| vec![format!("{file}: invalid TOML: {e}")])?;
    let mut errors = Vec::new();
    for key in table.keys() {
        if key != "rule" {
            errors.push(format!(
                "{file}: unknown top-level key `{key}` (rules go in [[rule]])"
            ));
        }
    }
    let rules = match table.get("rule") {
        None => Vec::new(),
        Some(toml::Value::Array(items)) => items.clone(),
        Some(_) => {
            errors.push(format!(
                "{file}: `rule` must be an array of tables ([[rule]])"
            ));
            Vec::new()
        }
    };
    let mut out = Vec::new();
    for (i, item) in rules.iter().enumerate() {
        match item {
            toml::Value::Table(t) => match parse_rule(file, i, t) {
                Ok(r) => out.push(r),
                Err(e) => errors.extend(e),
            },
            _ => errors.push(format!("{file}: rule #{} is not a table", i + 1)),
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn parse_rule(file: &str, index: usize, t: &toml::Table) -> Result<RuleSpec, Vec<String>> {
    let id = t.get("id").and_then(toml::Value::as_str);
    let at = match id {
        Some(id) => format!("{file}: rule {id}"),
        None => format!("{file}: rule #{}", index + 1),
    };
    let mut errors = Vec::new();
    for key in t.keys() {
        if !RULE_KEYS.contains(&key.as_str()) {
            errors.push(format!("{at}: unknown field `{key}`"));
        }
    }
    let mut string = |key: &str| -> String {
        match t.get(key) {
            Some(toml::Value::String(s)) if !s.trim().is_empty() => s.clone(),
            Some(toml::Value::String(_)) => {
                errors.push(format!("{at}: `{key}` must not be empty"));
                String::new()
            }
            Some(_) => {
                errors.push(format!("{at}: `{key}` must be a string"));
                String::new()
            }
            None => {
                errors.push(format!("{at}: missing field `{key}`"));
                String::new()
            }
        }
    };
    let id = string("id");
    let category = string("category");
    let severity = string("severity");
    let default_action = string("default_action");
    let stage = string("stage");
    let since = string("since");
    let message = string("message");
    let description = string("description");
    let locked = match t.get("locked") {
        Some(toml::Value::Boolean(b)) => *b,
        Some(_) => {
            errors.push(format!("{at}: `locked` must be true or false"));
            false
        }
        None => {
            errors.push(format!("{at}: missing field `locked`"));
            false
        }
    };
    let matcher = match t.get("match") {
        Some(m) => match parse_match(m) {
            Ok(m) => Some(m),
            Err(e) => {
                errors.push(format!("{at}: match: {e}"));
                None
            }
        },
        None => {
            errors.push(format!("{at}: missing field `match`"));
            None
        }
    };
    if !id.is_empty() && !is_valid_id(&id) {
        errors.push(format!(
            "{at}: invalid ID (expected CATEGORY.NAME, ^[A-Z0-9]+\\.[A-Z0-9_]+$)"
        ));
    }
    if !category.is_empty() {
        match category_prefix(&category) {
            None => errors.push(format!(
                "{at}: unknown category `{category}` (known: {})",
                CATEGORIES
                    .iter()
                    .map(|c| c.0)
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Some(prefix) => {
                if is_valid_id(&id) && id.split_once('.').map(|p| p.0) != Some(prefix) {
                    errors.push(format!(
                        "{at}: ID prefix must be `{prefix}.` for category `{category}`"
                    ));
                }
                let stem = file.rsplit('/').next().unwrap_or(file);
                if stem.strip_suffix(".toml") != Some(category.as_str()) {
                    errors.push(format!(
                        "{at}: category `{category}` rules go in rules/{category}.toml"
                    ));
                }
            }
        }
    }
    for (key, value, allowed) in [
        ("severity", &severity, SEVERITIES),
        ("default_action", &default_action, ACTIONS),
        ("stage", &stage, STAGES),
    ] {
        if !value.is_empty() && lookup(allowed, value).is_none() {
            errors.push(format!(
                "{at}: invalid {key} `{value}` (expected one of: {})",
                keys(allowed)
            ));
        }
    }
    if locked && !default_action.is_empty() && default_action != "block" {
        errors.push(format!(
            "{at}: a locked rule must have default_action = \"block\""
        ));
    }
    match matcher {
        Some(matcher) if errors.is_empty() => Ok(RuleSpec {
            file: file.to_string(),
            id,
            category,
            severity,
            default_action,
            locked,
            stage,
            since,
            message,
            description,
            matcher,
        }),
        _ => Err(errors),
    }
}

fn parse_match(v: &toml::Value) -> Result<MatchSpec, String> {
    let t = v
        .as_table()
        .ok_or("must be a table, e.g. { dict = { key = \"JS\" } }")?;
    if t.len() != 1 {
        return Err("needs exactly one of `dict`, `content_op`".into());
    }
    match t.iter().next() {
        Some((k, v)) if k == "dict" => parse_dict(v).map(MatchSpec::Dict),
        Some((k, v)) if k == "content_op" => match v.as_str() {
            Some(op) if is_operator(op) => Ok(MatchSpec::ContentOp(op.to_string())),
            _ => Err("`content_op` must be an operator name, e.g. \"PS\"".into()),
        },
        Some((k, _)) => Err(format!(
            "unknown match type `{k}` (expected `dict` or `content_op`)"
        )),
        None => Err("empty match".into()),
    }
}

fn is_operator(op: &str) -> bool {
    !op.is_empty()
        && op
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"()<>[]{}/%".contains(&b))
}

fn parse_dict(v: &toml::Value) -> Result<DictSpec, String> {
    let t = v.as_table().ok_or("`dict` must be a table")?;
    for combinator in ["all", "any"] {
        let Some(list) = t.get(combinator) else {
            continue;
        };
        if t.len() != 1 {
            return Err(format!(
                "`{combinator}` cannot be combined with other fields"
            ));
        }
        let items = list
            .as_array()
            .ok_or(format!("`{combinator}` must be an array of tables"))?;
        if items.is_empty() {
            return Err(format!("`{combinator}` must not be empty"));
        }
        let items = items.iter().map(parse_dict).collect::<Result<_, _>>()?;
        return Ok(if combinator == "all" {
            DictSpec::All(items)
        } else {
            DictSpec::Any(items)
        });
    }
    for k in t.keys() {
        if !["key", "name", "name_in", "int"].contains(&k.as_str()) {
            return Err(format!(
                "unknown field `{k}` (expected key, name, name_in, int, all, any)"
            ));
        }
    }
    let key = match t.get("key").and_then(toml::Value::as_str) {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => return Err("`key` (non-empty string) is required".into()),
    };
    match (t.get("name"), t.get("name_in"), t.get("int")) {
        (None, None, None) => Ok(DictSpec::Key(key)),
        (Some(n), None, None) => match n.as_str() {
            Some(name) if !name.is_empty() => Ok(DictSpec::Name {
                key,
                name: name.to_string(),
            }),
            _ => Err("`name` must be a non-empty string".into()),
        },
        (None, Some(list), None) => {
            let names = list
                .as_array()
                .and_then(|a| {
                    a.iter()
                        .map(|n| n.as_str().filter(|s| !s.is_empty()).map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .filter(|n| !n.is_empty())
                .ok_or("`name_in` must be a non-empty array of non-empty strings")?;
            Ok(DictSpec::NameIn { key, names })
        }
        (None, None, Some(i)) => match i.as_integer() {
            Some(value) => Ok(DictSpec::Int { key, value }),
            None => Err("`int` must be an integer".into()),
        },
        _ => Err("use at most one of `name`, `name_in`, `int`".into()),
    }
}

/// Cross-file checks: unique IDs (among declarative rules and code rule IDs
/// are checked at test time, since they live in Rust code).
pub fn validate(rules: &[RuleSpec]) -> Result<(), Vec<String>> {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    let mut errors = Vec::new();
    for r in rules {
        if let Some(first) = seen.insert(&r.id, &r.file) {
            errors.push(format!(
                "{}: rule {}: duplicate ID (also in {first})",
                r.file, r.id
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// One `src/rules/<category>/<module>.rs` file and the rule types it
/// implements.
#[derive(Clone, Debug, PartialEq)]
pub struct CodeModule {
    pub category: String,
    pub module: String,
    /// Absolute path, for `#[path]`.
    pub path: String,
    pub rules: Vec<String>,
}

/// Rule types implemented in `src`: every `impl Rule for X`.
pub fn find_rule_impls(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("impl Rule for ") {
            let ident: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() {
                out.push(ident);
            }
        }
    }
    out
}

/// Checks a code rule file found at `src/rules/<category>/<file>`.
pub fn code_module(
    category: &str,
    file: &str,
    path: &str,
    src: &str,
) -> Result<Option<CodeModule>, String> {
    let at = format!("src/rules/{category}/{file}");
    if category_variant(category).is_none() {
        return Err(format!(
            "src/rules/{category}/: directory is not a category key (known: {})",
            CATEGORIES
                .iter()
                .map(|c| c.0)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let Some(module) = file.strip_suffix(".rs") else {
        return Ok(None);
    };
    let valid_ident = module
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && module
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase())
        && module != "mod";
    if !valid_ident {
        return Err(format!(
            "{at}: file name must be a snake_case module name (one file per rule, no mod.rs)"
        ));
    }
    let rules = find_rule_impls(src);
    if rules.is_empty() {
        return Err(format!("{at}: no `impl Rule for X` found"));
    }
    Ok(Some(CodeModule {
        category: category.to_string(),
        module: module.to_string(),
        path: path.to_string(),
        rules,
    }))
}

fn dict_code(d: &DictSpec, out: &mut String) {
    let p = "crate::rules::declarative::DictMatch";
    match d {
        DictSpec::Key(k) => {
            let _ = write!(out, "{p}::Key({k:?})");
        }
        DictSpec::Name { key, name } => {
            let _ = write!(out, "{p}::Name {{ key: {key:?}, name: {name:?} }}");
        }
        DictSpec::NameIn { key, names } => {
            let _ = write!(out, "{p}::NameIn {{ key: {key:?}, names: &{names:?} }}");
        }
        DictSpec::Int { key, value } => {
            let _ = write!(out, "{p}::Int {{ key: {key:?}, value: {value} }}");
        }
        DictSpec::All(items) | DictSpec::Any(items) => {
            let kind = if matches!(d, DictSpec::All(_)) {
                "All"
            } else {
                "Any"
            };
            let _ = write!(out, "{p}::{kind}(&[");
            for i in items {
                dict_code(i, out);
                out.push_str(", ");
            }
            out.push_str("])");
        }
    }
}

/// The generated registry source (included by `rules::registry`).
pub fn generate(rules: &[RuleSpec], code: &[CodeModule]) -> String {
    let mut out = String::from(
        "// @generated by build.rs (build_support/rules_codegen.rs). Do not edit.\n\n",
    );
    let mut by_category: BTreeMap<&str, Vec<&CodeModule>> = BTreeMap::new();
    for m in code {
        by_category.entry(&m.category).or_default().push(m);
    }
    for (category, modules) in &by_category {
        let _ = writeln!(out, "pub(crate) mod {category} {{");
        for m in modules {
            let _ = writeln!(
                out,
                "    #[path = {:?}]\n    pub(crate) mod {};",
                m.path, m.module
            );
        }
        out.push_str("}\n\n");
    }
    let mut sorted: Vec<&RuleSpec> = rules.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    for (i, r) in sorted.iter().enumerate() {
        let variant =
            |table: &[(&str, &str)], k: &str| lookup(table, k).unwrap_or_default().to_string();
        let _ = writeln!(
            out,
            "static META_{i}: crate::rules::meta::RuleMeta = crate::rules::meta::RuleMeta {{\n    \
             id: {:?},\n    category: crate::rules::meta::Category::{},\n    \
             severity: crate::rules::meta::Severity::{},\n    \
             default_action: crate::rules::meta::Action::{},\n    locked: {},\n    \
             stage: crate::rules::meta::Stage::{},\n    since: {:?},\n    message: {:?},\n    \
             description: {:?},\n}};",
            r.id,
            category_variant(&r.category).unwrap_or_default(),
            variant(SEVERITIES, &r.severity),
            variant(ACTIONS, &r.default_action),
            r.locked,
            variant(STAGES, &r.stage),
            r.since,
            r.message,
            r.description,
        );
        let mut m = String::new();
        match &r.matcher {
            MatchSpec::Dict(d) => {
                m.push_str("crate::rules::declarative::Match::Dict(");
                dict_code(d, &mut m);
                m.push(')');
            }
            MatchSpec::ContentOp(op) => {
                let _ = write!(m, "crate::rules::declarative::Match::ContentOp({op:?})");
            }
        }
        let _ = writeln!(
            out,
            "static DECL_{i}: crate::rules::declarative::DeclRule = crate::rules::declarative::DeclRule {{ meta: &META_{i}, matcher: {m} }};\n"
        );
    }
    out.push_str("/// Every rule: code rules (by file), then declarative rules (by ID).\n");
    out.push_str("pub(crate) static ALL: &[&dyn crate::rules::Rule] = &[\n");
    for (category, modules) in &by_category {
        for m in modules {
            for r in &m.rules {
                let _ = writeln!(out, "    &{category}::{}::{r},", m.module);
            }
        }
    }
    for i in 0..sorted.len() {
        let _ = writeln!(out, "    &DECL_{i},");
    }
    out.push_str("];\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAUNCH: &str = r#"
[[rule]]
id = "ACTIVE.LAUNCH"
category = "active_content"
severity = "critical"
default_action = "block"
locked = true
stage = "stable"
since = "0.1.0"
message = "m"
description = "d"
match = { dict = { key = "S", name = "Launch" } }
"#;

    fn errors(file: &str, text: &str) -> Vec<String> {
        parse_file(file, text).expect_err("must fail")
    }

    fn one_error(file: &str, text: &str) -> String {
        let e = errors(file, text);
        assert_eq!(e.len(), 1, "{e:?}");
        e[0].clone()
    }

    fn with(field: &str, value: &str) -> String {
        LAUNCH
            .lines()
            .map(|l| {
                if l.starts_with(&format!("{field} =")) {
                    format!("{field} = {value}")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn parses_launch() {
        let r = parse_file("rules/active_content.toml", LAUNCH).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "ACTIVE.LAUNCH");
        assert!(r[0].locked);
        assert_eq!(
            r[0].matcher,
            MatchSpec::Dict(DictSpec::Name {
                key: "S".into(),
                name: "Launch".into()
            })
        );
    }

    #[test]
    fn id_format() {
        for ok in ["ACTIVE.LAUNCH", "A1.B_2", "X.Y"] {
            assert!(is_valid_id(ok), "{ok}");
        }
        for bad in [
            "active.launch",
            "ACTIVE",
            "ACTIVE.",
            ".X",
            "A.B.C",
            "A_B.C",
            "A.b",
            "A.B-C",
            "",
        ] {
            assert!(!is_valid_id(bad), "{bad}");
        }
        let e = one_error(
            "rules/active_content.toml",
            &with("id", "\"ACTIVE.launch\""),
        );
        assert!(e.contains("rule ACTIVE.launch: invalid ID"), "{e}");
    }

    #[test]
    fn prefix_must_match_category() {
        let e = one_error("rules/active_content.toml", &with("id", "\"EMBED.LAUNCH\""));
        assert!(
            e.contains(
                "rule EMBED.LAUNCH: ID prefix must be `ACTIVE.` for category `active_content`"
            ),
            "{e}"
        );
    }

    #[test]
    fn unknown_category() {
        let e = one_error("rules/active_content.toml", &with("category", "\"active\""));
        assert!(
            e.contains("rules/active_content.toml: rule ACTIVE.LAUNCH: unknown category `active`"),
            "{e}"
        );
    }

    #[test]
    fn category_must_match_file() {
        let e = one_error("rules/embedded.toml", LAUNCH);
        assert!(e.contains("rules go in rules/active_content.toml"), "{e}");
    }

    #[test]
    fn duplicate_ids_across_files() {
        let mut a = parse_file("rules/active_content.toml", LAUNCH).unwrap();
        a.extend(parse_file("x/active_content.toml", LAUNCH).unwrap());
        let e = validate(&a).unwrap_err();
        assert_eq!(
            e,
            vec![
                "x/active_content.toml: rule ACTIVE.LAUNCH: duplicate ID (also in rules/active_content.toml)"
            ]
        );
        let mut twice = LAUNCH.to_string();
        twice.push_str(LAUNCH);
        let r = parse_file("rules/active_content.toml", &twice).unwrap();
        assert!(validate(&r).is_err());
        assert!(validate(&r[..1]).is_ok());
    }

    #[test]
    fn enum_fields_and_locked() {
        let e = one_error("rules/active_content.toml", &with("severity", "\"severe\""));
        assert!(
            e.contains("invalid severity `severe` (expected one of: critical, high"),
            "{e}"
        );
        let e = one_error(
            "rules/active_content.toml",
            &with("default_action", "\"warn\""),
        );
        assert!(
            e.contains("locked rule must have default_action = \"block\""),
            "{e}"
        );
        let e = one_error("rules/active_content.toml", &with("stage", "\"beta\""));
        assert!(e.contains("invalid stage `beta`"), "{e}");
        let e = one_error("rules/active_content.toml", &with("locked", "\"yes\""));
        assert!(e.contains("`locked` must be true or false"), "{e}");
    }

    #[test]
    fn missing_and_unknown_fields() {
        let text: String = LAUNCH
            .lines()
            .filter(|l| !l.starts_with("message"))
            .map(|l| format!("{l}\n"))
            .collect();
        let e = one_error("rules/active_content.toml", &text);
        assert!(
            e.contains("rule ACTIVE.LAUNCH: missing field `message`"),
            "{e}"
        );
        let e = one_error(
            "rules/active_content.toml",
            &format!("{LAUNCH}severty = \"high\"\n"),
        );
        assert!(e.contains("unknown field `severty`"), "{e}");
        let e = one_error("rules/active_content.toml", &with("message", "\"  \""));
        assert!(e.contains("`message` must not be empty"), "{e}");
        let e = one_error("rules/active_content.toml", "[rules]\n");
        assert!(e.contains("unknown top-level key `rules`"), "{e}");
        let e = one_error("rules/active_content.toml", "rule = 1\n");
        assert!(e.contains("array of tables"), "{e}");
        let e = one_error("rules/active_content.toml", "[[rule\n");
        assert!(
            e.starts_with("rules/active_content.toml: invalid TOML"),
            "{e}"
        );
        let e = errors(
            "rules/active_content.toml",
            "[[rule]]\nmatch = { content_op = \"PS\" }\n",
        );
        assert_eq!(e.len(), 9, "{e:?}");
        assert_eq!(
            e[0],
            "rules/active_content.toml: rule #1: missing field `id`"
        );
    }

    fn matcher(m: &str) -> Result<MatchSpec, String> {
        let v: toml::Table = format!("m = {m}").parse().unwrap();
        parse_match(&v["m"])
    }

    #[test]
    fn match_kinds() {
        use DictSpec::*;
        let k = |s: &str| s.to_string();
        assert_eq!(
            matcher(r#"{ dict = { key = "JS" } }"#),
            Ok(MatchSpec::Dict(Key(k("JS"))))
        );
        assert_eq!(
            matcher(r#"{ dict = { key = "Subtype", name_in = ["RichMedia", "Movie"] } }"#),
            Ok(MatchSpec::Dict(NameIn {
                key: k("Subtype"),
                names: vec![k("RichMedia"), k("Movie")]
            }))
        );
        assert_eq!(
            matcher(r#"{ dict = { key = "FunctionType", int = 4 } }"#),
            Ok(MatchSpec::Dict(Int {
                key: k("FunctionType"),
                value: 4
            }))
        );
        assert_eq!(
            matcher(
                r#"{ dict = { all = [ { key = "Type", name = "EmbeddedFile" }, { key = "Length" } ] } }"#
            ),
            Ok(MatchSpec::Dict(All(vec![
                Name {
                    key: k("Type"),
                    name: k("EmbeddedFile")
                },
                Key(k("Length"))
            ])))
        );
        assert_eq!(
            matcher(
                r#"{ dict = { any = [ { key = "JS" }, { all = [ { key = "S", name = "JavaScript" } ] } ] } }"#
            ),
            Ok(MatchSpec::Dict(Any(vec![
                Key(k("JS")),
                All(vec![Name {
                    key: k("S"),
                    name: k("JavaScript")
                }])
            ])))
        );
        assert_eq!(
            matcher(r#"{ content_op = "PS" }"#),
            Ok(MatchSpec::ContentOp(k("PS")))
        );
    }

    #[test]
    fn bad_matches() {
        for (m, want) in [
            ("1", "must be a table"),
            (
                r#"{ dict = { key = "A" }, content_op = "PS" }"#,
                "exactly one",
            ),
            (r#"{ regex = "x" }"#, "unknown match type `regex`"),
            (r#"{ content_op = "P S" }"#, "operator name"),
            (r#"{ content_op = "" }"#, "operator name"),
            (r#"{ dict = { name = "Launch" } }"#, "`key`"),
            (
                r#"{ dict = { key = "S", name = "A", int = 1 } }"#,
                "at most one",
            ),
            (
                r#"{ dict = { key = "S", value = 1 } }"#,
                "unknown field `value`",
            ),
            (
                r#"{ dict = { key = "S", name_in = [] } }"#,
                "non-empty array",
            ),
            (
                r#"{ dict = { key = "S", name_in = [1] } }"#,
                "non-empty array",
            ),
            (r#"{ dict = { key = "S", int = 1.5 } }"#, "integer"),
            (r#"{ dict = { all = [] } }"#, "must not be empty"),
            (
                r#"{ dict = { all = [ { key = "A" } ], key = "B" } }"#,
                "cannot be combined",
            ),
            (r#"{ dict = { all = [ { name = "A" } ] } }"#, "`key`"),
            (r#"{ dict = { any = [] } }"#, "`any` must not be empty"),
            (r#"{ dict = { any = 1 } }"#, "`any` must be an array"),
            (
                r#"{ dict = { any = [ { key = "A" } ], key = "B" } }"#,
                "`any` cannot be combined",
            ),
            (
                r#"{ dict = { any = [ { key = "A" } ], all = [ { key = "B" } ] } }"#,
                "cannot be combined",
            ),
            (
                r#"{ dict = { any = [ { key = "A", int = "x" } ] } }"#,
                "integer",
            ),
        ] {
            let e = matcher(m).unwrap_err();
            assert!(e.contains(want), "{m}: {e}");
        }
    }

    #[test]
    fn finds_rule_impls() {
        let src = "pub struct A;\nimpl Rule for A {\n}\n  impl Rule for B_2{}\n// impl Other for C\nimpl crate::rules::Rule for D {}\n";
        assert_eq!(find_rule_impls(src), vec!["A", "B_2"]);
    }

    #[test]
    fn code_module_checks() {
        let src = "impl Rule for X {}";
        let m = code_module("filetype", "x_y.rs", "/abs/x_y.rs", src)
            .unwrap()
            .unwrap();
        assert_eq!(m.module, "x_y");
        assert_eq!(m.rules, vec!["X"]);
        assert_eq!(code_module("filetype", "README.md", "/a", src), Ok(None));
        let e = code_module("active", "x.rs", "/a", src).unwrap_err();
        assert!(
            e.contains("src/rules/active/: directory is not a category key"),
            "{e}"
        );
        let e = code_module("filetype", "mod.rs", "/a", src).unwrap_err();
        assert!(e.contains("src/rules/filetype/mod.rs: file name"), "{e}");
        let e = code_module("filetype", "X.rs", "/a", src).unwrap_err();
        assert!(e.contains("snake_case"), "{e}");
        let e = code_module("filetype", "x.rs", "/a", "struct X;").unwrap_err();
        assert!(
            e.contains("src/rules/filetype/x.rs: no `impl Rule for X` found"),
            "{e}"
        );
    }

    #[test]
    fn generates_any_and_all() {
        let text = LAUNCH.replace(
            r#"match = { dict = { key = "S", name = "Launch" } }"#,
            r#"match = { dict = { any = [ { key = "JS" }, { all = [ { key = "S", int = 1 } ] } ] } }"#,
        );
        let rules = parse_file("rules/active_content.toml", &text).unwrap();
        let src = generate(&rules, &[]);
        let p = "crate::rules::declarative::DictMatch";
        assert!(
            src.contains(&format!(
                "{p}::Any(&[{p}::Key(\"JS\"), {p}::All(&[{p}::Int {{ key: \"S\", value: 1 }}, ]), ])"
            )),
            "{src}"
        );
    }

    #[test]
    fn generates_registry() {
        let rules = parse_file("rules/active_content.toml", LAUNCH).unwrap();
        let code = vec![CodeModule {
            category: "filetype".into(),
            module: "not_pdf_header".into(),
            path: "/abs/not_pdf_header.rs".into(),
            rules: vec!["NotPdfHeader".into()],
        }];
        let src = generate(&rules, &code);
        assert!(src.contains("pub(crate) mod filetype {\n    #[path = \"/abs/not_pdf_header.rs\"]\n    pub(crate) mod not_pdf_header;"), "{src}");
        assert!(
            src.contains("category: crate::rules::meta::Category::ActiveContent,"),
            "{src}"
        );
        assert!(src.contains("matcher: crate::rules::declarative::Match::Dict(crate::rules::declarative::DictMatch::Name { key: \"S\", name: \"Launch\" })"), "{src}");
        assert!(
            src.contains("    &filetype::not_pdf_header::NotPdfHeader,\n    &DECL_0,\n];"),
            "{src}"
        );
    }
}
