//! The docs show what really happens (ADR #34 (f)):
//! - every caller example in docs/cli.md is the tested file in
//!   docs/examples/cli/ (run by scripts/docs-examples-test.mjs), verbatim;
//! - the sample verdict is the real output for its fixture;
//! - every sample policy is accepted by the engine;
//! - every `quelda …` command in README.md, docs/cli.md and docs/policy.md
//!   runs (exit 0 on a clean `upload.pdf`);
//! - the tables of docs/rules.md, docs/policy.md and the README showcases (repo, npm)
//!   (rules, preset actions, locked rules, limits, thresholds, engine errors,
//!   counts) are what the engine does.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(p: &str) -> String {
    fs::read_to_string(repo().join(p)).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn fixture(path: &str) -> PathBuf {
    let p = repo().join("tests/fixtures").join(path);
    assert!(
        p.is_file(),
        "{} not found: run `cargo run -p quelda-testkit --bin gen-fixtures` first",
        p.display()
    );
    p
}

/// Fenced code blocks: (marker comment on the line before, info string, body).
fn blocks(md: &str) -> Vec<(Option<String>, String, String)> {
    let mut out = Vec::new();
    let lines: Vec<&str> = md.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if let Some(info) = lines[i].strip_prefix("```") {
            let marker = i
                .checked_sub(1)
                .and_then(|j| lines[j].strip_prefix("<!-- "))
                .and_then(|m| m.strip_suffix(" -->"))
                .map(str::to_string);
            let start = i + 1;
            let mut end = start;
            while !lines[end].starts_with("```") {
                end += 1;
            }
            out.push((
                marker,
                info.to_string(),
                lines[start..end].join("\n") + "\n",
            ));
            i = end;
        }
        i += 1;
    }
    out
}

#[test]
fn caller_examples_are_the_tested_files() {
    let md = read("docs/cli.md");
    let mut shown = Vec::new();
    for (marker, _, body) in blocks(&md) {
        if let Some(name) = marker.as_deref().and_then(|m| m.strip_prefix("example: ")) {
            assert_eq!(
                body,
                read(&format!("docs/examples/cli/{name}")),
                "docs/cli.md block for {name} differs from docs/examples/cli/{name}"
            );
            shown.push(name.to_string());
        }
    }
    let mut files = Vec::new();
    for lang in fs::read_dir(repo().join("docs/examples/cli")).unwrap() {
        let lang = lang.unwrap().path();
        for f in fs::read_dir(&lang).unwrap() {
            let f = f.unwrap().path();
            files.push(format!(
                "{}/{}",
                lang.file_name().unwrap().to_str().unwrap(),
                f.file_name().unwrap().to_str().unwrap()
            ));
        }
    }
    shown.sort();
    files.sort();
    assert_eq!(shown, files, "every example file is shown once");
    assert_eq!(files.len(), 6, "Python, Ruby, Node, Go, PHP, Java");
}

#[test]
fn sample_verdict_is_real_output() {
    let md = read("docs/cli.md");
    let mut n = 0;
    for (marker, _, body) in blocks(&md) {
        let Some(file) = marker.as_deref().and_then(|m| m.strip_prefix("verdict: ")) else {
            continue;
        };
        let shown: Value = serde_json::from_str(&body).unwrap();
        let out = Command::cargo_bin("quelda")
            .unwrap()
            .args(["scan", fixture(file).to_str().unwrap()])
            .output()
            .unwrap();
        let mut real: Value = serde_json::from_slice(&out.stdout).unwrap();
        real["engine_version"] = Value::from("…");
        real["stats"]["duration_ms"] = Value::from(0);
        assert_eq!(shown, real, "docs/cli.md sample verdict for {file}");
        n += 1;
    }
    assert_eq!(n, 1);
}

#[test]
fn sample_policies_are_accepted() {
    let md = read("docs/cli.md");
    let minimal = fs::read(fixture("benign/minimal.pdf")).unwrap();
    let mut n = 0;
    for (marker, info, body) in blocks(&md) {
        if info != "json" || marker.is_some() {
            continue;
        }
        let v: Value = serde_json::from_str(&quelda_core::scan_json(&minimal, &body)).unwrap();
        assert_eq!(
            v["errors"],
            Value::Array(vec![]),
            "policy rejected:\n{body}"
        );
        n += 1;
    }
    assert!(n >= 1);
}

/// Splits a documented command line like a POSIX shell would for the simple
/// forms the docs use: words, '…' quotes, `< file`, trailing `# comment`.
fn shell_words(line: &str) -> (Vec<String>, Option<String>) {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    cur.push(q);
                }
            }
            '#' if !in_word => break,
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                assert!(
                    !"\"|;&$`>".contains(c),
                    "unsupported shell syntax in `{line}`"
                );
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    let stdin = match words.iter().position(|w| w == "<") {
        Some(i) => {
            let file = words.get(i + 1).cloned();
            words.truncate(i);
            file
        }
        None => None,
    };
    (words, stdin)
}

#[test]
fn shell_words_parses_the_documented_forms() {
    let (w, stdin) = shell_words(r#"quelda scan - < upload.pdf   # stdin"#);
    assert_eq!(
        (w, stdin),
        (
            vec!["quelda".into(), "scan".into(), "-".into()],
            Some("upload.pdf".into())
        )
    );
    let (w, _) = shell_words(r#"quelda scan a --policy-json '{"rules": {"X": "warn"}}'"#);
    assert_eq!(w[4], r#"{"rules": {"X": "warn"}}"#);
}

#[test]
fn documented_commands_run() {
    let dir = std::env::temp_dir().join(format!("quelda-docs-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::copy(fixture("benign/minimal.pdf"), dir.join("upload.pdf")).unwrap();
    fs::write(dir.join("policy.json"), r#"{"preset": "strict"}"#).unwrap();
    let mut n = 0;
    for doc in ["README.md", "docs/cli.md", "docs/policy.md"] {
        for (_, info, body) in blocks(&read(doc)) {
            if info != "bash" {
                continue;
            }
            for line in body.lines().filter(|l| l.starts_with("quelda ")) {
                let (words, stdin) = shell_words(line);
                let mut cmd = Command::cargo_bin("quelda").unwrap();
                cmd.current_dir(&dir).args(&words[1..]);
                if let Some(f) = stdin {
                    cmd.pipe_stdin(dir.join(f)).unwrap();
                }
                let out = cmd.output().unwrap();
                assert_eq!(
                    out.status.code(),
                    Some(0),
                    "{doc}: `{line}`\n{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                n += 1;
            }
        }
    }
    assert!(n >= 10, "{n} commands");
}

// ---- docs/rules.md, docs/policy.md, README: tables == the engine ----

use quelda_core::error::IssueCode;
use quelda_core::limits::{Limits, Thresholds};
use quelda_core::policy::{Policy, Preset, presets, resolve};
use quelda_core::rules::{Action, Category, RuleInfo};

/// Cells of the table rows of `md` whose first cell is code (`` `X` ``),
/// with the `##` section each row is in.
fn table_rows(md: &str) -> Vec<(String, Vec<String>)> {
    let mut section = String::new();
    let mut rows = Vec::new();
    for line in md.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            section = h.to_string();
        } else if line.starts_with("| `") {
            let cells = line
                .trim_matches('|')
                .split(" | ")
                .map(|c| c.trim().to_string())
                .collect();
            rows.push((section.clone(), cells));
        }
    }
    rows
}

/// `` `ID` 🔒 `` → ("ID", true).
fn code_cell(cell: &str) -> (String, bool) {
    let locked = cell.ends_with('🔒');
    let id = cell.trim_end_matches('🔒').trim().trim_matches('`');
    (id.to_string(), locked)
}

fn action(a: Action) -> &'static str {
    match a {
        Action::Block => "block",
        Action::Warn => "warn",
        Action::Off => "off",
    }
}

fn preset_policy(p: Preset) -> Policy {
    Policy {
        preset: Some(p),
        ..Policy::default()
    }
}

fn registry() -> Vec<RuleInfo> {
    quelda_core::list_rules()
}

#[test]
fn rules_md_lists_every_rule_with_its_preset_actions() {
    let md = read("docs/rules.md");
    let rules = registry();
    let rows = table_rows(&md);
    assert_eq!(rows.len(), rules.len(), "one row per rule");
    for (section, cells) in rows {
        let (id, locked) = code_cell(&cells[0]);
        let meta = quelda_core::rules::registry::all()
            .iter()
            .map(|r| r.meta())
            .find(|m| m.id == id)
            .unwrap_or_else(|| panic!("docs/rules.md: unknown rule {id}"));
        assert!(
            section.ends_with(&format!("(`{}`)", meta.category.key())),
            "{id} is under `{section}`"
        );
        assert_eq!(locked, meta.locked, "{id}: 🔒");
        for (i, p) in Preset::ALL.into_iter().enumerate() {
            assert_eq!(
                cells[2 + i],
                action(resolve(meta, &preset_policy(p))),
                "{id} under {}",
                p.key()
            );
        }
    }
    let header = format!(
        "**{} rules in {} categories**",
        rules.len(),
        Category::ALL.len()
    );
    assert!(md.contains(&header), "docs/rules.md: {header}");
}

#[test]
fn readme_showcase_counts_match_the_registry() {
    let rules = registry();
    let header = format!(
        "**{} rules in {} categories**, plus {} engine safeguards",
        rules.len(),
        Category::ALL.len(),
        IssueCode::ALL.len() - 1 // POLICY.INVALID is not a safeguard
    );
    for doc in ["README.md", "packages/quelda-js/README.md"] {
        let md = read(doc);
        assert!(md.contains(&header), "{doc}: {header}");
        let section = &md[md.find("## What quelda checks").unwrap()..];
        let section = &section[..section[3..].find("\n## ").unwrap()];
        let rows = table_rows(section);
        assert_eq!(rows.len(), Category::ALL.len(), "{doc}");
        for (_, cells) in rows {
            let (key, _) = code_cell(&cells[0]);
            let n = rules.iter().filter(|r| r.category.key() == key).count();
            assert!(n > 0, "{doc}: unknown category {key}");
            assert_eq!(cells[1], n.to_string(), "{doc}: rules in {key}");
        }
    }
}

#[test]
fn policy_md_presets_match_the_engine() {
    let md = read("docs/policy.md");
    let rows = table_rows(&md);
    // Category table: category, what it covers, strict, balanced, permissive.
    let cats: Vec<_> = rows
        .iter()
        .filter(|(s, c)| s == "Presets" && !c[0].contains('.'))
        .collect();
    assert_eq!(cats.len(), Category::ALL.len());
    for (_, cells) in &cats {
        let (key, _) = code_cell(&cells[0]);
        let cat = Category::ALL
            .into_iter()
            .find(|c| c.key() == key)
            .unwrap_or_else(|| panic!("unknown category {key}"));
        for (i, p) in Preset::ALL.into_iter().enumerate() {
            assert_eq!(
                cells[2 + i],
                action(presets::category_action(p, cat)),
                "{key}"
            );
        }
    }
    // Rules that differ from their category: rule, strict, balanced, permissive, why.
    let mut listed = Vec::new();
    for (_, cells) in rows
        .iter()
        .filter(|(s, c)| s == "Presets" && c[0].contains('.'))
    {
        let (id, _) = code_cell(&cells[0]);
        for (i, p) in Preset::ALL.into_iter().enumerate() {
            assert_eq!(
                cells[1 + i],
                action(presets::rule_override(p, &id).unwrap()),
                "{id}"
            );
        }
        listed.push(id);
    }
    let all = quelda_core::rules::registry::all();
    let mut want: Vec<String> = all
        .iter()
        .map(|r| r.meta().id)
        .filter(|id| presets::rule_override(Preset::Strict, id).is_some())
        .map(String::from)
        .collect();
    listed.sort();
    want.sort();
    assert_eq!(listed, want, "rules that differ from their category");
    // Locked list.
    for r in all {
        let m = r.meta();
        let named = md.contains(&format!("`{}`", m.id));
        if m.locked {
            assert!(named, "policy.md: locked rule {} not listed", m.id);
        }
    }
    let locked_line = md
        .lines()
        .skip_while(|l| !l.starts_with("**Locked rules**"))
        .take_while(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    // Backticked rule IDs (`permissive` is not one).
    let n = locked_line
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|w| w.contains('.'))
        .count();
    assert_eq!(
        n,
        all.iter().filter(|r| r.meta().locked).count(),
        "{locked_line}"
    );
}

#[test]
fn policy_md_reference_matches_the_engine() {
    let md = read("docs/policy.md");
    let keys: Vec<String> = Category::ALL
        .iter()
        .map(|c| format!("`{}`", c.key()))
        .collect();
    let flat = md.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains(&format!("Categories: {}.", keys.join(", "))),
        "policy.md: category list"
    );
    let rows = table_rows(&md);
    let first_number = |cell: &str| -> f64 {
        cell.trim_matches('`')
            .split('`')
            .next()
            .unwrap()
            .parse()
            .unwrap_or_else(|_| panic!("not a number: {cell}"))
    };
    let l = Limits::default();
    let limits = [
        (
            "max_file_bytes",
            l.max_file_bytes as f64,
            "LIMIT.FILE_BYTES",
        ),
        ("max_objects", l.max_objects as f64, "LIMIT.OBJECTS"),
        (
            "max_revisions",
            f64::from(l.max_revisions),
            "LIMIT.REVISIONS",
        ),
        (
            "max_nesting_depth",
            f64::from(l.max_nesting_depth),
            "LIMIT.NESTING_DEPTH",
        ),
        (
            "max_decoded_bytes_per_stream",
            l.max_decoded_bytes_per_stream as f64,
            "LIMIT.STREAM_DECODED_BYTES",
        ),
        (
            "max_decoded_bytes_total",
            l.max_decoded_bytes_total as f64,
            "LIMIT.DECODED_BYTES",
        ),
        (
            "max_compression_ratio",
            f64::from(l.max_compression_ratio),
            "LIMIT.COMPRESSION_RATIO",
        ),
    ];
    let got: Vec<_> = rows
        .iter()
        .filter(|(s, _)| s == "Reference")
        .filter(|(_, c)| c[2].starts_with("`LIMIT."))
        .collect();
    assert_eq!(got.len(), limits.len());
    for ((_, cells), (name, default, code)) in got.iter().zip(limits) {
        assert_eq!(code_cell(&cells[0]).0, name);
        assert_eq!(first_number(&cells[1]), default, "{name}");
        assert_eq!(cells[2], format!("`{code}`"), "{name}");
    }
    let t = Thresholds::default();
    let thresholds = [
        (
            "max_image_pixels",
            t.max_image_pixels as f64,
            "RESOURCE.IMAGE_DIMENSIONS",
        ),
        ("max_page_side_pt", t.max_page_side_pt, "RESOURCE.PAGE_SIZE"),
        ("max_pages", t.max_pages as f64, "RESOURCE.PAGE_COUNT"),
        (
            "max_filter_chain",
            f64::from(t.max_filter_chain),
            "STRUCT.FILTER_CHAIN",
        ),
        (
            "max_trailing_bytes",
            t.max_trailing_bytes as f64,
            "STRUCT.TRAILING_DATA",
        ),
    ];
    let got: Vec<_> = rows
        .iter()
        .filter(|(s, c)| s == "Reference" && c.len() == 3 && !c[2].starts_with("`LIMIT."))
        .filter(|(_, c)| c[0].starts_with("`max_"))
        .collect();
    assert_eq!(got.len(), thresholds.len());
    for ((_, cells), (name, default, rule)) in got.iter().zip(thresholds) {
        assert_eq!(code_cell(&cells[0]).0, name);
        assert_eq!(first_number(&cells[1]), default, "{name}");
        assert_eq!(cells[2], format!("`{rule}`"), "{name}");
    }
    // The schema documents the same limit and threshold names.
    let schema = read("schemas/policy.schema.json");
    for name in limits
        .iter()
        .map(|x| x.0)
        .chain(thresholds.iter().map(|x| x.0))
    {
        assert!(schema.contains(&format!("\"{name}\"")), "{name}");
    }
}

#[test]
fn policy_md_lists_every_engine_error() {
    let md = read("docs/policy.md");
    let codes: Vec<String> = table_rows(&md)
        .into_iter()
        .filter(|(s, _)| s == "Engine errors")
        .map(|(_, c)| code_cell(&c[0]).0)
        .collect();
    let want: Vec<String> = IssueCode::ALL
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();
    assert_eq!(codes, want);
    assert!(md.contains(&format!(
        "more than {} filters (fixed)",
        quelda_core::filters::MAX_FILTER_CHAIN
    )));
}

#[test]
fn policy_md_examples_are_valid_policies() {
    let md = read("docs/policy.md");
    let minimal = fs::read(fixture("benign/minimal.pdf")).unwrap();
    let mut n = 0;
    for (_, info, body) in blocks(&md) {
        if info != "json" {
            continue;
        }
        let v: Value = serde_json::from_str(&quelda_core::scan_json(&minimal, &body)).unwrap();
        assert_eq!(
            v["errors"],
            Value::Array(vec![]),
            "policy rejected:\n{body}"
        );
        n += 1;
    }
    assert!(n >= 6, "{n}");
}

// ---- links ----

/// Markdown files people read (CHANGELOG lists versions by design).
const LINKED_DOCS: &[&str] = &[
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "docs/cli.md",
    "docs/policy.md",
    "docs/rules.md",
    "packages/quelda-js/README.md",
    "schemas/README.md",
    "fuzz/README.md",
];

const GITHUB: &str = "https://github.com/tranhuucanh/quelda/";

/// GitHub's heading anchor: lowercase, spaces → `-`, punctuation dropped.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

fn anchors(md: &str) -> Vec<String> {
    let mut fenced = false;
    md.lines()
        .filter(|l| {
            if l.starts_with("```") {
                fenced = !fenced;
            }
            !fenced && l.starts_with('#')
        })
        .map(|l| slug(l.trim_start_matches('#')))
        .collect()
}

/// `[text](target)` targets outside code (fenced blocks and `inline code`).
fn links(md: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in md.lines() {
        if line.starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let mut code = false;
        let b = line.as_bytes();
        for i in 0..b.len() {
            if b[i] == b'`' {
                code = !code;
            } else if !code && b[i] == b']' && b.get(i + 1) == Some(&b'(') {
                if let Some(end) = line[i + 2..].find(')') {
                    out.push(line[i + 2..i + 2 + end].to_string());
                }
            }
        }
    }
    out
}

/// Every link to a file of this repo (relative, or github.com/…/blob|tree/main/…)
/// points at a file that exists, and every `#anchor` at a heading of it.
#[test]
fn doc_links_resolve() {
    let mut n = 0;
    for doc in LINKED_DOCS {
        let dir = Path::new(doc).parent().unwrap();
        for link in links(&read(doc)) {
            let (path, anchor) = match link.split_once('#') {
                Some((p, a)) => (p.to_string(), Some(a.to_string())),
                None => (link.clone(), None),
            };
            let local = if let Some(rest) = path.strip_prefix(GITHUB) {
                match rest.split_once("/main/") {
                    Some((kind, p)) if kind == "blob" || kind == "tree" => Some(PathBuf::from(p)),
                    _ => {
                        assert!(
                            rest.is_empty()
                                || ["releases", "releases/latest", "issues"]
                                    .contains(&rest.trim_end_matches('/')),
                            "{doc}: unexpected GitHub link {link}"
                        );
                        None
                    }
                }
            } else if path.starts_with("http") || path.starts_with("mailto:") {
                None
            } else if path.is_empty() {
                Some(PathBuf::from(doc))
            } else {
                Some(dir.join(&path))
            };
            let Some(local) = local else { continue };
            let file = repo().join(&local);
            assert!(file.exists(), "{doc}: broken link {link}");
            if let Some(a) = anchor {
                let target = if file.is_dir() {
                    file.join("README.md")
                } else {
                    file
                };
                let text = fs::read_to_string(&target).unwrap();
                assert!(
                    anchors(&text).contains(&a),
                    "{doc}: no heading #{a} in {link}"
                );
            }
            n += 1;
        }
    }
    assert!(n >= 40, "{n} links checked");
}

#[test]
fn slug_matches_github() {
    assert_eq!(
        slug(" Call it from your backend"),
        "call-it-from-your-backend"
    );
    assert_eq!(
        slug(" `scanner.scan(input, policy?, options?)`"),
        "scannerscaninput-policy-options"
    );
    assert_eq!(slug(" No build step (CDN)"), "no-build-step-cdn");
    assert_eq!(slug(" README, Development"), "readme-development");
}

/// The "Modes" tables of both READMEs group the categories by their action in
/// each preset; together they list every category once.
#[test]
fn readme_modes_match_the_presets() {
    for doc in ["README.md", "packages/quelda-js/README.md"] {
        let md = read(doc);
        let rows: Vec<_> = table_rows(&md)
            .into_iter()
            .filter(|(s, _)| s == "Modes: strict, balanced, permissive")
            .collect();
        assert_eq!(rows.len(), 3, "{doc}");
        let mut seen = Vec::new();
        for (_, cells) in rows {
            for key in cells[0].split(", ") {
                let (key, _) = code_cell(key);
                let cat = Category::ALL
                    .into_iter()
                    .find(|c| c.key() == key)
                    .unwrap_or_else(|| panic!("{doc}: unknown category {key}"));
                for (i, p) in Preset::ALL.into_iter().enumerate() {
                    assert_eq!(
                        cells[1 + i],
                        action(presets::category_action(p, cat)),
                        "{doc}: {key}"
                    );
                }
                seen.push(key);
            }
        }
        seen.sort();
        let mut all: Vec<_> = Category::ALL.iter().map(|c| c.key().to_string()).collect();
        all.sort();
        assert_eq!(seen, all, "{doc}");
    }
}
