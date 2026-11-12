//! The docs show what really happens (ADR #34 (f)):
//! - every caller example in docs/cli.md is the tested file in
//!   docs/examples/cli/ (run by scripts/docs-examples-test.mjs), verbatim;
//! - the sample verdict is the real output for its fixture;
//! - every sample policy is accepted by the engine;
//! - every `quelda …` command in README.md, docs/cli.md and docs/policy.md
//!   runs (exit 0 on a clean `upload.pdf`);
//! - the tables of docs/rules.md, docs/policy.md and the README showcases (repo, npm)
//!   (rules, preset actions, locked rules, limits, thresholds, engine errors,
//!   counts) are what the engine does, in English and in Japanese (`*.ja.md`);
//! - a Japanese doc has the same code blocks, headings and tables as the English one.

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

/// The `--format text` sample of a folder scan is the real output (only the
/// time and the number of jobs differ).
#[test]
fn sample_folder_report_is_real_output() {
    let md = read("docs/cli.md");
    let shown = blocks(&md)
        .into_iter()
        .find(|(m, _, _)| m.as_deref() == Some("batch-text"))
        .map(|(_, _, body)| body)
        .unwrap();
    let dir = std::env::temp_dir().join(format!("quelda-docs-batch-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    for (path, from) in [
        ("uploads/2026/11/invoice.pdf", "benign/minimal.pdf"),
        (
            "uploads/2026/11/brochure.pdf",
            "rules/FILETYPE.POSTSCRIPT_MAGIC/bad/ps-adobe.pdf",
        ),
        (
            "uploads/2026/12/form.pdf",
            "rules/ACTIVE.JAVASCRIPT/bad/plain.pdf",
        ),
        ("uploads/2026/12/logo.AI", "benign/minimal.pdf"),
    ] {
        let to = dir.join(path);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(fixture(from), to).unwrap();
    }
    fs::write(dir.join("uploads/notes.txt"), "x").unwrap();
    let out = Command::cargo_bin("quelda")
        .unwrap()
        .current_dir(&dir)
        .args(["scan", "uploads", "--format", "text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let real = String::from_utf8(out.stdout).unwrap();
    // `… 0 ERROR in 0.0 s (4 jobs)` → `… 0 ERROR`.
    let timeless = |t: &str| -> String {
        t.lines()
            .map(|l| l.split(" ERROR in ").next().unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        timeless(&shown),
        timeless(&real),
        "docs/cli.md folder sample"
    );
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
    // A folder for the folder examples: nested, valid files, one non-PDF.
    for sub in ["uploads/2026/11", "uploads/2026/12"] {
        fs::create_dir_all(dir.join(sub)).unwrap();
        fs::copy(fixture("benign/minimal.pdf"), dir.join(sub).join("a.pdf")).unwrap();
    }
    fs::write(dir.join("uploads/notes.txt"), "x").unwrap();
    let mut n = 0;
    for doc in ["README.md", "docs/cli.md", "docs/policy.md"] {
        for (_, info, body) in blocks(&read(doc)) {
            if info != "bash" {
                continue;
            }
            for line in body.lines().filter(|l| l.starts_with("quelda ")) {
                // The quelda part of a pipe or an output redirection.
                let command = line.split(['|', '>']).next().unwrap_or(line);
                let (words, stdin) = shell_words(command);
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

/// The docs in one language: `README.md` or `README.ja.md`, and the words the
/// table checks look for. `{r}` rules, `{c}` categories, `{s}` engine
/// safeguards, `{list}` the category keys, `{n}` the filter chain limit.
struct Lang {
    ext: &'static str,
    rules_count: &'static str,
    safeguards: &'static str,
    checks_section: &'static str,
    modes_section: &'static str,
    presets_section: &'static str,
    reference_section: &'static str,
    errors_section: &'static str,
    locked_rules: &'static str,
    categories_line: &'static str,
    filter_chain: &'static str,
}

const LANGS: [Lang; 2] = [
    Lang {
        ext: ".md",
        rules_count: "**{r} rules in {c} categories**",
        safeguards: ", plus {s} engine safeguards",
        checks_section: " What quelda checks\n",
        modes_section: "Modes: strict, balanced, permissive",
        presets_section: "Presets",
        reference_section: "Reference",
        errors_section: "Engine errors",
        locked_rules: "**Locked rules**",
        categories_line: "Categories: {list}.",
        filter_chain: "more than {n} filters (fixed)",
    },
    Lang {
        ext: ".ja.md",
        rules_count: "**{c} カテゴリ、{r} 個のルール**",
        safeguards: "に加え、{s} 個のエンジン保護機能",
        checks_section: " quelda が検査する内容\n",
        modes_section: "モード: strict, balanced, permissive",
        presets_section: "プリセット",
        reference_section: "リファレンス",
        errors_section: "エンジンエラー",
        locked_rules: "**ロックされたルール**",
        categories_line: "カテゴリ: {list}。",
        filter_chain: "{n} 個を超えるフィルタ（固定）",
    },
];

impl Lang {
    /// `docs/rules` → `docs/rules.md` or `docs/rules.ja.md`.
    fn doc(&self, stem: &str) -> String {
        format!("{stem}{}", self.ext)
    }
}

/// `template` with each `{key}` replaced by its value.
fn fill(template: &str, vars: &[(&str, String)]) -> String {
    vars.iter().fold(template.to_string(), |t, (k, v)| {
        t.replace(&format!("{{{k}}}"), v)
    })
}

fn rules_count() -> Vec<(&'static str, String)> {
    vec![
        ("r", registry().len().to_string()),
        ("c", Category::ALL.len().to_string()),
        // POLICY.INVALID is not a safeguard.
        ("s", (IssueCode::ALL.len() - 1).to_string()),
    ]
}

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
            // README headings start with an icon: `## ⚡ Speed and memory`.
            section = h
                .trim_start_matches(|c: char| !c.is_alphanumeric())
                .to_string();
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
    let rules = registry();
    for lang in &LANGS {
        let doc = lang.doc("docs/rules");
        let md = read(&doc);
        let rows = table_rows(&md);
        assert_eq!(rows.len(), rules.len(), "{doc}: one row per rule");
        for (section, cells) in rows {
            let (id, locked) = code_cell(&cells[0]);
            let meta = quelda_core::rules::registry::all()
                .iter()
                .map(|r| r.meta())
                .find(|m| m.id == id)
                .unwrap_or_else(|| panic!("{doc}: unknown rule {id}"));
            assert!(
                section.ends_with(&format!("(`{}`)", meta.category.key())),
                "{doc}: {id} is under `{section}`"
            );
            assert_eq!(locked, meta.locked, "{doc}: {id}: 🔒");
            for (i, p) in Preset::ALL.into_iter().enumerate() {
                assert_eq!(
                    cells[2 + i],
                    action(resolve(meta, &preset_policy(p))),
                    "{doc}: {id} under {}",
                    p.key()
                );
            }
        }
        let header = fill(lang.rules_count, &rules_count());
        assert!(md.contains(&header), "{doc}: {header}");
    }
}

#[test]
fn readme_showcase_counts_match_the_registry() {
    let rules = registry();
    for (lang, stem) in LANGS
        .iter()
        .flat_map(|l| ["README", "packages/quelda-js/README"].map(|s| (l, s)))
    {
        let doc = lang.doc(stem);
        let md = read(&doc);
        let header = fill(
            &format!("{}{}", lang.rules_count, lang.safeguards),
            &rules_count(),
        );
        assert!(md.contains(&header), "{doc}: {header}");
        let section = &md[md
            .find(lang.checks_section)
            .unwrap_or_else(|| panic!("{doc}: no section{}", lang.checks_section))..];
        let section = &section[..section.find("\n## ").unwrap()];
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
    for lang in &LANGS {
        policy_md_presets(lang);
    }
}

fn policy_md_presets(lang: &Lang) {
    let doc = lang.doc("docs/policy");
    let md = read(&doc);
    let rows = table_rows(&md);
    let presets_section = lang.presets_section;
    // Category table: category, what it covers, strict, balanced, permissive.
    let cats: Vec<_> = rows
        .iter()
        .filter(|(s, c)| s == presets_section && !c[0].contains('.'))
        .collect();
    assert_eq!(cats.len(), Category::ALL.len(), "{doc}");
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
                "{doc}: {key}"
            );
        }
    }
    // Rules that differ from their category: rule, strict, balanced, permissive, why.
    let mut listed = Vec::new();
    for (_, cells) in rows
        .iter()
        .filter(|(s, c)| s == presets_section && c[0].contains('.'))
    {
        let (id, _) = code_cell(&cells[0]);
        for (i, p) in Preset::ALL.into_iter().enumerate() {
            assert_eq!(
                cells[1 + i],
                action(presets::rule_override(p, &id).unwrap()),
                "{doc}: {id}"
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
    assert_eq!(listed, want, "{doc}: rules that differ from their category");
    // Locked list.
    for r in all {
        let m = r.meta();
        let named = md.contains(&format!("`{}`", m.id));
        if m.locked {
            assert!(named, "{doc}: locked rule {} not listed", m.id);
        }
    }
    let locked_line = md
        .lines()
        .skip_while(|l| !l.starts_with(lang.locked_rules))
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
        "{doc}: {locked_line}"
    );
}

#[test]
fn policy_md_reference_matches_the_engine() {
    for lang in &LANGS {
        policy_md_reference(lang);
    }
}

fn policy_md_reference(lang: &Lang) {
    let doc = lang.doc("docs/policy");
    let md = read(&doc);
    let keys: Vec<String> = Category::ALL
        .iter()
        .map(|c| format!("`{}`", c.key()))
        .collect();
    let flat = md.split_whitespace().collect::<Vec<_>>().join(" ");
    let list = fill(lang.categories_line, &[("list", keys.join(", "))]);
    assert!(flat.contains(&list), "{doc}: {list}");
    let reference = lang.reference_section;
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
        .filter(|(s, _)| s == reference)
        .filter(|(_, c)| c[2].starts_with("`LIMIT."))
        .collect();
    assert_eq!(got.len(), limits.len(), "{doc}");
    for ((_, cells), (name, default, code)) in got.iter().zip(limits) {
        assert_eq!(code_cell(&cells[0]).0, name, "{doc}");
        assert_eq!(first_number(&cells[1]), default, "{doc}: {name}");
        assert_eq!(cells[2], format!("`{code}`"), "{doc}: {name}");
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
        .filter(|(s, c)| s == reference && c.len() == 3 && !c[2].starts_with("`LIMIT."))
        .filter(|(_, c)| c[0].starts_with("`max_"))
        .collect();
    assert_eq!(got.len(), thresholds.len(), "{doc}");
    for ((_, cells), (name, default, rule)) in got.iter().zip(thresholds) {
        assert_eq!(code_cell(&cells[0]).0, name, "{doc}");
        assert_eq!(first_number(&cells[1]), default, "{doc}: {name}");
        assert_eq!(cells[2], format!("`{rule}`"), "{doc}: {name}");
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
    let want: Vec<String> = IssueCode::ALL
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();
    for lang in &LANGS {
        let doc = lang.doc("docs/policy");
        let md = read(&doc);
        let codes: Vec<String> = table_rows(&md)
            .into_iter()
            .filter(|(s, _)| s == lang.errors_section)
            .map(|(_, c)| code_cell(&c[0]).0)
            .collect();
        assert_eq!(codes, want, "{doc}");
        let chain = fill(
            lang.filter_chain,
            &[("n", quelda_core::filters::MAX_FILTER_CHAIN.to_string())],
        );
        assert!(md.contains(&chain), "{doc}: {chain}");
    }
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
    "README.ja.md",
    "docs/cli.ja.md",
    "docs/policy.ja.md",
    "docs/rules.ja.md",
    "packages/quelda-js/README.ja.md",
];

const GITHUB: &str = "https://github.com/tranhuucanh/quelda/";

/// GitHub's heading anchor: lowercase, every character that is not a word
/// character (`\p{Word}`: letters, digits, marks, `_`, joiners), `-` or a space
/// dropped, spaces → `-`. Marks stay: `🎚️` keeps its invisible U+FE0F.
fn slug(heading: &str) -> String {
    let mark = |c: char| {
        matches!(c,
            '\u{0300}'..='\u{036F}' | '\u{1AB0}'..='\u{1AFF}' | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}' | '\u{3099}'..='\u{309A}' | '\u{FE00}'..='\u{FE0F}'
            | '\u{FE20}'..='\u{FE2F}' | '\u{E0100}'..='\u{E01EF}' | '\u{200C}' | '\u{200D}')
    };
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || mark(c) || c == '-' || c == '_' => Some(c),
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
/// The file of this repo a link of `doc` goes to (relative, or
/// github.com/…/blob|tree/main/…; the project page is `README.md`), and its
/// `#anchor`. `None` for a link outside the repo.
fn link_target(doc: &str, link: &str) -> Option<(PathBuf, Option<String>)> {
    let (path, anchor) = match link.split_once('#') {
        Some((p, a)) => (p, Some(a.to_string())),
        None => (link, None),
    };
    let local = if path == GITHUB.trim_end_matches('/') {
        PathBuf::from("README.md")
    } else if let Some(rest) = path.strip_prefix(GITHUB) {
        match rest.split_once("/main/") {
            Some((kind, p)) if kind == "blob" || kind == "tree" => PathBuf::from(p),
            _ => {
                assert!(
                    rest.is_empty()
                        || ["releases", "releases/latest", "issues"]
                            .contains(&rest.trim_end_matches('/')),
                    "{doc}: unexpected GitHub link {link}"
                );
                return None;
            }
        }
    } else if path.starts_with("http") || path.starts_with("mailto:") {
        return None;
    } else if path.is_empty() {
        PathBuf::from(doc)
    } else {
        Path::new(doc).parent().unwrap().join(path)
    };
    Some((local, anchor))
}

/// Every link to a file of this repo points at a file that exists, and every
/// `#anchor` at a heading of it.
#[test]
fn doc_links_resolve() {
    let mut n = 0;
    for doc in LINKED_DOCS {
        for link in links(&read(doc)) {
            let Some((local, anchor)) = link_target(doc, &link) else {
                continue;
            };
            let file = repo().join(&local);
            assert!(file.exists(), "{doc}: broken link {link}");
            if let Some(a) = anchor {
                let file = if file.is_dir() {
                    file.join("README.md")
                } else {
                    file
                };
                let text = fs::read_to_string(&file).unwrap();
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
    assert_eq!(slug(" ⚡ 速度とメモリ"), "-速度とメモリ");
    assert_eq!(
        slug(" 🎚 モード: strict, balanced, permissive"),
        "-モード-strict-balanced-permissive"
    );
    // Seen on github.com: the variation selector of `🎚️` stays in the anchor.
    assert_eq!(slug(" 🎚\u{FE0F} Modes"), "\u{FE0F}-modes");
}

/// The "Modes" tables of both READMEs group the categories by their action in
/// each preset; together they list every category once.
#[test]
fn readme_modes_match_the_presets() {
    for (lang, stem) in LANGS
        .iter()
        .flat_map(|l| ["README", "packages/quelda-js/README"].map(|s| (l, s)))
    {
        let doc = lang.doc(stem);
        let md = read(&doc);
        let rows: Vec<_> = table_rows(&md)
            .into_iter()
            .filter(|(s, _)| s == lang.modes_section)
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

// ---- translations ----

/// The layout of a doc outside code blocks: heading levels, the cells of each
/// table row (a cell in backticks as written, others only counted), and the
/// list items.
#[derive(Debug, PartialEq)]
struct Shape {
    headings: Vec<usize>,
    tables: Vec<Vec<Option<String>>>,
    list_items: Vec<String>,
}

fn shape(md: &str) -> Shape {
    let mut fenced = false;
    let mut s = Shape {
        headings: Vec::new(),
        tables: Vec::new(),
        list_items: Vec::new(),
    };
    for line in md.lines() {
        if line.starts_with("```") {
            fenced = !fenced;
        } else if fenced {
        } else if line.starts_with('#') {
            s.headings
                .push(line.chars().take_while(|&c| c == '#').count());
        } else if line.starts_with('|') {
            s.tables.push(
                line.trim_matches('|')
                    .split(" | ")
                    .map(|c| c.trim())
                    .map(|c| {
                        let code = c.starts_with('`')
                            && (c.ends_with('`') || c.ends_with('🔒'))
                            && c.matches('`').count() == 2;
                        code.then(|| c.to_string())
                    })
                    .collect(),
            );
        } else if let Some(marker) = ["- ", "1. ", "2. ", "3. ", "4. ", "5. "]
            .into_iter()
            .find(|m| line.trim_start().starts_with(m))
        {
            s.list_items.push(format!(
                "{}{marker}",
                &line[..line.len() - line.trim_start().len()]
            ));
        }
    }
    s
}

/// `docs/cli.ja.md` → `docs/cli.md`.
fn english(path: &Path) -> PathBuf {
    let s = path.to_str().unwrap();
    PathBuf::from(
        s.strip_suffix(".ja.md")
            .map_or(s.to_string(), |b| format!("{b}.md")),
    )
}

/// The links of `doc` below the language switch, each as the English file it
/// stands for and the index of the heading it goes to (outside links as written),
/// checking that each one stays in the language of `doc`.
fn link_map(doc: &str) -> Vec<(String, Option<usize>)> {
    let md = read(doc);
    let body: String = md.lines().skip(3).collect::<Vec<_>>().join("\n");
    let ja = doc.ends_with(".ja.md");
    links(&body)
        .into_iter()
        .map(|link| match link_target(doc, &link) {
            None => (link, None),
            Some((file, anchor)) => {
                let name = file.to_str().unwrap();
                let translated = english(&file) != file;
                let has_ja = name.ends_with(".md")
                    && repo()
                        .join(english(&file).to_str().unwrap().replace(".md", ".ja.md"))
                        .exists();
                assert_eq!(
                    translated,
                    ja && has_ja,
                    "{doc}: {link} leaves the language of the doc"
                );
                let heading = anchor.map(|a| {
                    anchors(&read(name))
                        .iter()
                        .position(|h| *h == a)
                        .unwrap_or_else(|| panic!("{doc}: no heading #{a} in {link}"))
                });
                (english(&file).to_str().unwrap().to_string(), heading)
            }
        })
        .collect()
}

/// Code blocks, with the body of a plain `text` block (prose, translated) left
/// out; a marked block (real output) is code.
fn code_blocks(md: &str) -> Vec<(Option<String>, String, Option<String>)> {
    blocks(md)
        .into_iter()
        .map(|(marker, info, body)| {
            let prose = marker.is_none() && info == "text";
            (marker, info, (!prose).then_some(body))
        })
        .collect()
}

/// A Japanese doc is the English one translated: the same code blocks, word for
/// word (commands, examples and outputs stay tested once), the same headings and
/// tables, and a link to the other language at the top of each.
#[test]
fn japanese_docs_match_the_english_ones() {
    for stem in [
        "README",
        "packages/quelda-js/README",
        "docs/cli",
        "docs/policy",
        "docs/rules",
    ] {
        let en = read(&format!("{stem}.md"));
        let ja = read(&format!("{stem}.ja.md"));
        assert_eq!(
            code_blocks(&ja),
            code_blocks(&en),
            "{stem}.ja.md: code blocks"
        );
        assert_eq!(
            shape(&ja),
            shape(&en),
            "{stem}.ja.md: headings, tables, lists"
        );
        assert_eq!(
            link_map(&format!("{stem}.ja.md")),
            link_map(&format!("{stem}.md")),
            "{stem}.ja.md: the same links, to the same sections"
        );
        let top = |md: &str| md.lines().take(3).collect::<Vec<_>>().join("\n");
        assert!(
            top(&en).contains("[日本語]("),
            "{stem}.md: link to Japanese"
        );
        assert!(
            top(&ja).contains("[English]("),
            "{stem}.ja.md: link to English"
        );
    }
}
