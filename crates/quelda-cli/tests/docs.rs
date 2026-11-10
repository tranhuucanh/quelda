//! The docs show what really happens (ADR #34 (f)):
//! - every caller example in docs/cli.md is the tested file in
//!   docs/examples/cli/ (run by scripts/docs-examples-test.mjs), verbatim;
//! - the sample verdict is the real output for its fixture;
//! - every sample policy is accepted by the engine;
//! - every `quelda …` command in README.md and docs/cli.md runs (exit 0 on a
//!   clean `upload.pdf`).

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
    for doc in ["README.md", "docs/cli.md"] {
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
