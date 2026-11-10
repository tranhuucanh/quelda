//! Corpus evaluation (plan Step 13): scan every file under a directory with
//! each preset and write the results as CSV (one row per file × preset) and
//! JSONL (the full verdicts).
//!
//! Files are labelled by their path: a directory named `NG` or `incidents`
//! means "expected bad", `OK` means "expected good"; anything else is
//! unlabelled (assumed good, the owner does not know). Matching is
//! case-insensitive. Hidden files (`.DS_Store`, …) and symlinks are skipped.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use serde_json::Value;

/// Presets every file is scanned with, in output order.
pub const PRESETS: [&str; 3] = ["strict", "balanced", "permissive"];

/// CSV header; [`Record::csv_row`] writes the same columns.
pub const CSV_HEADER: &str =
    "file,label,preset,status,valid,outcome,violations,warnings,errors,bytes,decoded_bytes,ms";

/// What the corpus layout says the file should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    /// Under `NG/` or `incidents/`: must be rejected.
    Bad,
    /// Under `OK/`: must pass.
    Good,
    /// No label: assumed good.
    Unlabelled,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Bad => "bad",
            Label::Good => "good",
            Label::Unlabelled => "unlabelled",
        }
    }
}

/// Label from the path relative to the corpus root (innermost label wins).
pub fn label(rel: &Path) -> Label {
    let mut out = Label::Unlabelled;
    for c in rel.components() {
        if let Component::Normal(name) = c {
            let name = name.to_string_lossy().to_ascii_lowercase();
            match name.as_str() {
                "ng" | "incidents" => out = Label::Bad,
                "ok" => out = Label::Good,
                _ => {}
            }
        }
    }
    out
}

/// Every regular file under `root`, recursively, sorted; hidden entries and
/// symlinks are skipped.
pub fn walk(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Result of one file × preset.
#[derive(Debug, Clone)]
pub struct Record {
    /// Path relative to the corpus root, `/`-separated.
    pub file: String,
    pub label: Label,
    pub preset: &'static str,
    /// `PASS` / `REJECT` / `ERROR`, or `READ_ERROR` when the file could not be read.
    pub status: String,
    pub valid: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
    /// Error codes (`LIMIT.*`, `ENGINE.*`, …), or the I/O error.
    pub errors: Vec<String>,
    pub bytes: u64,
    pub decoded_bytes: u64,
    /// Native wall time of `scan_json`.
    pub ms: f64,
    /// Full verdict (`null` on read errors).
    pub verdict: Value,
}

impl Record {
    /// `ok` when the result matches the label, else `MISSED` (bad file passed)
    /// or `FLAGGED` (good / unlabelled file rejected or errored).
    pub fn outcome(&self) -> &'static str {
        match (self.label, self.valid) {
            (Label::Bad, false) | (Label::Good | Label::Unlabelled, true) => "ok",
            (Label::Bad, true) => "MISSED",
            (Label::Good | Label::Unlabelled, false) => "FLAGGED",
        }
    }

    pub fn csv_row(&self) -> String {
        let fields = [
            csv_field(&self.file),
            self.label.as_str().to_string(),
            self.preset.to_string(),
            self.status.clone(),
            self.valid.to_string(),
            self.outcome().to_string(),
            csv_field(&self.violations.join(";")),
            csv_field(&self.warnings.join(";")),
            csv_field(&self.errors.join(";")),
            self.bytes.to_string(),
            self.decoded_bytes.to_string(),
            format!("{:.1}", self.ms),
        ];
        fields.join(",")
    }
}

/// RFC 4180 quoting when needed.
pub fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn ids(verdict: &Value, list: &str, key: &str) -> Vec<String> {
    verdict[list]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v[key].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Scans `bytes` with `preset` and builds the record.
pub fn scan_one(file: &str, label: Label, preset: &'static str, bytes: &[u8]) -> Record {
    let policy = format!("{{\"preset\":\"{preset}\"}}");
    let start = Instant::now();
    let json = quelda_core::scan_json(bytes, &policy);
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    let verdict: Value = serde_json::from_str(&json).unwrap_or(Value::Null);
    Record {
        file: file.to_string(),
        label,
        preset,
        status: verdict["status"]
            .as_str()
            .unwrap_or("INVALID_VERDICT")
            .to_string(),
        valid: verdict["valid"].as_bool() == Some(true),
        violations: ids(&verdict, "violations", "rule_id"),
        warnings: ids(&verdict, "warnings", "rule_id"),
        errors: ids(&verdict, "errors", "code"),
        bytes: bytes.len() as u64,
        decoded_bytes: verdict["stats"]["decoded_bytes"].as_u64().unwrap_or(0),
        ms,
        verdict,
    }
}

/// Scans every file under `root` with every preset.
pub fn evaluate(root: &Path) -> io::Result<Vec<Record>> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let file = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let label = label(rel);
        match fs::read(&path) {
            Ok(bytes) => {
                for preset in PRESETS {
                    out.push(scan_one(&file, label, preset, &bytes));
                }
            }
            Err(e) => {
                for preset in PRESETS {
                    out.push(Record {
                        file: file.clone(),
                        label,
                        preset,
                        status: "READ_ERROR".to_string(),
                        valid: false,
                        violations: Vec::new(),
                        warnings: Vec::new(),
                        errors: vec![e.to_string()],
                        bytes: 0,
                        decoded_bytes: 0,
                        ms: 0.0,
                        verdict: Value::Null,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// CSV text: header + one row per record.
pub fn to_csv(records: &[Record]) -> String {
    let mut s = String::from(CSV_HEADER);
    s.push('\n');
    for r in records {
        s.push_str(&r.csv_row());
        s.push('\n');
    }
    s
}

/// JSONL text: `{file, label, preset, ms, verdict}` per record.
pub fn to_jsonl(records: &[Record]) -> String {
    let mut s = String::new();
    for r in records {
        let line = serde_json::json!({
            "file": r.file,
            "label": r.label.as_str(),
            "preset": r.preset,
            "ms": r.ms,
            "verdict": r.verdict,
        });
        let _ = writeln!(s, "{line}");
    }
    s
}

/// Short per-preset summary (counts by status and outcome).
pub fn summary(records: &[Record]) -> String {
    let mut s = String::new();
    for preset in PRESETS {
        let rs: Vec<&Record> = records.iter().filter(|r| r.preset == preset).collect();
        let count = |f: &dyn Fn(&Record) -> bool| rs.iter().filter(|r| f(r)).count();
        let _ = writeln!(
            s,
            "{preset:<10} files={} PASS={} REJECT={} ERROR={} | MISSED={} FLAGGED={}",
            rs.len(),
            count(&|r| r.status == "PASS"),
            count(&|r| r.status == "REJECT"),
            count(&|r| r.status != "PASS" && r.status != "REJECT"),
            count(&|r| r.outcome() == "MISSED"),
            count(&|r| r.outcome() == "FLAGGED"),
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_from_path() {
        assert_eq!(label(Path::new("important/NG/x.pdf")), Label::Bad);
        assert_eq!(label(Path::new("important/ng/x.pdf")), Label::Bad);
        assert_eq!(label(Path::new("incidents/a/x.pdf")), Label::Bad);
        assert_eq!(label(Path::new("important/OK/x.pdf")), Label::Good);
        assert_eq!(label(Path::new("a/b/x.pdf")), Label::Unlabelled);
        // Innermost label wins; file names are not labels.
        assert_eq!(label(Path::new("NG/OK/x.pdf")), Label::Good);
        assert_eq!(label(Path::new("OK/NG/x.pdf")), Label::Bad);
        assert_eq!(label(Path::new("a/ng")), Label::Bad); // a file named `ng` still counts
        assert_eq!(label(Path::new("a/NGx/x.pdf")), Label::Unlabelled);
    }

    #[test]
    fn csv_quoting() {
        assert_eq!(csv_field("a"), "a");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
        assert_eq!(csv_field(""), "");
    }

    #[test]
    fn outcomes() {
        let mut r = scan_one("x", Label::Bad, "balanced", b"%!PS-Adobe-3.0\nshowpage\n");
        assert_eq!(r.status, "REJECT");
        assert!(
            r.violations
                .iter()
                .any(|v| v == "FILETYPE.POSTSCRIPT_MAGIC")
        );
        assert_eq!(r.outcome(), "ok");
        r.label = Label::Good;
        assert_eq!(r.outcome(), "FLAGGED");
        r.label = Label::Unlabelled;
        assert_eq!(r.outcome(), "FLAGGED");
        r.valid = true;
        assert_eq!(r.outcome(), "ok");
        r.label = Label::Bad;
        assert_eq!(r.outcome(), "MISSED");
    }

    #[test]
    fn row_has_header_columns() {
        let r = scan_one("dir/a,b.pdf", Label::Unlabelled, "strict", b"");
        let row = r.csv_row();
        assert!(row.starts_with("\"dir/a,b.pdf\",unlabelled,strict,"));
        // Quoted comma is one field.
        let unquoted = row.replacen("\"dir/a,b.pdf\"", "f", 1);
        assert_eq!(unquoted.split(',').count(), CSV_HEADER.split(',').count());
        assert!(!r.valid);
    }

    #[test]
    fn walk_skips_hidden_and_recurses() {
        let root = std::env::temp_dir().join(format!("quelda-eval-walk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("a/b/.hidden")).unwrap();
        fs::write(root.join("top.pdf"), b"x").unwrap();
        fs::write(root.join("a/b/deep.ai"), b"x").unwrap();
        fs::write(root.join("a/.DS_Store"), b"x").unwrap();
        fs::write(root.join("a/b/.hidden/no.pdf"), b"x").unwrap();
        let got: Vec<String> = walk(&root)
            .unwrap()
            .iter()
            .map(|p| {
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(got, vec!["a/b/deep.ai", "top.pdf"]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn summary_counts() {
        let mut read_error = scan_one("unreadable", Label::Good, "strict", b"");
        read_error.status = "READ_ERROR".to_string();
        let recs = vec![
            scan_one("bad", Label::Bad, "strict", b"%!PS\n"),
            scan_one("empty", Label::Good, "strict", b""),
            read_error,
        ];
        let s = summary(&recs);
        assert!(
            s.contains("strict     files=3 PASS=0 REJECT=2 ERROR=1 | MISSED=0 FLAGGED=2"),
            "{s}"
        );
        assert!(s.contains("balanced   files=0"));
    }
}
