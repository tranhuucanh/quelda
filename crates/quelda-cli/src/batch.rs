//! `quelda scan` on folders or several files: walks the folders, scans the
//! files in parallel and writes one result per file, in a fixed order (the
//! arguments in order; inside a folder, paths sorted by name).
//!
//! Every file that cannot be scanned (and every folder that cannot be listed)
//! gets its own `ERROR` result: nothing is dropped silently.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, DirEntry};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Instant;

use quelda_core::verdict::Status;
use quelda_core::{Policy, Verdict};
use serde_json::Value;

use crate::args::{Format, Input, Scan};
use crate::{EXIT_ERROR, EXIT_IO, EXIT_PASS, EXIT_REJECT, scan, text};

/// Extensions scanned in folders without `--all` (any case).
pub const EXTENSIONS: [&str; 2] = ["pdf", "ai"];

/// Worker stack: as large as the main thread's, so a file never behaves
/// differently in a batch.
const STACK_BYTES: usize = 8 << 20;

/// What to scan, in output order.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Walk {
    pub items: Vec<Item>,
    /// Files in folders without a `.pdf` / `.ai` extension (`--all` scans them).
    pub skipped_extension: u64,
    /// Symbolic links inside folders (never followed).
    pub skipped_links: u64,
    /// Pipes, sockets and devices inside folders.
    pub skipped_special: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Item {
    Scan(Input),
    /// A folder (or folder entry) that cannot be read: its `ENGINE.READ` message.
    Unreadable(PathBuf, String),
}

/// True when `scan` must use the batch output: several inputs, a folder, or a
/// several-file format.
pub fn is_batch(scan: &Scan) -> bool {
    scan.inputs.len() > 1
        || matches!(scan.format, Some(Format::Jsonl | Format::Csv))
        || scan
            .inputs
            .iter()
            .any(|i| matches!(i, Input::Path(p) if fs::metadata(p).is_ok_and(|m| m.is_dir())))
}

/// Lists what to scan. Files named on the command line are always scanned;
/// inside folders only `.pdf` / `.ai` files (every regular file with `all`),
/// recursively, without following symbolic links.
pub fn walk(inputs: &[Input], all: bool, absolute: bool) -> Walk {
    let mut w = Walk::default();
    for input in inputs {
        let path = match input {
            Input::Stdin => {
                w.items.push(Item::Scan(Input::Stdin));
                continue;
            }
            Input::Path(p) if absolute => std::path::absolute(p).unwrap_or_else(|_| p.clone()),
            Input::Path(p) => p.clone(),
        };
        if fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
            walk_dir(path, all, &mut w);
        } else {
            w.items.push(Item::Scan(Input::Path(path)));
        }
    }
    w
}

/// Depth-first, entries of each folder sorted by name; an explicit stack, so
/// deep trees cannot overflow the call stack.
fn walk_dir(root: PathBuf, all: bool, w: &mut Walk) {
    let mut stack = Vec::new();
    if let Some(entries) = list(&root, w) {
        stack.push(entries.into_iter());
    }
    while let Some(top) = stack.last_mut() {
        let Some(entry) = top.next() else {
            stack.pop();
            continue;
        };
        let path = entry.path();
        match entry.file_type() {
            Err(e) => {
                let msg = format!("cannot read {}: {e}", path.display());
                w.items.push(Item::Unreadable(path, msg));
            }
            Ok(t) if t.is_symlink() => w.skipped_links += 1,
            Ok(t) if t.is_dir() => {
                if let Some(entries) = list(&path, w) {
                    stack.push(entries.into_iter());
                }
            }
            Ok(t) if t.is_file() => {
                if all || has_scanned_extension(&path) {
                    w.items.push(Item::Scan(Input::Path(path)));
                } else {
                    w.skipped_extension += 1;
                }
            }
            Ok(_) => w.skipped_special += 1,
        }
    }
}

/// The entries of `dir`, sorted by name; `None` (and an `Unreadable` item)
/// when it cannot be listed.
fn list(dir: &Path, w: &mut Walk) -> Option<Vec<DirEntry>> {
    let unreadable = |e: io::Error| {
        Item::Unreadable(
            dir.to_path_buf(),
            format!("cannot read folder {}: {e}", dir.display()),
        )
    };
    let entries = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            w.items.push(unreadable(e));
            return None;
        }
    };
    let mut out = Vec::new();
    for entry in entries {
        match entry {
            Ok(e) => out.push(e),
            Err(e) => w.items.push(unreadable(e)),
        }
    }
    out.sort_by_key(DirEntry::file_name);
    Some(out)
}

fn has_scanned_extension(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| EXTENSIONS.iter().any(|e| ext.eq_ignore_ascii_case(e)))
}

/// One scanned file.
struct Record {
    /// The path as given (or absolute with `--absolute`); `-` for stdin.
    name: String,
    sha256: Option<String>,
    verdict: Verdict,
}

fn scan_item(item: &Item, policy: &Policy, hash: bool, stdin: &mut dyn Read) -> Record {
    match item {
        Item::Scan(input) => {
            let (verdict, sha256) = scan::run_with(input, policy, hash, stdin);
            let name = match input {
                Input::Stdin => "-".to_string(),
                Input::Path(p) => p.display().to_string(),
            };
            Record {
                name,
                sha256,
                verdict,
            }
        }
        Item::Unreadable(path, msg) => Record {
            name: path.display().to_string(),
            sha256: None,
            verdict: quelda_core::read_error(msg, policy),
        },
    }
}

/// Runs a batch scan; returns the exit code (0 when every file is `PASS`,
/// 2 when any is `ERROR`, else 1 when any is `REJECT`).
pub fn run(
    scan: &Scan,
    format: Format,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let started = Instant::now();
    let policy = match scan::policy(scan) {
        Ok(p) => {
            scan::warn_ignored_unlocks(&p, err);
            p
        }
        Err(e) => {
            let _ = writeln!(err, "quelda: {} (nothing scanned)", e.0);
            return EXIT_ERROR;
        }
    };
    let walk = walk(&scan.inputs, scan.all, scan.absolute);
    if walk.items.is_empty() {
        let _ = writeln!(
            err,
            "quelda: no files to scan{}",
            skipped(&walk).map_or(String::new(), |s| format!(" (skipped {s})"))
        );
        return EXIT_ERROR;
    }
    let jobs = scan
        .jobs
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .min(walk.items.len());
    let mut report = Report::new(format, out);
    let written = if jobs <= 1 {
        walk.items
            .iter()
            .try_for_each(|item| report.add(scan_item(item, &policy, scan.hash, stdin)))
    } else {
        parallel(&walk.items, &policy, scan.hash, jobs, &mut report)
    };
    let done = written.and_then(|()| {
        if report.seen < walk.items.len() {
            let _ = writeln!(err, "quelda: could not start the scan threads");
        }
        report.finish(&walk, started, jobs, err)
    });
    match done {
        Err(e) => {
            let _ = writeln!(err, "quelda: cannot write output: {e}");
            EXIT_IO
        }
        Ok(()) if report.seen < walk.items.len() || report.error > 0 => EXIT_ERROR,
        Ok(()) if report.reject > 0 => EXIT_REJECT,
        Ok(()) => EXIT_PASS,
    }
}

/// Scans `items` on `jobs` threads and reports them in order as soon as each
/// one and all before it are done. Stops early when the output fails.
fn parallel(
    items: &[Item],
    policy: &Policy,
    hash: bool,
    jobs: usize,
    report: &mut Report,
) -> io::Result<()> {
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel::<(usize, Record)>();
    std::thread::scope(|s| {
        for _ in 0..jobs {
            let tx = tx.clone();
            let (next, stop) = (&next, &stop);
            let worker = move || {
                while !stop.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    let record = scan_item(item, policy, hash, &mut io::empty());
                    if tx.send((i, record)).is_err() {
                        break;
                    }
                }
            };
            // A thread that cannot start leaves its share to the others.
            let _ = std::thread::Builder::new()
                .stack_size(STACK_BYTES)
                .spawn_scoped(s, worker);
        }
        drop(tx);
        let mut pending = BTreeMap::new();
        for (i, record) in rx {
            pending.insert(i, record);
            while let Some(record) = pending.remove(&report.seen) {
                if let Err(e) = report.add(record) {
                    stop.store(true, Ordering::Relaxed);
                    return Err(e);
                }
            }
        }
        Ok(())
    })
}

/// Writes each record and keeps the totals for the summary.
struct Report<'a> {
    format: Format,
    out: &'a mut dyn Write,
    seen: usize,
    pass: usize,
    reject: usize,
    error: usize,
    /// (rule ID, `block`/`warn`) → files; error code → files.
    by_rule: BTreeMap<(&'static str, &'static str), Vec<String>>,
    by_error: BTreeMap<&'static str, Vec<String>>,
}

impl<'a> Report<'a> {
    fn new(format: Format, out: &'a mut dyn Write) -> Self {
        Report {
            format,
            out,
            seen: 0,
            pass: 0,
            reject: 0,
            error: 0,
            by_rule: BTreeMap::new(),
            by_error: BTreeMap::new(),
        }
    }

    fn add(&mut self, r: Record) -> io::Result<()> {
        if self.seen == 0 && self.format == Format::Csv {
            self.out.write_all(CSV_HEADER.as_bytes())?;
        }
        self.seen += 1;
        match r.verdict.status {
            Status::Pass => self.pass += 1,
            Status::Reject => self.reject += 1,
            Status::Error => self.error += 1,
        }
        for (label, list) in [
            ("block", &r.verdict.violations),
            ("warn", &r.verdict.warnings),
        ] {
            for v in list {
                self.by_rule
                    .entry((v.rule_id, label))
                    .or_default()
                    .push(r.name.clone());
            }
        }
        for e in &r.verdict.errors {
            self.by_error
                .entry(e.code)
                .or_default()
                .push(r.name.clone());
        }
        let line = match self.format {
            Format::Csv => csv_row(&r),
            Format::Text => {
                let v: Value = serde_json::from_str(&r.verdict.to_json()).unwrap_or_default();
                text::findings(&v, &r.name)
            }
            Format::Json | Format::Jsonl => jsonl(&r),
        };
        self.out.write_all(line.as_bytes())
    }

    /// The summary: on stdout for `text`, on stderr (one line) otherwise.
    fn finish(
        &mut self,
        walk: &Walk,
        started: Instant,
        jobs: usize,
        err: &mut dyn Write,
    ) -> io::Result<()> {
        let totals = format!(
            "{}: {} PASS, {} REJECT, {} ERROR in {:.1} s ({})",
            text::plural(self.seen, "file", "files"),
            self.pass,
            self.reject,
            self.error,
            started.elapsed().as_secs_f64(),
            text::plural(jobs.max(1), "job", "jobs"),
        );
        let skipped = skipped(walk);
        if self.format != Format::Text {
            let _ = writeln!(
                err,
                "quelda: {totals}{}",
                skipped.map_or(String::new(), |s| format!("; skipped {s}"))
            );
            return self.out.flush();
        }
        let mut s = format!("\n{totals}\n");
        if let Some(skipped) = skipped {
            s.push_str(&format!("Skipped: {skipped}\n"));
        }
        for ((rule, label), files) in &self.by_rule {
            s.push_str(&format!(
                "\n{rule} ({label}): {}\n",
                text::plural(files.len(), "file", "files")
            ));
            for f in files {
                s.push_str(&format!("  {}\n", text::printable(f)));
            }
        }
        for (code, files) in &self.by_error {
            s.push_str(&format!(
                "\n{code} (error): {}\n",
                text::plural(files.len(), "file", "files")
            ));
            for f in files {
                s.push_str(&format!("  {}\n", text::printable(f)));
            }
        }
        self.out.write_all(s.as_bytes())?;
        self.out.flush()
    }
}

/// What the walk left out (`2 files not .pdf or .ai …`), or `None`.
fn skipped(w: &Walk) -> Option<String> {
    let mut parts = Vec::new();
    if w.skipped_extension > 0 {
        parts.push(format!(
            "{} not .pdf or .ai (--all scans them)",
            text::plural(w.skipped_extension as usize, "file", "files")
        ));
    }
    if w.skipped_links > 0 {
        parts.push(format!(
            "{} (not followed)",
            text::plural(w.skipped_links as usize, "symbolic link", "symbolic links")
        ));
    }
    if w.skipped_special > 0 {
        parts.push(format!(
            "{} (pipes, sockets, devices)",
            text::plural(w.skipped_special as usize, "special file", "special files")
        ));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// `{"file":…,"sha256":…,"verdict":{…}}` on one line.
fn jsonl(r: &Record) -> String {
    format!(
        "{{\"file\":{},\"sha256\":{},\"verdict\":{}}}\n",
        Value::String(r.name.clone()),
        r.sha256.clone().map_or(Value::Null, Value::String),
        r.verdict.to_json()
    )
}

const CSV_HEADER: &str = "file,status,valid,violations,warnings,errors,sha256,bytes,duration_ms\n";

/// One CSV row (RFC 4180 quoting). Rule IDs are joined with spaces, errors
/// with `; `.
fn csv_row(r: &Record) -> String {
    let v = &r.verdict;
    let ids = |list: &[quelda_core::verdict::Violation]| {
        list.iter().map(|f| f.rule_id).collect::<Vec<_>>().join(" ")
    };
    let errors = v
        .errors
        .iter()
        .map(|e| format!("{}: {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join("; ");
    let cells = [
        r.name.clone(),
        match v.status {
            Status::Pass => "PASS",
            Status::Reject => "REJECT",
            Status::Error => "ERROR",
        }
        .to_string(),
        v.valid.to_string(),
        ids(&v.violations),
        ids(&v.warnings),
        errors,
        r.sha256.clone().unwrap_or_default(),
        v.stats.bytes.to_string(),
        v.stats.duration_ms.to_string(),
    ];
    let mut row = cells
        .iter()
        .map(|c| csv_cell(c))
        .collect::<Vec<_>>()
        .join(",");
    row.push('\n');
    row
}

/// Quotes a cell when needed. A cell that a spreadsheet would run as a
/// formula (`=`, `+`, `-`, `@`, tab, CR first) gets a leading `'`: file names
/// and messages come from uploads.
fn csv_cell(cell: &str) -> String {
    let cell = if cell.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{cell}")
    } else {
        cell.to_string()
    };
    if cell.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::PolicySource;

    #[test]
    fn extensions_any_case() {
        for name in ["a.pdf", "a.PDF", "a.Pdf", "b.ai", "b.AI", "x.tar.pdf"] {
            assert!(has_scanned_extension(Path::new(name)), "{name}");
        }
        for name in ["a", "a.pdfx", "a.txt", ".pdf", "pdf", "a.pdf.txt", "a.ait"] {
            assert!(!has_scanned_extension(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn csv_cells() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell(""), "");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
        assert_eq!(csv_cell("cr\r"), "\"cr\r\"");
        for f in ["=1+1", "+1", "-1", "@SUM(A1)", "\tx"] {
            assert_eq!(csv_cell(f), format!("'{f}"), "{f:?}");
        }
        assert_eq!(csv_cell("\rx"), "\"'\rx\"");
        assert_eq!(csv_cell("=a,b"), "\"'=a,b\"");
        assert_eq!(csv_cell("a=b"), "a=b");
    }

    #[test]
    fn skipped_summary() {
        let mut w = Walk::default();
        assert_eq!(skipped(&w), None);
        w.skipped_extension = 1;
        assert_eq!(
            skipped(&w).unwrap(),
            "1 file not .pdf or .ai (--all scans them)"
        );
        w.skipped_extension = 2;
        w.skipped_links = 1;
        w.skipped_special = 3;
        assert_eq!(
            skipped(&w).unwrap(),
            "2 files not .pdf or .ai (--all scans them), 1 symbolic link (not followed), 3 special files (pipes, sockets, devices)"
        );
    }

    #[test]
    fn jsonl_line_escapes_the_name() {
        let r = Record {
            name: "a \"b\"\n.pdf".to_string(),
            sha256: None,
            verdict: quelda_core::read_error("m", &Policy::default()),
        };
        let line = jsonl(&r);
        assert!(line.ends_with("}\n") && line.matches('\n').count() == 1);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["file"], "a \"b\"\n.pdf");
        assert_eq!(v["sha256"], Value::Null);
        assert_eq!(v["verdict"]["status"], "ERROR");
        assert!(line.starts_with("{\"file\":"), "{line}");
    }

    fn scan_of(inputs: Vec<Input>) -> Scan {
        Scan {
            inputs,
            policy: None,
            preset: None,
            rules: Vec::new(),
            stop_on_first: false,
            format: None,
            all: false,
            absolute: false,
            hash: true,
            jobs: None,
        }
    }

    fn tmp_tree(name: &str, files: usize) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("quelda-batch-unit-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for i in 0..files {
            fs::write(dir.join(format!("{i:03}.pdf")), b"%PDF-1.7\n%%EOF\n").unwrap();
        }
        dir
    }

    #[test]
    fn walk_reports_missing_roots_as_files() {
        let missing = std::env::temp_dir().join("quelda-batch-no-such-dir");
        let w = walk(&[Input::Path(missing.clone())], false, false);
        assert_eq!(w.items, [Item::Scan(Input::Path(missing))]);
    }

    #[test]
    fn deep_trees_do_not_overflow() {
        let root = tmp_tree("deep", 0);
        let mut p = root.clone();
        for _ in 0..200 {
            p.push("d");
        }
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("x.pdf"), b"").unwrap();
        let w = walk(&[Input::Path(root)], false, false);
        assert_eq!(w.items, [Item::Scan(Input::Path(p.join("x.pdf")))]);
    }

    /// Many files on many threads still come out in order, once each, and
    /// match a one-thread run.
    #[test]
    fn parallel_output_is_ordered() {
        let dir = tmp_tree("order", 300);
        let mut s = scan_of(vec![Input::Path(dir.clone())]);
        let mut outputs = Vec::new();
        for jobs in [1, 7, 64] {
            s.jobs = Some(jobs);
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = run(&s, Format::Jsonl, &mut io::empty(), &mut out, &mut err);
            assert_eq!(code, EXIT_PASS, "{}", String::from_utf8_lossy(&err));
            let names: Vec<String> = String::from_utf8(out)
                .unwrap()
                .lines()
                .map(|l| {
                    serde_json::from_str::<Value>(l).unwrap()["file"]
                        .as_str()
                        .unwrap()
                        .to_string()
                })
                .collect();
            outputs.push(names);
        }
        let want: Vec<String> = (0..300)
            .map(|i| dir.join(format!("{i:03}.pdf")).display().to_string())
            .collect();
        for o in &outputs {
            assert_eq!(o, &want);
        }
    }

    #[test]
    fn closed_output_stops_the_scan_with_exit_74() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let dir = tmp_tree("closed", 50);
        for jobs in [1, 4] {
            let mut s = scan_of(vec![Input::Path(dir.clone())]);
            s.jobs = Some(jobs);
            let mut err = Vec::new();
            let code = run(&s, Format::Text, &mut io::empty(), &mut Closed, &mut err);
            assert_eq!(code, EXIT_IO);
            let err = String::from_utf8(err).unwrap();
            assert!(err.starts_with("quelda: cannot write output"), "{err}");
        }
    }

    #[test]
    fn invalid_policy_writes_nothing() {
        let dir = tmp_tree("policy", 2);
        let mut s = scan_of(vec![Input::Path(dir)]);
        s.policy = Some(PolicySource::Json("{".into()));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&s, Format::Jsonl, &mut io::empty(), &mut out, &mut err);
        assert_eq!(code, EXIT_ERROR);
        assert!(out.is_empty());
        assert!(String::from_utf8(err).unwrap().contains("nothing scanned"));
    }
}
