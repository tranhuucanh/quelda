//! `quelda scan` on folders and several files, end to end: every line equals
//! a single-file scan, paths and order are exact, nothing is dropped
//! silently, the formats (jsonl, text, csv) and the exit codes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    let dir = repo().join("tests/fixtures");
    assert!(
        dir.is_dir(),
        "{} not found: run `cargo run -p quelda-testkit --bin gen-fixtures` first",
        dir.display()
    );
    dir
}

fn fixture(path: &str) -> PathBuf {
    fixtures().join(path)
}

const PS: &str = "rules/FILETYPE.POSTSCRIPT_MAGIC/bad/ps-adobe.pdf";
const MINIMAL: &str = "benign/minimal.pdf";

fn run_in(dir: &Path, args: &[&str]) -> Output {
    Command::cargo_bin("quelda")
        .unwrap()
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

/// A fresh, empty folder for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("quelda-batch-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn put(dir: &Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

fn read_fixture(path: &str) -> Vec<u8> {
    fs::read(fixture(path)).unwrap()
}

/// The line schema, with the verdict schema in place of its `$ref`.
fn line_schema() -> jsonschema::Validator {
    let load = |name: &str| -> Value {
        serde_json::from_slice(&fs::read(repo().join(format!("schemas/{name}"))).unwrap()).unwrap()
    };
    let mut line = load("scan-line.schema.json");
    let mut verdict = load("verdict.schema.json");
    assert_eq!(line["properties"]["verdict"]["$ref"], verdict["$id"]);
    let v = verdict.as_object_mut().unwrap();
    v.remove("$schema");
    v.remove("$id");
    // `#/$defs/…` pointers resolve against the root.
    if let Some(defs) = v.remove("$defs") {
        line["$defs"] = defs;
    }
    line["properties"]["verdict"] = verdict;
    jsonschema::draft202012::new(&line).unwrap()
}

/// The JSON Lines on stdout, each checked against the schema.
fn lines(o: &Output) -> Vec<Value> {
    let schema = line_schema();
    let text = stdout(o);
    assert!(text.is_empty() || text.ends_with('\n'), "{text}");
    text.lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            let errors: Vec<String> = schema.iter_errors(&v).map(|e| e.to_string()).collect();
            assert!(errors.is_empty(), "{errors:?}\n{l}");
            v
        })
        .collect()
}

fn files(lines: &[Value]) -> Vec<&str> {
    lines.iter().map(|l| l["file"].as_str().unwrap()).collect()
}

fn without_time(mut v: Value) -> Value {
    v["stats"]["duration_ms"] = Value::from(0);
    v
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every fixture, scanned as one folder: one line per `.pdf`, in sorted
/// path order, each verdict == the Rust lib on that file, each hash right;
/// the same with 1 job and with many.
#[test]
fn folder_scan_equals_lib_on_every_fixture() {
    let dir = fixtures();
    let mut want: Vec<PathBuf> = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "pdf") {
                want.push(p.strip_prefix(&dir).unwrap().to_path_buf());
            }
        }
    }
    // Sorted by path components == the walk's order.
    want.sort();
    assert!(want.len() >= 400, "{}", want.len());

    let one = run_in(&dir, &["scan", ".", "--preset", "strict", "-j", "1"]);
    let many = run_in(&dir, &["scan", ".", "--preset", "strict", "--jobs=8"]);
    // Some fixtures are REJECT, some ERROR (limits).
    assert_eq!(one.status.code(), Some(2), "{}", stderr(&one));
    assert_eq!(many.status.code(), Some(2));
    let one = lines(&one);
    let many = lines(&many);
    let names: Vec<String> = want
        .iter()
        .map(|p| Path::new(".").join(p).display().to_string())
        .collect();
    assert_eq!(files(&one), names);
    assert_eq!(files(&many), names);

    let policy = quelda_core::Policy::from_json(r#"{"preset":"strict"}"#).unwrap();
    for (a, b) in one.iter().zip(&many) {
        let name = a["file"].as_str().unwrap();
        let bytes = fs::read(dir.join(name)).unwrap();
        let lib: Value =
            serde_json::from_str(&quelda_core::scan(&bytes, &policy).to_json()).unwrap();
        let lib = without_time(lib);
        assert_eq!(without_time(a["verdict"].clone()), lib, "{name}");
        assert_eq!(without_time(b["verdict"].clone()), lib, "{name} (8 jobs)");
        assert_eq!(a["sha256"], sha256_hex(&bytes), "{name}");
        assert_eq!(b["sha256"], a["sha256"]);
    }
}

/// A tree with every kind of entry: nested folders, extension case, other
/// files, symbolic links, an empty folder.
fn tree(name: &str) -> PathBuf {
    let d = scratch(name);
    let ps = read_fixture(PS);
    let ok = read_fixture(MINIMAL);
    put(&d, "up/b.pdf", &ok);
    put(&d, "up/a/z.PDF", &ps);
    put(&d, "up/a/y.Ai", &ok);
    put(&d, "up/a/deep/er/x.pdf", &ok);
    put(&d, "up/notes.txt", b"hello");
    put(&d, "up/noext", &ps);
    fs::create_dir_all(d.join("up/empty")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(d.join("up/a/z.PDF"), d.join("up/link.pdf")).unwrap();
        std::os::unix::fs::symlink(d.join("up/a"), d.join("up/linkdir")).unwrap();
    }
    d
}

#[test]
fn walk_order_extensions_links_and_skips() {
    let d = tree("walk");
    let o = run_in(&d, &["scan", "up"]);
    let l = lines(&o);
    assert_eq!(
        files(&l),
        ["up/a/deep/er/x.pdf", "up/a/y.Ai", "up/a/z.PDF", "up/b.pdf"]
    );
    assert_eq!(o.status.code(), Some(1), "z.PDF is PostScript");
    let err = stderr(&o);
    assert!(
        err.starts_with("quelda: 4 files: 3 PASS, 1 REJECT, 0 ERROR in "),
        "{err}"
    );
    assert!(
        err.contains("skipped 2 files not .pdf or .ai (--all scans them)"),
        "{err}"
    );
    #[cfg(unix)]
    assert!(err.contains("2 symbolic links (not followed)"), "{err}");

    // --all: every regular file; links still not followed.
    let o = run_in(&d, &["scan", "up", "--all"]);
    let l = lines(&o);
    assert_eq!(
        files(&l),
        [
            "up/a/deep/er/x.pdf",
            "up/a/y.Ai",
            "up/a/z.PDF",
            "up/b.pdf",
            "up/noext",
            "up/notes.txt"
        ]
    );
    // `noext` is found by content, not by name.
    assert_eq!(l[4]["verdict"]["status"], "REJECT");
    assert!(!stderr(&o).contains("not .pdf"));

    // The path is kept as typed: trailing slash, `./`, absolute.
    let o = run_in(&d, &["scan", "./up/a/"]);
    assert_eq!(
        files(&lines(&o)),
        ["./up/a/deep/er/x.pdf", "./up/a/y.Ai", "./up/a/z.PDF"]
    );
    let abs = d.join("up/a").display().to_string();
    let o = run_in(&d, &["scan", &abs]);
    assert_eq!(files(&lines(&o))[0], format!("{abs}/deep/er/x.pdf"));
    let o = run_in(&d, &["scan", "up/a", "--absolute"]);
    // The working directory as the process sees it (macOS: /private/var/…).
    let want_abs = fs::canonicalize(&d).unwrap().join("up/a/y.Ai");
    assert_eq!(files(&lines(&o))[1], want_abs.display().to_string());

    // A link named on the command line is followed, like a single file.
    #[cfg(unix)]
    {
        let o = run_in(&d, &["scan", "up/linkdir", "up/link.pdf"]);
        assert_eq!(
            files(&lines(&o)),
            [
                "up/linkdir/deep/er/x.pdf",
                "up/linkdir/y.Ai",
                "up/linkdir/z.PDF",
                "up/link.pdf"
            ]
        );
    }
}

#[test]
fn several_files_in_argument_order_any_extension() {
    let d = tree("args");
    let o = run_in(
        &d,
        &["scan", "up/notes.txt", "up/b.pdf", "missing.pdf", "up/a"],
    );
    let l = lines(&o);
    assert_eq!(
        files(&l),
        [
            "up/notes.txt",
            "up/b.pdf",
            "missing.pdf",
            "up/a/deep/er/x.pdf",
            "up/a/y.Ai",
            "up/a/z.PDF"
        ]
    );
    // A file named on the command line is scanned whatever its name.
    assert_eq!(l[0]["verdict"]["status"], "REJECT");
    // A missing file is its own ERROR line, not a crash or a skip.
    assert_eq!(l[2]["verdict"]["status"], "ERROR");
    assert_eq!(l[2]["verdict"]["errors"][0]["code"], "ENGINE.READ");
    assert_eq!(l[2]["sha256"], Value::Null);
    assert_eq!(o.status.code(), Some(2));
    // The same file twice is scanned twice.
    let o = run_in(&d, &["scan", "up/b.pdf", "up/b.pdf"]);
    assert_eq!(files(&lines(&o)), ["up/b.pdf", "up/b.pdf"]);
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn exit_code_is_the_worst_status() {
    let d = scratch("exit");
    put(&d, "ok/a.pdf", &read_fixture(MINIMAL));
    put(&d, "ok/b.pdf", &read_fixture(MINIMAL));
    put(&d, "bad/a.pdf", &read_fixture(MINIMAL));
    put(&d, "bad/b.pdf", &read_fixture(PS));
    put(&d, "err/a.pdf", &read_fixture(PS));
    // One byte over the limit below: ERROR (LIMIT.FILE_BYTES).
    let max = read_fixture(MINIMAL).len().max(read_fixture(PS).len());
    put(&d, "err/b.pdf", &vec![b' '; max + 1]);
    let policy = format!(r#"{{"limits":{{"max_file_bytes":{max}}}}}"#);
    for (dir, code) in [("ok", 0), ("bad", 1), ("err", 2)] {
        let o = run_in(&d, &["scan", dir, "--policy-json", &policy]);
        assert_eq!(o.status.code(), Some(code), "{dir}");
        assert_eq!(lines(&o).len(), 2);
    }
    // `-j` larger than the number of files is fine.
    let o = run_in(&d, &["scan", "ok", "-j", "64"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stderr(&o).contains("(2 jobs)"), "{}", stderr(&o));
}

#[test]
fn nothing_to_scan_is_exit_2() {
    let d = scratch("empty");
    fs::create_dir_all(d.join("none/sub")).unwrap();
    put(&d, "txt/a.txt", b"x");
    let o = run_in(&d, &["scan", "none"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    assert_eq!(stderr(&o), "quelda: no files to scan\n");
    // Files that were left out are named, so a wrong filter is obvious.
    let o = run_in(&d, &["scan", "txt"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(
        stderr(&o),
        "quelda: no files to scan (skipped 1 file not .pdf or .ai (--all scans them))\n"
    );
}

#[cfg(unix)]
#[test]
fn unreadable_folder_is_an_error_line() {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch("perm");
    put(&d, "up/a.pdf", &read_fixture(MINIMAL));
    put(&d, "up/locked/b.pdf", &read_fixture(MINIMAL));
    let locked = d.join("up/locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    // root can read anything: nothing to test then.
    if fs::read_dir(&locked).is_ok() {
        return;
    }
    let o = run_in(&d, &["scan", "up"]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    let l = lines(&o);
    assert_eq!(files(&l), ["up/a.pdf", "up/locked"]);
    assert_eq!(l[1]["verdict"]["status"], "ERROR");
    assert_eq!(l[1]["verdict"]["errors"][0]["code"], "ENGINE.READ");
    let msg = l[1]["verdict"]["errors"][0]["message"].as_str().unwrap();
    assert!(msg.starts_with("cannot read folder up/locked: "), "{msg}");
    assert_eq!(o.status.code(), Some(2));
}

#[cfg(unix)]
#[test]
fn special_files_in_folders_are_skipped() {
    let d = scratch("fifo");
    put(&d, "up/a.pdf", &read_fixture(MINIMAL));
    let fifo = d.join("up/pipe.pdf");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|s| s.success());
    if !made {
        return;
    }
    // Reading a FIFO would block forever; the walk must not open it.
    let o = run_in(&d, &["scan", "up"]);
    assert_eq!(files(&lines(&o)), ["up/a.pdf"]);
    assert!(
        stderr(&o).contains("skipped 1 special file (pipes, sockets, devices)"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn no_hash_and_options_apply_to_every_file() {
    let d = tree("opts");
    let o = run_in(&d, &["scan", "up", "--no-hash"]);
    assert!(lines(&o).iter().all(|l| l["sha256"].is_null()));
    let o = run_in(
        &d,
        &["scan", "up", "--preset", "permissive", "--stop-on-first"],
    );
    for l in lines(&o) {
        assert_eq!(l["verdict"]["policy"]["preset"], "permissive");
        assert_eq!(l["verdict"]["policy"]["stop_on_first"], true);
    }
    let o = run_in(
        &d,
        &[
            "scan",
            "up",
            "--policy-json",
            r#"{"limits":{"max_file_bytes":10}}"#,
        ],
    );
    let l = lines(&o);
    assert!(
        l.iter()
            .all(|l| l["verdict"]["errors"][0]["code"] == "LIMIT.FILE_BYTES")
    );
    // Too large to scan is still hashed (the file was named, not piped).
    assert_eq!(
        l[3]["sha256"],
        sha256_hex(&read_fixture(MINIMAL)),
        "{}",
        l[3]
    );
}

#[test]
fn bad_policy_scans_nothing() {
    let d = tree("policy");
    for args in [
        &["scan", "up", "--policy-json", "{"][..],
        &["scan", "up", "--policy", "missing.json"],
    ] {
        let o = run_in(&d, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty());
        let err = stderr(&o);
        assert!(err.starts_with("quelda: "), "{err}");
        assert!(err.ends_with("(nothing scanned)\n"), "{err}");
    }
}

#[test]
fn usage_errors() {
    let d = tree("usage");
    for (args, needle) in [
        (
            &["scan", "up", "--format", "json"][..],
            "--format json prints one verdict",
        ),
        (
            &["scan", "up/b.pdf", "up/b.pdf", "--format=json"],
            "--format json",
        ),
        (&["scan", "-", "up/b.pdf"], "cannot be combined"),
        (&["scan", "up", "--jobs", "0"], "--jobs"),
        (&["scan", "up", "-j", "x"], "--jobs"),
        (&["scan", "up", "-j"], "needs a value"),
        (&["scan", "up", "--all=1"], "no value"),
        (&["scan", "up", "--format", "xml"], "json, jsonl, text, csv"),
        (&["rules", "--format", "csv"], "json, text"),
        (&["rules", "-j", "2"], "unknown option `-j`"),
    ] {
        let o = run_in(&d, args);
        assert_eq!(o.status.code(), Some(64), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
        assert!(stderr(&o).contains(needle), "{args:?}: {}", stderr(&o));
    }
}

/// One file keeps the single-verdict output; `--format jsonl` (or csv) gives
/// the batch format for one file too, for scripts that pass a glob.
#[test]
fn one_file_output_is_unchanged_unless_asked() {
    let d = tree("single");
    let o = run_in(&d, &["scan", "up/b.pdf"]);
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["status"], "PASS");
    assert!(o.stderr.is_empty());
    let o = run_in(&d, &["scan", "up/b.pdf", "--format", "jsonl"]);
    let l = lines(&o);
    assert_eq!(files(&l), ["up/b.pdf"]);
    assert_eq!(without_time(l[0]["verdict"].clone()), without_time(v));
    // stdin in the batch format.
    let o = Command::cargo_bin("quelda")
        .unwrap()
        .args(["scan", "-", "--format", "jsonl"])
        .write_stdin(read_fixture(MINIMAL))
        .output()
        .unwrap();
    let l = lines(&o);
    assert_eq!(files(&l), ["-"]);
    assert_eq!(l[0]["sha256"], sha256_hex(&read_fixture(MINIMAL)));
}

#[test]
fn text_report_names_every_file_and_groups_by_rule() {
    let d = tree("text");
    put(&d, "up/bad\x1b[31m.pdf", &read_fixture(PS));
    let o = run_in(&d, &["scan", "up", "--format", "text"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(o.stderr.is_empty(), "{}", stderr(&o));
    let t = stdout(&o);
    assert!(t.starts_with("PASS    up/a/deep/er/x.pdf\n"), "{t}");
    assert!(
        t.contains("\nREJECT  up/a/z.PDF\n  block  FILETYPE.NOT_PDF_HEADER"),
        "{t}"
    );
    // A file name cannot send escape sequences to the terminal.
    assert!(!t.contains('\x1b'), "{t:?}");
    assert!(t.contains("REJECT  up/bad\\u{1b}[31m.pdf\n"), "{t}");
    assert!(
        t.contains("\n5 files: 3 PASS, 2 REJECT, 0 ERROR in "),
        "{t}"
    );
    assert!(
        t.contains("\nSkipped: 2 files not .pdf or .ai (--all scans them)"),
        "{t}"
    );
    assert!(
        t.contains(
            "\nFILETYPE.POSTSCRIPT_MAGIC (block): 2 files\n  up/a/z.PDF\n  up/bad\\u{1b}[31m.pdf\n"
        ),
        "{t}"
    );
}

/// RFC 4180 fields of one CSV text (quotes, doubled quotes, newlines).
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                cell.push('"');
            }
            (true, '"') => quoted = false,
            (true, c) => cell.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut cell)),
            (false, '\n') => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => cell.push(c),
        }
    }
    assert!(cell.is_empty() && row.is_empty(), "no final newline");
    rows
}

#[test]
fn csv_quotes_and_defuses_formulas() {
    let d = scratch("csv");
    put(&d, "up/=cmd|calc.pdf", &read_fixture(PS));
    put(&d, "up/a,\"b\"\nc.pdf", &read_fixture(MINIMAL));
    put(&d, "up/ok.pdf", &read_fixture(MINIMAL));
    put(&d, "up/empty.pdf", b"");
    let o = run_in(&d, &["scan", "up", "--format", "csv"]);
    assert_eq!(o.status.code(), Some(1));
    let rows = parse_csv(&stdout(&o));
    assert_eq!(
        rows[0],
        [
            "file",
            "status",
            "valid",
            "violations",
            "warnings",
            "errors",
            "sha256",
            "bytes",
            "duration_ms"
        ]
    );
    let by_name = |n: &str| rows.iter().find(|r| r[0] == n).unwrap().clone();
    // Sorted by name: `=` < `a` < `e` < `o`.
    assert_eq!(rows.len(), 5);
    let ps = by_name("up/=cmd|calc.pdf");
    assert_eq!(rows[1], ps, "the cell starts with up/, not =");
    assert_eq!(ps[1], "REJECT");
    assert_eq!(ps[2], "false");
    assert!(
        ps[3].split(' ').any(|id| id == "FILETYPE.POSTSCRIPT_MAGIC"),
        "{ps:?}"
    );
    assert_eq!(ps[6], sha256_hex(&read_fixture(PS)));
    assert_eq!(by_name("up/a,\"b\"\nc.pdf")[1], "PASS");
    let empty = by_name("up/empty.pdf");
    assert_eq!(
        empty[1..6],
        [
            "REJECT",
            "false",
            "FILETYPE.NOT_PDF_HEADER STRUCT.MISSING_EOF",
            "STRUCT.XREF_MISMATCH",
            ""
        ]
    );
    assert_eq!(empty[7], "0");

    // A cell that would start with a formula character gets a leading `'`.
    let o = run_in(
        &d.join("up"),
        &[
            "scan",
            "=cmd|calc.pdf",
            "ok.pdf",
            "-x.pdf",
            "--format",
            "csv",
        ],
    );
    assert_eq!(o.status.code(), Some(64), "-x.pdf is an option");
    let o = run_in(
        &d.join("up"),
        &[
            "scan",
            "--format",
            "csv",
            "--",
            "=cmd|calc.pdf",
            "ok.pdf",
            "-x.pdf",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    let rows = parse_csv(&stdout(&o));
    assert_eq!(rows[1][0], "'=cmd|calc.pdf");
    assert_eq!(rows[2][0], "ok.pdf");
    assert_eq!(rows[3][0], "'-x.pdf");
    assert_eq!(rows[3][1], "ERROR");
    assert!(
        rows[3][5].starts_with("ENGINE.READ: cannot open -x.pdf: "),
        "{:?}",
        rows[3]
    );
    assert_eq!(rows[3][6], "", "no hash for a file that cannot be read");
}
