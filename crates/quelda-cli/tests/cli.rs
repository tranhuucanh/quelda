//! The `quelda` binary end to end (plan Step 14): exit codes, stdin, JSON
//! schemas, usage errors, and CLI verdict == Rust lib verdict on every
//! fixture of `tests/fixtures/manifest.json` and every conformance case.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::OnceLock;

use assert_cmd::Command;
use jsonschema::Validator;
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tests_dir(sub: &str) -> PathBuf {
    let dir = repo().join("tests").join(sub);
    assert!(
        dir.is_dir(),
        "{} not found: run `cargo run -p quelda-testkit --bin gen-fixtures` first",
        dir.display()
    );
    dir
}

fn fixture(path: &str) -> PathBuf {
    tests_dir("fixtures").join(path)
}

fn quelda() -> Command {
    Command::cargo_bin("quelda").unwrap()
}

fn run(args: &[&str]) -> Output {
    quelda().args(args).output().unwrap()
}

fn schema(name: &str) -> &'static Validator {
    static VERDICT: OnceLock<Validator> = OnceLock::new();
    static RULES: OnceLock<Validator> = OnceLock::new();
    let cell = if name == "verdict" { &VERDICT } else { &RULES };
    cell.get_or_init(|| {
        let path = repo().join(format!("schemas/{name}.schema.json"));
        let s: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        jsonschema::draft202012::new(&s).unwrap()
    })
}

/// The verdict on stdout, checked against the schema and the exit code.
fn verdict(out: &Output) -> Value {
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(text.ends_with('\n'), "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    let errors: Vec<String> = schema("verdict")
        .iter_errors(&v)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{text}");
    let want = match v["status"].as_str() {
        Some("PASS") => 0,
        Some("REJECT") => 1,
        _ => 2,
    };
    assert_eq!(out.status.code(), Some(want), "{text}");
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    v
}

fn without_time(mut v: Value) -> Value {
    v["stats"]["duration_ms"] = Value::from(0);
    v
}

fn lib(input: &[u8], policy: &str) -> Value {
    without_time(serde_json::from_str(&quelda_core::scan_json(input, policy)).unwrap())
}

fn codes(v: &Value) -> Vec<&str> {
    v["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["code"].as_str().unwrap())
        .collect()
}

#[test]
fn exit_codes_pass_reject_error() {
    let pass = verdict(&run(&[
        "scan",
        fixture("benign/minimal.pdf").to_str().unwrap(),
    ]));
    assert_eq!(pass["status"], "PASS");
    assert_eq!(pass["valid"], true);

    let ps = fixture("rules/FILETYPE.POSTSCRIPT_MAGIC/bad/ps-adobe.pdf");
    let reject = verdict(&run(&["scan", ps.to_str().unwrap()]));
    assert_eq!(reject["status"], "REJECT");
    let ids: Vec<&Value> = reject["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| &v["rule_id"])
        .collect();
    assert!(
        ids.contains(&&Value::from("FILETYPE.POSTSCRIPT_MAGIC")),
        "{ids:?}"
    );

    let error = verdict(&run(&[
        "scan",
        fixture("benign/minimal.pdf").to_str().unwrap(),
        "--policy-json",
        r#"{"limits":{"max_file_bytes":1}}"#,
    ]));
    assert_eq!(codes(&error), ["LIMIT.FILE_BYTES"]);
}

#[test]
fn stdin_dash() {
    let path = fixture("rules/FILETYPE.POSTSCRIPT_MAGIC/bad/ps-adobe.pdf");
    let bytes = fs::read(&path).unwrap();
    let out = quelda()
        .args(["scan", "-", "--preset", "strict"])
        .write_stdin(bytes.clone())
        .output()
        .unwrap();
    let v = without_time(verdict(&out));
    assert_eq!(v, lib(&bytes, r#"{"preset":"strict"}"#));
    // Empty stdin is a file like any other (not PDF: rejected).
    let out = quelda()
        .args(["scan", "-"])
        .write_stdin("")
        .output()
        .unwrap();
    assert_eq!(verdict(&out)["valid"], false);
}

#[test]
fn bad_policy_file_is_exit_2_policy_invalid() {
    let dir = std::env::temp_dir().join(format!("quelda-cli-it-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let broken = dir.join("broken.json");
    fs::write(&broken, r#"{"preset": "strict", "rules": {"#).unwrap();
    let unknown_rule = dir.join("unknown-rule.json");
    fs::write(&unknown_rule, r#"{"rules": {"NOPE.RULE": "off"}}"#).unwrap();
    let pdf = fixture("benign/minimal.pdf");
    for policy in [broken, unknown_rule, dir.join("missing.json")] {
        let out = run(&[
            "scan",
            pdf.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ]);
        let v = verdict(&out);
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(codes(&v), ["POLICY.INVALID"], "{}", policy.display());
    }
}

#[test]
fn missing_input_is_exit_2_engine_read() {
    let out = run(&["scan", "/nonexistent/quelda/upload.pdf"]);
    let v = verdict(&out);
    assert_eq!(codes(&v), ["ENGINE.READ"]);
    assert!(
        v["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("/nonexistent/quelda/upload.pdf")
    );
}

#[test]
fn usage_errors_exit_64_with_empty_stdout() {
    let pdf = fixture("benign/minimal.pdf");
    let pdf = pdf.to_str().unwrap();
    for args in [
        &[][..],
        &["nope"],
        &["scan"],
        &["scan", pdf, pdf],
        &["scan", pdf, "--preset", "paranoid"],
        &["scan", pdf, "--format", "yaml"],
        &["scan", pdf, "--policy", "a", "--policy-json", "{}"],
        &["scan", pdf, "--unknown"],
        &["rules", "--policy", "x"],
        &["version", "extra"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.starts_with("quelda: "), "{args:?}: {err}");
    }
}

#[test]
fn text_format() {
    let ps = fixture("rules/FILETYPE.POSTSCRIPT_MAGIC/bad/ps-adobe.pdf");
    let out = run(&["scan", ps.to_str().unwrap(), "--format", "text"]);
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("REJECT  "), "{text}");
    assert!(text.contains("block  FILETYPE.POSTSCRIPT_MAGIC"), "{text}");
    assert!(text.contains("valid: false"), "{text}");
}

#[test]
fn stop_on_first_and_preset_override() {
    let pdf = fixture("benign/minimal.pdf");
    let out = run(&[
        "scan",
        pdf.to_str().unwrap(),
        "--policy-json",
        r#"{"preset":"permissive"}"#,
        "--preset",
        "strict",
        "--stop-on-first",
    ]);
    let v = without_time(verdict(&out));
    let bytes = fs::read(&pdf).unwrap();
    assert_eq!(
        v,
        lib(&bytes, r#"{"preset":"strict","stop_on_first":true}"#)
    );
    assert_eq!(v["policy"]["preset"], "strict");
    assert_eq!(v["policy"]["stop_on_first"], true);
}

#[test]
fn rules_and_version() {
    let out = run(&["rules"]);
    assert_eq!(out.status.code(), Some(0));
    let rules: Value = serde_json::from_slice(&out.stdout).unwrap();
    let errors: Vec<String> = schema("rules")
        .iter_errors(&rules)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    let n = rules.as_array().unwrap().len();
    assert_eq!(n, quelda_core::list_rules().len());

    let out = run(&["rules", "--format", "text"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .ends_with(&format!("{n} rules\n"))
    );

    let version = env!("CARGO_PKG_VERSION");
    for args in [&["--version"][..], &["-V"], &["version"]] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(0));
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.starts_with(&format!("quelda {version}\n")), "{text}");
        assert!(text.contains(&format!("rules:   {n}\n")), "{text}");
    }
    let out = run(&["version", "--format", "json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["version"], version);
    assert_eq!(v["rules"], n);

    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("Exit codes")
    );
}

/// Runs `jobs` on a few threads (each one spawns the binary).
fn parallel<T: Send, R: Send>(jobs: Vec<T>, f: impl Fn(T) -> R + Sync) -> Vec<R> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let chunk = jobs.len().div_ceil(threads).max(1);
    let mut jobs = jobs;
    let mut chunks = Vec::new();
    while !jobs.is_empty() {
        let rest = jobs.split_off(chunk.min(jobs.len()));
        chunks.push(std::mem::replace(&mut jobs, rest));
    }
    std::thread::scope(|s| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|c| s.spawn(|| c.into_iter().map(&f).collect::<Vec<R>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    })
}

/// CLI == Rust lib on every fixture × preset (file path), and every fixture
/// through stdin.
#[test]
fn cli_equals_lib_on_whole_manifest() {
    let dir = tests_dir("fixtures");
    let manifest: Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let mut jobs = Vec::new();
    for path in manifest["files"].as_object().unwrap().keys() {
        for preset in ["strict", "balanced", "permissive"] {
            jobs.push((path.clone(), Some(preset)));
        }
        jobs.push((path.clone(), None)); // stdin, default policy
    }
    let n = jobs.len();
    let problems: Vec<String> = parallel(jobs, |(path, preset)| {
        let file = dir.join(&path);
        let bytes = fs::read(&file).unwrap();
        let (out, policy) = match preset {
            Some(p) => (
                run(&["scan", file.to_str().unwrap(), "--preset", p]),
                format!(r#"{{"preset":"{p}"}}"#),
            ),
            None => (
                quelda()
                    .args(["scan", "-"])
                    .write_stdin(bytes.clone())
                    .output()
                    .unwrap(),
                "{}".to_string(),
            ),
        };
        let got = without_time(verdict(&out));
        let want = lib(&bytes, &policy);
        (got != want).then(|| format!("{path} [{preset:?}]:\n  cli {got}\n  lib {want}"))
    })
    .into_iter()
    .flatten()
    .collect();
    assert!(n >= 4 * 250, "{n}");
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

/// CLI == Rust lib on every conformance case, policy given as a file.
#[test]
fn cli_equals_lib_on_conformance_cases() {
    let cases_dir = tests_dir("conformance");
    let tmp = std::env::temp_dir().join(format!("quelda-cli-conf-{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();
    let mut cases: Vec<PathBuf> = fs::read_dir(&cases_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    cases.sort();
    assert!(cases.len() >= 20);
    let problems: Vec<String> = parallel(cases, |case_path| {
        let case: Value = serde_json::from_slice(&fs::read(&case_path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap().to_string();
        let policy = match case.get("policy_raw") {
            Some(raw) => raw.as_str().unwrap().to_string(),
            None => case["policy"].to_string(),
        };
        let policy_file = tmp.join(format!("{name}.json"));
        fs::write(&policy_file, &policy).unwrap();
        let file = fixture(case["file"].as_str().unwrap());
        let out = run(&[
            "scan",
            file.to_str().unwrap(),
            "--policy",
            policy_file.to_str().unwrap(),
        ]);
        let got = without_time(verdict(&out));
        let want = lib(&fs::read(&file).unwrap(), &policy);
        (got != want).then(|| format!("{name}:\n  cli {got}\n  lib {want}"))
    })
    .into_iter()
    .flatten()
    .collect();
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
