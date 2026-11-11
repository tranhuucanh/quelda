//! `quelda` CLI (design §8.3): a thin wrapper around `quelda-core`.
//!
//! Exit codes: 0 `PASS`, 1 `REJECT`, 2 `ERROR`, 64 usage error, 74 output
//! could not be written (for several files: the worst status of any file).
//! Callers must treat anything but 0 as invalid.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod args;
mod batch;
mod scan;
mod text;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::process::ExitCode;

use args::{Command, Format};
use quelda_core::verdict::Status;

pub const EXIT_PASS: u8 = 0;
pub const EXIT_REJECT: u8 = 1;
pub const EXIT_ERROR: u8 = 2;
/// `EX_USAGE` (sysexits.h).
pub const EXIT_USAGE: u8 = 64;
/// `EX_IOERR` (sysexits.h): stdout closed or full.
pub const EXIT_IO: u8 = 74;

/// Commit and build date, set by `build.rs`.
const COMMIT: &str = env!("QUELDA_BUILD_COMMIT");
const BUILD_DATE: &str = env!("QUELDA_BUILD_DATE");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const HOMEPAGE: &str = env!("CARGO_PKG_REPOSITORY");
const LICENSE: &str = env!("CARGO_PKG_LICENSE");

const HELP: &str = "\
quelda — PDF security scanner: one PDF + policy in, verdict out

Usage:
  quelda scan <file|-> [options]   Scan one file (`-`: stdin); verdict JSON on stdout
  quelda scan <folder|file>... [options]
                                   Scan folders (recursively) and files; one line per file
  quelda rules [--format json|text]  List every rule
  quelda version [--format json|text]
  quelda --version | --help

Exit codes: 0 PASS, 1 REJECT, 2 ERROR, 64 usage error, 74 output error.
Treat every exit code other than 0 as invalid.

Run `quelda help scan` for scan options.
";

const HELP_SCAN: &str = "\
quelda scan <file|-> [options]
quelda scan <folder|file>... [options]

Scans one file and prints the verdict (JSON by default) on stdout.
`-` reads the file from stdin.

With a folder or several files, prints one result per file in a fixed
order (arguments in order, folders sorted by path): JSON Lines by default,
each line {\"file\", \"sha256\", \"verdict\"}. Folders are scanned
recursively for .pdf and .ai files (any case); symbolic links inside
folders are not followed. A summary goes to stderr (to stdout with text).

Options:
  --preset strict|balanced|permissive
                         Preset (default: balanced, or the policy's preset).
                         Overrides the preset in --policy / --policy-json.
  --policy <file>        Policy JSON file (schemas/policy.schema.json).
  --policy-json <json>   Policy as a JSON string.
  --stop-on-first        Stop at the first blocking finding (faster, fewer reasons).
  --format json|jsonl|text|csv
                         Output format (default: json for one file, jsonl for
                         several; json is for one file only).
  --                     End of options (for a file name starting with `-`).

Folders and several files:
  --all                  Scan every file in folders, not only .pdf and .ai.
  --absolute             Print absolute paths.
  --no-hash              Do not compute each file's SHA-256 (sha256: null).
  -j, --jobs <n>         Files scanned at once (default: one per CPU).

Exit codes: 0 PASS, 1 REJECT, 2 ERROR (including an invalid or unreadable
policy, and a file that cannot be read), 64 usage error, 74 output error.
Several files: 0 only when every file is PASS; 2 when any file is ERROR or
nothing was found to scan; otherwise 1.
Always pass arguments as an array (no shell) and set a timeout.
";

const HELP_RULES: &str = "\
quelda rules [--format json|text]

Lists every rule the engine knows (ID, category, severity, default action,
locked, message). JSON: schemas/rules.schema.json.
";

const HELP_VERSION: &str = "\
quelda version [--format json|text]
quelda --version

Prints the version, commit, build date, number of rules and authors
(text by default; --format json for programs).
";

fn main() -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let code = run(
        std::env::args_os().skip(1),
        &mut std::io::stdin().lock(),
        &mut stdout,
        &mut stderr,
    );
    ExitCode::from(code)
}

/// The whole CLI, minus the process: returns the exit code.
fn run(
    args: impl IntoIterator<Item = OsString>,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let command = match args::parse(args) {
        Ok(c) => c,
        Err(args::UsageError(msg)) => {
            // Nothing useful to do if stderr is gone; the exit code says it.
            let _ = writeln!(err, "quelda: {msg}\nRun `quelda --help` for usage.");
            return EXIT_USAGE;
        }
    };
    let (text, code) = match command {
        Command::Help { topic } => (help(topic).to_string(), EXIT_PASS),
        Command::Version { format } => (version(format), EXIT_PASS),
        Command::Rules { format } => {
            let json = quelda_core::list_rules_json();
            // The parser only gives `json` or `text` here.
            let text = match format {
                Format::Text => text::rules(&json),
                Format::Json | Format::Jsonl | Format::Csv => json + "\n",
            };
            (text, EXIT_PASS)
        }
        Command::Scan(s) if batch::is_batch(&s) => {
            return match s.format {
                Some(Format::Json) => {
                    let _ = writeln!(
                        err,
                        "quelda: scan: --format json prints one verdict; use jsonl, text or csv for a folder or several files\nRun `quelda --help` for usage."
                    );
                    EXIT_USAGE
                }
                format => batch::run(&s, format.unwrap_or(Format::Jsonl), stdin, out, err),
            };
        }
        Command::Scan(s) => {
            let input = s.inputs.first().cloned().unwrap_or(args::Input::Stdin);
            let verdict = scan::run(&s, &input, stdin);
            let code = match verdict.status {
                Status::Pass => EXIT_PASS,
                Status::Reject => EXIT_REJECT,
                Status::Error => EXIT_ERROR,
            };
            let json = verdict.to_json();
            let text = match s.format.unwrap_or_default() {
                Format::Json | Format::Jsonl | Format::Csv => json + "\n",
                Format::Text => {
                    let name = match &input {
                        args::Input::Stdin => "-".to_string(),
                        args::Input::Path(p) => p.display().to_string(),
                    };
                    text::verdict(&json, &name)
                }
            };
            (text, code)
        }
    };
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => code,
        Err(e) => {
            let _ = writeln!(err, "quelda: cannot write output: {e}");
            EXIT_IO
        }
    }
}

fn help(topic: Option<&str>) -> &'static str {
    match topic {
        Some("scan") => HELP_SCAN,
        Some("rules") => HELP_RULES,
        Some("version") => HELP_VERSION,
        _ => HELP,
    }
}

fn version(format: Format) -> String {
    let rules = quelda_core::list_rules().len();
    let engine = quelda_core::version();
    match format {
        Format::Text => format!(
            "quelda {engine}\ncommit:  {COMMIT}\nbuilt:   {BUILD_DATE}\nrules:   {rules}\nauthors: {}\nlicense: {LICENSE}\nhome:    {HOMEPAGE}\n",
            AUTHORS.replace(':', ", ")
        ),
        Format::Json | Format::Jsonl | Format::Csv => format!(
            "{}\n",
            serde_json::json!({
                "version": engine,
                "commit": COMMIT,
                "build_date": BUILD_DATE,
                "rules": rules,
                "authors": AUTHORS.split(':').collect::<Vec<_>>(),
                "license": LICENSE,
                "homepage": HOMEPAGE,
            })
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(args: &[&str], stdin: &[u8]) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            args.iter().map(OsString::from),
            &mut std::io::Cursor::new(stdin.to_vec()),
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn version_matches_core() {
        assert_eq!(quelda_core::version(), env!("CARGO_PKG_VERSION"));
        let (code, out, _) = call(&["--version"], b"");
        assert_eq!(code, EXIT_PASS);
        assert!(out.starts_with(&format!("quelda {}\n", env!("CARGO_PKG_VERSION"))));
        assert!(out.contains(&format!("rules:   {}\n", quelda_core::list_rules().len())));
        assert!(out.contains("0xTh3OKrypt <tranhuucanh39@gmail.com>"));
        assert_eq!(call(&["version"], b"").1, out);
        let (_, json, _) = call(&["version", "--format", "json"], b"");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["rules"], quelda_core::list_rules().len());
        assert_eq!(v["commit"], COMMIT);
        assert_eq!(v["build_date"], BUILD_DATE);
        assert!(!COMMIT.is_empty() && !BUILD_DATE.is_empty());
    }

    #[test]
    fn exit_codes_follow_status() {
        let (code, out, err) = call(&["scan", "-"], b"%!PS-Adobe-3.0\n");
        assert_eq!(code, EXIT_REJECT, "{out}{err}");
        assert!(err.is_empty());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["status"], "REJECT");
        let (code, out, _) = call(&["scan", "-", "--policy-json", "{"], b"");
        assert_eq!(code, EXIT_ERROR);
        assert!(out.contains("POLICY.INVALID"));
        let (code, out, err) = call(&["scan"], b"");
        assert_eq!(code, EXIT_USAGE);
        assert!(out.is_empty());
        assert!(err.starts_with("quelda: scan: missing <file>"), "{err}");
    }

    #[test]
    fn help_goes_to_stdout() {
        let (code, out, err) = call(&["--help"], b"");
        assert_eq!((code, out.as_str(), err.as_str()), (EXIT_PASS, HELP, ""));
        let (_, out, _) = call(&["scan", "-h"], b"");
        assert_eq!(out, HELP_SCAN);
        for (t, h) in [("rules", HELP_RULES), ("version", HELP_VERSION)] {
            assert_eq!(call(&["help", t], b"").1, h);
        }
    }

    #[test]
    fn rules_json_and_text() {
        let (code, out, _) = call(&["rules"], b"");
        assert_eq!(code, EXIT_PASS);
        assert_eq!(out, quelda_core::list_rules_json() + "\n");
        let (_, out, _) = call(&["rules", "--format", "text"], b"");
        assert!(out.contains("ACTIVE.JAVASCRIPT"));
    }

    #[test]
    fn output_write_failure_is_exit_74() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut err = Vec::new();
        let code = run(
            ["rules"].map(OsString::from),
            &mut std::io::empty(),
            &mut Closed,
            &mut err,
        );
        assert_eq!(code, EXIT_IO);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("cannot write output")
        );
    }
}
