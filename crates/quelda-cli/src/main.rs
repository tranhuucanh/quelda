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

/// `quelda --help`; `{version}` is replaced by the version.
const HELP: &str = "\
quelda {version} — PDF & Illustrator security scanner

Usage:
  quelda scan <file|folder>... [options]   Scan files and folders
  quelda scan - [options]                  Scan stdin
  quelda rules                             List every rule
  quelda version                           Version and build

Common options:
  -p, --preset <name>       strict | balanced (default) | permissive
      --rule <ID>=<action>  Change one rule: off | warn | block (repeatable)
      --policy <file>       Policy JSON file: turn rules off, raise or lower them
      --policy-json <json>  Same, as a string
  -f, --format <fmt>        json | jsonl | text | csv
  -h, --help                Help (quelda help scan: every scan option;
                            quelda help policy: how to change rules)
  -v, --version             Version

Examples:
  quelda scan file.pdf -f text
  quelda scan uploads/ -f csv > report.csv
  quelda scan file.pdf -p strict --rule EXTERNAL.URI=off

Exit: 0 PASS · 1 REJECT · 2 ERROR · 64 usage. Anything but 0 = do not accept.
Policies: https://github.com/tranhuucanh/quelda/blob/main/docs/policy.md
More: https://github.com/tranhuucanh/quelda
";

const HELP_SCAN: &str = "\
quelda scan <file|folder>... [options]
quelda scan - [options]                  (file read from stdin)

One file: prints its verdict (JSON by default).
Folders or several files: one result per file, in a fixed order (arguments
in order, folders sorted by path). Folders are scanned with their
subfolders, for .pdf and .ai files (any case); symbolic links are not
followed. A summary goes to stderr (to stdout with -f text).

Policy:
  -p, --preset <name>       strict | balanced (default) | permissive;
                            replaces the preset of --policy / --policy-json
      --rule <ID>=<action>  off | warn | block for one rule; repeat for more
                            (beats --policy / --policy-json; quelda help policy)
      --policy <file>       Policy JSON file (docs/policy.md)
      --policy-json <json>  Policy as a JSON string
      --stop-on-first       Stop at the first blocking finding (faster)

Output:
  -f, --format <fmt>        json   one file (default for one file)
                            jsonl  one JSON line per file (default for several)
                            text   easy to read, with a summary
                            csv    one row per file

Folders and several files:
  -j, --jobs <n>            Files scanned at once (default: one per CPU core)
      --all                 Scan every file, not only .pdf and .ai
      --absolute            Print absolute paths
      --no-hash             Skip each file's SHA-256 (sha256: null)

Other:
  -h, --help                This help
      --                    End of options (a file name starting with -)

Examples:
  quelda scan file.pdf -p strict -f text
  quelda scan uploads/ archive/ -j 4 -f csv > report.csv
  quelda scan file.pdf --policy my-policy.json
  quelda scan - < file.pdf

Exit: 0 every file PASS · 1 a file REJECT · 2 a file ERROR, a bad policy or
nothing to scan · 64 usage · 74 output error.
From a program: pass arguments as an array (no shell) and set a timeout.
";

const HELP_RULES: &str = "\
quelda rules [-f json|text]

Lists every rule the engine knows (ID, category, severity, default action,
locked, message). JSON: schemas/rules.schema.json.

Examples:
  quelda rules -f text
  quelda rules | jq -r '.[].id'
";

const HELP_POLICY: &str = "\
How strict a scan is. Every rule always runs; a policy only chooses what
each finding does:
  block  the file is rejected (exit 1)
  warn   reported, the file stays valid
  off    the rule is skipped

Start from a preset, then change single rules (the most specific wins):
  quelda scan file.pdf -p strict
  quelda scan file.pdf --rule EXTERNAL.URI=off --rule EMBED.EMBEDDED_FILE=warn

Rule IDs and their default actions: quelda rules -f text
Locked rules (marked [locked]) always block: lowering one prints a warning
and has no effect, unless the policy sets \"unsafe_allow_unlock\": true.

From a program, or for many changes, pass the policy as JSON:
  quelda scan file.pdf --policy my-policy.json
  quelda scan file.pdf --policy-json '{\"rules\":{\"EXTERNAL.URI\":\"off\"}}'

  {
    \"preset\": \"balanced\",
    \"categories\": { \"external\": \"warn\" },
    \"rules\": { \"EXTERNAL.URI\": \"off\" },
    \"limits\": { \"max_file_bytes\": 52428800 },
    \"stop_on_first\": false
  }

Every field is optional. Categories: filetype, postscript, active_content,
embedded, external, forms, xml, structure, encryption, codecs, resource.
-p and --rule beat the same settings in the JSON. A typo or an unknown rule
ID is an ERROR (exit 2), never ignored.

Every field, limit and recipe:
https://github.com/tranhuucanh/quelda/blob/main/docs/policy.md
";

const HELP_VERSION: &str = "\
quelda version [-f json|text]
quelda -v | --version

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
        Command::Help { topic } => (help(topic), EXIT_PASS),
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
            let verdict = scan::run(&s, &input, stdin, err);
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

fn help(topic: Option<&str>) -> String {
    match topic {
        Some("scan") => HELP_SCAN.to_string(),
        Some("rules") => HELP_RULES.to_string(),
        Some("version") => HELP_VERSION.to_string(),
        Some("policy") => HELP_POLICY.to_string(),
        _ => HELP.replace("{version}", quelda_core::version()),
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
        assert_eq!(
            (code, out.as_str(), err.as_str()),
            (EXIT_PASS, help(None).as_str(), "")
        );
        let first = format!(
            "quelda {} — PDF & Illustrator security scanner",
            quelda_core::version()
        );
        assert_eq!(out.lines().next(), Some(first.as_str()));
        assert_eq!(call(&["-h"], b"").1, out);
        let (_, out, _) = call(&["scan", "-h"], b"");
        assert_eq!(out, HELP_SCAN);
        for (t, h) in [
            ("rules", HELP_RULES),
            ("version", HELP_VERSION),
            ("policy", HELP_POLICY),
        ] {
            assert_eq!(call(&["help", t], b"").1, h);
        }
    }

    #[test]
    fn rule_flags_change_the_verdict_and_warn_about_locked_rules() {
        const PS: &[u8] = b"%!PS-Adobe-3.0\n";
        let status = |args: &[&str]| {
            let (code, out, err) = call(args, PS);
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            let ids = |k: &str| -> Vec<String> {
                let list = v[k].as_array().unwrap();
                list.iter()
                    .map(|f| f["rule_id"].as_str().unwrap().to_string())
                    .collect()
            };
            (code, ids("violations"), ids("warnings"), err)
        };
        // A warning raised to block, and back off.
        let (code, violations, _, err) =
            status(&["scan", "-", "--rule", "STRUCT.MISSING_EOF=block"]);
        assert_eq!(code, EXIT_REJECT);
        assert!(
            violations.contains(&"STRUCT.MISSING_EOF".to_string()),
            "{violations:?}"
        );
        assert!(err.is_empty(), "{err}");
        let (_, violations, warnings, _) = status(&["scan", "-", "--rule=STRUCT.MISSING_EOF=off"]);
        assert!(
            !violations
                .iter()
                .chain(&warnings)
                .any(|r| r == "STRUCT.MISSING_EOF")
        );
        // A locked rule turned off: still blocks, and stderr says why.
        let (code, violations, _, err) =
            status(&["scan", "-", "--rule", "FILETYPE.POSTSCRIPT_MAGIC=off"]);
        assert_eq!(code, EXIT_REJECT);
        assert!(violations.contains(&"FILETYPE.POSTSCRIPT_MAGIC".to_string()));
        assert_eq!(
            err,
            "quelda: warning: FILETYPE.POSTSCRIPT_MAGIC is locked and still blocks (lowering it needs \"unsafe_allow_unlock\": true in the policy)\n"
        );
        // Unlocked by the policy: no warning, the rule is lowered.
        let (code, _, warnings, err) = status(&[
            "scan",
            "-",
            "--policy-json",
            r#"{"unsafe_allow_unlock":true}"#,
            "--rule",
            "FILETYPE.POSTSCRIPT_MAGIC=warn",
            "--rule",
            "FILETYPE.NOT_PDF_HEADER=off",
        ]);
        assert_eq!((code, err.as_str()), (EXIT_PASS, ""));
        assert!(warnings.contains(&"FILETYPE.POSTSCRIPT_MAGIC".to_string()));
        // An unknown rule ID is POLICY.INVALID, like in a policy file.
        let (code, out, _) = call(&["scan", "-", "--rule", "STRUCT.MISSING_EOFF=off"], PS);
        assert_eq!(code, EXIT_ERROR);
        assert!(out.contains("unknown rule `STRUCT.MISSING_EOFF`"), "{out}");
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
