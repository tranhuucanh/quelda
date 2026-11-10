//! Generates `tests/fixtures/` + `manifest.json`, and the conformance cases
//! in `tests/conformance/`.
//!
//! Usage: `gen-fixtures [--out DIR] [--conformance-out DIR] [--check]`
//! `--check` writes nothing and exits 1 if a directory is out of date.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use quelda_testkit::{fixtures, manifest};

fn main() -> ExitCode {
    let mut out = manifest::default_dir();
    let mut conf_out = manifest::default_conformance_dir();
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => match args.next() {
                Some(dir) => out = PathBuf::from(dir),
                None => return usage("--out needs a directory"),
            },
            "--conformance-out" => match args.next() {
                Some(dir) => conf_out = PathBuf::from(dir),
                None => return usage("--conformance-out needs a directory"),
            },
            "--check" => check = true,
            "-h" | "--help" => return usage(""),
            other => return usage(&format!("unknown argument `{other}`")),
        }
    }

    let start = Instant::now();
    let all = fixtures::all();
    let bytes: usize = all.iter().map(|f| f.bytes.len()).sum();

    if check {
        let diffs = manifest::diff_dir(&out, &all).and_then(|mut d| {
            d.extend(
                manifest::diff_conformance_dir(&conf_out)?
                    .into_iter()
                    .map(|x| format!("conformance {x}")),
            );
            Ok(d)
        });
        return match diffs {
            Ok(diffs) if diffs.is_empty() => {
                println!(
                    "{} and {}: up to date ({} fixtures)",
                    out.display(),
                    conf_out.display(),
                    all.len()
                );
                ExitCode::SUCCESS
            }
            Ok(diffs) => {
                for d in &diffs {
                    eprintln!("{d}");
                }
                eprintln!(
                    "{} difference(s); run gen-fixtures to regenerate",
                    diffs.len()
                );
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("error reading {}: {e}", out.display());
                ExitCode::FAILURE
            }
        };
    }

    let written = manifest::write_dir(&out, &all)
        .and_then(|files| Ok((files, manifest::write_conformance_dir(&conf_out)?)));
    match written {
        Ok((files, cases)) => {
            println!(
                "wrote {files} files ({} fixtures, {:.1} KiB) to {} and {cases} conformance cases to {} in {:.2?}",
                all.len(),
                bytes as f64 / 1024.0,
                out.display(),
                conf_out.display(),
                start.elapsed()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "error writing {} / {}: {e}",
                out.display(),
                conf_out.display()
            );
            ExitCode::FAILURE
        }
    }
}

fn usage(err: &str) -> ExitCode {
    if !err.is_empty() {
        eprintln!("error: {err}");
    }
    eprintln!("usage: gen-fixtures [--out DIR] [--conformance-out DIR] [--check]");
    if err.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(64)
    }
}
