//! Generates `tests/fixtures/` + `manifest.json`.
//!
//! Usage: `gen-fixtures [--out DIR] [--check]`
//! `--check` writes nothing and exits 1 if the directory is out of date.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use quelda_testkit::{fixtures, manifest};

fn main() -> ExitCode {
    let mut out = manifest::default_dir();
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => match args.next() {
                Some(dir) => out = PathBuf::from(dir),
                None => return usage("--out needs a directory"),
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
        return match manifest::diff_dir(&out, &all) {
            Ok(diffs) if diffs.is_empty() => {
                println!("{}: up to date ({} fixtures)", out.display(), all.len());
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

    match manifest::write_dir(&out, &all) {
        Ok(files) => {
            println!(
                "wrote {files} files ({} fixtures, {:.1} KiB) to {} in {:.2?}",
                all.len(),
                bytes as f64 / 1024.0,
                out.display(),
                start.elapsed()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error writing {}: {e}", out.display());
            ExitCode::FAILURE
        }
    }
}

fn usage(err: &str) -> ExitCode {
    if !err.is_empty() {
        eprintln!("error: {err}");
    }
    eprintln!("usage: gen-fixtures [--out DIR] [--check]");
    if err.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(64)
    }
}
