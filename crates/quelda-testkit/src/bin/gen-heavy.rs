//! Writes the heavy benchmark PDFs (plan Step 16, `quelda_testkit::heavy`)
//! to `target/bench/heavy/` (gitignored). Files that already exist with the
//! expected generator version are kept; `--force` rewrites them.
//!
//! Usage: `gen-heavy [--out DIR] [--small] [--force] [NAME...]`
//! `--small` writes the tiny test variants instead; NAMEs pick a subset.

use std::fs::{self, File};
use std::io::BufWriter;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use quelda_testkit::heavy;

fn main() -> ExitCode {
    let mut out = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bench/heavy"
    ));
    let mut small = false;
    let mut force = false;
    let mut names = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => match args.next() {
                Some(dir) => out = PathBuf::from(dir),
                None => return usage("--out needs a directory"),
            },
            "--small" => small = true,
            "--force" => force = true,
            "-h" | "--help" => return usage(""),
            a if a.starts_with('-') => return usage(&format!("unknown argument `{a}`")),
            name => names.push(name.to_string()),
        }
    }
    let all = if small {
        heavy::small_catalog()
    } else {
        heavy::catalog()
    };
    if let Some(bad) = names.iter().find(|n| !all.iter().any(|h| h.name == *n)) {
        return usage(&format!("unknown heavy file `{bad}`"));
    }
    if let Err(e) = fs::create_dir_all(&out) {
        eprintln!("error: cannot create {}: {e}", out.display());
        return ExitCode::from(1);
    }
    for h in all
        .iter()
        .filter(|h| names.is_empty() || names.contains(&h.name.to_string()))
    {
        let path = out.join(format!("{}.pdf", h.name));
        let stamp = out.join(format!(".{}.kind", h.name));
        let want = format!("{:?}\n", h.kind);
        if !force && path.is_file() && fs::read_to_string(&stamp).is_ok_and(|s| s == want) {
            println!("{:<20} kept", h.name);
            continue;
        }
        let start = Instant::now();
        let written = File::create(&path).and_then(|f| {
            let mut w = BufWriter::with_capacity(1 << 20, f);
            heavy::write(h.kind, &mut w)
        });
        match written.and_then(|n| fs::write(&stamp, &want).map(|()| n)) {
            Ok(n) => println!(
                "{:<20} {:>8.1} MiB in {:>5.1}s  {}",
                h.name,
                n as f64 / 1048576.0,
                start.elapsed().as_secs_f64(),
                h.note
            ),
            Err(e) => {
                let _ = fs::remove_file(&path);
                eprintln!("error: {}: {e}", path.display());
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

fn usage(msg: &str) -> ExitCode {
    if !msg.is_empty() {
        eprintln!("error: {msg}");
    }
    eprintln!("usage: gen-heavy [--out DIR] [--small] [--force] [NAME...]");
    for h in heavy::catalog() {
        eprintln!("  {:<20} {}", h.name, h.note);
    }
    ExitCode::from(2)
}
