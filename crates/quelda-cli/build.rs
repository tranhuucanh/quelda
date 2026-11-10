//! Commit and build date for `quelda version`. Release builds set
//! `QUELDA_BUILD_COMMIT` / `QUELDA_BUILD_DATE`; otherwise they come from git
//! (the commit date, so a rebuild of the same commit prints the same), or
//! `unknown` outside a git checkout.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

fn value(env: &str, git_args: &[&str]) -> String {
    println!("cargo:rerun-if-env-changed={env}");
    std::env::var(env)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| git(git_args))
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // A new commit moves HEAD's reflog; rebuild then (dev builds only).
    if let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        for f in ["HEAD", "logs/HEAD"] {
            let p = Path::new(&dir).join(f);
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
    let commit = value("QUELDA_BUILD_COMMIT", &["rev-parse", "--short=12", "HEAD"]);
    let date = value("QUELDA_BUILD_DATE", &["log", "-1", "--format=%cs"]);
    println!("cargo:rustc-env=QUELDA_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=QUELDA_BUILD_DATE={date}");
}
