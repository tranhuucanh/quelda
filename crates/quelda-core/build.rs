//! Generates the rule registry (design §5.4, §5.5, ADR #19):
//! - declarative rules from `rules/*.toml`, validated (a bad rule is a build
//!   error naming the file and rule);
//! - code rules discovered in `src/rules/<category>/*.rs` (`impl Rule for X`).
//!
//! The logic lives in `build_support/rules_codegen.rs` (unit-tested in the crate).

#[path = "build_support/rules_codegen.rs"]
mod rules_codegen;

use std::fs;
use std::path::{Path, PathBuf};

fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

fn fail(errors: &[String]) -> ! {
    for e in errors {
        println!("cargo::error={e}");
    }
    eprintln!("rule validation failed:\n  {}", errors.join("\n  "));
    std::process::exit(1);
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| fail(&[format!("{}: cannot read: {e}", path.display())]))
}

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let rules_dir = root.join("rules");
    let code_dir = root.join("src/rules");
    println!("cargo::rerun-if-changed=build_support/rules_codegen.rs");
    println!("cargo::rerun-if-changed=rules");
    println!("cargo::rerun-if-changed=src/rules");

    let mut errors = Vec::new();
    let mut specs = Vec::new();
    for path in sorted_entries(&rules_dir) {
        if path.extension().is_some_and(|e| e == "toml") {
            let name = format!(
                "rules/{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            match rules_codegen::parse_file(&name, &read(&path)) {
                Ok(r) => specs.extend(r),
                Err(e) => errors.extend(e),
            }
        }
    }
    if let Err(e) = rules_codegen::validate(&specs) {
        errors.extend(e);
    }

    let mut code = Vec::new();
    for dir in sorted_entries(&code_dir).into_iter().filter(|p| p.is_dir()) {
        let category = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        for path in sorted_entries(&dir) {
            let file = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let src = if file.ends_with(".rs") {
                read(&path)
            } else {
                String::new()
            };
            match rules_codegen::code_module(&category, &file, &path.to_string_lossy(), &src) {
                Ok(Some(m)) => code.push(m),
                Ok(None) => {}
                Err(e) => errors.push(e),
            }
        }
    }
    if !errors.is_empty() {
        fail(&errors);
    }

    let out =
        PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default()).join("rules_generated.rs");
    if let Err(e) = fs::write(&out, rules_codegen::generate(&specs, &code)) {
        fail(&[format!("{}: cannot write: {e}", out.display())]);
    }
}
