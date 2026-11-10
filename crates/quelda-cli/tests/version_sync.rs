//! One version everywhere (ADR #34 (j)): Cargo.toml is the source; Cargo.lock,
//! the npm package, its lockfiles and CHANGELOG.md must agree, and docs must
//! not spell it. `scripts/bump-version.sh` must produce exactly that.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every place that holds the version: (place, version).
fn versions(root: &Path) -> Vec<(String, String)> {
    let read = |p: &str| fs::read_to_string(root.join(p)).unwrap_or_else(|e| panic!("{p}: {e}"));
    let json = |p: &str| -> Value { serde_json::from_str(&read(p)).unwrap() };
    let quoted_after = |s: &str, prefix: &str| -> String {
        let at = s.find(prefix).unwrap_or_else(|| panic!("no `{prefix}`")) + prefix.len();
        s[at..].split('"').next().unwrap().to_string()
    };
    let mut out = Vec::new();

    let cargo = read("Cargo.toml");
    let ws = &cargo[cargo.find("[workspace.package]").unwrap()..];
    out.push(("Cargo.toml [workspace.package]".into(), quoted_after(ws, "\nversion = \"")));
    out.push((
        "Cargo.toml quelda-core dependency".into(),
        quoted_after(&cargo, "quelda-core = { path = \"crates/quelda-core\", version = \""),
    ));

    let lock = read("Cargo.lock");
    let mut crates = 0;
    for block in lock.split("[[package]]") {
        if let Some(name) = block.lines().find_map(|l| l.strip_prefix("name = \"quelda-")) {
            out.push((
                format!("Cargo.lock quelda-{}", name.trim_end_matches('"')),
                quoted_after(block, "\nversion = \""),
            ));
            crates += 1;
        }
    }
    assert!(crates >= 5, "Cargo.lock: {crates} quelda crates");

    let pkg = "packages/quelda-js";
    let s = |v: &Value| v.as_str().unwrap_or("<missing>").to_string();
    out.push((format!("{pkg}/package.json"), s(&json(&format!("{pkg}/package.json"))["version"])));
    let lock = json(&format!("{pkg}/package-lock.json"));
    out.push((format!("{pkg}/package-lock.json"), s(&lock["version"])));
    out.push((format!("{pkg}/package-lock.json packages.\"\""), s(&lock["packages"][""]["version"])));
    for ex in ["vite", "webpack"] {
        let p = format!("{pkg}/examples/{ex}/package-lock.json");
        out.push((p.clone(), s(&json(&p)["packages"]["../.."]["version"])));
    }
    out
}

fn base(version: &str) -> &str {
    version.split('-').next().unwrap()
}

#[test]
fn every_place_has_the_cargo_version() {
    let wrong: Vec<_> = versions(&repo())
        .into_iter()
        .filter(|(_, v)| v != VERSION)
        .collect();
    assert!(
        wrong.is_empty(),
        "version {VERSION} expected; run scripts/bump-version.sh {VERSION}: {wrong:?}"
    );
}

#[test]
fn changelog_has_a_section_for_this_version() {
    let changelog = fs::read_to_string(repo().join("CHANGELOG.md")).unwrap();
    let heading = format!("\n## [{}]", base(VERSION));
    assert!(changelog.contains(&heading), "CHANGELOG.md: no `{}`", heading.trim());
}

/// Docs link `releases/latest` instead of spelling the version, so a release
/// never leaves them stale.
#[test]
fn docs_do_not_spell_the_version() {
    let mut docs = vec![
        repo().join("README.md"),
        repo().join("SECURITY.md"),
        repo().join("packages/quelda-js/README.md"),
    ];
    for dir in ["docs", "packaging/homebrew"] {
        if let Ok(rd) = fs::read_dir(repo().join(dir)) {
            docs.extend(rd.map(|e| e.unwrap().path()));
        }
    }
    for doc in docs {
        let text = fs::read_to_string(&doc).unwrap_or_default();
        for v in [VERSION, &format!("v{}", base(VERSION))] {
            assert!(!text.contains(v), "{} spells version {v}", doc.display());
        }
    }
}

#[test]
fn bump_script_updates_every_place() {
    let tmp = std::env::temp_dir().join(format!("quelda-bump-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    for f in [
        "Cargo.toml",
        "Cargo.lock",
        "CHANGELOG.md",
        "packages/quelda-js/package.json",
        "packages/quelda-js/package-lock.json",
        "packages/quelda-js/examples/vite/package-lock.json",
        "packages/quelda-js/examples/webpack/package-lock.json",
    ] {
        let to = tmp.join(f);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(repo().join(f), to).unwrap();
    }
    let bump = |v: &str| {
        Command::new("bash")
            .arg(repo().join("scripts/bump-version.sh"))
            .arg(v)
            .env("QUELDA_ROOT", &tmp)
            .output()
            .unwrap()
    };
    for v in ["9.8.7-rc.3", "9.8.7", "10.0.0"] {
        let out = bump(v);
        assert!(out.status.success(), "{v}: {}", String::from_utf8_lossy(&out.stderr));
        let wrong: Vec<_> = versions(&tmp).into_iter().filter(|(_, x)| x != v).collect();
        assert!(wrong.is_empty(), "{v}: {wrong:?}");
        let changelog = fs::read_to_string(tmp.join("CHANGELOG.md")).unwrap();
        let heading = format!("\n## [{}]", base(v));
        assert_eq!(changelog.matches(&heading).count(), 1, "{v}");
        // The newest section comes first.
        assert!(changelog.find(&heading) <= changelog.find("\n## [0.1.0]"));
    }
    // Other crates' versions in Cargo.lock are untouched.
    let before = fs::read_to_string(repo().join("Cargo.lock")).unwrap();
    let after = fs::read_to_string(tmp.join("Cargo.lock")).unwrap();
    assert_eq!(before.lines().count(), after.lines().count());
    let changed = before.lines().zip(after.lines()).filter(|(a, b)| a != b).count();
    assert_eq!(changed, versions(&repo()).iter().filter(|(p, _)| p.starts_with("Cargo.lock")).count());

    for bad in ["", "1.2", "v1.2.3", "1.2.3-beta.1", "01.2.3", "1.2.3-rc.0"] {
        assert_eq!(bump(bad).status.code(), Some(64), "{bad:?}");
    }
    fs::remove_dir_all(&tmp).unwrap();
}
