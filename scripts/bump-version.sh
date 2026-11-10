#!/usr/bin/env bash
# Sets the one quelda version everywhere (ADR #34 (j)):
#   scripts/bump-version.sh 0.1.0          # release
#   scripts/bump-version.sh 0.1.0-rc.1     # release candidate (npm dist-tag `next`)
#
# Source of truth: `[workspace.package] version` in Cargo.toml (every crate
# inherits it; the CLI and engine read CARGO_PKG_VERSION). This script also
# updates Cargo.lock, the npm package (package.json, package-lock.json, the
# examples' lockfiles) and makes sure CHANGELOG.md has a `## [X.Y.Z]` section.
# Docs never spell the version (links use releases/latest).
# crates/quelda-cli/tests/version_sync.rs fails if anything disagrees.
#
# QUELDA_ROOT=<dir> works on a copy (tests). Needs node.
set -euo pipefail

root="${QUELDA_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
version="${1:-}"
if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$ ]]; then
  echo "usage: $0 X.Y.Z[-rc.N]" >&2
  exit 64
fi
base="${version%%-*}"

node - "$root" "$version" "$base" <<'EOF'
const fs = require('node:fs');
const path = require('node:path');
const [root, version, base] = process.argv.slice(2);
const file = (p) => path.join(root, p);
const edit = (p, f) => {
  const before = fs.readFileSync(file(p), 'utf8');
  const after = f(before);
  if (after === before && !before.includes(version)) throw new Error(`${p}: nothing to update`);
  fs.writeFileSync(file(p), after);
};

// Cargo.toml: [workspace.package] version + the quelda-core path dependency.
edit('Cargo.toml', (s) => {
  const ws = /(\[workspace\.package\]\n(?:[^\[\n].*\n)*?version = ")[^"]*(")/;
  if (!ws.test(s)) throw new Error('Cargo.toml: no [workspace.package] version');
  return s
    .replace(ws, `$1${version}$2`)
    .replace(/(quelda-core = \{ path = "crates\/quelda-core", version = ")[^"]*(")/, `$1${version}$2`);
});

// Cargo.lock: every workspace crate (quelda-*).
edit('Cargo.lock', (s) => s.replace(/(name = "quelda-[a-z]+"\nversion = ")[^"]*(")/g, `$1${version}$2`));

// npm package and its lockfiles.
const json = (p, f) =>
  edit(p, (s) => {
    const v = JSON.parse(s);
    f(v);
    return `${JSON.stringify(v, null, 2)}\n`;
  });
json('packages/quelda-js/package.json', (v) => {
  v.version = version;
});
json('packages/quelda-js/package-lock.json', (v) => {
  v.version = version;
  v.packages[''].version = version;
});
for (const ex of ['vite', 'webpack']) {
  json(`packages/quelda-js/examples/${ex}/package-lock.json`, (v) => {
    v.packages['../..'].version = version;
  });
}

// CHANGELOG.md: a section for the release (rc versions share it).
const changelog = fs.readFileSync(file('CHANGELOG.md'), 'utf8');
if (!changelog.includes(`\n## [${base}]`)) {
  const at = changelog.indexOf('\n## ');
  const section = `\n## [${base}] — unreleased\n`;
  fs.writeFileSync(
    file('CHANGELOG.md'),
    at < 0 ? `${changelog.trimEnd()}\n${section}` : `${changelog.slice(0, at)}${section}${changelog.slice(at)}`,
  );
}
console.log(`version ${version} (changelog section ${base})`);
EOF
