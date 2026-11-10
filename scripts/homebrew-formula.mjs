#!/usr/bin/env node
// Writes the Homebrew formula for a release (ADR #34 (b)) to stdout:
//
//   node scripts/homebrew-formula.mjs 0.1.0 dist/SHA256SUMS > Formula/quelda.rb
//
// The formula installs the prebuilt binaries from GitHub Releases (macOS
// arm64, Linux x64/arm64). The release workflow runs this for final releases
// only (never `-rc`), tests the formula with `brew install` / `brew test` /
// `brew audit --strict`, then pushes it to tranhuucanh/homebrew-quelda.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const REPO = 'tranhuucanh/quelda';

/** Release asset per Homebrew platform block. */
export const ASSETS = {
  macos_arm: 'quelda-aarch64-apple-darwin.tar.gz',
  linux_intel: 'quelda-x86_64-unknown-linux-musl.tar.gz',
  linux_arm: 'quelda-aarch64-unknown-linux-musl.tar.gz',
};

/** `sha256  name` lines (sha256sum format) → Map(name → sha256). */
export function parseSums(text) {
  const sums = new Map();
  for (const line of text.split('\n')) {
    const m = /^([0-9a-f]{64}) [ *]?(\S+)$/.exec(line.trim());
    if (m) sums.set(m[2], m[1]);
  }
  return sums;
}

export function formula(version, sums) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`not a final release version: ${version}`);
  const block = (key) => {
    const asset = ASSETS[key];
    const sha = sums.get(asset);
    if (!sha) throw new Error(`SHA256SUMS has no ${asset}`);
    return `url "https://github.com/${REPO}/releases/download/v${version}/${asset}"\n      sha256 "${sha}"`;
  };
  const tpl = readFileSync(new URL('../packaging/homebrew/quelda.rb.in', import.meta.url), 'utf8');
  return tpl
    .replace('@MACOS_ARM@', block('macos_arm'))
    .replace('@LINUX_INTEL@', block('linux_intel'))
    .replace('@LINUX_ARM@', block('linux_arm'));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [version, sumsPath] = process.argv.slice(2);
  try {
    if (!version || !sumsPath) throw new Error('usage: homebrew-formula.mjs <X.Y.Z> <SHA256SUMS>');
    process.stdout.write(formula(version, parseSums(readFileSync(sumsPath, 'utf8'))));
  } catch (e) {
    console.error(`homebrew-formula: ${e.message}`);
    process.exit(1);
  }
}
