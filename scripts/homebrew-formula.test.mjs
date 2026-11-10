// node --test scripts/homebrew-formula.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ASSETS, formula, parseSums } from './homebrew-formula.mjs';

const sha = (c) => c.repeat(64);
const sums = `${sha('a')}  ${ASSETS.macos_arm}\n${sha('b')} *${ASSETS.linux_intel}\n${sha('c')}  ${ASSETS.linux_arm}\n${sha('d')}  quelda-extra.tar.gz\nnot a line\n`;

test('parseSums reads sha256sum text and binary mode lines', () => {
  const m = parseSums(sums);
  assert.equal(m.get(ASSETS.macos_arm), sha('a'));
  assert.equal(m.get(ASSETS.linux_intel), sha('b'));
  assert.equal(m.size, 4);
});

test('formula pins each platform to its asset and checksum', () => {
  const f = formula('1.2.3', parseSums(sums));
  assert.doesNotMatch(f, /@[A-Z_]+@/);
  for (const [asset, c] of [[ASSETS.macos_arm, 'a'], [ASSETS.linux_intel, 'b'], [ASSETS.linux_arm, 'c']]) {
    const url = `url "https://github.com/tranhuucanh/quelda/releases/download/v1.2.3/${asset}"`;
    assert.ok(f.includes(`${url}\n      sha256 "${sha(c)}"`), asset);
  }
  assert.match(f, /class Quelda < Formula/);
  assert.match(f, /test do/);
  // macOS Intel and Windows are not released (ADR #34).
  assert.doesNotMatch(f, /x86_64-apple-darwin|windows/);
});

test('formula refuses release candidates and missing assets', () => {
  assert.throws(() => formula('1.2.3-rc.1', parseSums(sums)), /not a final release/);
  assert.throws(() => formula('1.2.3', parseSums(`${sha('a')}  ${ASSETS.macos_arm}\n`)), /SHA256SUMS has no/);
});
