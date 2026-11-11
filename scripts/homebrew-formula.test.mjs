// node --test scripts/homebrew-formula.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ASSETS, formula, parseSums } from './homebrew-formula.mjs';

const sha = (c) => c.repeat(64);
const sums = `${sha('a')}  ${ASSETS.macos_arm}\n${sha('b')} *quelda-x86_64-unknown-linux-musl.tar.gz\n${sha('d')}  quelda-extra.tar.gz\nnot a line\n`;

test('parseSums reads sha256sum text and binary mode lines', () => {
  const m = parseSums(sums);
  assert.equal(m.get(ASSETS.macos_arm), sha('a'));
  assert.equal(m.get('quelda-x86_64-unknown-linux-musl.tar.gz'), sha('b'));
  assert.equal(m.size, 3);
});

test('formula pins the macOS arm64 asset and its checksum; macOS arm64 only', () => {
  const f = formula('1.2.3', parseSums(sums));
  assert.doesNotMatch(f, /@[A-Z_]+@/);
  const url = `url "https://github.com/tranhuucanh/quelda/releases/download/v1.2.3/${ASSETS.macos_arm}"`;
  assert.ok(f.includes(`${url}\n  sha256 "${sha('a')}"`));
  assert.match(f, /class Quelda < Formula/);
  assert.match(f, /depends_on arch: :arm64\n  depends_on :macos/);
  assert.match(f, /test do/);
  // Homebrew on Linux is not offered (ADR #38); macOS Intel and Windows are not released.
  assert.doesNotMatch(f, /linux|x86_64|windows/);
});

test('formula refuses release candidates and missing assets', () => {
  assert.throws(() => formula('1.2.3-rc.1', parseSums(sums)), /not a final release/);
  assert.throws(() => formula('1.2.3', parseSums(`${sha('b')}  quelda-x86_64-unknown-linux-musl.tar.gz\n`)), /SHA256SUMS has no/);
});

test('--local: a test formula downloading from file://DIR/releases/download/v<version>/, rc allowed', () => {
  const f = formula('1.2.3-rc.4', parseSums(sums), { local: '/tmp/rel/' });
  assert.ok(f.includes(`url "file:///tmp/rel/releases/download/v1.2.3-rc.4/${ASSETS.macos_arm}"\n  sha256 "${sha('a')}"`));
  assert.doesNotMatch(f, /url "https:/);
  assert.throws(() => formula('1.2', parseSums(sums), { local: '/tmp/rel' }), /not a final release/);
});
