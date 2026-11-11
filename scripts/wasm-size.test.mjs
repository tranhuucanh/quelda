// Tests for scripts/wasm-size.mjs. Run: node --test scripts/wasm-size.test.mjs
import { deepStrictEqual, match, ok, strictEqual, throws } from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { main, measure, overBudget, parseArgs } from './wasm-size.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, 'wasm-size.mjs');
const dir = mkdtempSync(join(tmpdir(), 'wasm-size-test-'));
after(() => rmSync(dir, { recursive: true, force: true }));

// 4 KiB of pseudo-random bytes (compresses poorly) behind a wasm header.
const blob = Buffer.alloc(4096);
let x = 1;
for (let i = 0; i < blob.length; i++) {
  x = (x * 1103515245 + 12345) >>> 0;
  blob[i] = x >>> 24;
}
blob.set([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
const wasm = join(dir, 'fake.wasm');
writeFileSync(wasm, blob);

const run = (...args) => spawnSync(process.execPath, [script, wasm, ...args], { encoding: 'utf8' });

test('measure: raw is the length; gzip/brotli shrink compressible data', () => {
  const zeros = Buffer.alloc(10000);
  const s = measure(zeros);
  strictEqual(s.raw, 10000);
  ok(s.gzip > 0 && s.gzip < 200, `gzip ${s.gzip}`);
  ok(s.brotli > 0 && s.brotli < 200, `brotli ${s.brotli}`);
  strictEqual(measure(Buffer.alloc(0)).raw, 0);
});

test('overBudget: only exceeded, defined limits; equal is within budget', () => {
  const sizes = { raw: 100, gzip: 50, brotli: 40 };
  deepStrictEqual(overBudget(sizes, {}), []);
  deepStrictEqual(overBudget(sizes, { raw: 100, gzip: 50, brotli: 40 }), []);
  deepStrictEqual(overBudget(sizes, { raw: 99, brotli: 100 }), [{ kind: 'raw', size: 100, max: 99 }]);
  strictEqual(overBudget(sizes, { raw: 1, gzip: 1, brotli: 1 }).length, 3);
});

test('parseArgs: budget file, overrides win, bad usage throws', () => {
  const budget = join(dir, 'b.json');
  writeFileSync(budget, JSON.stringify({ raw_bytes: 10, gzip_bytes: 5 }));
  const o = parseArgs(['f.wasm', '--budget', budget, '--max-gzip', '7', '--no-fail', '--json', 'o.json']);
  deepStrictEqual(o, { file: 'f.wasm', budget: { raw: 10, gzip: 7 }, json: 'o.json', fail: false });
  throws(() => parseArgs([]), /missing/);
  throws(() => parseArgs(['a', 'b']), /unexpected/);
  throws(() => parseArgs(['a', '--max-raw']), /needs a value/);
  throws(() => parseArgs(['a', '--max-raw', '-1']), /non-negative/);
  throws(() => parseArgs(['a', '--max-raw', '1.5']), /non-negative/);
  throws(() => parseArgs(['a', '--max-zstd', '1']), /unexpected/);
  writeFileSync(budget, JSON.stringify({ raw_bytes: 'big' }));
  throws(() => parseArgs(['a', '--budget', budget]), /non-negative/);
});

test('CLI fails (exit 1) when a small fake threshold is exceeded', () => {
  for (const kind of ['raw', 'gzip', 'brotli']) {
    const r = run(`--max-${kind}`, '100');
    strictEqual(r.status, 1, `${kind}: ${r.stderr}`);
    match(r.stderr, new RegExp(`${kind} size \\d+ B is over budget 100 B`));
  }
});

test('CLI passes (exit 0) within budget, and with --no-fail', () => {
  const r = run('--max-raw', '1000000', '--max-gzip', '1000000', '--max-brotli', '1000000');
  strictEqual(r.status, 0, r.stderr);
  match(r.stdout, /raw\s+4096 B/);
  strictEqual(run('--max-raw', '1', '--no-fail').status, 0);
  strictEqual(run('--max-raw', '4096').status, 0); // equal = within budget
  strictEqual(run('--max-raw', '4095').status, 1);
});

test('CLI writes --json report and reads --budget file', () => {
  const budget = join(dir, 'budget.json');
  writeFileSync(budget, JSON.stringify({ raw_bytes: 10 }));
  const out = join(dir, 'size.json');
  strictEqual(run('--budget', budget, '--json', out).status, 1);
  const rep = JSON.parse(readFileSync(out, 'utf8'));
  strictEqual(rep.sizes.raw, 4096);
  deepStrictEqual(rep.over, [{ kind: 'raw', size: 4096, max: 10 }]);
});

test('CLI usage errors exit 2', () => {
  strictEqual(spawnSync(process.execPath, [script], { encoding: 'utf8' }).status, 2);
  strictEqual(spawnSync(process.execPath, [script, join(dir, 'missing.wasm')], { encoding: 'utf8' }).status, 2);
  strictEqual(main(['--bogus'], () => {}, () => {}), 2);
});

test('the committed budget is design §8.2 (704 KiB raw, 288 KiB gzip; ADR #42)', () => {
  const b = JSON.parse(readFileSync(join(here, '../crates/quelda-wasm/size-budget.json'), 'utf8'));
  deepStrictEqual(b, { raw_bytes: 704 * 1024, gzip_bytes: 288 * 1024 });
});
