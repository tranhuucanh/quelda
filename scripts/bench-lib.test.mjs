// Tests for scripts/bench-lib.mjs. Run: node --test scripts/bench-lib.test.mjs
import { match, ok, strictEqual } from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { canonicalVerdict, compare, digest, listFiles, median, parseJsonl, record, regressions, sortedJson, table } from './bench-lib.mjs';

const dir = mkdtempSync(join(tmpdir(), 'bench-lib-test-'));
after(() => rmSync(dir, { recursive: true, force: true }));

test('canonical verdict: duration dropped, keys sorted, same as serde_json', () => {
  const a = '{"valid":true,"stats":{"duration_ms":5,"bytes":3},"status":"PASS"}';
  const b = '{"status":"PASS","stats":{"bytes":3,"duration_ms":99},"valid":true}';
  // Same string as crates/quelda-eval/src/bench.rs canonical_drops_duration_and_sorts_keys.
  strictEqual(canonicalVerdict(a), '{"stats":{"bytes":3},"status":"PASS","valid":true}');
  strictEqual(digest(a), digest(b));
  strictEqual(digest(a).length, 16);
  ok(digest(a) !== digest('{"status":"REJECT"}'));
  strictEqual(canonicalVerdict('oops'), 'oops');
  strictEqual(sortedJson({ b: [1, { d: null, c: 'x"' }], a: false }), '{"a":false,"b":[1,{"c":"x\\"","d":null}]}');
});

test('median', () => {
  strictEqual(median([]), 0);
  strictEqual(median([3]), 3);
  strictEqual(median([5, 1, 3]), 3);
  strictEqual(median([4, 1, 3, 2]), 2.5);
});

test('record fields match the native record', () => {
  const verdict = '{"status":"PASS","valid":true,"stats":{"decoded_bytes":7,"duration_ms":0}}';
  const r = record({ file: 'a.pdf', bytes: 2 * 1048576, ms: [400, 1000, 500], cpuMs: 480, rssPeak: 30 * 1048576, wasmMem: 1048576 / 2, verdict });
  strictEqual(r.engine, 'wasm-node');
  strictEqual(r.runs, 3);
  strictEqual(r.ms_median, 500);
  strictEqual(r.ms_min, 400);
  strictEqual(r.mb_s, 4);
  strictEqual(r.rss_peak_mb, 30);
  strictEqual(r.wasm_mem_mb, 0.5);
  strictEqual(r.decoded_bytes, 7);
  strictEqual(r.status, 'PASS');
  strictEqual(r.digest, digest(verdict));
  strictEqual(record({ file: 'x', bytes: 0, ms: [1], cpuMs: 0, rssPeak: 0, wasmMem: 0, verdict: 'nope' }).status, 'INVALID_VERDICT');
});

const rec = (file, ms, rss, d = 'x', extra = {}) => ({ file, bytes: 1048576, ms_median: ms, mb_s: 1, cpu_ms: ms, rss_peak_mb: rss, heap_peak_mb: 2, decoded_bytes: 0, status: 'PASS', digest: d, ...extra });

test('table rows and total (same layout as bench.rs)', () => {
  const t = table([rec('a', 500, 10), rec('b', 1500, 20)]);
  match(t, /\| a \| 1\.0 \| 500\.0 \| 1\.0 \| 500\.0 \| 10\.0 \| 2\.0 \| 0\.0 \| PASS \|/);
  match(t, /\| \*\*total \(2 files\)\*\* \| 2\.0 \| 2000\.0 \| 1\.0 \| 2000\.0 \| max 20\.0 \| max 2\.0 \| 0\.0 \| \|/);
  ok(!table([rec('a', 1, 1)]).includes('total'));
  // WASM records use wasm_mem_mb.
  match(table([{ ...rec('w', 1, 1), heap_peak_mb: undefined, wasm_mem_mb: 64 }]), /\| 64\.0 \|/);
});

test('compare: speed-up, verdict diffs, missing files', () => {
  const same = compare([rec('a', 1000, 10)], [rec('a', 250, 5)], ['old', 'new']);
  match(same.text, /\| file \| old ms \| new ms /);
  match(same.text, /\| a \| 1000\.0 \| 250\.0 \| 4\.00 \| 10\.0 \| 5\.0 \| 2\.0 \| 2\.0 \| same \|/);
  strictEqual(same.mismatches, 0);
  strictEqual(same.missing, 0);
  const diff = compare([rec('a', 1, 1, 'x'), rec('b', 1, 1)], [rec('a', 1, 1, 'y', { status: 'REJECT' }), rec('c', 1, 1)]);
  strictEqual(diff.mismatches, 1);
  strictEqual(diff.missing, 2);
  match(diff.text, /\*\*DIFF\*\* PASS→REJECT/);
  match(diff.text, /\| b \|.*missing/);
  match(diff.text, /\| c \|.*missing/);
});

test('parseJsonl skips blank lines', () => {
  strictEqual(parseJsonl('{"a":1}\n\n{"a":2}\n').length, 2);
});

test('listFiles walks directories, skips hidden, keeps file args', () => {
  mkdirSync(join(dir, 'c/sub/.hid'), { recursive: true });
  writeFileSync(join(dir, 'c/b.pdf'), 'x');
  writeFileSync(join(dir, 'c/sub/a.pdf'), 'x');
  writeFileSync(join(dir, 'c/.DS_Store'), 'x');
  writeFileSync(join(dir, 'c/sub/.hid/no.pdf'), 'x');
  writeFileSync(join(dir, 'single.pdf'), 'x');
  const got = listFiles([join(dir, 'c'), join(dir, 'single.pdf')]).map((f) => f.name);
  strictEqual(JSON.stringify(got), JSON.stringify(['c/b.pdf', 'c/sub/a.pdf', 'single.pdf']));
});

test('regressions: slower than pct on ms_min, small and missing files skipped', () => {
  const r = (file, ms_min, ms_median = ms_min) => ({ file, ms_min, ms_median });
  const a = [r('a', 100), r('b', 100), r('c', 10), r('d', 100), r('e', 200, 300)];
  const b = [r('a', 114), r('b', 116, 90), r('c', 100), r('e', 100)];
  const got = regressions(a, b, 15);
  strictEqual(got.length, 1);
  strictEqual(got[0].file, 'b');
  strictEqual(Math.round(got[0].pct), 16);
  strictEqual(regressions(a, b, 15, 5).length, 2);
  strictEqual(regressions([{ file: 'x', ms_median: 50 }], [{ file: 'x', ms_median: 100 }], 15).length, 1);
});
