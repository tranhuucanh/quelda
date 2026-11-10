#!/usr/bin/env node
// WASM benchmark on Node (plan Step 16 Phase 0): the *built* package
// (scripts/wasm-build.sh output) scans each file `--runs` times (default 3)
// in a child process of its own, so peak RSS and WASM memory are that file's.
// Writes one JSON line per file (scripts/bench-lib.mjs `record`) to --out
// (default target/bench/wasm-node.jsonl) and prints a Markdown table.
//
//   node scripts/wasm-bench.mjs [--pkg DIR] [--policy JSON] [--runs N] [--out FILE] PATH...
//
// Measures: wall time of `scan` (performance.now; includes the copy of the
// input into WASM memory, as in production), user+sys CPU
// (process.cpuUsage), peak RSS (process.resourceUsage().maxRSS) and the final
// WASM memory size (it only grows, so final = peak).
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { argv, exit } from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { DEFAULT_POLICY, listFiles, record, table } from './bench-lib.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const usage = () => {
  console.error('usage: node scripts/wasm-bench.mjs [--pkg DIR] [--policy JSON] [--runs N] [--out FILE] PATH...');
  exit(2);
};

const opts = { pkg: join(root, 'target/wasm-pkg'), policy: DEFAULT_POLICY, runs: 3, out: join(root, 'target/bench/wasm-node.jsonl'), one: null, paths: [] };
const args = argv.slice(2);
while (args.length) {
  const a = args.shift();
  const val = () => args.shift() ?? usage();
  if (a === '--pkg') opts.pkg = resolve(val());
  else if (a === '--policy') opts.policy = val();
  else if (a === '--runs') opts.runs = Number(val()) || usage();
  else if (a === '--out') opts.out = resolve(val());
  else if (a === '--one') opts.one = val();
  else if (!a.startsWith('-')) opts.paths.push(a);
  else usage();
}

if (opts.one) {
  const mod = await import(pathToFileURL(join(opts.pkg, 'quelda.js')).href);
  const wasm = mod.initSync({ module: readFileSync(join(opts.pkg, 'quelda_bg.wasm')) });
  const input = readFileSync(opts.one);
  const ms = [];
  let verdict = '';
  const cpu0 = process.cpuUsage();
  for (let i = 0; i < Math.max(1, opts.runs); i++) {
    const t0 = performance.now();
    verdict = mod.scan(input, opts.policy);
    ms.push(performance.now() - t0);
  }
  const cpu = process.cpuUsage(cpu0);
  const rec = record({
    file: opts.one,
    bytes: input.length,
    ms,
    cpuMs: (cpu.user + cpu.system) / 1000 / ms.length,
    rssPeak: process.resourceUsage().maxRSS * 1024,
    wasmMem: wasm.memory.buffer.byteLength,
    verdict,
  });
  console.log(JSON.stringify(rec));
  exit(0);
}

if (opts.paths.length === 0) usage();
const self = fileURLToPath(import.meta.url);
const records = [];
for (const { path, name } of listFiles(opts.paths)) {
  const r = spawnSync(
    process.execPath,
    // 4 GiB of WASM memory needs a large enough old space for the JS copy too.
    ['--max-old-space-size=8192', self, '--one', path, '--pkg', opts.pkg, '--policy', opts.policy, '--runs', String(opts.runs)],
    { encoding: 'utf8', maxBuffer: 1 << 20 },
  );
  let rec = null;
  try {
    if (r.status === 0) rec = JSON.parse(r.stdout);
  } catch {}
  if (!rec) {
    // E.g. the WASM memory cannot hold the file: recorded, not fatal.
    console.error(`${name}: child failed (${r.status ?? r.signal}): ${(r.stderr || '').trim().split('\n').pop()}`);
    rec = { engine: 'wasm-node', file: name, bytes: 0, runs: 0, ms_median: 0, ms_min: 0, mb_s: 0, cpu_ms: 0, rss_peak_mb: 0, wasm_mem_mb: 0, decoded_bytes: 0, status: 'CRASH', digest: '' };
  }
  rec.file = name;
  console.error(`${name}: ${rec.ms_median} ms, ${rec.mb_s} MB/s, RSS ${rec.rss_peak_mb} MiB, WASM ${rec.wasm_mem_mb} MiB, ${rec.status}`);
  records.push(rec);
}
mkdirSync(dirname(opts.out), { recursive: true });
writeFileSync(opts.out, records.map((r) => JSON.stringify(r) + '\n').join(''));
process.stdout.write(table(records));
console.log(`\npolicy: ${opts.policy}  runs: ${opts.runs}  → ${opts.out}`);
