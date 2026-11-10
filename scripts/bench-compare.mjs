#!/usr/bin/env node
// Compares two benchmark runs (plan Step 16: before/after each phase, or
// native vs WASM): time, speed-up, peak RSS / memory, identical verdicts.
// Exit 1 when a verdict differs (the differential check) or a file is missing,
// or, with --max-regress PCT, when a file got more than PCT % slower
// (fastest run; files under 20 ms skipped) — the CI gate (ADR #29).
//
//   node scripts/bench-compare.mjs BEFORE.jsonl AFTER.jsonl [--labels A,B] [--max-regress PCT]
import { readFileSync } from 'node:fs';
import { argv, exit } from 'node:process';

import { compare, parseJsonl, regressions } from './bench-lib.mjs';

const args = argv.slice(2);
let labels = ['before', 'after'];
const li = args.indexOf('--labels');
if (li >= 0) {
  labels = (args[li + 1] ?? '').split(',');
  args.splice(li, 2);
}
let maxRegress = null;
const ri = args.indexOf('--max-regress');
if (ri >= 0) {
  maxRegress = Number(args[ri + 1]);
  args.splice(ri, 2);
}
if (args.length !== 2 || labels.length !== 2 || Number.isNaN(maxRegress)) {
  console.error('usage: node scripts/bench-compare.mjs BEFORE.jsonl AFTER.jsonl [--labels A,B] [--max-regress PCT]');
  exit(2);
}
const [a, b] = args.map((f) => parseJsonl(readFileSync(f, 'utf8')));
const { text, mismatches, missing } = compare(a, b, labels);
process.stdout.write(text);
let slow = [];
if (maxRegress !== null) {
  slow = regressions(a, b, maxRegress);
  for (const s of slow) {
    console.log(`REGRESSION ${s.file}: ${s.before.toFixed(1)} → ${s.after.toFixed(1)} ms (+${s.pct.toFixed(0)} % > ${maxRegress} %)`);
  }
}
exit(mismatches || missing || slow.length ? 1 : 0);
