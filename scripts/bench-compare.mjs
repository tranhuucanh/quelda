#!/usr/bin/env node
// Compares two benchmark runs (plan Step 16: before/after each phase, or
// native vs WASM): time, speed-up, peak RSS / memory, identical verdicts.
// Exit 1 when a verdict differs (the differential check) or a file is missing.
//
//   node scripts/bench-compare.mjs BEFORE.jsonl AFTER.jsonl [--labels A,B]
import { readFileSync } from 'node:fs';
import { argv, exit } from 'node:process';

import { compare, parseJsonl } from './bench-lib.mjs';

const args = argv.slice(2);
let labels = ['before', 'after'];
const li = args.indexOf('--labels');
if (li >= 0) {
  labels = (args[li + 1] ?? '').split(',');
  args.splice(li, 2);
}
if (args.length !== 2 || labels.length !== 2) {
  console.error('usage: node scripts/bench-compare.mjs BEFORE.jsonl AFTER.jsonl [--labels A,B]');
  exit(2);
}
const [a, b] = args.map((f) => parseJsonl(readFileSync(f, 'utf8')));
const { text, mismatches, missing } = compare(a, b, labels);
process.stdout.write(text);
exit(mismatches || missing ? 1 : 0);
