#!/usr/bin/env node
// Runs the *built* package (scripts/wasm-build.sh output: wasm-bindgen
// --target web + wasm-opt) in Node and checks every golden case
// (tests/wasm/golden.json, from `cargo run -p quelda-wasm --example wasm_golden`):
// the shipped .wasm must give the native lib's verdicts, `stats.duration_ms` aside.
//
//   node scripts/wasm-smoke.mjs [pkg_dir]        (default: target/wasm-pkg)
import { deepStrictEqual, strictEqual } from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { argv, exit } from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = resolve(argv[2] ?? join(root, 'target/wasm-pkg'));
const tests = join(root, 'tests');

const comparable = (json) => {
  const v = JSON.parse(json);
  delete v.stats.duration_ms;
  return v;
};

let golden;
try {
  golden = JSON.parse(readFileSync(join(tests, 'wasm/golden.json'), 'utf8'));
} catch (e) {
  console.error(`wasm-smoke: ${e.message}\nrun gen-fixtures and \`cargo run -p quelda-wasm --example wasm_golden\` first`);
  exit(2);
}

const mod = await import(pathToFileURL(join(pkg, 'quelda.js')).href);
mod.initSync({ module: readFileSync(join(pkg, 'quelda_bg.wasm')) });

strictEqual(mod.version(), golden.version, 'version()');
strictEqual(mod.list_rules(), golden.list_rules, 'list_rules()');
const files = new Map();
let failed = 0;
for (const c of golden.cases) {
  if (!files.has(c.file)) files.set(c.file, readFileSync(join(tests, 'fixtures', c.file)));
  const out = mod.scan(files.get(c.file), c.policy);
  try {
    deepStrictEqual(comparable(out), comparable(c.verdict));
  } catch {
    failed++;
    if (failed <= 5) console.error(`wasm-smoke: ${c.file} under ${c.policy}: verdict differs from native\n  wasm:   ${out}\n  native: ${c.verdict}`);
  }
}
console.log(`wasm-smoke: ${golden.cases.length - failed}/${golden.cases.length} cases match the native lib (${pkg})`);
exit(failed === 0 ? 0 : 1);
