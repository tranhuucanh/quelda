#!/usr/bin/env node
// Builds the npm package into dist/:
//   1. copies the wasm-bindgen output (scripts/wasm-build.sh at the repo root;
//      default target/wasm-pkg, or QUELDA_WASM_PKG) into src/wasm/ (gitignored);
//   2. tsc (src → dist);
//   3. copies the glue + .wasm into dist/wasm/ and the licenses next to package.json.
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkg = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(pkg, '../..');
const wasmPkg = resolve(process.env.QUELDA_WASM_PKG ?? join(root, 'target/wasm-pkg'));
const GLUE = ['quelda.js', 'quelda.d.ts', 'quelda_bg.wasm'];

for (const f of GLUE) {
  if (!existsSync(join(wasmPkg, f))) {
    console.error(`build: ${join(wasmPkg, f)} not found: run scripts/wasm-build.sh at the repo root first`);
    process.exit(1);
  }
}

const srcWasm = join(pkg, 'src/wasm');
rmSync(srcWasm, { recursive: true, force: true });
mkdirSync(srcWasm, { recursive: true });
for (const f of GLUE) copyFileSync(join(wasmPkg, f), join(srcWasm, f));

rmSync(join(pkg, 'dist'), { recursive: true, force: true });
execFileSync(process.execPath, [join(pkg, 'node_modules/typescript/bin/tsc'), '-p', join(pkg, 'tsconfig.json')], {
  stdio: 'inherit',
});

const distWasm = join(pkg, 'dist/wasm');
mkdirSync(distWasm, { recursive: true });
for (const f of GLUE) copyFileSync(join(srcWasm, f), join(distWasm, f));
for (const f of ['LICENSE']) copyFileSync(join(root, f), join(pkg, f));
console.log(`build: dist/ ready (engine from ${wasmPkg})`);
