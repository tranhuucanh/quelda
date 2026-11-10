#!/usr/bin/env node
// Builds examples/vite and examples/webpack against the *packed* package, the
// way a user would install it, and checks the bundles: the .wasm is emitted as
// a separate file identical to ours, the worker is a separate chunk, and each
// file references the next (page → worker → .wasm).
//
//   npm run build && npm run test:examples        (needs network on first run)
//   QUELDA_KEEP_EXAMPLES=1 …                       keep the temp dir to serve it
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';

const pkg = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
const fail = (msg) => {
  console.error(`build-examples: ${msg}`);
  process.exit(1);
};

const ourWasm = join(pkg, 'dist/wasm/quelda_bg.wasm');
if (!existsSync(ourWasm)) fail('dist/ missing: run `npm run build` first');

const app = (p) => readFileSync(join(pkg, 'examples', p), 'utf8');
if (app('vite/main.js') !== app('webpack/src/main.js')) fail('examples/vite/main.js and examples/webpack/src/main.js differ');

/**
 * Runs a bundled ES-module worker chunk in a Node worker thread (test/helpers/
 * node-worker-bootstrap.mjs, with fetch() reading file: URLs) and scans a clean
 * PDF and a PostScript file: proves the bundler's worker → .wasm URL works.
 */
async function smokeWorker(name, workerFile, root) {
  const w = new Worker(new URL('../test/helpers/node-worker-bootstrap.mjs', import.meta.url), {
    workerData: { entry: pathToFileURL(workerFile).href, fileFetch: true, fileRoot: root },
  });
  const replies = [];
  let wake;
  w.on('message', (m) => {
    replies.push(m);
    wake?.();
  });
  w.on('error', (e) => fail(`[${name}] bundled worker crashed: ${e.message}`));
  const next = async () => {
    const deadline = Date.now() + 20_000;
    while (replies.length === 0) {
      if (Date.now() > deadline) fail(`[${name}] bundled worker did not answer`);
      await new Promise((r) => {
        wake = r;
        setTimeout(r, 100);
      });
    }
    return replies.shift();
  };
  try {
    w.postMessage({ type: 'init' });
    const ready = await next();
    if (ready.type !== 'ready') fail(`[${name}] bundled worker: ${JSON.stringify(ready)}`);
    const pdf = new TextEncoder().encode('%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n');
    const ps = new TextEncoder().encode('%!PS-Adobe-3.0\nshowpage\n');
    for (const [id, bytes, want] of [[1, pdf, undefined], [2, ps, 'REJECT']]) {
      w.postMessage({ type: 'scan', id, bytes: bytes.buffer, policy: '{}' }, [bytes.buffer]);
      const r = await next();
      const status = r.type === 'scan' ? JSON.parse(r.verdict).status : r.type;
      if (r.type !== 'scan' || (want !== undefined && status !== want)) fail(`[${name}] bundled worker scan ${id}: ${status}`);
    }
    console.log(`[${name}] bundled worker loads its .wasm and scans (engine ${ready.version})`);
  } finally {
    await w.terminate();
  }
}

const tmp = mkdtempSync(join(tmpdir(), 'quelda-examples-'));
const listFiles = (dir) =>
  readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name));

try {
  const packed = JSON.parse(run(npm, ['pack', '--json', '--pack-destination', tmp], pkg))[0];
  const tarball = join(tmp, packed.filename);
  console.log(`packed ${packed.filename}: ${packed.files.length} files, ${packed.size} B`);

  const wasmBytes = readFileSync(ourWasm);
  for (const [name, outDir] of [
    ['vite', 'dist'],
    ['webpack', 'dist'],
  ]) {
    const src = join(pkg, 'examples', name);
    const dir = join(tmp, name);
    cpSync(src, dir, {
      recursive: true,
      filter: (p) => !['node_modules', 'dist'].includes(basename(p)),
    });
    // Install the tarball instead of the `file:../..` link.
    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    manifest.dependencies.quelda = `file:${tarball}`;
    writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest, null, 2));
    console.log(`[${name}] npm install`);
    run(npm, ['install', '--no-audit', '--no-fund', '--loglevel=error'], dir);
    console.log(`[${name}] build`);
    run(npm, ['run', 'build'], dir);

    const out = join(dir, outDir);
    const files = listFiles(out);
    const wasm = files.filter((f) => f.endsWith('.wasm'));
    if (wasm.length !== 1) fail(`[${name}] expected 1 .wasm in the bundle, found ${wasm.length}`);
    if (!readFileSync(wasm[0]).equals(wasmBytes)) fail(`[${name}] bundled .wasm differs from dist/wasm/quelda_bg.wasm`);
    const wasmName = basename(wasm[0]);
    const js = files.filter((f) => f.endsWith('.js'));
    const worker = js.filter((f) => readFileSync(f, 'utf8').includes(wasmName));
    if (worker.length !== 1) fail(`[${name}] expected 1 JS chunk referencing ${wasmName}, found ${worker.length}`);
    const workerName = basename(worker[0]);
    // Vite names the worker file; webpack loads chunk `<id>.main.js` by id (`__webpack_require__.u(<id>)`).
    const chunkId = /^(\d+)\./.exec(workerName)?.[1];
    const startsWorker = (code) =>
      /new Worker\(/.test(code) && (code.includes(workerName) || (chunkId !== undefined && code.includes(`.u(${chunkId})`)));
    const pages = js.filter((f) => f !== worker[0] && startsWorker(readFileSync(f, 'utf8')));
    if (pages.length === 0) fail(`[${name}] no JS chunk starts the worker ${workerName}`);
    const html = files.find((f) => f.endsWith('index.html'));
    if (html === undefined) fail(`[${name}] no index.html in the bundle`);
    if (/\bbase64,AGFzbQ/.test(files.filter((f) => f.endsWith('.js')).map((f) => readFileSync(f, 'utf8')).join('')))
      fail(`[${name}] the .wasm is inlined as base64`);
    if (name === 'vite') await smokeWorker(name, worker[0], out);
    console.log(`[${name}] OK: page ${basename(pages[0])} → worker ${workerName} → ${wasmName} (${wasmBytes.length} B)`);
    console.log(`[${name}]     serve: node ${join(pkg, 'examples/serve.mjs')} ${out}`);
  }
  console.log('build-examples: both examples built');
} finally {
  if (process.env.QUELDA_KEEP_EXAMPLES === '1') console.log(`kept ${tmp}`);
  else rmSync(tmp, { recursive: true, force: true });
}
