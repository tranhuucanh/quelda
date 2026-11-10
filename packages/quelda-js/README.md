# quelda

PDF security scanner for the browser. You give it one PDF and a policy; it returns a verdict:
valid or invalid, with the rules the file violates. It never renders or previews the file.

The engine is written in Rust and compiled to WebAssembly. It runs in a Web Worker, so a scan
does not block the page.

> **Status:** early development, not published yet.

> **The browser is not a security boundary.** A check in the browser is a convenience: it
> gives users fast feedback and saves an upload. Anyone can skip it or send a file straight
> to your server. **Always scan again on the server** with the same engine version (the
> `quelda` CLI, coming soon) before a file reaches Ghostscript, ImageMagick or any other PDF
> processor.

## Usage

```ts
import { createScanner } from 'quelda';

const scanner = await createScanner();             // starts a worker, loads the .wasm once
const verdict = await scanner.scan(file, { preset: 'strict' });
if (!verdict.valid) showReasons(verdict.violations);

const rules = await scanner.listRules();           // for a settings screen
scanner.terminate();                               // when you no longer need it
```

Treat **anything but `verdict.valid === true` as invalid**. `valid` is `true` exactly when
`status` is `"PASS"`.

### `createScanner(options?)`

Starts the worker and resolves once the engine is loaded. Rejects with a `QueldaError`
(`code`, `message`) if it cannot start (Web Workers unavailable, `.wasm` not found, CSP, …).

| Option | Default | |
|---|---|---|
| `timeoutMs` | `30000` | Per scan / `listRules` / worker start. `Infinity` disables it. |
| `wasm` | the bundled `.wasm` | A URL (string or `URL`, resolved against the page) or a compiled `WebAssembly.Module`. |
| `worker` | the bundled worker | Advanced: a function returning a `Worker` that runs `quelda/worker.js`. |

### `scanner.scan(input, policy?, options?)`

- `input`: `File`, `Blob`, `ArrayBuffer`, or any typed array / `DataView` (`Uint8Array`,
  Node `Buffer`, …). Only the bytes of a view are scanned.
- `policy`: a policy object, or policy JSON text (passed to the engine as is). Default `{}`
  = the `balanced` preset. See [Policy](#policy).
- `options.timeoutMs`: overrides the scanner's timeout for this scan.
- `options.signal`: an `AbortSignal`.
- `options.transfer`: see [Memory](#memory-and-transfer).

**`scan` never rejects.** Every failure becomes a verdict with `status: "ERROR"` and
`valid: false` (fail-closed):

| `errors[].code` | Made by | When |
|---|---|---|
| `LIMIT.*`, `ENGINE.*`, `POLICY.INVALID` | engine | a limit was exceeded, the file could not be inspected, the policy is invalid |
| `LIMIT.TIMEOUT` | package | the scan took longer than `timeoutMs`; the worker was killed |
| `ENGINE.ABORTED` | package | the `signal` fired, or `terminate()` was called |
| `ENGINE.WORKER` | package | the worker or the engine crashed, failed to load, or replied with something malformed |
| `ENGINE.INPUT` | package | the input is not a supported type, the file could not be read, or an option is invalid |
| `POLICY.INVALID` | package | the policy object cannot be turned into JSON (cycle, `BigInt`, …) |

Verdicts follow [`verdict.schema.json`](../../schemas/verdict.schema.json). The engine has no
clock in WebAssembly, so the package fills `stats.duration_ms` with the time the engine call
took, measured in the worker with `performance.now()` (whole milliseconds; queueing and file
reading are not included).

Scans run **one at a time**, in call order (WebAssembly is single-threaded). The timeout of
a scan starts when the scan starts, not when it is queued. A timeout, an abort of a running
scan, or a crash kills the worker; the next scan starts a fresh one. A worker whose engine
threw is never reused.

### `scanner.listRules(options?)`

Every rule the engine knows (`id`, `category`, `severity`, `default_action`, `locked`,
`stage`, `since`, `message`, `description`; see
[`rules.schema.json`](../../schemas/rules.schema.json)), sorted by `id`. Rejects with a
`QueldaError`. `scanner.engineVersion` is the engine version.

### `scanner.terminate()`

Kills the worker. Pending scans resolve with `ENGINE.ABORTED`; later calls fail. Safe to call
twice.

## Policy

Three levels; the most specific wins: **preset → categories → rules**
([`policy.schema.json`](../../schemas/policy.schema.json)).

```ts
await scanner.scan(file, {
  preset: 'balanced',                                   // strict | balanced | permissive
  categories: { external: 'warn', codecs: 'off' },      // block | warn | off
  rules: { 'ACTIVE.OPEN_ACTION': 'off' },
  limits: { max_file_bytes: 50 * 1024 * 1024 },
});
```

Defaults are strict on purpose (safety first). If a rule blocks files your users legitimately
upload, relax **that rule** rather than the whole category or preset. For example,
`ACTIVE.OPEN_ACTION` blocks files that do something when opened; many PDF tools add an
`/OpenAction` that only jumps to a page. After checking your own files, you can turn it into a
warning:

```ts
{ rules: { 'ACTIVE.OPEN_ACTION': 'warn' } }   // still reported in verdict.warnings
```

Locked rules (`locked: true` in `listRules()`: PostScript, Launch actions, files that are not
PDF, …) stay `block` whatever the policy says, unless the policy also sets
`unsafe_allow_unlock: true` (reported in `verdict.policy`; do not do this for untrusted files).

The engine parses the policy **strictly**: unknown fields, `null`, wrong types, unknown
categories and **rule IDs this engine version does not know** give an `ERROR` verdict
(`POLICY.INVALID`) instead of being ignored, because a silently ignored typo could switch a
rule off.

### Keep the browser and the server on the same rule set

A policy written for a newer engine (naming a rule an older engine does not have) makes every
scan of the older engine `ERROR`. Either ship the same quelda version in the browser and on
the server, or drop the rules the engine does not know before scanning:

```ts
const known = new Set((await scanner.listRules()).map((r) => r.id));
const policy = { ...serverPolicy, rules: Object.fromEntries(
  Object.entries(serverPolicy.rules ?? {}).filter(([id]) => known.has(id))) };
```

(The server must keep using the full policy.)

## Memory and transfer

The whole file is copied into the engine's memory (limit: `limits.max_file_bytes`, default
256 MiB).

- `File` / `Blob`: read when `scan` is called; your object is untouched.
- `ArrayBuffer` / typed array: **copied when `scan` is called**; changing your buffer
  afterwards does not affect the scan.
- `transfer: true`: hands your `ArrayBuffer` (or the buffer of a typed array that spans it
  whole) to the worker without a copy. **Your buffer is detached (length 0) as soon as `scan`
  is called.** A view of part of a buffer is still copied.

## Bundlers

The package is ESM and ships the worker (`dist/worker.js`) and the engine
(`dist/wasm/quelda_bg.wasm`, a separate file, not inlined) next to the API. It finds them with
`new URL(..., import.meta.url)`, which Vite and webpack 5 understand without plugins. Serve
`.wasm` files as `application/wasm` for the fastest load.

- **Vite**: exclude the package from dependency pre-bundling, which breaks
  `new URL(..., import.meta.url)` in dev mode, and build ES module workers:

  ```js
  // vite.config.js
  export default { optimizeDeps: { exclude: ['quelda'] }, worker: { format: 'es' } };
  ```

- **webpack 5**: no configuration needed.

Working examples: [`examples/vite`](examples/vite), [`examples/webpack`](examples/webpack).

**Content Security Policy:** WebAssembly needs `script-src 'wasm-unsafe-eval'`, and the worker
needs `worker-src 'self'` (or wherever you serve it).

**Browsers:** module workers and WebAssembly: Chrome/Edge 80+, Firefox 114+, Safari 15+.

## Node

Needs **Node ≥ 20**. Node has no Web Workers, so `createScanner()` does not work there out of
the box; on a server use the `quelda` CLI (coming soon). The package's own tests run the real
worker in Node through `worker_threads` (see `test/helpers/node-worker.ts`).

## Development

```bash
../../scripts/wasm-build.sh                         # engine → target/wasm-pkg (needs wasm-bindgen-cli, wasm-opt)
cargo run -p quelda-testkit --bin gen-fixtures      # test PDFs (repo root)
cargo run -p quelda-wasm --example wasm_golden      # native verdicts the package must match
npm ci
npm test            # build + tsc --noEmit + vitest (mock worker, real engine, schemas, pack)
npm run test:examples   # npm pack → install into the Vite and webpack examples → build both
```

## License

MIT OR Apache-2.0.
