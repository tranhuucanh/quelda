# quelda

Checks **PDF and Adobe Illustrator (`.ai`) files** for attacks, right in the browser, before
they are uploaded. It never renders or previews the file.

- **WebAssembly in a Web Worker**: a scan never blocks the page, and the file never leaves
  the user's machine.
- **Any frontend**: Vite, webpack, esbuild, plain HTML with `<script type="module">`, or
  straight from a CDN with no build step; any framework (React, Vue, Svelte, …) on top.
  [Every setup below](#works-with) is tested in a real browser.
- **40 rules, fail-closed**: anything it cannot fully inspect is invalid.
- **Fast and light**: files are read in place, never loaded whole; a 1 GB file of images scans
  in under a second with a few MB of engine memory ([numbers](#speed-and-memory)).

> **The browser is not a security boundary.** A check in the browser gives users instant
> feedback and saves a pointless upload, but anyone can skip it and send a file straight to
> your server. **Always scan again on the server** before a file reaches Ghostscript,
> ImageMagick or any other PDF processor. quelda has a server version with the same engine and
> the same verdicts: see the [project page](https://github.com/tranhuucanh/quelda).

## Documentation

| Guide | Read it to |
|---|---|
| [**Rules**](https://github.com/tranhuucanh/quelda/blob/main/docs/rules.md) | See every rule: what it catches, and whether it blocks, warns or is off in each preset |
| [**Policies**](https://github.com/tranhuucanh/quelda/blob/main/docs/policy.md) | Choose a preset, write your own policy, relax or tighten one rule, raise limits |
| [**Server version**](https://github.com/tranhuucanh/quelda) | Scan the same files again on your server, with the same verdicts |

## Install

```bash
npm install quelda
```

Or no install at all: load it from a CDN ([below](#no-build-step-cdn)).

## Quick start

```ts
import { createScanner } from 'quelda';

const scanner = await createScanner();   // starts a worker, loads the engine once
const verdict = await scanner.scan(file, { preset: 'balanced' });

if (verdict.valid) {
  upload(file);
} else {
  showError(verdict.violations.map((v) => v.message).join('\n'));
}
```

Treat **anything but `verdict.valid === true` as invalid**. A verdict looks like this
(shortened):

```json
{
  "valid": false,
  "status": "REJECT",
  "violations": [
    {
      "rule_id": "ACTIVE.JAVASCRIPT",
      "action": "block",
      "message": "Document contains JavaScript"
    }
  ],
  "warnings": [],
  "errors": []
}
```

`status` is `PASS` (valid), `REJECT` (a rule set to `block` fired) or `ERROR` (the file could
not be fully inspected: damaged, over a limit, or the scan failed). Full format:
[`verdict.schema.json`](https://github.com/tranhuucanh/quelda/blob/main/schemas/verdict.schema.json).

### A file input

```html
<input type="file" id="upload" accept=".pdf,.ai,application/pdf" />
<p id="result"></p>

<script type="module">
  import { createScanner } from 'quelda';

  const scanner = await createScanner();

  document.getElementById('upload').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    const verdict = await scanner.scan(file);
    document.getElementById('result').textContent = verdict.valid
      ? 'OK, uploading…'
      : `Refused: ${[...verdict.violations, ...verdict.errors].map((r) => r.message).join('; ')}`;
  });
</script>
```

(With a bundler, put the script in your app code. Without one, see [Works with](#works-with).)

### React

One scanner for the component's lifetime; it loads the engine once and scans files one after
another.

```tsx
import { useEffect, useRef, useState, type ChangeEvent } from 'react';
import { createScanner, type Scanner, type Verdict } from 'quelda';

export function PdfUpload({ onAccepted }: { onAccepted: (file: File) => void }) {
  const scanner = useRef<Promise<Scanner> | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);

  useEffect(() => {
    const started = createScanner();
    scanner.current = started;
    return () => {
      started.then((s) => s.terminate(), () => {});
    };
  }, []);

  async function onChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !scanner.current) return;
    const v = await (await scanner.current).scan(file, { preset: 'balanced' });
    setVerdict(v);
    if (v.valid) onAccepted(file);
  }

  return (
    <>
      <input type="file" accept=".pdf,.ai,application/pdf" onChange={onChange} />
      {verdict && !verdict.valid && (
        <ul>
          {[...verdict.violations, ...verdict.errors].map((r, i) => (
            <li key={i}>{r.message}</li>
          ))}
        </ul>
      )}
    </>
  );
}
```

Vue, Svelte, Angular and others work the same way: create the scanner once (on mount), call
`scan(file)` on change, `terminate()` on unmount.

### No build step (CDN)

```html
<script type="module">
  import { createScanner } from 'https://cdn.jsdelivr.net/npm/quelda/dist/index.js';

  const scanner = await createScanner();
  // … same as above
</script>
```

Public npm CDNs such as [jsDelivr](https://www.jsdelivr.com/package/npm/quelda) and
[unpkg](https://unpkg.com/quelda/) serve every package published to npm automatically: nothing
to set up, the URL works as soon as a version is on npm. Pin a version in production
(`…/npm/quelda@X.Y.Z/dist/index.js`, the version from `npm view quelda version`) so a new
release cannot change your verdicts unannounced. The package starts its worker from the CDN by
itself. To serve the files from your own server instead, see [No bundler](#works-with).

## Works with

The package is plain ESM. It ships the worker (`dist/worker.js`) and the engine
(`dist/wasm/quelda_bg.wasm`, a separate file, not inlined) next to the API and finds them with
`new URL(..., import.meta.url)`. Each setup below is built and run in headless Chrome on every
release (clean PDF must pass, PostScript must be rejected, through the real worker and engine):

| Setup | What to do |
|---|---|
| **Vite** | `optimizeDeps: { exclude: ['quelda'] }` and `worker: { format: 'es' }` in `vite.config.js` (below) |
| **webpack 5** | nothing |
| **esbuild** | bundle as usual (`--format=esm`), then copy `node_modules/quelda/dist/` next to the bundle |
| **No bundler** | copy `node_modules/quelda/dist/` to your site (e.g. `/quelda/`) and `import { createScanner } from './quelda/index.js'` |
| **Import map** | as above, plus `<script type="importmap">{ "imports": { "quelda": "./quelda/index.js" } }</script>` so `import … from 'quelda'` works |
| **CDN** | [see above](#no-build-step-cdn) |

```js
// vite.config.js: pre-bundling breaks new URL(..., import.meta.url) in dev mode
export default { optimizeDeps: { exclude: ['quelda'] }, worker: { format: 'es' } };
```

Any other bundler: if it does not copy `worker.js` and the `.wasm` file by itself, copy
`dist/` next to your bundle as with esbuild, or tell the package where they are:

```ts
const scanner = await createScanner({
  wasm: '/static/quelda_bg.wasm',
  worker: () => new Worker('/static/quelda/worker.js', { type: 'module' }),
});
```

Working projects: [Vite](https://github.com/tranhuucanh/quelda/tree/main/packages/quelda-js/examples/vite),
[webpack](https://github.com/tranhuucanh/quelda/tree/main/packages/quelda-js/examples/webpack).

Serve `.wasm` files as `application/wasm` for the fastest load.

**Content Security Policy:** WebAssembly needs `script-src 'wasm-unsafe-eval'`. The worker
needs `worker-src 'self'` (or wherever you serve it); from a CDN, `worker-src blob:`, and the
CDN in `script-src` and `connect-src`.

**Browsers:** module workers and WebAssembly SIMD: Chrome/Edge 91+, Firefox 114+, Safari 16.4+.

## What quelda checks

**40 rules in 11 categories**, plus 12 engine safeguards that refuse to judge what cannot be
fully inspected. Full list with explanations: [docs/rules.md](https://github.com/tranhuucanh/quelda/blob/main/docs/rules.md).

| Category | Rules | Catches, for example |
|---|---|---|
| `filetype` | 4 | PostScript/EPS/legacy `.ai` renamed to `.pdf` (even behind a BOM or a printer header), SVG/HTML/MVG/ZIP/executables disguised as PDF, PDF + ZIP/HTML polyglots |
| `postscript` | 3 | PostScript code inside a PDF: the `PS` operator, PostScript XObjects, non-standard Type 4 functions |
| `active_content` | 5 | JavaScript (anywhere, any encoding), Launch actions, actions run on open or on events |
| `embedded` | 4 | Attached files, file attachment annotations, portfolios, Flash/3D/multimedia |
| `external` | 5 | Links, remote documents (SMB credential leaks), form submission to a URL, network file references |
| `forms` | 2 | AcroForm and XFA forms |
| `xml` | 1 | DOCTYPE/ENTITY in XMP or XFA (XXE, billion laughs), in UTF-8/16/32 |
| `structure` | 9 | Tampered or ambiguous structure: hidden revisions, conflicting objects, mismatched xref, page-tree loops, data after `%%EOF`, multiple headers |
| `encryption` | 1 | Encrypted files whose content cannot be inspected |
| `codecs` | 3 | JBIG2 (FORCEDENTRY), JPEG 2000, Type 1 fonts |
| `resource` | 3 | Pixel bombs, gigantic or broken pages, page-count bombs |

**Tested on thousands of cases**: attack variants of every rule, clean look-alikes that must not
trigger a rule, damaged and disguised files, and real-world PDFs. The test files are not
published, because antivirus software may flag them; if you need them, email the maintainer
(tranhuucanh39@gmail.com).

How strict it is depends on the [policy](https://github.com/tranhuucanh/quelda/blob/main/docs/policy.md): three presets (`strict`, `balanced`,
`permissive`), then per-category and per-rule changes. A policy adjusts a preset; every rule
always runs.

## Speed and memory

Scan time and engine memory of the WebAssembly engine on an Apple M2 Pro (Node 22, a `File`
read in place; files over 256 MiB need `limits.max_file_bytes` raised):

| File | Size | Time | Engine memory |
|---|---:|---:|---:|
| Real-world brochure | 54 MB | 0.06 s | 2.4 MB |
| Images only | 50 MB | 0.04 s | 2.4 MB |
| Images only | 200 MB | 0.14 s | 2.4 MB |
| Images only | 1 GB | 0.8 s | 2.4 MB |

A file is heavy because of its structure, not its size: many objects, deep nesting, page
content that must be decompressed. quelda handles files far heavier than real documents:

| Heavy file | Size | Time | Engine memory |
|---|---:|---:|---:|
| 900,000 objects | 62 MB | 1.9 s | 284 MB |
| 505,000 objects in 5,000 compressed object streams | 10 MB | 1.1 s | 246 MB |
| 10,000 objects nested 120 levels deep | 18 MB | 0.73 s | 126 MB |
| 200,000 objects full of `#xx` escapes | 33 MB | 0.55 s | 112 MB |
| 999 incremental updates, 100,000 objects | 7 MB | 0.20 s | 34 MB |
| 4 page streams, 480 MiB once decompressed | 53 MB | 3.7 s | 271 MB |
| Arrays nested 100,000 levels deep (parser crash attack) | 0.2 MB | < 0.01 s | 1.6 MB |

## Supported files

Files are identified by content, not by extension. **PDF** and **modern `.ai` files**
(Illustrator 9 and later, which are PDF inside) are scanned. **PostScript, EPS and legacy `.ai`**
(Illustrator 8 and earlier) are always rejected with `FILETYPE.POSTSCRIPT_MAGIC`, a locked rule:
PostScript is a programming language and cannot be proven safe by a scan.

## API

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
  …). Only the bytes of a view are scanned.
- `policy`: a policy object, or policy JSON text. Default `{}` = the `balanced` preset. See
  [Policy](#policy).
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
| `ENGINE.READ` | engine | the `File` / `Blob` could not be read while scanning (e.g. it changed or was deleted) |
| `POLICY.INVALID` | package | the policy object cannot be turned into JSON (cycle, `BigInt`, …) |

The engine has no clock in WebAssembly, so the package fills `stats.duration_ms` with the time
the engine call took, measured in the worker (whole milliseconds; queueing and file reading are
not included).

Scans run **one at a time**, in call order (WebAssembly is single-threaded). The timeout of
a scan starts when the scan starts, not when it is queued. A timeout, an abort of a running
scan, or a crash kills the worker; the next scan starts a fresh one. A worker whose engine
threw is never reused, nor one whose WebAssembly memory grew past 64 MiB (it never
shrinks; a fresh worker returns it to the system).

### `scanner.listRules(options?)`

Every rule the engine knows (`id`, `category`, `severity`, `default_action`, `locked`,
`stage`, `since`, `message`, `description`; see
[`rules.schema.json`](https://github.com/tranhuucanh/quelda/blob/main/schemas/rules.schema.json)),
sorted by `id`. Handy for a settings screen. Rejects with a `QueldaError`.
`scanner.engineVersion` is the engine version.

### `scanner.terminate()`

Kills the worker. Pending scans resolve with `ENGINE.ABORTED`; later calls fail. Safe to call
twice.

## Policy

**Every rule always runs**: a policy starts from a preset and changes the action (`block`,
`warn`, `off`) of the categories and rules you name; everything else keeps its preset action.
Full guide (presets, recipes, limits, engine errors):
[policy.md](https://github.com/tranhuucanh/quelda/blob/main/docs/policy.md).

Three levels; the most specific wins: **preset → categories → rules**
([`policy.schema.json`](https://github.com/tranhuucanh/quelda/blob/main/schemas/policy.schema.json)).

```ts
await scanner.scan(file, {
  preset: 'balanced',                                   // strict | balanced | permissive
  categories: { external: 'warn', codecs: 'off' },      // block | warn | off
  rules: { 'ACTIVE.OPEN_ACTION': 'off' },
  limits: { max_file_bytes: 50 * 1024 * 1024 },
});
```

- **`strict`**: rejects anything unusual, including links, forms and damaged structure.
- **`balanced`** (default): blocks everything that can execute, carry a payload or exhaust a
  server; only warns about links, forms, structure repairs and risky codecs.
- **`permissive`**: files from sources you mostly trust; most rules only warn.

Defaults are strict on purpose. If a rule blocks files your users legitimately upload, relax
**that rule** rather than the whole category or preset. For example, `EMBED.EMBEDDED_FILE`
blocks files that carry attachments (some e-books and reports do):

```ts
{ rules: { 'EMBED.EMBEDDED_FILE': 'warn' } }   // still reported in verdict.warnings
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
scan of the older engine `ERROR`. Either use the same quelda version in the browser and on the
server, or drop the rules the engine does not know before scanning:

```ts
const known = new Set((await scanner.listRules()).map((r) => r.id));
const policy = { ...serverPolicy, rules: Object.fromEntries(
  Object.entries(serverPolicy.rules ?? {}).filter(([id]) => known.has(id))) };
```

(The server must keep using the full policy.)

## Memory and transfer

Prefer passing the `File` / `Blob` itself (limit: `limits.max_file_bytes`, default 256 MiB).

- `File` / `Blob` (recommended): **never loaded whole.** The worker reads it in place with
  `FileReaderSync`: one pass in 1 MiB blocks, then only the parts the engine must parse or
  decode (image, font and other opaque data are not read again). The engine's memory stays
  a few MiB whatever the file size, plus the data it must decompress. Your object is
  untouched; the file must not change until the scan resolves (if it does: `ENGINE.READ`).
- `ArrayBuffer` / typed array: **copied when `scan` is called**, then copied whole into
  the engine's memory; changing your buffer afterwards does not affect the scan.
- `transfer: true`: hands your `ArrayBuffer` (or the buffer of a typed array that spans it
  whole) to the worker without a copy. **Your buffer is detached (length 0) as soon as `scan`
  is called.** A view of part of a buffer is still copied.

## Node

The package targets browsers. Node (≥ 20) has no Web Workers, so `createScanner()` does not
work there out of the box; on a server, use the server version from the
[project page](https://github.com/tranhuucanh/quelda).

## License

[MIT](https://github.com/tranhuucanh/quelda/blob/main/LICENSE).

Security issues: please report them privately (see
[SECURITY.md](https://github.com/tranhuucanh/quelda/blob/main/SECURITY.md)).
