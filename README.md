# quelda

quelda checks **PDF and Adobe Illustrator (`.ai`) files** for attacks, and runs **both on the
client and on the server**, with the same engine, the same rules and the same verdict:

| | Client (browser) | Server (backend) |
|---|---|---|
| **Form** | WebAssembly package on npm: [`quelda`](https://www.npmjs.com/package/quelda) | `quelda` CLI, a single static binary ([docs/cli.md](docs/cli.md)) |
| **Runs** | In a Web Worker, in the user's browser | macOS and Linux (x64, arm64), Docker, any backend language |
| **Use it to** | Refuse a bad file instantly, before it is uploaded | Block a bad file before it reaches Ghostscript, ImageMagick, a print RIP or a thumbnailer |
| **Works with** | Vite, webpack, esbuild, plain `<script type="module">`, CDN | Python, Ruby, Node.js, Go, PHP, Java, … |

It stops PostScript/EPS disguised as PDF, embedded PostScript, JavaScript, Launch actions,
compression bombs and tampered structure, and says which rule each file breaks.

## What quelda checks

**40 rules in 11 categories**, plus 12 engine safeguards that refuse to judge what cannot be
fully inspected. Full list with explanations: [docs/rules.md](docs/rules.md).

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

How strict it is depends on the [policy](docs/policy.md): three presets (`strict`, `balanced`,
`permissive`), then per-category and per-rule changes. A policy adjusts a preset; every rule
always runs.

## Speed and memory

Scan time and peak memory of the CLI on an Apple M2 Pro (files over 256 MiB need
`limits.max_file_bytes` raised):

| File | Size | Time | Peak memory |
|---|---:|---:|---:|
| Real-world brochure | 54 MB | 0.02 s | 3 MB |
| Images only | 50 MB | 0.02 s | 3 MB |
| Images only | 200 MB | 0.09 s | 3 MB |
| Images only | 1 GB | 0.44 s | 3 MB |

A file is heavy because of its structure, not its size: many objects, deep nesting, page
content that must be decompressed. quelda handles files far heavier than real documents:

| Heavy file | Size | Time | Peak memory |
|---|---:|---:|---:|
| 900,000 objects | 62 MB | 1.5 s | 443 MB |
| 505,000 objects in 5,000 compressed object streams | 10 MB | 0.84 s | 333 MB |
| 10,000 objects nested 120 levels deep | 18 MB | 0.55 s | 218 MB |
| 200,000 objects full of `#xx` escapes | 33 MB | 0.44 s | 164 MB |
| 999 incremental updates, 100,000 objects | 7 MB | 0.17 s | 57 MB |
| 4 page streams, 480 MiB once decompressed | 53 MB | 3.0 s | 290 MB |
| Arrays nested 100,000 levels deep (parser crash attack) | 0.2 MB | < 0.01 s | 2 MB |

## Install

**macOS or Linux, with Homebrew:**

```bash
brew install tranhuucanh/quelda/quelda
```

**Linux server** (any distribution, x64 or arm64; one static binary, no dependencies):

```bash
curl -fsSL "https://github.com/tranhuucanh/quelda/releases/latest/download/quelda-$(uname -m)-unknown-linux-musl.tar.gz" \
  | sudo tar -xz -C /usr/local/bin quelda
```

In a Docker image (ECS, Kubernetes, Cloud Run, …), pinning a version, checking the download, and
building from source: [docs/cli.md](docs/cli.md#install). Every release ships `SHA256SUMS` and
build provenance attestations.

## Quick start

```bash
quelda scan upload.pdf                          # JSON verdict on stdout
quelda scan upload.pdf --preset strict --format text
quelda rules --format text                      # every rule and its default action
```

Exit code `0` means valid; `1` rejected; `2` could not be inspected (invalid); `64` usage
error. **Treat anything other than `0` as invalid.** From a backend, call it with an argument
array (no shell) and a timeout: see the examples for
[Python, Ruby, Node.js, Go, PHP and Java](docs/cli.md#call-it-from-your-backend).

## In the browser

The same engine, compiled to WebAssembly, is on npm as
[**`quelda`**](https://www.npmjs.com/package/quelda): it scans a `File` in a Web Worker, without
uploading it and without blocking the page, and gives the same verdict as the CLI. Use it to
tell users right away that a file will be refused. Install, framework and CDN examples:
[the npm package's README](packages/quelda-js/README.md).

A browser check is a convenience, not a security boundary: always scan again on the server.

## Supported files

quelda identifies a file by its content, not by its extension.

- **PDF** and **modern Adobe Illustrator `.ai` files** (Illustrator 9 and later, which are PDF
  files with extra Illustrator data) are scanned.
- **PostScript, EPS and legacy `.ai` files** (Illustrator 8 and earlier, which are PostScript)
  are **always rejected** with `FILETYPE.POSTSCRIPT_MAGIC`. This is a locked rule. PostScript is
  a full programming language, so a static scan cannot prove it safe, and it is the main way
  attackers reach Ghostscript. If you must accept EPS, handle it outside quelda: use its
  embedded preview image, or convert it to PDF in a locked-down sandbox and scan the result.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p quelda-core --target wasm32-unknown-unknown --profile release-wasm
cargo deny check licenses
```

Test PDFs are generated, not committed. Generate them before running tests that need fixtures:

```bash
cargo run -p quelda-testkit --bin gen-fixtures   # writes tests/fixtures/ and tests/conformance/
```

npm package (`packages/quelda-js`, Node ≥ 20):

```bash
scripts/wasm-build.sh                               # WASM engine → target/wasm-pkg
cargo run -p quelda-wasm --example wasm_golden      # native verdicts the package must match
cd packages/quelda-js && npm ci && npm test
npm run test:examples   # Vite, webpack, esbuild, no bundler, import map, CDN in headless Chrome
```

CLI as released (static Linux binary in containers, caller examples in each language's image,
the install instructions of docs/cli.md; needs Docker and Node ≥ 20):

```bash
cargo run -p quelda-wasm --example wasm_golden      # native verdicts every binary must match
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release -p quelda-cli --target x86_64-unknown-linux-musl
node scripts/cli-dist-test.mjs --bin target/x86_64-unknown-linux-musl/release/quelda --docker linux/amd64
node scripts/docs-examples-test.mjs --bin target/x86_64-unknown-linux-musl/release/quelda --docker linux/amd64
```

Releases: `scripts/bump-version.sh X.Y.Z` (or `X.Y.Z-rc.N`) sets the one version everywhere;
merge to `main`, then push the tag `vX.Y.Z`. `.github/workflows/release.yml` builds and tests
the binaries, publishes the GitHub Release, the npm package and (final releases) the Homebrew
formula.

| Path | Contents |
|---|---|
| `crates/quelda-core` | Engine: parser, filters, facts, rules, policy, verdict |
| `crates/quelda-wasm` | WebAssembly binding (thin wrapper) |
| `crates/quelda-cli` | `quelda` CLI (thin wrapper) |
| `crates/quelda-testkit` | Dev-only: deterministic PDF builder and fixture generator |
| `packages/quelda-js` | npm package `quelda` |
| `schemas/` | JSON Schemas for policy, verdict and rule list |
| `fuzz/` | cargo-fuzz targets |
| `docs/cli.md` | CLI guide: install, options, exit codes, verdict, backend examples |
| `docs/policy.md` | Policies: how they work, presets, custom policies, limits, engine errors |
| `docs/rules.md` | Every rule: what it catches, action per preset |
| `docs/examples/cli/` | Backend caller examples (tested) |
| `docs/ADDING_A_RULE.md` | Checklist for adding a rule |
| `packaging/homebrew/` | Homebrew formula template |

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
