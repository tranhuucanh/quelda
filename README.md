# quelda

quelda is a PDF security scanner. You give it one PDF and a policy, and it returns a verdict:
the file is either valid or invalid, with a reason for each rule it violates. It never renders
or previews the file. Its main job is to block files that attack server PDF pipelines
(Ghostscript, ImageMagick): PostScript/EPS disguised as PDF, embedded PostScript, JavaScript,
Launch actions, and malformed structure.

The core engine is written in Rust and ships in two forms that give the same verdicts:

- a native CLI, `quelda`, for backends written in any language ([docs/cli.md](docs/cli.md));
- a WebAssembly build, published to npm as [`quelda`](packages/quelda-js/README.md), for early
  checks in the browser.

> **Status:** first release (0.x). The verdict format and rule IDs are stable; defaults may
> still be tuned. See the [changelog](CHANGELOG.md).

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

The engine safeguards stop compression bombs, absurd nesting, object floods, endless revision
chains and crafted overlapping objects, and reject damaged data that must be inspected: such a
file is `ERROR` (invalid), never silently passed.

How it looks at a file:

- **Content, not names.** A file is identified by its bytes; `invoice.pdf` that is really
  PostScript is rejected before anything else.
- **Everything, every time.** Every object of every revision is scanned, including old
  revisions, objects hidden from the cross-reference table and objects packed in compressed
  object streams. quelda never repairs a file and picks one interpretation: if any reader could
  see it, it is checked.
- **No obfuscation tricks.** Names (`/J#61vaScript`), strings (hex, UTF-16) and streams (Flate,
  LZW, ASCII85, ASCIIHex, RunLength, stacked) are decoded before any rule looks at them.
- **Fail-closed.** Anything it cannot parse, decode or read makes the file invalid.
- **Fast and light.** It reads only what it needs: on an Apple M2 Pro, a real 100 MB PDF takes
  0.07 s and 8 MB of memory, and a 1 GB PDF of images 0.5 s and 3 MB (with `max_file_bytes`
  raised). Our slowest test file, built with nearly a million objects, takes under 2 s.
- **Same verdict everywhere.** The CLI, the browser package and the Rust library run the same
  engine; every release is tested to give identical verdicts on hundreds of generated attack
  files and conformance cases.

How strict it is depends on the [policy](docs/policy.md): three presets (`strict`, `balanced`,
`permissive`), then per-category and per-rule changes. A policy adjusts a preset; every rule
always runs.

## Install

```bash
brew install tranhuucanh/quelda/quelda          # macOS (Apple Silicon), Linux
npm install quelda                              # browser / Node package
```

Static Linux binaries (x64, arm64) and the macOS binary are on
[GitHub Releases](https://github.com/tranhuucanh/quelda/releases/latest), with `SHA256SUMS`
and build provenance attestations. See [docs/cli.md](docs/cli.md#install) for `curl`, Docker
and source installs.

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

In the browser:

```ts
import { createScanner } from 'quelda';

const scanner = await createScanner();
const verdict = await scanner.scan(file, { preset: 'strict' });
if (!verdict.valid) showReasons(verdict.violations);
```

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

npm package (`packages/quelda-js`, Node ≥ 20; see its README):

```bash
scripts/wasm-build.sh                               # WASM engine → target/wasm-pkg
cargo run -p quelda-wasm --example wasm_golden      # native verdicts the package must match
cd packages/quelda-js && npm ci && npm test && npm run test:examples
```

CLI as released (static Linux binary in containers, caller examples in each language's image;
needs Docker and Node ≥ 20):

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

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
