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
| `docs/cli.md` | CLI guide: install, options, exit codes, policy, backend examples |
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
