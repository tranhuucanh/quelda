# quelda

quelda is a PDF security scanner. You give it one PDF and a policy, and it returns a verdict:
the file is either valid or invalid, with a reason for each rule it violates. It never renders
or previews the file. Its main job is to block files that attack server PDF pipelines
(Ghostscript, ImageMagick): PostScript/EPS disguised as PDF, embedded PostScript, JavaScript,
Launch actions, and malformed structure.

The core engine is written in Rust and ships in two forms:

- a WebAssembly build, published to npm as `quelda`, for early checks in the browser;
- a native CLI, `quelda`, for backends written in any language.

> **Status:** early development, not usable yet.

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

| Path | Contents |
|---|---|
| `crates/quelda-core` | Engine: parser, filters, facts, rules, policy, verdict |
| `crates/quelda-wasm` | WebAssembly binding (thin wrapper) |
| `crates/quelda-cli` | `quelda` CLI (thin wrapper) |
| `crates/quelda-testkit` | Dev-only: deterministic PDF builder and fixture generator |
| `packages/quelda-js` | npm package `quelda` |
| `schemas/` | JSON Schemas for policy and verdict |
| `fuzz/` | cargo-fuzz targets |
| `docs/ADDING_A_RULE.md` | Checklist for adding a rule |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
