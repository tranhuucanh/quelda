# fuzz

cargo-fuzz targets for `quelda-core`, added in Step 15. Requirement: no input may make the
engine panic, hang, or exceed its limits without returning `ERROR`.

| Target | What it runs |
| --- | --- |
| `lexer` | the lexer, `parse_object`, `parse_indirect_object`, the content-stream tokenizer |
| `structure` | the raw keyword scan and `Document::parse` (xref, trailers, object index) |
| `filters` | `filters::decode`; the first 4 bytes pick the filter chain and `/DecodeParms` |
| `scan` | `scan_json` with the 3 presets; the verdict must be JSON and an `ERROR` never `valid` |

Needs Rust nightly and cargo-fuzz (both outside the repo):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
```

Seed the corpus from the fixtures (`cargo run -p quelda-testkit --bin gen-fixtures` first):

```sh
cd fuzz
for t in lexer structure scan; do
  mkdir -p corpus/$t
  find ../tests/fixtures -type f -name '*.pdf' -size -1024k -exec cp {} corpus/$t/ \;
done
mkdir -p corpus/filters   # any bytes; the target makes its own chains
```

Run one target for 30 minutes on 2 cores, with memory and input-size limits, collecting every
crash, timeout and out-of-memory input instead of stopping at the first:

```sh
cargo +nightly fuzz run -s none -a scan -- \
  -fork=2 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
  -max_total_time=1800 -rss_limit_mb=1536 -max_len=1048576 -timeout=10
```

Findings land in `artifacts/<target>/`. Reproduce and shrink one with
`cargo +nightly fuzz run -s none -a <target> <file>` and `cargo +nightly fuzz tmin -s none -a <target> <file>`.

`fuzz/target/`, `fuzz/artifacts/` and `fuzz/corpus/` are gitignored: findings and corpora are
never committed.
