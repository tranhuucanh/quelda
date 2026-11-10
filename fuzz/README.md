# fuzz

cargo-fuzz targets for `quelda-core`, added in Step 15. Requirement: no input may make the
engine panic, hang, or exceed its limits without returning `ERROR`.

`fuzz/target/`, `fuzz/artifacts/` and `fuzz/corpus/` are gitignored.
