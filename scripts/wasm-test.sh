#!/usr/bin/env bash
# All WASM checks of plan Step 11 (CI job `wasm` runs this):
#   1. native golden verdicts      (cargo run -p quelda-wasm --example wasm_golden)
#   2. wasm-bindgen-test on Node   (wasm32 build == native lib, duration_ms aside)
#   3. size-check script tests     (node --test scripts/wasm-size.test.mjs)
#   4. build + size budget         (scripts/wasm-build.sh)
#   5. built package on Node       (scripts/wasm-smoke.mjs)
# Needs fixtures (cargo run -p quelda-testkit --bin gen-fixtures), Node >= 20
# (Node 18 crashes in wasm-bindgen-test-runner), and the tools listed in
# scripts/wasm-build.sh.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ ! -f tests/fixtures/manifest.json ]]; then
  echo "error: tests/fixtures missing: run cargo run -p quelda-testkit --bin gen-fixtures" >&2
  exit 1
fi

cargo run -q -p quelda-wasm --example wasm_golden
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test -p quelda-wasm --target wasm32-unknown-unknown
node --test scripts/wasm-size.test.mjs
scripts/wasm-build.sh
node scripts/wasm-smoke.mjs
