#!/usr/bin/env bash
# Builds the WASM package (design §8.2, plan Step 11):
#   cargo (release-wasm, wasm32) → wasm-bindgen --target web → wasm-opt -Oz
# then checks the size budget (scripts/wasm-size.mjs).
#
# Usage: scripts/wasm-build.sh [out_dir]      (default: target/wasm-pkg)
# Output: <out_dir>/quelda.js, quelda.d.ts, quelda_bg.wasm, size.json
#
# Tools (versions are checked):
#   wasm-bindgen  = the `wasm-bindgen` crate version in crates/quelda-wasm/Cargo.toml
#                   (cargo install wasm-bindgen-cli --version <v> --locked)
#   wasm-opt      binaryen ≥ 116; override with WASM_OPT=/path/to/wasm-opt
#   node          ≥ 18 (size check)
# Set QUELDA_SKIP_BUDGET=1 to measure without failing on the budget.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/target/wasm-pkg}"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
wasm_opt="${WASM_OPT:-wasm-opt}"

want="$(sed -n 's/^wasm-bindgen = "=\([0-9.]*\)".*/\1/p' "$root/crates/quelda-wasm/Cargo.toml")"
have="$(wasm-bindgen --version | awk '{print $2}')"
if [[ -z "$want" || "$want" != "$have" ]]; then
  echo "error: wasm-bindgen CLI is '$have', crate pins '$want'" >&2
  echo "       cargo install wasm-bindgen-cli --version $want --locked" >&2
  exit 1
fi
command -v "$wasm_opt" >/dev/null || {
  echo "error: wasm-opt not found (binaryen release or WASM_OPT=...)" >&2
  exit 1
}

cargo build --manifest-path "$root/Cargo.toml" -p quelda-wasm \
  --target wasm32-unknown-unknown --profile release-wasm

mkdir -p "$out"
# The glue is ESM; lets plain Node import it (scripts/wasm-smoke.mjs).
# Step 12's npm package supplies its own package.json.
printf '{ "type": "module", "private": true }\n' > "$out/package.json"
wasm-bindgen --target web --out-dir "$out" --out-name quelda \
  "$target_dir/wasm32-unknown-unknown/release-wasm/quelda_wasm.wasm"

# Features rustc's wasm32 target enables by default; wasm-opt must accept them.
"$wasm_opt" -Oz --strip-debug --strip-producers \
  --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  --enable-mutable-globals --enable-multivalue --enable-reference-types \
  "$out/quelda_bg.wasm" -o "$out/quelda_bg.wasm"

budget_args=()
[[ "${QUELDA_SKIP_BUDGET:-}" == 1 ]] && budget_args+=(--no-fail)
node "$root/scripts/wasm-size.mjs" "$out/quelda_bg.wasm" \
  --budget "$root/crates/quelda-wasm/size-budget.json" \
  --json "$out/size.json" "${budget_args[@]+"${budget_args[@]}"}"
