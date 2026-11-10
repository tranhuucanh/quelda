#!/usr/bin/env bash
# Throughput gate (plan Step 16, ADR #29): benches BASE (a git ref, default
# origin/main) and the working tree on the same machine, then fails when a
# verdict differs or a file got more than MAX_REGRESS % (default 15) slower.
# RAM gate (Phase B): the working tree scans opaque-200m through a `Source`
# (`quelda-bench --source`); peak RSS above MAX_RSS_MB (default 64) fails.
# Native only; heavy files from gen-heavy (a subset that runs in minutes).
#
# Usage: scripts/bench-gate.sh [BASE_REF]
# Env:   MAX_REGRESS (percent), BENCH_RUNS (default 5), MAX_RSS_MB
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
base_ref="${1:-origin/main}"
max_regress="${MAX_REGRESS:-15}"
max_rss="${MAX_RSS_MB:-64}"
runs="${BENCH_RUNS:-5}"
out="$root/target/bench/gate"
work="$(mktemp -d)"
cleanup() {
  git -C "$root" worktree remove --force "$work/base" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

names=(opaque-200m fake-keywords-50m deep-long ops-2m flate-pages-5000 objstm-big revisions-1000 type4-annots)
mkdir -p "$out"

cargo build --manifest-path "$root/Cargo.toml" --release -p quelda-eval --bin quelda-bench
cargo run --manifest-path "$root/Cargo.toml" --release -p quelda-testkit --bin gen-heavy -- "${names[@]}"

git -C "$root" worktree add --detach "$work/base" "$base_ref" >/dev/null
CARGO_TARGET_DIR="$root/target/bench-base" cargo build \
  --manifest-path "$work/base/Cargo.toml" --release -p quelda-eval --bin quelda-bench

files=()
for n in "${names[@]}"; do files+=("$root/target/bench/heavy/$n.pdf"); done

"$root/target/bench-base/release/quelda-bench" --runs "$runs" --out "$out/base.jsonl" "${files[@]}" >/dev/null
"$root/target/release/quelda-bench" --runs "$runs" --out "$out/head.jsonl" "${files[@]}" >/dev/null

node "$root/scripts/bench-compare.mjs" "$out/base.jsonl" "$out/head.jsonl" \
  --labels base,head --max-regress "$max_regress"

"$root/target/release/quelda-bench" --source --runs 1 --out "$out/source.jsonl" \
  "$root/target/bench/heavy/opaque-200m.pdf" >/dev/null
node -e '
const [file, max] = process.argv.slice(1);
const r = JSON.parse(require("fs").readFileSync(file, "utf8").trim());
console.log(`RAM gate: ${r.file} via Source: RSS ${r.rss_peak_mb} MiB (max ${max}), ${r.status}`);
if (!(r.rss_peak_mb <= Number(max)) || r.status !== "PASS") process.exit(1);
' "$out/source.jsonl" "$max_rss"
