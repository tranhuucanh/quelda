// Shared helpers of the Step 16 benchmarks: verdict digest, the Markdown
// tables, and comparing two runs. A run is a JSONL file with one record per
// file (crates/quelda-eval/src/bench.rs writes the native ones,
// scripts/wasm-bench.mjs the WASM ones; same fields, except the memory
// column: `heap_peak_mb` native, `wasm_mem_mb` WASM).
// Tests: node --test scripts/bench-lib.test.mjs
import { createHash } from 'node:crypto';
import { readdirSync, statSync } from 'node:fs';
import { basename, join, relative } from 'node:path';

const MIB = 1048576;

/** Default bench policy: balanced, files over 256 MiB still scanned (= bench.rs). */
export const DEFAULT_POLICY = '{"limits":{"max_file_bytes":4294967296}}';

/** JSON with object keys sorted, compact: serde_json's `Value::to_string`. */
export function sortedJson(v) {
  if (Array.isArray(v)) return `[${v.map(sortedJson).join(',')}]`;
  if (v && typeof v === 'object') {
    const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((k) => `${JSON.stringify(k)}:${sortedJson(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

/** Verdict without `stats.duration_ms`, keys sorted (= bench.rs `canonical_verdict`). */
export function canonicalVerdict(json) {
  let v;
  try {
    v = JSON.parse(json);
  } catch {
    return json;
  }
  if (v && v.stats && typeof v.stats === 'object') delete v.stats.duration_ms;
  return sortedJson(v);
}

/** First 16 hex digits of the SHA-256 of the canonical verdict (= bench.rs `digest`). */
export function digest(json) {
  return createHash('sha256').update(canonicalVerdict(json)).digest('hex').slice(0, 16);
}

export function median(xs) {
  const v = [...xs].sort((a, b) => a - b);
  if (v.length === 0) return 0;
  const m = v.length >> 1;
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
}

const round1 = (x) => Math.round(x * 10) / 10;

/** The JSONL record of one WASM measure (fields as bench.rs `Measure::record`). */
export function record({ file, bytes, ms, cpuMs, rssPeak, wasmMem, verdict }) {
  let v = null;
  try {
    v = JSON.parse(verdict);
  } catch {}
  const med = median(ms);
  return {
    engine: 'wasm-node',
    file,
    bytes,
    runs: ms.length,
    ms_median: round1(med),
    ms_min: round1(Math.min(...ms)),
    mb_s: med > 0 ? round1(bytes / MIB / (med / 1000)) : 0,
    cpu_ms: round1(cpuMs),
    rss_peak_mb: round1(rssPeak / MIB),
    wasm_mem_mb: round1(wasmMem / MIB),
    decoded_bytes: v?.stats?.decoded_bytes ?? 0,
    status: v?.status ?? 'INVALID_VERDICT',
    digest: digest(verdict),
  };
}

/** Every regular file under the paths (directories walked, hidden skipped), with display names. */
export function listFiles(paths) {
  const out = [];
  const walk = (dir, acc) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name.startsWith('.')) continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p, acc);
      else if (e.isFile()) acc.push(p);
    }
    return acc;
  };
  for (const p of paths) {
    if (!statSync(p).isDirectory()) {
      out.push({ path: p, name: basename(p) });
      continue;
    }
    // Sorted full paths per argument, like the native `quelda_eval::walk`.
    const files = walk(p, []).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const f of files) out.push({ path: f, name: join(basename(p), relative(p, f)).split('\\').join('/') });
  }
  return out;
}

const mem = (r) => r.heap_peak_mb ?? r.wasm_mem_mb ?? 0;

/** Markdown table of records, plus a total row (= bench.rs `table`). */
export function table(records) {
  const rows = [
    '| file | MiB | ms (median) | MB/s | CPU ms | RSS peak MiB | heap/WASM MiB | decoded MiB | status |',
    '|---|---:|---:|---:|---:|---:|---:|---:|---|',
  ];
  let bytes = 0, ms = 0, cpu = 0, rss = 0, heap = 0, decoded = 0;
  for (const r of records) {
    rows.push(
      `| ${r.file} | ${(r.bytes / MIB).toFixed(1)} | ${r.ms_median.toFixed(1)} | ${r.mb_s.toFixed(1)} | ${r.cpu_ms.toFixed(1)} | ${r.rss_peak_mb.toFixed(1)} | ${mem(r).toFixed(1)} | ${(r.decoded_bytes / MIB).toFixed(1)} | ${r.status} |`,
    );
    bytes += r.bytes;
    decoded += r.decoded_bytes;
    ms += r.ms_median;
    cpu += r.cpu_ms;
    rss = Math.max(rss, r.rss_peak_mb);
    heap = Math.max(heap, mem(r));
  }
  if (records.length > 1) {
    const mbs = ms > 0 ? bytes / MIB / (ms / 1000) : 0;
    rows.push(
      `| **total (${records.length} files)** | ${(bytes / MIB).toFixed(1)} | ${ms.toFixed(1)} | ${mbs.toFixed(1)} | ${cpu.toFixed(1)} | max ${rss.toFixed(1)} | max ${heap.toFixed(1)} | ${(decoded / MIB).toFixed(1)} | |`,
    );
  }
  return rows.join('\n') + '\n';
}

/** Parses JSONL text into records. */
export function parseJsonl(text) {
  return text
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l));
}

/**
 * Side-by-side table of two runs (before A, after B) joined by file name:
 * time, speed-up, peak RSS, peak heap/WASM memory, and whether the verdicts
 * are identical (digest). Returns { text, mismatches, missing }.
 */
export function compare(a, b, labels = ['A', 'B']) {
  const byFile = new Map(b.map((r) => [r.file, r]));
  const [la, lb] = labels;
  const rows = [
    `| file | ${la} ms | ${lb} ms | ×speed | ${la} RSS | ${lb} RSS | ${la} mem | ${lb} mem | verdict |`,
    '|---|---:|---:|---:|---:|---:|---:|---:|---|',
  ];
  let mismatches = 0, missing = 0, ta = 0, tb = 0;
  for (const ra of a) {
    const rb = byFile.get(ra.file);
    if (!rb) {
      missing++;
      rows.push(`| ${ra.file} | ${ra.ms_median.toFixed(1)} | — | | ${ra.rss_peak_mb.toFixed(1)} | — | ${mem(ra).toFixed(1)} | — | missing |`);
      continue;
    }
    byFile.delete(ra.file);
    const same = ra.digest === rb.digest;
    if (!same) mismatches++;
    ta += ra.ms_median;
    tb += rb.ms_median;
    const x = rb.ms_median > 0 ? (ra.ms_median / rb.ms_median).toFixed(2) : '∞';
    rows.push(
      `| ${ra.file} | ${ra.ms_median.toFixed(1)} | ${rb.ms_median.toFixed(1)} | ${x} | ${ra.rss_peak_mb.toFixed(1)} | ${rb.rss_peak_mb.toFixed(1)} | ${mem(ra).toFixed(1)} | ${mem(rb).toFixed(1)} | ${same ? 'same' : `**DIFF** ${ra.status}→${rb.status}`} |`,
    );
  }
  for (const rb of byFile.values()) {
    missing++;
    rows.push(`| ${rb.file} | — | ${rb.ms_median.toFixed(1)} | | — | ${rb.rss_peak_mb.toFixed(1)} | — | ${mem(rb).toFixed(1)} | missing |`);
  }
  if (tb > 0) rows.push(`| **total** | ${ta.toFixed(1)} | ${tb.toFixed(1)} | ${(ta / tb).toFixed(2)} | | | | | ${mismatches} diff, ${missing} missing |`);
  return { text: rows.join('\n') + '\n', mismatches, missing };
}
