//! Benchmark records (plan Step 16 Phase 0): one JSON line per file, the same
//! shape for the native bench (`quelda-bench`) and the WASM one
//! (`scripts/wasm-bench.mjs`), so `scripts/bench-compare.mjs` can put any two
//! runs side by side.
//!
//! The OS-specific measuring (rusage, the counting allocator, one child
//! process per file) lives in the `quelda-bench` binary; this module holds
//! the parts that can be tested.

use std::fmt::Write as _;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Default bench policy: `balanced` with `max_file_bytes` raised so files
/// over 256 MiB are scanned instead of rejected up front.
pub const DEFAULT_POLICY: &str = r#"{"limits":{"max_file_bytes":4294967296}}"#;

/// Verdict without `stats.duration_ms`, keys sorted (serde_json's default
/// map), so native and WASM verdicts of the same file compare equal.
pub fn canonical_verdict(json: &str) -> String {
    match serde_json::from_str::<Value>(json) {
        Ok(mut v) => {
            if let Some(stats) = v.get_mut("stats").and_then(Value::as_object_mut) {
                stats.remove("duration_ms");
            }
            v.to_string()
        }
        Err(_) => json.to_string(),
    }
}

/// First 16 hex digits of the SHA-256 of [`canonical_verdict`].
pub fn digest(verdict_json: &str) -> String {
    let h = Sha256::digest(canonical_verdict(verdict_json).as_bytes());
    h.iter().take(8).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Median of a non-empty sample (mean of the middle two for even lengths).
pub fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    match v.len() {
        0 => 0.0,
        n if n % 2 == 1 => v[n / 2],
        n => (v[n / 2 - 1] + v[n / 2]) / 2.0,
    }
}

/// What one child process measured for one file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Measure {
    pub bytes: u64,
    /// Wall time of each scan.
    pub ms: Vec<f64>,
    /// user + sys CPU over all scans, divided by the number of scans.
    pub cpu_ms: f64,
    /// Process peak resident set (includes the input buffer).
    pub rss_peak: u64,
    /// Peak heap allocated by the scans on top of what was live before
    /// (the input buffer is not counted).
    pub heap_peak: u64,
    pub verdict: String,
}

const MIB: f64 = 1048576.0;

impl Measure {
    /// The JSON line of this measure; `file` is the display name.
    pub fn record(&self, engine: &str, file: &str) -> Value {
        let v: Value = serde_json::from_str(&self.verdict).unwrap_or(Value::Null);
        let med = median(&self.ms);
        json!({
            "engine": engine,
            "file": file,
            "bytes": self.bytes,
            "runs": self.ms.len(),
            "ms_median": round1(med),
            "ms_min": round1(self.ms.iter().copied().fold(f64::INFINITY, f64::min)),
            "mb_s": if med > 0.0 { round1(self.bytes as f64 / MIB / (med / 1000.0)) } else { 0.0 },
            "cpu_ms": round1(self.cpu_ms),
            "rss_peak_mb": round1(self.rss_peak as f64 / MIB),
            "heap_peak_mb": round1(self.heap_peak as f64 / MIB),
            "decoded_bytes": v["stats"]["decoded_bytes"].as_u64().unwrap_or(0),
            "status": v["status"].as_str().unwrap_or("INVALID_VERDICT"),
            "digest": digest(&self.verdict),
        })
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Markdown table of records (native or WASM), plus a total row.
pub fn table(records: &[Value]) -> String {
    let mut s = String::from(
        "| file | MiB | ms (median) | MB/s | CPU ms | RSS peak MiB | heap/WASM MiB | decoded MiB | status |\n|---|---:|---:|---:|---:|---:|---:|---:|---|\n",
    );
    let (mut bytes, mut ms, mut cpu, mut rss, mut heap, mut decoded) =
        (0u64, 0f64, 0f64, 0f64, 0f64, 0u64);
    for r in records {
        let mem = r
            .get("heap_peak_mb")
            .or_else(|| r.get("wasm_mem_mb"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let b = r["bytes"].as_u64().unwrap_or(0);
        let d = r["decoded_bytes"].as_u64().unwrap_or(0);
        let _ = writeln!(
            s,
            "| {} | {:.1} | {} | {} | {} | {} | {:.1} | {:.1} | {} |",
            r["file"].as_str().unwrap_or("?"),
            b as f64 / MIB,
            r["ms_median"],
            r["mb_s"],
            r["cpu_ms"],
            r["rss_peak_mb"],
            mem,
            d as f64 / MIB,
            r["status"].as_str().unwrap_or("?"),
        );
        bytes += b;
        decoded += d;
        ms += r["ms_median"].as_f64().unwrap_or(0.0);
        cpu += r["cpu_ms"].as_f64().unwrap_or(0.0);
        rss = rss.max(r["rss_peak_mb"].as_f64().unwrap_or(0.0));
        heap = heap.max(mem);
    }
    if records.len() > 1 {
        let mbs = if ms > 0.0 {
            bytes as f64 / MIB / (ms / 1000.0)
        } else {
            0.0
        };
        let _ = writeln!(
            s,
            "| **total ({} files)** | {:.1} | {:.1} | {:.1} | {:.1} | max {:.1} | max {:.1} | {:.1} | |",
            records.len(),
            bytes as f64 / MIB,
            ms,
            mbs,
            cpu,
            rss,
            heap,
            decoded as f64 / MIB,
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_drops_duration_and_sorts_keys() {
        let a = r#"{"valid":true,"stats":{"duration_ms":5,"bytes":3},"status":"PASS"}"#;
        let b = r#"{"status":"PASS","stats":{"bytes":3,"duration_ms":99},"valid":true}"#;
        assert_eq!(canonical_verdict(a), canonical_verdict(b));
        assert_eq!(
            canonical_verdict(a),
            r#"{"stats":{"bytes":3},"status":"PASS","valid":true}"#
        );
        assert_eq!(digest(a), digest(b));
        assert_eq!(digest(a).len(), 16);
        assert_ne!(digest(a), digest(r#"{"status":"REJECT"}"#));
        // Not JSON: kept as-is.
        assert_eq!(canonical_verdict("oops"), "oops");
    }

    #[test]
    fn medians() {
        assert_eq!(median(&[]), 0.0);
        assert_eq!(median(&[3.0]), 3.0);
        assert_eq!(median(&[5.0, 1.0, 3.0]), 3.0);
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), 2.5);
    }

    #[test]
    fn record_fields() {
        let verdict = quelda_core::scan_json(b"%PDF-1.7\n%%EOF\n", "{}");
        let m = Measure {
            bytes: 2 * 1048576,
            ms: vec![400.0, 1000.0, 500.0],
            cpu_ms: 480.0,
            rss_peak: 30 * 1048576,
            heap_peak: 1048576 / 2,
            verdict: verdict.clone(),
        };
        let r = m.record("native", "a.pdf");
        assert_eq!(r["engine"], "native");
        assert_eq!(r["runs"], 3);
        assert_eq!(r["ms_median"], 500.0);
        assert_eq!(r["ms_min"], 400.0);
        assert_eq!(r["mb_s"], 4.0);
        assert_eq!(r["rss_peak_mb"], 30.0);
        assert_eq!(r["heap_peak_mb"], 0.5);
        assert_eq!(r["digest"], digest(&verdict));
        assert!(r["status"].is_string());
    }

    #[test]
    fn table_rows_and_total() {
        let rec = |file: &str, ms: f64, rss: f64| {
            json!({"file": file, "bytes": 1048576, "ms_median": ms, "mb_s": 1.0, "cpu_ms": ms,
                   "rss_peak_mb": rss, "heap_peak_mb": 2.0, "decoded_bytes": 0, "status": "PASS"})
        };
        let t = table(&[rec("a", 500.0, 10.0), rec("b", 1500.0, 20.0)]);
        assert!(t.contains("| a | 1.0 | 500.0 | 1.0 | 500.0 | 10.0 | 2.0 | 0.0 | PASS |"));
        assert!(
            t.contains(
                "| **total (2 files)** | 2.0 | 2000.0 | 1.0 | 2000.0 | max 20.0 | max 2.0 | 0.0 | |"
            ),
            "{t}"
        );
        assert!(!table(&[rec("a", 1.0, 1.0)]).contains("total"));
    }
}
