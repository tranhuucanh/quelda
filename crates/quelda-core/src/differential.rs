//! Differential tests (plan Step 16 Phase B): the verdict through a
//! [`Source`] read on demand — with pages, blocks and windows down to a few
//! bytes, so every pattern and object straddles their edges — is the
//! verdict through the slice, byte for byte (`duration_ms` aside).

use std::cell::Cell;
use std::path::{Path, PathBuf};

use crate::parser::input::Tuning;
use crate::source::{ReadError, Source};
use crate::{Policy, scan, scan_source_json, scan_source_tuned};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests");

const TUNINGS: &[Tuning] = &[
    Tuning::DEFAULT,
    Tuning {
        page: 7,
        pages: 2,
        block: 13,
        window: 1,
    },
    Tuning {
        page: 64,
        pages: 3,
        block: 1,
        window: 5,
    },
    Tuning {
        page: 4096,
        pages: 1,
        block: 100_000,
        window: 64,
    },
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "pdf") {
            out.push(p);
        }
    }
}

fn fixtures() -> Vec<PathBuf> {
    let mut v = Vec::new();
    walk(&Path::new(FIXTURES).join("fixtures"), &mut v);
    v.sort();
    assert!(v.len() > 100, "run gen-fixtures first ({} files)", v.len());
    v
}

fn json(v: &crate::Verdict) -> String {
    let mut j: serde_json::Value = serde_json::from_str(&v.to_json()).unwrap();
    j["stats"]["duration_ms"] = 0.into();
    j.to_string()
}

fn presets() -> Vec<Policy> {
    ["strict", "balanced", "permissive"]
        .iter()
        .map(|p| Policy::from_json(&format!(r#"{{"preset": "{p}"}}"#)).unwrap())
        .collect()
}

fn check(name: &str, bytes: &[u8], policy: &Policy, tunings: &[Tuning]) {
    let want = json(&scan(bytes, policy));
    for &t in tunings {
        let got = json(&scan_source_tuned(&bytes, policy, t));
        assert_eq!(got, want, "{name} {t:?}");
    }
}

#[test]
fn every_fixture_every_preset() {
    let presets = presets();
    for path in fixtures() {
        let bytes = std::fs::read(&path).unwrap();
        let name = path.to_string_lossy();
        for p in &presets {
            check(&name, &bytes, p, TUNINGS);
        }
    }
}

#[test]
fn conformance_cases() {
    let dir = Path::new(FIXTURES).join("conformance");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let case: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(e.unwrap().path()).unwrap()).unwrap();
        let file = case["file"].as_str().unwrap();
        let bytes = std::fs::read(Path::new(FIXTURES).join("fixtures").join(file)).unwrap();
        let policy = match &case["policy"] {
            serde_json::Value::Null => "{}".to_string(),
            p => p.to_string(),
        };
        match Policy::from_json(&policy) {
            Ok(p) => check(file, &bytes, &p, TUNINGS),
            Err(_) => assert_eq!(
                scan_source_json(&bytes, &policy),
                crate::scan_json(&bytes, &policy),
                "{file}"
            ),
        }
        n += 1;
    }
    assert!(n > 20);
}

#[test]
fn heavy_kinds() {
    for h in quelda_testkit::heavy::small_catalog() {
        let bytes = quelda_testkit::heavy::build(h.kind);
        for p in presets() {
            check(h.name, &bytes, &p, TUNINGS);
        }
    }
}

/// Deterministic xorshift.
fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }
}

/// Every tuning from 1 byte up, on fixtures cut and spliced at random:
/// damaged input exercises the parser's error paths at window edges too.
#[test]
fn random_tunings_on_damaged_fixtures() {
    let files = fixtures();
    let policy = Policy::default();
    let mut next = rng(7);
    for i in 0..300 {
        let a = std::fs::read(&files[(next() % files.len() as u64) as usize]).unwrap();
        let b = std::fs::read(&files[(next() % files.len() as u64) as usize]).unwrap();
        let cut_a = (next() % (a.len() as u64 + 1)) as usize;
        let cut_b = (next() % (b.len() as u64 + 1)) as usize;
        let mut bytes = a[..cut_a].to_vec();
        bytes.extend_from_slice(&b[cut_b..]);
        let t = Tuning {
            page: 1 + (next() % 300) as usize,
            pages: 1 + (next() % 4) as usize,
            block: 1 + (next() % 500) as usize,
            window: 1 + (next() % 100) as usize,
        };
        check(&format!("case {i}"), &bytes, &policy, &[t]);
    }
}

/// Counts bytes read; fails the read that crosses `fail_at`.
struct Probe<'a> {
    bytes: &'a [u8],
    read: Cell<u64>,
    fail_at: Option<u64>,
}

impl Source for Probe<'_> {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let end = offset + buf.len() as u64;
        self.read.set(self.read.get() + buf.len() as u64);
        if self.fail_at.is_some_and(|f| offset <= f && f < end) {
            return Err(ReadError("disk on fire".to_string()));
        }
        self.bytes.read_at(offset, buf)
    }
}

#[test]
fn read_error_is_engine_read_error() {
    let bytes = quelda_testkit::heavy::build(quelda_testkit::heavy::Kind::FlatePages { pages: 3 });
    let mut next = rng(3);
    for k in 0..50 {
        let at = if k == 0 {
            0
        } else {
            next() % bytes.len() as u64
        };
        let probe = Probe {
            bytes: &bytes,
            read: Cell::new(0),
            fail_at: Some(at),
        };
        let v: serde_json::Value = serde_json::from_str(&scan_source_json(&probe, "{}")).unwrap();
        assert_eq!(v["status"], "ERROR", "fail at {at}");
        assert_eq!(v["valid"], false);
        let codes: Vec<_> = v["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["code"].as_str().unwrap().to_string())
            .collect();
        assert!(codes.contains(&"ENGINE.READ".to_string()), "{codes:?}");
    }
}

/// A source shorter than it claims: the short read is an error.
#[test]
fn short_source_is_engine_read_error() {
    struct Liar;
    impl Source for Liar {
        fn len(&self) -> u64 {
            1000
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            let pdf: &[u8] = b"%PDF-1.7\n";
            pdf.read_at(offset, buf)
        }
    }
    let v: serde_json::Value = serde_json::from_str(&scan_source_json(&Liar, "{}")).unwrap();
    assert_eq!(v["status"], "ERROR");
    assert_eq!(v["errors"][0]["code"], "ENGINE.READ");
    assert_eq!(v["stats"]["bytes"], 1000);
}

/// Opaque stream data is read once (the sequential pass), not again.
#[test]
fn opaque_data_is_read_once() {
    let bytes =
        quelda_testkit::heavy::build(quelda_testkit::heavy::Kind::Opaque { bytes: 8 << 20 });
    let probe = Probe {
        bytes: &bytes,
        read: Cell::new(0),
        fail_at: None,
    };
    let v: serde_json::Value = serde_json::from_str(&scan_source_json(&probe, "{}")).unwrap();
    assert_eq!(v["status"], "PASS");
    let read = probe.read.get();
    let len = bytes.len() as u64;
    assert!(read >= len, "{read}");
    assert!(read < len + (1 << 20), "read {read} of {len}");
}

#[test]
fn policy_errors_and_limits_same_as_slice() {
    let pdf: &[u8] = b"%PDF-1.7\n1 0 obj << >> endobj\n%%EOF\n";
    let v: serde_json::Value = serde_json::from_str(&scan_source_json(&pdf, "nope")).unwrap();
    assert_eq!(v["errors"][0]["code"], "POLICY.INVALID");
    assert_eq!(v["stats"]["bytes"], pdf.len());
    let small = Policy::from_json(r#"{"limits": {"max_file_bytes": 10}}"#).unwrap();
    check("too large", pdf, &small, TUNINGS);
}

#[test]
fn read_error_verdict() {
    let v: serde_json::Value =
        serde_json::from_str(&crate::read_error_json("no size", r#"{"preset":"strict"}"#)).unwrap();
    assert_eq!(v["status"], "ERROR");
    assert_eq!(v["errors"][0]["code"], "ENGINE.READ");
    assert_eq!(v["errors"][0]["message"], "no size");
    assert_eq!(v["policy"]["preset"], "strict");
    let v: serde_json::Value = serde_json::from_str(&crate::read_error_json("x", "[")).unwrap();
    assert_eq!(v["errors"][0]["code"], "POLICY.INVALID");
}
