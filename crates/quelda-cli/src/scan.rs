//! `quelda scan`: reads the policy and the input, then calls the engine.
//! Every failure here becomes a verdict (`POLICY.INVALID`, `ENGINE.READ`),
//! never a crash: callers always get JSON and exit 2 (fail-closed).

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use quelda_core::policy::PolicyError;
use quelda_core::source::FileSource;
use quelda_core::{Policy, ReadError, Source, Verdict};
use sha2::{Digest, Sha256};

use crate::args::{Input, PolicySource, Scan};

/// Policy files are small; a larger one is a mistake (wrong path).
pub const MAX_POLICY_BYTES: u64 = 1 << 20;

/// Runs one scan of `input`.
pub fn run(scan: &Scan, input: &Input, stdin: &mut dyn Read) -> Verdict {
    let policy = policy(scan);
    // The input is read even when the policy is invalid, for `stats.bytes`
    // (and so a writer to our stdin is not cut off).
    let cap = policy.as_ref().map_or(0, |p| p.limits().max_file_bytes);
    let input = load(input, cap, stdin);
    match policy {
        Ok(p) => input.scan(&p),
        Err(e) => quelda_core::policy_error(&e, input.len()),
    }
}

/// Scans `input` with a policy already read, and hashes it when asked
/// (`None`: not asked, or the bytes were not kept or could not be read).
pub fn run_with(
    input: &Input,
    policy: &Policy,
    hash: bool,
    stdin: &mut dyn Read,
) -> (Verdict, Option<String>) {
    let input = load(input, policy.limits().max_file_bytes, stdin);
    let verdict = input.scan(policy);
    let sha256 = if hash { input.sha256() } else { None };
    (verdict, sha256)
}

fn load(input: &Input, cap: u64, stdin: &mut dyn Read) -> Loaded {
    match input {
        Input::Stdin => read_stream(stdin, cap, "stdin"),
        Input::Path(path) => open(path, cap),
    }
}

/// The policy with the command-line overrides applied.
pub fn policy(scan: &Scan) -> Result<Policy, PolicyError> {
    let mut policy = match &scan.policy {
        None => Policy::default(),
        Some(PolicySource::Json(json)) => Policy::from_json(json)?,
        Some(PolicySource::File(path)) => Policy::from_json(&read_policy_file(path)?)?,
    };
    if let Some(preset) = scan.preset {
        policy.preset = Some(preset);
    }
    if scan.stop_on_first {
        policy.stop_on_first = Some(true);
    }
    Ok(policy)
}

fn read_policy_file(path: &Path) -> Result<String, PolicyError> {
    let fail = |e: &dyn std::fmt::Display| {
        PolicyError(format!("cannot read policy file {}: {e}", path.display()))
    };
    let file = File::open(path).map_err(|e| fail(&e))?;
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| fail(&e))?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(fail(&format_args!("larger than {MAX_POLICY_BYTES} bytes")));
    }
    String::from_utf8(bytes).map_err(|_| fail(&"not UTF-8"))
}

/// The input, ready for the engine.
enum Loaded {
    /// A regular file, read on demand (`pread`).
    File(FileSource),
    /// A stream (stdin, pipe, device) read into memory.
    Bytes(Vec<u8>),
    /// A stream longer than `max_file_bytes`: only its length was kept.
    Oversized(u64),
    /// Cannot be read: the message for `ENGINE.READ`.
    Failed(String),
}

impl Loaded {
    fn len(&self) -> u64 {
        match self {
            Loaded::File(f) => f.len(),
            Loaded::Bytes(b) => b.len() as u64,
            Loaded::Oversized(n) => *n,
            Loaded::Failed(_) => 0,
        }
    }

    fn scan(&self, policy: &Policy) -> Verdict {
        match self {
            Loaded::File(f) => quelda_core::scan_source(f, policy),
            Loaded::Bytes(b) => quelda_core::scan(b, policy),
            Loaded::Oversized(len) => quelda_core::scan_source(&SizeOnly(*len), policy),
            Loaded::Failed(msg) => quelda_core::read_error(msg, policy),
        }
    }

    /// Lowercase hex SHA-256 of the whole input, read through the same open
    /// file as the scan.
    fn sha256(&self) -> Option<String> {
        let mut h = Sha256::new();
        match self {
            Loaded::Bytes(b) => h.update(b),
            Loaded::File(f) => {
                let mut buf = vec![0u8; HASH_CHUNK];
                let mut offset = 0;
                while offset < f.len() {
                    let n = (f.len() - offset).min(HASH_CHUNK as u64) as usize;
                    let chunk = buf.get_mut(..n)?;
                    f.read_at(offset, chunk).ok()?;
                    h.update(&*chunk);
                    offset += n as u64;
                }
            }
            Loaded::Oversized(_) | Loaded::Failed(_) => return None,
        }
        Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }
}

const HASH_CHUNK: usize = 1 << 20;

fn open(path: &Path, cap: u64) -> Loaded {
    let name = path.display().to_string();
    let fail = |e: std::io::Error| Loaded::Failed(format!("cannot open {name}: {e}"));
    match std::fs::metadata(path) {
        Err(e) => fail(e),
        Ok(m) if m.is_dir() => Loaded::Failed(format!("cannot open {name}: is a directory")),
        Ok(m) if m.is_file() => FileSource::open(path).map_or_else(fail, Loaded::File),
        // Pipes, process substitution, devices: no usable length.
        Ok(_) => match File::open(path) {
            Ok(mut f) => read_stream(&mut f, cap, &name),
            Err(e) => fail(e),
        },
    }
}

/// Reads a stream to the end, keeping at most `cap` bytes; beyond that only
/// counts (memory stays bounded; the engine reports `LIMIT.FILE_BYTES`).
fn read_stream(r: &mut dyn Read, cap: u64, name: &str) -> Loaded {
    let mut kept = Vec::new();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = buf.get(..n).unwrap_or_default();
                total = total.saturating_add(n as u64);
                if total <= cap {
                    kept.extend_from_slice(chunk);
                } else if !kept.is_empty() {
                    kept = Vec::new();
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Loaded::Failed(format!("cannot read {name}: {e}")),
        }
    }
    if total > cap {
        Loaded::Oversized(total)
    } else {
        Loaded::Bytes(kept)
    }
}

/// A stream that was too large to keep. The engine checks the size before
/// reading any byte, so `read_at` is never called; if it were, the verdict
/// would be `ERROR` anyway.
struct SizeOnly(u64);

impl Source for SizeOnly {
    fn len(&self) -> u64 {
        self.0
    }

    fn read_at(&self, _: u64, _: &mut [u8]) -> Result<(), ReadError> {
        Err(ReadError(
            "input not kept: larger than limits.max_file_bytes".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quelda_core::policy::Preset;
    use quelda_core::verdict::Status;
    use std::io::Cursor;

    const MINIMAL: &[u8] = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n";

    fn scan_of(input: Input) -> Scan {
        Scan {
            inputs: vec![input],
            policy: None,
            preset: None,
            stop_on_first: false,
            format: None,
            all: false,
            absolute: false,
            hash: true,
            jobs: None,
        }
    }

    /// `run` on the scan's one input.
    fn run1(scan: &Scan, stdin: &mut dyn Read) -> Verdict {
        run(scan, &scan.inputs[0], stdin)
    }

    fn tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("quelda-cli-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn strip_time(v: &Verdict) -> String {
        let mut v = v.clone();
        v.stats.duration_ms = 0;
        v.to_json()
    }

    #[test]
    fn stdin_file_and_lib_agree() {
        let path = tmp("minimal.pdf", MINIMAL);
        let lib = quelda_core::scan(MINIMAL, &Policy::default());
        let from_file = run1(&scan_of(Input::Path(path)), &mut Cursor::new(Vec::new()));
        let from_stdin = run1(&scan_of(Input::Stdin), &mut Cursor::new(MINIMAL.to_vec()));
        assert_eq!(strip_time(&from_file), strip_time(&lib));
        assert_eq!(strip_time(&from_stdin), strip_time(&lib));
    }

    #[test]
    fn overrides_apply_to_the_policy() {
        let mut s = scan_of(Input::Stdin);
        s.policy = Some(PolicySource::Json(r#"{"preset":"permissive"}"#.into()));
        s.preset = Some(Preset::Strict);
        s.stop_on_first = true;
        let p = policy(&s).unwrap();
        assert_eq!(p.preset, Some(Preset::Strict));
        assert_eq!(p.stop_on_first, Some(true));
        let v = run1(&s, &mut Cursor::new(MINIMAL.to_vec()));
        assert_eq!(v.policy.preset, Some(Preset::Strict));
        assert!(v.policy.stop_on_first);
        // Without flags the policy is used as written.
        s.preset = None;
        s.stop_on_first = false;
        assert_eq!(
            policy(&s).unwrap(),
            Policy::from_json(r#"{"preset":"permissive"}"#).unwrap()
        );
    }

    #[test]
    fn bad_policies_are_policy_invalid_with_input_size() {
        let missing = std::env::temp_dir().join("quelda-no-such-policy.json");
        let big = tmp("big.json", &vec![b' '; MAX_POLICY_BYTES as usize + 1]);
        let latin1 = tmp("latin1.json", b"{\"x\":\"\xff\"}");
        let broken = tmp("broken.json", b"{\"preset\":");
        for (src, needle) in [
            (PolicySource::File(missing), "cannot read policy file"),
            (PolicySource::File(big), "larger than"),
            (PolicySource::File(latin1), "not UTF-8"),
            (PolicySource::File(broken), "invalid policy"),
            (PolicySource::Json("[]".into()), "invalid policy"),
        ] {
            let mut s = scan_of(Input::Stdin);
            s.policy = Some(src);
            s.preset = Some(Preset::Strict); // does not rescue a bad policy
            let v = run1(&s, &mut Cursor::new(MINIMAL.to_vec()));
            assert_eq!(v.status, Status::Error);
            assert_eq!(v.errors[0].code, "POLICY.INVALID");
            assert!(
                v.errors[0].message.contains(needle),
                "{}",
                v.errors[0].message
            );
            assert_eq!(v.stats.bytes, MINIMAL.len() as u64);
        }
        // A policy of exactly the maximum size is read.
        let mut max = vec![b' '; MAX_POLICY_BYTES as usize - 2];
        max.splice(0..0, *b"{}");
        let mut s = scan_of(Input::Stdin);
        s.policy = Some(PolicySource::File(tmp("max.json", &max)));
        assert!(policy(&s).is_ok());
    }

    #[test]
    fn unreadable_input_is_engine_read() {
        let missing = std::env::temp_dir().join("quelda-no-such-input.pdf");
        let dir = std::env::temp_dir();
        for path in [missing, dir] {
            let v = run1(&scan_of(Input::Path(path)), &mut Cursor::new(Vec::new()));
            assert_eq!(v.status, Status::Error);
            assert_eq!(v.errors[0].code, "ENGINE.READ");
            assert!(v.errors[0].message.starts_with("cannot open"));
        }

        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        let v = run1(&scan_of(Input::Stdin), &mut Broken);
        assert_eq!(v.errors[0].code, "ENGINE.READ");
        assert_eq!(v.errors[0].message, "cannot read stdin: boom");
    }

    #[test]
    fn oversized_stdin_is_limit_file_bytes_without_keeping_it() {
        let mut s = scan_of(Input::Stdin);
        s.policy = Some(PolicySource::Json(
            r#"{"limits":{"max_file_bytes":100}}"#.into(),
        ));
        let input = vec![b'x'; 200_000];
        let v = run1(&s, &mut Cursor::new(input));
        assert_eq!(v.status, Status::Error);
        assert_eq!(v.errors[0].code, "LIMIT.FILE_BYTES");
        assert_eq!(v.stats.bytes, 200_000);
        // Exactly at the limit: scanned.
        let v = run1(&s, &mut Cursor::new(vec![b'x'; 100]));
        assert_ne!(v.errors.first().map(|e| e.code), Some("LIMIT.FILE_BYTES"));
    }

    #[test]
    fn read_stream_keeps_up_to_cap() {
        let data = vec![7u8; 150_000];
        match read_stream(&mut Cursor::new(&data), 150_000, "s") {
            Loaded::Bytes(b) => assert_eq!(b, data),
            _ => panic!("expected bytes"),
        }
        assert!(matches!(
            read_stream(&mut Cursor::new(&data), 149_999, "s"),
            Loaded::Oversized(150_000)
        ));
        assert!(matches!(
            read_stream(&mut Cursor::new(&data), 0, "s"),
            Loaded::Oversized(150_000)
        ));
        assert!(
            matches!(read_stream(&mut Cursor::new(b""), 0, "s"), Loaded::Bytes(b) if b.is_empty())
        );
    }

    #[test]
    fn run_with_hashes_what_it_scanned() {
        let path = tmp("hash.pdf", MINIMAL);
        let p = Policy::default();
        let want: String = Sha256::digest(MINIMAL)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let empty = &mut Cursor::new(Vec::new());
        let (v, h) = run_with(&Input::Path(path.clone()), &p, true, empty);
        assert_eq!(h.as_deref(), Some(want.as_str()));
        assert_eq!(strip_time(&v), strip_time(&quelda_core::scan(MINIMAL, &p)));
        assert_eq!(
            run_with(&Input::Path(path.clone()), &p, false, empty).1,
            None
        );
        let stdin = &mut Cursor::new(MINIMAL.to_vec());
        assert_eq!(run_with(&Input::Stdin, &p, true, stdin).1, Some(want));
        // Empty file: the hash of nothing.
        let (_, h) = run_with(&Input::Path(tmp("empty.pdf", b"")), &p, true, empty);
        assert_eq!(
            h.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        // Larger than one read chunk.
        let big = vec![b'a'; HASH_CHUNK * 2 + 3];
        let (_, h) = run_with(&Input::Path(tmp("big.bin", &big)), &p, true, empty);
        let want: String = Sha256::digest(&big)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(h, Some(want));
        // Unreadable or not kept: no hash.
        let missing = std::env::temp_dir().join("quelda-no-such-hash.pdf");
        assert_eq!(run_with(&Input::Path(missing), &p, true, empty).1, None);
        let small = Policy::from_json(r#"{"limits":{"max_file_bytes":4}}"#).unwrap();
        let stdin = &mut Cursor::new(MINIMAL.to_vec());
        assert_eq!(run_with(&Input::Stdin, &small, true, stdin).1, None);
    }

    #[test]
    fn size_only_never_reads() {
        assert!(SizeOnly(5).read_at(0, &mut [0; 1]).is_err());
        assert_eq!(SizeOnly(5).len(), 5);
    }

    #[cfg(unix)]
    #[test]
    fn non_regular_files_are_read_as_streams() {
        // /dev/null: a character device with no data.
        let v = run1(
            &scan_of(Input::Path("/dev/null".into())),
            &mut Cursor::new(Vec::new()),
        );
        assert_eq!(v.stats.bytes, 0);
        assert!(!v.valid);
        assert_eq!(
            strip_time(&v),
            strip_time(&quelda_core::scan(b"", &Policy::default()))
        );
    }
}
