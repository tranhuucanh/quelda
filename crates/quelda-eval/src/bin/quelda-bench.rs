//! `quelda-bench [--source] [--policy JSON] [--runs N] [--out FILE] PATH...`: native
//! benchmark (plan Step 16 Phase 0). Each file (directories are walked) is
//! scanned `--runs` times (default 3) in a child process of its own, so the
//! peak RSS is that file's. Writes one JSON line per file to `--out`
//! (default `target/bench/native.jsonl`, see `quelda_eval::bench`) and prints
//! a Markdown table. `--source` scans through `quelda_core::scan_source`
//! (the file read on demand, `engine` = `native-source`) instead of reading
//! it whole first.
//!
//! Peak heap comes from a counting global allocator; peak RSS and CPU time
//! from `getrusage`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use quelda_eval::bench::{self, Measure};
use serde_json::Value;

/// Counts live heap bytes and their high-water mark.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(n: usize) {
    let live = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: forwards to the system allocator unchanged; only counts bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            grew(new_size);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// (user + sys CPU ms, peak RSS bytes) of this process.
fn rusage() -> (f64, u64) {
    // SAFETY: `getrusage` only writes the struct we pass.
    let ru = unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
        ru
    };
    let ms = |t: libc::timeval| t.tv_sec as f64 * 1000.0 + t.tv_usec as f64 / 1000.0;
    // ru_maxrss: bytes on macOS, KiB on Linux.
    let rss = ru.ru_maxrss.max(0) as u64;
    let rss = if cfg!(target_os = "macos") {
        rss
    } else {
        rss * 1024
    };
    (ms(ru.ru_utime) + ms(ru.ru_stime), rss)
}

/// Child: scan one file `runs` times, print the measure as one JSON line.
fn one(path: &Path, policy: &str, runs: usize, source: bool) -> ExitCode {
    let input = if source {
        quelda_core::source::FileSource::open(path).map(Input::File)
    } else {
        std::fs::read(path).map(Input::Bytes)
    };
    let input = match input {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {}: {e}", path.display());
            return ExitCode::from(1);
        }
    };
    // Heap is the engine's: the input buffer (slice mode) is not counted.
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let (cpu0, _) = rusage();
    let mut m = Measure {
        bytes: match &input {
            Input::Bytes(b) => b.len() as u64,
            Input::File(f) => quelda_core::Source::len(f),
        },
        ..Measure::default()
    };
    for _ in 0..runs.max(1) {
        let start = Instant::now();
        let verdict = match &input {
            Input::Bytes(b) => quelda_core::scan_json(b, policy),
            Input::File(f) => quelda_core::scan_source_json(f, policy),
        };
        m.ms.push(start.elapsed().as_secs_f64() * 1000.0);
        m.verdict = verdict;
    }
    let (cpu1, rss) = rusage();
    m.cpu_ms = (cpu1 - cpu0) / m.ms.len() as f64;
    m.rss_peak = rss;
    m.heap_peak = PEAK.load(Ordering::Relaxed).saturating_sub(base) as u64;
    let engine = if source { "native-source" } else { "native" };
    println!("{}", m.record(engine, &path.to_string_lossy()));
    ExitCode::SUCCESS
}

enum Input {
    Bytes(Vec<u8>),
    File(quelda_core::source::FileSource),
}

/// Every file to bench with its display name (relative to a directory argument).
fn files(paths: &[PathBuf]) -> std::io::Result<Vec<(PathBuf, String)>> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            for f in quelda_eval::walk(p)? {
                let name = Path::new(p.file_name().unwrap_or_default())
                    .join(f.strip_prefix(p).unwrap_or(&f))
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((f, name));
            }
        } else {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            out.push((p.clone(), name));
        }
    }
    Ok(out)
}

fn main() -> ExitCode {
    let mut policy = bench::DEFAULT_POLICY.to_string();
    let mut runs = 3usize;
    let mut out = PathBuf::from("target/bench/native.jsonl");
    let mut child = None;
    let mut source = false;
    let mut paths = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--policy" => match args.next() {
                Some(v) => policy = v,
                None => return usage(),
            },
            "--runs" => match args.next().and_then(|v| v.parse().ok()) {
                Some(n) => runs = n,
                None => return usage(),
            },
            "--out" => match args.next() {
                Some(v) => out = PathBuf::from(v),
                None => return usage(),
            },
            "--source" => source = true,
            "--one" => match args.next() {
                Some(v) => child = Some(PathBuf::from(v)),
                None => return usage(),
            },
            _ if !a.starts_with('-') => paths.push(PathBuf::from(a)),
            _ => return usage(),
        }
    }
    if let Some(path) = child {
        return one(&path, &policy, runs, source);
    }
    if paths.is_empty() {
        return usage();
    }
    let list = match files(&paths) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let mut records = Vec::new();
    let mut lines = String::new();
    for (path, name) in &list {
        let res = Command::new(&exe)
            .arg("--one")
            .arg(path)
            .args(["--policy", &policy, "--runs", &runs.to_string()])
            .args(source.then_some("--source"))
            .output();
        let rec = res
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok());
        let Some(mut rec) = rec else {
            eprintln!("error: {name}: child failed");
            return ExitCode::from(1);
        };
        rec["file"] = Value::from(name.as_str());
        eprintln!(
            "{name}: {} ms, {} MB/s, RSS {} MiB, {}",
            rec["ms_median"], rec["mb_s"], rec["rss_peak_mb"], rec["status"]
        );
        lines.push_str(&rec.to_string());
        lines.push('\n');
        records.push(rec);
    }
    if let Err(e) = out
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&out, &lines))
    {
        eprintln!("error: cannot write {}: {e}", out.display());
        return ExitCode::from(1);
    }
    print!("{}", bench::table(&records));
    println!("\npolicy: {policy}  runs: {runs}  → {}", out.display());
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("usage: quelda-bench [--source] [--policy JSON] [--runs N] [--out FILE] PATH...");
    ExitCode::from(2)
}
