//! End-to-end checks of the fixture set (implementation plan, Step 2).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use miniz_oxide::inflate::decompress_to_vec_zlib;
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use quelda_testkit::fixtures::{self, Fixture, Kind};
use quelda_testkit::{manifest, rules};

fn all() -> &'static [Fixture] {
    static ALL: OnceLock<Vec<Fixture>> = OnceLock::new();
    ALL.get_or_init(fixtures::all)
}

fn by_path(path: &str) -> &'static Fixture {
    all()
        .iter()
        .find(|f| f.path == path)
        .unwrap_or_else(|| panic!("no fixture {path}"))
}

fn variants_of(rule: &str, kind: Kind) -> BTreeSet<&'static str> {
    all()
        .iter()
        .filter(|f| f.kind == kind && f.rule == Some(rule))
        .map(|f| f.variant.as_str())
        .collect()
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("quelda-testkit-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn every_rule_has_bad_and_good() {
    for r in rules::RULES {
        assert!(
            !variants_of(r.id, Kind::Bad).is_empty(),
            "{} has no bad fixture",
            r.id
        );
        assert!(
            !variants_of(r.id, Kind::Good).is_empty(),
            "{} has no good fixture",
            r.id
        );
    }
}

/// Evasion variants required by design §5.7.
#[test]
fn required_evasion_variants_exist() {
    let standard = [
        "plain",
        "name-encoded",
        "in-objstm",
        "old-revision",
        "nested-dict",
    ];
    let dict_rules = [
        "POSTSCRIPT.XOBJECT",
        "POSTSCRIPT.TYPE4_FUNCTION",
        "ACTIVE.JAVASCRIPT",
        "ACTIVE.LAUNCH",
        "ACTIVE.OPEN_ACTION",
        "ACTIVE.ADDITIONAL_ACTIONS",
        "ACTIVE.OTHER_ACTIONS",
        "EMBED.EMBEDDED_FILE",
        "EMBED.FILE_ATTACHMENT",
        "EMBED.RICH_MEDIA",
        "EMBED.PORTFOLIO",
        "EXTERNAL.URI",
        "EXTERNAL.REMOTE_GOTO",
        "EXTERNAL.SUBMIT_FORM",
        "EXTERNAL.IMPORT_DATA",
        "EXTERNAL.URL_FILESPEC",
        "FORMS.XFA",
        "FORMS.ACROFORM",
        "CODEC.JBIG2",
        "CODEC.JPX",
        "CODEC.TYPE1_FONT",
        "RESOURCE.IMAGE_DIMENSIONS",
        "RESOURCE.PAGE_SIZE",
    ];
    let mut required: BTreeMap<&str, Vec<&str>> =
        dict_rules.iter().map(|r| (*r, standard.to_vec())).collect();
    required.entry("ACTIVE.JAVASCRIPT").or_default().extend([
        "js-stream",
        "js-utf16",
        "js-names-tree",
        "js-annotation",
        "js-openaction",
    ]);
    required.insert("FORMS.XFA", [standard.as_slice(), &["xfa-script"]].concat());
    required.insert(
        "FILETYPE.NOT_PDF_HEADER",
        vec!["junk-before-header", "header-after-1024"],
    );
    required.insert(
        "POSTSCRIPT.CONTENT_OP",
        vec![
            "plain",
            "flate",
            "filter-chain",
            "lzw",
            "old-revision",
            "form-xobject",
            "appearance-stream",
            "type3-charproc",
        ],
    );
    required.insert(
        "XML.DOCTYPE",
        vec![
            "plain",
            "flate",
            "filter-chain",
            "lzw",
            "old-revision",
            "in-xfa",
        ],
    );
    for (rule, vars) in required {
        let have = variants_of(rule, Kind::Bad);
        for v in vars {
            assert!(have.contains(v), "{rule} lacks bad variant `{v}`");
        }
    }
}

#[test]
fn fixture_specs_are_consistent() {
    let mut paths = BTreeSet::new();
    for f in all() {
        assert!(paths.insert(f.path.as_str()), "duplicate path {}", f.path);
        for id in &f.fires {
            assert!(rules::rule(id).is_some(), "{}: unknown rule {id}", f.path);
        }
        match f.kind {
            Kind::Bad => {
                let rule = f.rule.expect("bad fixture has a rule");
                assert!(f.fires.contains(&rule), "{} must fire {rule}", f.path);
                assert!(
                    f.path.starts_with(&format!("rules/{rule}/bad/")),
                    "{}",
                    f.path
                );
            }
            Kind::Good => {
                let rule = f.rule.expect("good fixture has a rule");
                assert!(!f.fires.contains(&rule), "{} fires its own rule", f.path);
                assert!(
                    f.path.starts_with(&format!("rules/{rule}/good/")),
                    "{}",
                    f.path
                );
            }
            _ => assert!(f.rule.is_none()),
        }
        assert!(f.path.ends_with(".pdf"));
        assert!(!f.note.is_empty(), "{} has no note", f.path);
    }
}

#[test]
fn pdfs_start_with_header_unless_testing_it() {
    for f in all() {
        let header_rule = f
            .fires
            .iter()
            .any(|r| r.starts_with("FILETYPE.") && *r != "FILETYPE.POLYGLOT");
        let truncated = f.path == "malformed/truncated.pdf";
        if !header_rule && !truncated {
            assert!(
                f.bytes.starts_with(b"%PDF-"),
                "{} does not start with %PDF-",
                f.path
            );
        }
    }
}

#[test]
fn payloads_are_inert_markers() {
    // XML namespace identifiers are not fetched; anything else must be example.invalid.
    const NAMESPACES: [&str; 5] = [
        "http://www.w3.org/",
        "http://ns.adobe.com/",
        "http://purl.org/",
        "http://www.xfa.org/",
        "adobe:ns:meta/",
    ];
    for f in all() {
        let text = String::from_utf8_lossy(&f.bytes);
        for forbidden in [
            "/bin/",
            "cmd.exe",
            "powershell",
            "%pipe%",
            "file://",
            "ftp://",
            "url(",
        ] {
            assert!(
                !text.contains(forbidden),
                "{} contains `{forbidden}`",
                f.path
            );
        }
        for (at, _) in text.match_indices("https://") {
            assert!(
                text[at..].starts_with("https://example.invalid/"),
                "{}: external URL",
                f.path
            );
        }
        for (at, _) in text.match_indices("http://") {
            assert!(
                NAMESPACES.iter().any(|ns| text[at..].starts_with(ns)),
                "{}: external URL",
                f.path
            );
        }
    }
}

#[test]
fn set_is_small() {
    let total: usize = all().iter().map(|f| f.bytes.len()).sum();
    assert!(total < 2 * 1024 * 1024, "fixtures total {total} bytes");
    assert!(all().len() >= 250, "only {} fixtures", all().len());
}

#[test]
fn generation_is_deterministic() {
    let again = fixtures::all();
    assert_eq!(again.len(), all().len());
    for (a, b) in all().iter().zip(&again) {
        assert_eq!(a.path, b.path);
        assert!(a.bytes == b.bytes, "{} differs between runs", a.path);
    }
    assert_eq!(
        manifest::manifest_json(all()),
        manifest::manifest_json(&again)
    );
}

/// Inflates a zlib stream with a fixed 64 KiB buffer, returning only the byte count.
fn inflated_len(data: &[u8]) -> u64 {
    let mut state = InflateState::new_boxed(DataFormat::Zlib);
    let mut buf = vec![0u8; 64 * 1024];
    let mut input = data;
    let mut total = 0u64;
    loop {
        let r = inflate(&mut state, input, &mut buf, MZFlush::None);
        input = &input[r.bytes_consumed..];
        total += r.bytes_written as u64;
        match r.status {
            Ok(MZStatus::StreamEnd) => return total,
            Ok(_) => {}
            Err(e) => panic!("inflate error {e:?}"),
        }
    }
}

fn stream_data(pdf: &[u8], dict_marker: &[u8]) -> Vec<u8> {
    let at = pdf
        .windows(dict_marker.len())
        .position(|w| w == dict_marker)
        .expect("dict");
    let rest = &pdf[at..];
    let len_at = rest
        .windows(8)
        .position(|w| w == b"/Length ")
        .expect("length")
        + 8;
    let len: usize = rest[len_at..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .fold(0, |n, &b| n * 10 + usize::from(b - b'0'));
    let data_at = rest
        .windows(7)
        .position(|w| w == b"stream\n")
        .expect("stream")
        + 7;
    rest[data_at..data_at + len].to_vec()
}

#[test]
fn flate_bomb_is_small_and_inflates_past_1_gib() {
    let f = by_path("malformed/flate-bomb.pdf");
    assert!(
        f.bytes.len() < 1024 * 1024,
        "bomb file is {} bytes",
        f.bytes.len()
    );
    let outer = stream_data(&f.bytes, b"/Filter [/FlateDecode /FlateDecode]");
    let inner = decompress_to_vec_zlib(&outer).expect("outer layer");
    let total = inflated_len(&inner);
    assert!(total > 1 << 30, "inflates to only {total} bytes");
    assert_eq!(f.engine_error, Some("LIMIT"));
}

#[test]
fn single_layer_bomb_ratio() {
    let f = by_path("malformed/flate-bomb-single.pdf");
    let data = stream_data(&f.bytes, b"/Filter /FlateDecode");
    let total = inflated_len(&data);
    assert_eq!(total, 256 << 20);
    assert!(
        total / data.len() as u64 > 900,
        "ratio {}",
        total / data.len() as u64
    );
}

#[test]
fn expected_verdicts_follow_presets() {
    let m: serde_json::Value = serde_json::from_str(&manifest::manifest_json(all())).unwrap();
    let files = &m["files"];
    let launch = &files["rules/ACTIVE.LAUNCH/bad/plain.pdf"]["expected"];
    for p in ["strict", "balanced", "permissive"] {
        assert_eq!(launch[p]["status"], "REJECT", "locked rule in {p}");
    }
    let uri = &files["benign/link-uri.pdf"]["expected"];
    assert_eq!(uri["strict"]["status"], "REJECT");
    assert_eq!(uri["balanced"]["status"], "PASS");
    assert_eq!(uri["balanced"]["warnings"][0], "EXTERNAL.URI");
    assert_eq!(uri["permissive"]["warnings"].as_array().unwrap().len(), 0);
    for p in ["strict", "balanced", "permissive"] {
        assert_eq!(
            files["malformed/flate-bomb.pdf"]["expected"][p]["status"],
            "ERROR"
        );
        assert_eq!(files["benign/minimal.pdf"]["expected"][p]["status"], "PASS");
    }
}

#[test]
fn binary_writes_and_checks() {
    let dir = temp_dir("bin");
    let bin = env!("CARGO_BIN_EXE_gen-fixtures");
    let run = |args: &[&str]| {
        Command::new(bin)
            .args(args)
            .output()
            .expect("run gen-fixtures")
    };
    let out = dir.to_str().unwrap();

    let check_missing = run(&["--out", out, "--check"]);
    assert!(!check_missing.status.success());

    let write = run(&["--out", out]);
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    assert!(dir.join("manifest.json").is_file());
    assert!(dir.join("rules/ACTIVE.LAUNCH/bad/plain.pdf").is_file());
    assert!(manifest::require_dir(&dir).is_ok());

    let check = run(&["--out", out, "--check"]);
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );

    std::fs::write(dir.join("benign/minimal.pdf"), b"tampered").unwrap();
    let check = run(&["--out", out, "--check"]);
    assert_eq!(check.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&check.stderr).contains("changed: benign/minimal.pdf"));

    assert_eq!(run(&["--bogus"]).status.code(), Some(64));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Catches "forgot to regenerate" when a local tests/fixtures exists.
#[test]
fn local_fixtures_dir_is_up_to_date() {
    let dir = manifest::default_dir();
    if manifest::require_dir(&dir).is_err() {
        eprintln!("skipped: {} not generated", dir.display());
        return;
    }
    let diffs = manifest::diff_dir(&dir, all()).unwrap();
    assert!(
        diffs.is_empty(),
        "tests/fixtures is stale ({} diffs, e.g. {:?}): run gen-fixtures",
        diffs.len(),
        &diffs[..diffs.len().min(5)]
    );
}

fn qpdf_check(path: &Path) -> Result<(), String> {
    let out = Command::new("qpdf")
        .arg("--check")
        .arg(path)
        .output()
        .map_err(|e| e.to_string())?;
    // 0 = ok, 3 = warnings only; 2 = errors.
    match out.status.code() {
        Some(0) => Ok(()),
        _ => Err(format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )),
    }
}

/// Optional oracle (Apache-2.0 tool, run as a separate process, never linked).
#[test]
fn qpdf_accepts_benign_files() {
    if Command::new("qpdf").arg("--version").output().is_err() {
        eprintln!("skipped: qpdf not installed");
        return;
    }
    let dir = temp_dir("qpdf");
    std::fs::create_dir_all(&dir).unwrap();
    for f in all().iter().filter(|f| f.kind == Kind::Benign) {
        let p = dir.join(f.path.replace('/', "_"));
        std::fs::write(&p, &f.bytes).unwrap();
        if let Err(e) = qpdf_check(&p) {
            panic!("qpdf --check failed on {}:\n{e}", f.path);
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
