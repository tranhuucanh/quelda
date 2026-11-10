//! Smoke test (plan Step 13): run the evaluation over `tests/fixtures/benign`.

use std::path::Path;

use quelda_eval::{CSV_HEADER, Label, PRESETS, evaluate, to_csv, to_jsonl, walk};

#[test]
fn benign_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/benign");
    assert!(
        root.is_dir(),
        "{} missing: run `cargo run -p quelda-testkit --bin gen-fixtures` first",
        root.display()
    );
    let files = walk(&root).unwrap();
    assert!(!files.is_empty());

    let records = evaluate(&root).unwrap();
    assert_eq!(records.len(), files.len() * PRESETS.len());
    assert!(records.iter().all(|r| r.label == Label::Unlabelled));
    assert!(
        records
            .iter()
            .all(|r| ["PASS", "REJECT", "ERROR"].contains(&r.status.as_str()))
    );

    let csv = to_csv(&records);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines[0], CSV_HEADER);
    assert_eq!(lines.len(), records.len() + 1);
    assert_eq!(to_jsonl(&records).lines().count(), records.len());

    // Benign fixtures pass at balanced (manifest: none is rejected there).
    for r in records.iter().filter(|r| r.preset == "balanced") {
        assert!(
            r.valid,
            "{} rejected at balanced: {:?} {:?}",
            r.file, r.violations, r.errors
        );
    }
}
