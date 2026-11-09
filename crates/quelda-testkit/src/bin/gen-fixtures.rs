//! Generates `tests/fixtures/` + `manifest.json`. Implemented in Step 2.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "gen-fixtures (quelda-testkit {}): not implemented yet (Step 2)",
        quelda_testkit::version()
    );
    ExitCode::FAILURE
}
