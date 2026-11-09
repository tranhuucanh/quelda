//! `quelda` CLI. Thin wrapper around `quelda_core::scan_json`; the real
//! interface (args, exit codes 0/1/2/64+) arrives in Step 14.

/// Returns the engine version.
fn version() -> &'static str {
    quelda_core::version()
}

fn main() {
    println!("quelda {}", version());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_core() {
        assert_eq!(version(), quelda_core::VERSION);
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
