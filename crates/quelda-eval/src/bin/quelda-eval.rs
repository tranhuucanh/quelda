//! `quelda-eval <corpus_dir> [--out <dir>]`: scan every file under the corpus
//! with each preset; write `results.csv` + `verdicts.jsonl` to `--out`
//! (default `target/eval`) and print a summary. See `quelda_eval` docs.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut root = None;
    let mut out = PathBuf::from("target/eval");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => match args.next() {
                Some(v) => out = PathBuf::from(v),
                None => return usage(),
            },
            _ if root.is_none() && !a.starts_with('-') => root = Some(PathBuf::from(a)),
            _ => return usage(),
        }
    }
    let Some(root) = root else { return usage() };

    let records = match quelda_eval::evaluate(&root) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", root.display());
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::create_dir_all(&out)
        .and_then(|()| std::fs::write(out.join("results.csv"), quelda_eval::to_csv(&records)))
        .and_then(|()| std::fs::write(out.join("verdicts.jsonl"), quelda_eval::to_jsonl(&records)))
    {
        eprintln!("error: cannot write to {}: {e}", out.display());
        return ExitCode::from(1);
    }
    print!("{}", quelda_eval::summary(&records));
    println!("wrote {} rows to {}", records.len(), out.display());
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("usage: quelda-eval <corpus_dir> [--out <dir>]");
    ExitCode::from(2)
}
