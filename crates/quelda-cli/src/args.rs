//! Command-line arguments (design §8.3). Hand-written: a usage error must
//! exit 64, never 2 (2 is an `ERROR` verdict), and the grammar is small.
//!
//! Every option takes `--name value` or `--name=value`, at most once; `--`
//! ends options (for a file named `-x`); `-` is stdin.

use std::ffi::OsString;
use std::path::PathBuf;

use quelda_core::policy::Preset;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Json,
    Text,
}

/// Where the policy comes from (`{}` when neither is given).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicySource {
    File(PathBuf),
    Json(String),
}

/// What to scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Stdin,
    Path(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scan {
    pub input: Input,
    pub policy: Option<PolicySource>,
    /// Overrides the policy's `preset`.
    pub preset: Option<Preset>,
    /// Sets the policy's `stop_on_first`.
    pub stop_on_first: bool,
    pub format: Format,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Scan(Scan),
    Rules {
        format: Format,
    },
    Version {
        format: Format,
    },
    /// `topic`: the command whose help to print (`None`: general help).
    Help {
        topic: Option<&'static str>,
    },
}

/// A usage error: the message for stderr (exit 64).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageError(pub String);

fn usage(msg: impl Into<String>) -> UsageError {
    UsageError(msg.into())
}

/// Parses `args` (without the program name).
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, UsageError> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Err(usage("missing command"));
    };
    let rest: Vec<OsString> = args.collect();
    match first.to_str() {
        Some("scan") => parse_scan(rest),
        Some("rules") => {
            let o = Options::parse(rest, &["format"], &[], "rules")?;
            if let Some(help) = o.help {
                return Ok(help);
            }
            o.no_positionals("rules")?;
            Ok(Command::Rules {
                format: o.format()?,
            })
        }
        Some("version") => {
            let o = Options::parse(rest, &["format"], &[], "version")?;
            if let Some(help) = o.help {
                return Ok(help);
            }
            o.no_positionals("version")?;
            Ok(Command::Version {
                format: o.format_or(Format::Text)?,
            })
        }
        Some("--version" | "-V") if rest.is_empty() => Ok(Command::Version {
            format: Format::Text,
        }),
        Some("help" | "--help" | "-h") => match rest.first().and_then(|a| a.to_str()) {
            None => Ok(Command::Help { topic: None }),
            Some(t @ ("scan" | "rules" | "version")) if rest.len() == 1 => Ok(Command::Help {
                topic: Some(static_topic(t)),
            }),
            Some(_) => Err(usage(format!("unknown help topic `{}`", lossy(&rest[0])))),
        },
        _ => Err(usage(format!("unknown command `{}`", lossy(&first)))),
    }
}

fn static_topic(t: &str) -> &'static str {
    match t {
        "scan" => "scan",
        "rules" => "rules",
        _ => "version",
    }
}

fn parse_scan(rest: Vec<OsString>) -> Result<Command, UsageError> {
    let o = Options::parse(
        rest,
        &["policy", "policy-json", "preset", "format"],
        &["stop-on-first"],
        "scan",
    )?;
    if let Some(help) = o.help {
        return Ok(help);
    }
    let input = match o.positionals.as_slice() {
        [] => return Err(usage("scan: missing <file> (use `-` for stdin)")),
        [one] if one.as_os_str() == "-" => Input::Stdin,
        [one] => Input::Path(PathBuf::from(one)),
        [_, extra, ..] => {
            return Err(usage(format!(
                "scan: unexpected argument `{}` (one file per run)",
                lossy(extra)
            )));
        }
    };
    let policy = match (o.value("policy"), o.value("policy-json")) {
        (Some(_), Some(_)) => {
            return Err(usage(
                "scan: --policy and --policy-json cannot be used together",
            ));
        }
        (Some(path), None) => Some(PolicySource::File(PathBuf::from(path))),
        (None, Some(json)) => Some(PolicySource::Json(
            json.to_str()
                .ok_or_else(|| usage("scan: --policy-json is not valid UTF-8"))?
                .to_string(),
        )),
        (None, None) => None,
    };
    let preset = match o.value("preset").map(|v| v.to_str()) {
        None => None,
        Some(Some("strict")) => Some(Preset::Strict),
        Some(Some("balanced")) => Some(Preset::Balanced),
        Some(Some("permissive")) => Some(Preset::Permissive),
        Some(_) => {
            return Err(usage(
                "scan: --preset must be strict, balanced or permissive",
            ));
        }
    };
    Ok(Command::Scan(Scan {
        input,
        policy,
        preset,
        stop_on_first: o.flags.contains(&"stop-on-first"),
        format: o.format()?,
    }))
}

/// Options of one command, checked against what it accepts.
struct Options {
    values: Vec<(&'static str, OsString)>,
    flags: Vec<&'static str>,
    positionals: Vec<OsString>,
    help: Option<Command>,
}

impl Options {
    fn parse(
        args: Vec<OsString>,
        valued: &[&'static str],
        flags: &[&'static str],
        command: &'static str,
    ) -> Result<Options, UsageError> {
        let mut o = Options {
            values: Vec::new(),
            flags: Vec::new(),
            positionals: Vec::new(),
            help: None,
        };
        let mut args = args.into_iter();
        let mut options_ended = false;
        while let Some(arg) = args.next() {
            let text = arg.to_str();
            if options_ended || arg == "-" || !text.is_some_and(|t| t.starts_with('-')) {
                o.positionals.push(arg);
                continue;
            }
            let text = text.unwrap_or_default();
            if text == "--" {
                options_ended = true;
                continue;
            }
            if text == "-h" || text == "--help" {
                o.help = Some(Command::Help {
                    topic: Some(command),
                });
                continue;
            }
            let Some(body) = text.strip_prefix("--") else {
                return Err(usage(format!("{command}: unknown option `{text}`")));
            };
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(OsString::from(v))),
                None => (body, None),
            };
            if let Some(&flag) = flags.iter().find(|f| **f == name) {
                if inline.is_some() {
                    return Err(usage(format!("{command}: --{flag} takes no value")));
                }
                if o.flags.contains(&flag) {
                    return Err(usage(format!("{command}: --{flag} given twice")));
                }
                o.flags.push(flag);
            } else if let Some(&key) = valued.iter().find(|v| **v == name) {
                let value = match inline {
                    Some(v) => v,
                    None => args
                        .next()
                        .ok_or_else(|| usage(format!("{command}: --{key} needs a value")))?,
                };
                if o.value(key).is_some() {
                    return Err(usage(format!("{command}: --{key} given twice")));
                }
                o.values.push((key, value));
            } else {
                return Err(usage(format!("{command}: unknown option `--{name}`")));
            }
        }
        Ok(o)
    }

    fn value(&self, key: &str) -> Option<&OsString> {
        self.values.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    fn format(&self) -> Result<Format, UsageError> {
        self.format_or(Format::Json)
    }

    fn format_or(&self, default: Format) -> Result<Format, UsageError> {
        match self.value("format").map(|v| v.to_str()) {
            None => Ok(default),
            Some(Some("json")) => Ok(Format::Json),
            Some(Some("text")) => Ok(Format::Text),
            Some(_) => Err(usage("--format must be json or text")),
        }
    }

    fn no_positionals(&self, command: &str) -> Result<(), UsageError> {
        match self.positionals.first() {
            None => Ok(()),
            Some(a) => Err(usage(format!(
                "{command}: unexpected argument `{}`",
                lossy(a)
            ))),
        }
    }
}

fn lossy(s: &OsString) -> String {
    s.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, UsageError> {
        parse(args.iter().map(OsString::from))
    }

    fn scan(args: &[&str]) -> Scan {
        match p(args) {
            Ok(Command::Scan(s)) => s,
            other => panic!("{args:?}: {other:?}"),
        }
    }

    fn err(args: &[&str]) -> String {
        match p(args) {
            Err(UsageError(m)) => m,
            ok => panic!("{args:?} parsed: {ok:?}"),
        }
    }

    #[test]
    fn scan_defaults() {
        let s = scan(&["scan", "a.pdf"]);
        assert_eq!(s.input, Input::Path("a.pdf".into()));
        assert_eq!(s.policy, None);
        assert_eq!(s.preset, None);
        assert!(!s.stop_on_first);
        assert_eq!(s.format, Format::Json);
        assert_eq!(scan(&["scan", "-"]).input, Input::Stdin);
    }

    #[test]
    fn scan_options_in_any_order_and_with_equals() {
        let s = scan(&[
            "scan",
            "--format=text",
            "--policy",
            "p.json",
            "x.pdf",
            "--stop-on-first",
            "--preset=strict",
        ]);
        assert_eq!(s.input, Input::Path("x.pdf".into()));
        assert_eq!(s.policy, Some(PolicySource::File("p.json".into())));
        assert_eq!(s.preset, Some(Preset::Strict));
        assert!(s.stop_on_first);
        assert_eq!(s.format, Format::Text);
        let s = scan(&["scan", "-", "--policy-json", r#"{"preset":"strict"}"#]);
        assert_eq!(
            s.policy,
            Some(PolicySource::Json(r#"{"preset":"strict"}"#.into()))
        );
        // `=` inside the value is kept.
        let s = scan(&["scan", "-", "--policy-json={\"a\":\"=\"}"]);
        assert_eq!(s.policy, Some(PolicySource::Json("{\"a\":\"=\"}".into())));
        for (v, preset) in [
            ("balanced", Preset::Balanced),
            ("permissive", Preset::Permissive),
        ] {
            assert_eq!(scan(&["scan", "f", "--preset", v]).preset, Some(preset));
        }
    }

    #[test]
    fn double_dash_ends_options() {
        assert_eq!(
            scan(&["scan", "--", "--policy"]).input,
            Input::Path("--policy".into())
        );
        assert_eq!(scan(&["scan", "--", "-"]).input, Input::Stdin);
    }

    #[test]
    fn scan_usage_errors() {
        assert!(err(&["scan"]).contains("missing <file>"));
        assert!(err(&["scan", "a", "b"]).contains("one file per run"));
        assert!(err(&["scan", "a", "--policy", "p", "--policy-json", "{}"]).contains("together"));
        assert!(err(&["scan", "a", "--preset", "paranoid"]).contains("--preset"));
        assert!(err(&["scan", "a", "--preset", "Strict"]).contains("--preset"));
        assert!(err(&["scan", "a", "--format", "xml"]).contains("--format"));
        assert!(err(&["scan", "a", "--policy"]).contains("needs a value"));
        assert!(err(&["scan", "a", "--preset", "strict", "--preset=strict"]).contains("twice"));
        assert!(err(&["scan", "a", "--stop-on-first", "--stop-on-first"]).contains("twice"));
        assert!(err(&["scan", "a", "--stop-on-first=yes"]).contains("no value"));
        assert!(err(&["scan", "a", "--nope"]).contains("unknown option `--nope`"));
        assert!(err(&["scan", "a", "-x"]).contains("unknown option `-x`"));
        // Options of other commands are not accepted.
        assert!(err(&["rules", "--policy", "p"]).contains("unknown option"));
    }

    #[test]
    fn other_commands() {
        assert_eq!(
            p(&["rules"]),
            Ok(Command::Rules {
                format: Format::Json
            })
        );
        assert_eq!(
            p(&["rules", "--format", "text"]),
            Ok(Command::Rules {
                format: Format::Text
            })
        );
        assert!(err(&["rules", "extra"]).contains("unexpected argument"));
        assert_eq!(
            p(&["version"]),
            Ok(Command::Version {
                format: Format::Text
            })
        );
        assert_eq!(
            p(&["version", "--format=json"]),
            Ok(Command::Version {
                format: Format::Json
            })
        );
        for v in ["--version", "-V"] {
            assert_eq!(
                p(&[v]),
                Ok(Command::Version {
                    format: Format::Text
                })
            );
        }
        assert!(err(&["--version", "x"]).contains("unknown command"));
        assert!(err(&["version", "x"]).contains("unexpected argument"));
    }

    #[test]
    fn help() {
        for args in [&["help"][..], &["--help"], &["-h"]] {
            assert_eq!(p(args), Ok(Command::Help { topic: None }));
        }
        assert_eq!(
            p(&["help", "scan"]),
            Ok(Command::Help {
                topic: Some("scan")
            })
        );
        // `--help` wins over a missing <file>.
        assert_eq!(
            p(&["scan", "--help"]),
            Ok(Command::Help {
                topic: Some("scan")
            })
        );
        assert_eq!(
            p(&["rules", "-h"]),
            Ok(Command::Help {
                topic: Some("rules")
            })
        );
        assert!(err(&["help", "nope"]).contains("unknown help topic"));
    }

    #[test]
    fn missing_or_unknown_command() {
        assert!(err(&[]).contains("missing command"));
        assert!(err(&["scna"]).contains("unknown command `scna`"));
        assert!(err(&["a.pdf"]).contains("unknown command"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_kept() {
        use std::os::unix::ffi::OsStringExt;
        let name = OsString::from_vec(vec![b'a', 0xff, b'.', b'p']);
        let c = parse([OsString::from("scan"), name.clone()]);
        assert_eq!(
            c.map(|c| match c {
                Command::Scan(s) => s.input,
                _ => Input::Stdin,
            }),
            Ok(Input::Path(PathBuf::from(name)))
        );
    }
}
