//! `--format text`: a human-readable view of the JSON output. Rendered from
//! the JSON contract itself, so it can never say something the JSON does not.

use serde_json::Value;

/// A string field, made printable.
fn s(v: &Value, key: &str) -> String {
    printable(v.get(key).and_then(Value::as_str).unwrap_or(""))
}

/// `text` with control characters escaped (`\u{1b}`): file names and strings
/// from inside a PDF must not drive the terminal.
pub fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// One line per finding / error, then a summary line.
pub fn verdict(json: &str, input: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return format!("ERROR  {}\n  (unreadable verdict)\n", printable(input));
    };
    let mut out = findings(&v, input);
    out.push_str(&summary_line(&v));
    out
}

/// The status line (`PASS    name`, statuses aligned), then one line per error and finding.
pub fn findings(v: &Value, input: &str) -> String {
    let mut out = format!("{:<6}  {}\n", s(v, "status"), printable(input));
    for e in list(v, "errors") {
        out.push_str(&format!("  error  {}  {}\n", s(e, "code"), s(e, "message")));
    }
    for (label, key) in [("block", "violations"), ("warn ", "warnings")] {
        for f in list(v, key) {
            let count = f.get("count").and_then(Value::as_u64).unwrap_or(0);
            out.push_str(&format!(
                "  {label}  {}  [{}]  {}{}\n",
                s(f, "rule_id"),
                s(f, "severity"),
                s(f, "message"),
                if count > 1 {
                    format!(" (×{count})")
                } else {
                    String::new()
                },
            ));
            if let Some(at) = list(f, "locations").first().map(location) {
                out.push_str(&format!("         at {at}\n"));
            }
        }
    }
    out
}

fn summary_line(v: &Value) -> String {
    let preset = v["policy"]
        .get("preset")
        .and_then(Value::as_str)
        .unwrap_or("none");
    format!(
        "valid: {}; {}, {}, {}; preset {preset}; {} bytes, {} ms\n",
        v.get("valid").and_then(Value::as_bool).unwrap_or(false),
        plural(list(v, "violations").len(), "violation", "violations"),
        plural(list(v, "warnings").len(), "warning", "warnings"),
        plural(list(v, "errors").len(), "error", "errors"),
        v["stats"]["bytes"].as_u64().unwrap_or(0),
        v["stats"]["duration_ms"].as_u64().unwrap_or(0),
    )
}

/// `object 5 0, /OpenAction/JS` style, from whichever fields are set.
fn location(l: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(o) = l.get("object").and_then(Value::as_str) {
        parts.push(format!("object {o}"));
    }
    if let Some(src) = l.get("source").and_then(Value::as_str) {
        parts.push(src.to_string());
    }
    if let Some(p) = l.get("path").and_then(Value::as_str) {
        parts.push(p.to_string());
    }
    if let Some(off) = l.get("offset").and_then(Value::as_u64) {
        parts.push(format!("offset {off}"));
    }
    if let Some(off) = l.get("op_offset").and_then(Value::as_u64) {
        parts.push(format!("content offset {off}"));
    }
    if let Some(d) = l.get("detail").and_then(Value::as_str) {
        parts.push(d.to_string());
    }
    if parts.is_empty() {
        "document".to_string()
    } else {
        printable(&parts.join(", "))
    }
}

/// One rule per line: ID, category, default action, locked, message.
pub fn rules(json: &str) -> String {
    let rules: Vec<Value> = serde_json::from_str(json).unwrap_or_default();
    let width = rules.iter().map(|r| s(r, "id").len()).max().unwrap_or(0);
    let mut out = String::new();
    for r in &rules {
        let locked = r.get("locked").and_then(Value::as_bool).unwrap_or(false);
        out.push_str(&format!(
            "{:<width$}  {:<14}  {:<5}  {}{}\n",
            s(r, "id"),
            s(r, "category"),
            s(r, "default_action"),
            if locked { "[locked] " } else { "" },
            s(r, "message"),
        ));
    }
    out.push_str(&format!("{}\n", plural(rules.len(), "rule", "rules")));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_lists_errors_findings_and_summary() {
        let json = r#"{"valid":false,"status":"REJECT",
          "violations":[{"rule_id":"ACTIVE.JAVASCRIPT","category":"active_content","severity":"high","action":"block","message":"Document contains JavaScript","count":3,
            "locations":[{"object":"5 0","path":"/OpenAction/JS"},{"object":"6 0"}]}],
          "warnings":[{"rule_id":"STRUCT.X","category":"structure","severity":"low","action":"warn","message":"m","count":1,"locations":[]}],
          "errors":[],"engine_version":"0","policy":{"preset":"strict","digest":"d","unsafe_allow_unlock":false,"stop_on_first":false},
          "stats":{"bytes":10,"objects":1,"revisions":1,"decoded_bytes":0,"duration_ms":2}}"#;
        assert_eq!(
            verdict(json, "a.pdf"),
            "REJECT  a.pdf\n\
             \x20 block  ACTIVE.JAVASCRIPT  [high]  Document contains JavaScript (×3)\n\
             \x20        at object 5 0, /OpenAction/JS\n\
             \x20 warn   STRUCT.X  [low]  m\n\
             valid: false; 1 violation, 1 warning, 0 errors; preset strict; 10 bytes, 2 ms\n"
        );
    }

    #[test]
    fn verdict_error_and_unknown_preset() {
        let json = r#"{"valid":false,"status":"ERROR","violations":[],"warnings":[],
          "errors":[{"code":"POLICY.INVALID","message":"bad"}],"engine_version":"0",
          "policy":{"preset":null,"digest":null,"unsafe_allow_unlock":false,"stop_on_first":false},
          "stats":{"bytes":0,"objects":0,"revisions":0,"decoded_bytes":0,"duration_ms":0}}"#;
        assert_eq!(
            verdict(json, "-"),
            "ERROR   -\n  error  POLICY.INVALID  bad\n\
             valid: false; 0 violations, 0 warnings, 1 error; preset none; 0 bytes, 0 ms\n"
        );
        assert!(verdict("nope", "x").starts_with("ERROR  x\n"));
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(
            printable("a\x1b[31mb\nc\u{7f}"),
            "a\\u{1b}[31mb\\u{a}c\\u{7f}"
        );
        assert_eq!(printable("tên tệp.pdf"), "tên tệp.pdf");
        let v: Value = serde_json::from_str(
            r#"{"status":"REJECT","errors":[{"code":"ENGINE.READ","message":"cannot open \u001b]0;x"}],
              "violations":[{"rule_id":"R","severity":"low","message":"m","count":1,
                "locations":[{"detail":"\u001b[2J"}]}]}"#,
        )
        .unwrap();
        let out = findings(&v, "f\x07.pdf");
        assert!(!out.contains(['\x1b', '\x07']), "{out:?}");
        assert!(out.starts_with("REJECT  f\\u{7}.pdf\n"), "{out}");
        assert!(out.contains("cannot open \\u{1b}]0;x"), "{out}");
        assert!(out.contains("at \\u{1b}[2J"), "{out}");
    }

    #[test]
    fn location_fields() {
        let l: Value = serde_json::from_str(
            r#"{"object":"7 0","source":"objstm:3","offset":12,"op_offset":4,"detail":"d"}"#,
        )
        .unwrap();
        assert_eq!(
            location(&l),
            "object 7 0, objstm:3, offset 12, content offset 4, d"
        );
        assert_eq!(location(&Value::Null), "document");
    }

    #[test]
    fn rules_table_from_the_real_registry() {
        let out = rules(&quelda_core::list_rules_json());
        let n = quelda_core::list_rules().len();
        assert_eq!(out.lines().count(), n + 1);
        assert!(out.ends_with(&format!("{n} rules\n")));
        let ps = out
            .lines()
            .find(|l| l.starts_with("FILETYPE.POSTSCRIPT_MAGIC "))
            .unwrap();
        assert!(ps.contains("[locked]"), "{ps}");
        assert!(ps.contains("block"));
        assert_eq!(rules("[]"), "0 rules\n");
    }
}
