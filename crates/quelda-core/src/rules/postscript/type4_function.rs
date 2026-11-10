//! `POSTSCRIPT.TYPE4_FUNCTION`: a PostScript calculator function whose
//! program is not plain ISO 32000 §7.10.5 calculator code (ADR #26).
//!
//! The program is checked against an allowlist: the 42 operators of the
//! spec, numbers in every PostScript syntax, comments, and `{ }` procedures
//! used only as the operands of `if` / `ifelse`, the whole program being a
//! single procedure. Anything else — another name, a literal name, a string,
//! an array, a dictionary, a stray procedure — and programs that are too long,
//! too deeply nested, not a stream or not decodable are reported.

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::values;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct Type4Function;

static META: RuleMeta = RuleMeta {
    id: "POSTSCRIPT.TYPE4_FUNCTION",
    category: Category::Postscript,
    severity: Severity::Medium,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.1.0",
    message: "PostScript calculator (Type 4) function outside the spec",
    description: "A function dictionary with /FunctionType 4 (ISO 32000-2 §7.10.5) whose \
        program is not plain calculator code: it uses a token other than the 42 operators \
        of the spec, numbers and comments (any other name, a literal name, a string, an \
        array or dictionary), a procedure that is not an operand of if/ifelse, is not a \
        single { } procedure, is longer than 64 KiB or nested deeper than 100, gives \
        copy/index/roll a literal count above 65535 or below 0, is not a stream, or \
        cannot be decoded. The program runs in the renderer's PostScript interpreter; \
        the colour functions written by Illustrator, InDesign and other tools pass.",
};

/// Longest program accepted (decoded bytes).
const MAX_LEN: usize = 64 * 1024;
/// Deepest procedure nesting accepted (the program itself is depth 1).
const MAX_DEPTH: usize = 100;
/// Largest literal count accepted by `copy`, `index` and `roll`.
const MAX_COUNT: f64 = 65_535.0;

/// ISO 32000-2 §7.10.5, Table 42.
const OPERATORS: [&str; 42] = [
    // Arithmetic.
    "abs", "add", "atan", "ceiling", "cos", "cvi", "cvr", "div", "exp", "floor", "idiv", "ln",
    "log", "mod", "mul", "neg", "round", "sin", "sqrt", "sub", "truncate",
    // Relational, boolean and bitwise.
    "and", "bitshift", "eq", "false", "ge", "gt", "le", "lt", "ne", "not", "or", "true", "xor",
    // Conditional.
    "if", "ifelse",
    // Stack.
    "copy", "dup", "exch", "index", "pop", "roll",
];

/// PDF whitespace (NUL, tab, LF, FF, CR, space).
fn is_space(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn is_regular(b: u8) -> bool {
    !is_space(b) && !is_delimiter(b)
}

/// A PostScript number: integer, real (`.5`, `5.`, `-0.0`, `1.0E-5`,
/// `1e5`) or radix (`16#FF`).
fn number(t: &[u8]) -> Option<f64> {
    let s = std::str::from_utf8(t).ok()?;
    if let Some((base, digits)) = s.split_once('#') {
        if base.is_empty() || !base.bytes().all(|b| b.is_ascii_digit()) || digits.is_empty() {
            return None;
        }
        let base: u32 = base.parse().ok()?;
        if !(2..=36).contains(&base) {
            return None;
        }
        return digits.chars().try_fold(0f64, |acc, c| {
            Some(acc * f64::from(base) + f64::from(c.to_digit(base)?))
        });
    }
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    if int.len() + frac.len() == 0 || !digits(int) || !digits(frac) {
        return None;
    }
    if let Some(e) = exponent {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        if e.is_empty() || !digits(e) {
            return None;
        }
    }
    s.parse().ok()
}

#[derive(Clone, Copy)]
enum Item<'a> {
    Num(f64),
    Op(&'a str),
    /// A `{ … }` procedure, at this offset.
    Proc(usize),
}

/// A token for messages: printable, at most 32 characters.
fn shown(t: &[u8]) -> String {
    let s = t.escape_ascii().to_string();
    match s.char_indices().nth(32) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s,
    }
}

/// Checks the items of one procedure (or of the whole program).
fn check_items(items: &[Item]) -> Result<(), String> {
    let count = |i: usize, back: usize, op: &str| -> Result<(), String> {
        if let Some(Item::Num(n)) = i.checked_sub(back).and_then(|j| items.get(j)) {
            if *n < 0.0 || *n > MAX_COUNT {
                return Err(format!("`{op}` with count {n}"));
            }
        }
        Ok(())
    };
    let mut i = 0;
    while let Some(item) = items.get(i) {
        match *item {
            Item::Proc(off) => match (items.get(i + 1), items.get(i + 2)) {
                (Some(Item::Op("if")), _) => i += 2,
                (Some(Item::Proc(_)), Some(Item::Op("ifelse"))) => i += 3,
                _ => return Err(format!("procedure at offset {off} is not an if/ifelse operand")),
            },
            Item::Op(op @ ("if" | "ifelse")) => {
                return Err(format!("`{op}` without its procedure operands"));
            }
            Item::Op(op @ ("index" | "copy")) => {
                count(i, 1, op)?;
                i += 1;
            }
            Item::Op("roll") => {
                count(i, 2, "roll")?;
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// `Err(the first problem)` unless `src` is plain calculator code.
fn validate(src: &[u8]) -> Result<(), String> {
    if src.len() > MAX_LEN {
        return Err(format!("program is {} bytes (max {MAX_LEN})", src.len()));
    }
    // Open procedures; `frames[0]` is the top level.
    let mut frames: Vec<(usize, Vec<Item>)> = vec![(0, Vec::new())];
    let mut i = 0;
    while let Some(&b) = src.get(i) {
        match b {
            _ if is_space(b) => i += 1,
            b'%' => {
                while src.get(i).is_some_and(|&c| c != b'\n' && c != b'\r') {
                    i += 1;
                }
            }
            b'{' => {
                if frames.len() > MAX_DEPTH {
                    return Err(format!("procedures nested deeper than {MAX_DEPTH}"));
                }
                frames.push((i, Vec::new()));
                i += 1;
            }
            b'}' => {
                if frames.len() == 1 {
                    return Err(format!("unbalanced `}}` at offset {i}"));
                }
                let (start, items) = frames.pop().unwrap_or_default();
                check_items(&items)?;
                if let Some((_, parent)) = frames.last_mut() {
                    parent.push(Item::Proc(start));
                }
                i += 1;
            }
            _ if is_delimiter(b) => {
                // A literal name, string, array or dictionary.
                let end = src[i + 1..]
                    .iter()
                    .position(|&c| !is_regular(c))
                    .map_or(src.len(), |n| i + 1 + n);
                let end = if b == b'/' { end } else { i + 1 };
                return Err(format!("token `{}` at offset {i}", shown(&src[i..end])));
            }
            _ => {
                let end = src[i..]
                    .iter()
                    .position(|&c| !is_regular(c))
                    .map_or(src.len(), |n| i + n);
                let t = &src[i..end];
                let item = match OPERATORS.iter().find(|op| op.as_bytes() == t) {
                    Some(op) => Item::Op(op),
                    None => match number(t) {
                        Some(n) => Item::Num(n),
                        None => return Err(format!("token `{}` at offset {i}", shown(t))),
                    },
                };
                if let Some((_, items)) = frames.last_mut() {
                    items.push(item);
                }
                i = end;
            }
        }
    }
    match frames.as_slice() {
        [(_, top)] => match top.as_slice() {
            [Item::Proc(_)] => Ok(()),
            [] => Err("empty program".to_string()),
            _ => Err("program is not a single { } procedure".to_string()),
        },
        _ => Err("unclosed `{`".to_string()),
    }
}

impl Rule for Type4Function {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if !values(ctx, dict, "FunctionType").any(|v| v.as_number() == Some(4.0)) {
            return;
        }
        let is_stream = loc.is_object()
            && ctx
                .objects()
                .get(loc.object)
                .is_some_and(|e| matches!(e.object, PdfObject::Stream(_)));
        let problem = if !is_stream {
            Err("function is not a stream".to_string())
        } else {
            match ctx.decoded_stream(loc) {
                Some(data) if data.is_usable() => validate(&data),
                _ => Err("program cannot be decoded".to_string()),
            }
        };
        if let Err(detail) = problem {
            out.report(&META, loc, Some(detail));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    /// From a real Illustrator → ilovepdf file (colour conversion).
    const ILLUSTRATOR: &[u8] = b"{2 index 1.000000 cvr exch sub 4 1 roll 1 index 1.000000 cvr exch sub \n4 1 roll 0 index 1.000000 cvr exch sub 4 1 roll 1.000000 4 1 \nroll 7 -1 roll 1.000000 cvr exch sub 7 1 roll 6 -1 roll 1.000000 \ncvr exch sub 6 1 roll 5 -1 roll 1.000000 cvr exch sub 5 1 \nroll 4 -1 roll 1.000000 cvr exch sub 4 1 roll pop pop pop }\n";
    /// From a real print file (tint transform with if).
    const WITH_IF: &[u8] = b"{  1.000000 exch dup 0.000000 gt { exch pop dup 0.000000 sub -1.000000 mul 1.000000 add exch } if dup 1.000000 gt { exch pop 0.000000 exch } if pop }\n";

    #[test]
    fn spec_programs_pass() {
        let ok: Vec<&[u8]> = vec![
            ILLUSTRATOR,
            WITH_IF,
            b"{ dup }",
            b"{}",
            b"  % leading comment\r\n{ 0 1 add } % trailing\n",
            b"\0\x0C{\0dup\x0Cpop\t}\0",
            b"{ abs add atan ceiling cos cvi cvr div exp floor idiv ln log mod mul neg round sin sqrt sub truncate }",
            b"{ and bitshift eq false ge gt le lt ne not or true xor }",
            b"{ copy dup exch index pop roll }",
            b"{ 1 2 3 -4 +5 .5 5. -0.0 1.0E-5 1e5 -.5e+3 2#1010 16#FF 36#Zz 8#777 }",
            b"{ dup 0.5 gt { pop 1 } { 0 mul } ifelse }",
            b"{ dup 0 gt { dup 1 gt { pop 1 } if } { pop 0 } ifelse }",
            b"{ 3 1 roll 2 index 65535 copy 4 -1 roll 0 index }",
            b"{ 1 { pop } if } ",
            b"{dup%comment}\n}",
        ];
        for p in ok {
            assert_eq!(validate(p), Ok(()), "{}", String::from_utf8_lossy(p));
        }
        // Nesting up to the limit.
        let deep = [
            "{ true ".to_string(),
            "{ true ".repeat(MAX_DEPTH - 1),
            "} if ".repeat(MAX_DEPTH - 1),
            "}".to_string(),
        ]
        .concat();
        assert_eq!(validate(deep.as_bytes()), Ok(()));
    }

    #[test]
    fn everything_else_is_reported() {
        let bad: Vec<(&[u8], &str)> = vec![
            (b"{ exec }", "token `exec` at offset 2"),
            (b"{ (x) file }", "token `(` at offset 2"),
            (b"{ run }", "token `run` at offset 2"),
            (b"{ currentfile }", "token `currentfile` at offset 2"),
            (b"{ /x 1 def }", "token `/x` at offset 2"),
            (b"{ <414243> pop }", "token `<` at offset 2"),
            (b"{ [ 1 ] pop }", "token `[` at offset 2"),
            (b"{ << >> pop }", "token `<` at offset 2"),
            (b"{ { dup } exec }", "token `exec` at offset 10"),
            (b"{ { dup } 1 if }", "procedure at offset 2 is not an if/ifelse operand"),
            (b"{ { dup } }", "procedure at offset 2 is not an if/ifelse operand"),
            (b"{ { a } { b } if }", "token `a` at offset 4"),
            (b"{ { } { } if }", "procedure at offset 2 is not an if/ifelse operand"),
            (b"{ true if }", "`if` without its procedure operands"),
            (b"{ true { } ifelse }", "procedure at offset 7 is not an if/ifelse operand"),
            (b"{ true ifelse }", "`ifelse` without its procedure operands"),
            (b"{ dup } }", "unbalanced `}` at offset 8"),
            (b"{ dup ", "unclosed `{`"),
            (b"{ } { }", "program is not a single { } procedure"),
            (b"1 { }", "program is not a single { } procedure"),
            (b"{ } if", "program is not a single { } procedure"),
            (b"", "empty program"),
            (b" % only a comment", "empty program"),
            (b"{ 100000 index }", "`index` with count 100000"),
            (b"{ -1 copy }", "`copy` with count -1"),
            (b"{ 70000 1 roll }", "`roll` with count 70000"),
            (b"{ 16#FFFFF index }", "`index` with count 1048575"),
            (b"{ DUP }", "token `DUP` at offset 2"),
            (b"{ 1.2.3 }", "token `1.2.3` at offset 2"),
            (b"{ 1e }", "token `1e` at offset 2"),
            (b"{ 37#1 }", "token `37#1` at offset 2"),
            (b"{ 2#102 }", "token `2#102` at offset 2"),
            (b"{ -16#F }", "token `-16#F` at offset 2"),
            (b"{ inf nan }", "token `inf` at offset 2"),
            (b"{ . }", "token `.` at offset 2"),
            (b"{ dup\xffpop }", "token `dup\\xffpop` at offset 2"),
        ];
        for (p, expected) in bad {
            assert_eq!(
                validate(p),
                Err(expected.to_string()),
                "{}",
                String::from_utf8_lossy(p)
            );
        }
        let long = [b"{ ".as_slice(), &b"dup pop ".repeat(MAX_LEN / 8), b"}"].concat();
        assert_eq!(
            validate(&long),
            Err(format!("program is {} bytes (max {MAX_LEN})", long.len()))
        );
        let deep = format!(
            "{}{}",
            "{ true ".repeat(MAX_DEPTH + 1),
            "} if ".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(
            validate(deep.as_bytes()),
            Err(format!("procedures nested deeper than {MAX_DEPTH}"))
        );
        let token = [b"{ ".as_slice(), &[b'x'; 40], b" }"].concat();
        assert_eq!(
            validate(&token),
            Err(format!("token `{}…` at offset 2", "x".repeat(32)))
        );
    }

    fn details(src: &[u8]) -> Vec<Option<String>> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&Type4Function])
            .iter()
            .map(|f| f.detail.clone())
            .collect()
    }

    fn function(num: u32, dict: &str, data: &[u8]) -> Vec<u8> {
        [
            format!(
                "{num} 0 obj << /Domain [0 1] /Range [0 1] {dict} /Length {} >> stream\n",
                data.len()
            )
            .as_bytes(),
            data,
            b"\nendstream endobj\n",
        ]
        .concat()
    }

    #[test]
    fn checks_every_function_stream() {
        let z = miniz_oxide::deflate::compress_to_vec_zlib(ILLUSTRATOR, 6);
        let zbad = miniz_oxide::deflate::compress_to_vec_zlib(b"{ 1 exec }", 6);
        let src = [
            function(1, "/FunctionType 4", ILLUSTRATOR),
            function(2, "/FunctionType 4 /Filter /FlateDecode", &z),
            function(3, "/FunctionType 4.0 /Filter /FlateDecode", &zbad),
            function(4, "/Function#54ype 4", b"{ (x) pop }"),
            function(5, "/FunctionType 9 0 R", b"{ x }"),
            b"9 0 obj 4 endobj\n".to_vec(),
            function(6, "/FunctionType 4 /Filter /Bogus", ILLUSTRATOR),
            function(7, "/FunctionType 4 /Filter /FlateDecode", b"\x78\x9c\xff\xff"),
            function(8, "/FunctionType 2", b"{ exec }"),
            b"10 0 obj << /Shading << /Function << /FunctionType 4 /Domain [0 1] >> >> >> endobj\n"
                .to_vec(),
        ]
        .concat();
        assert_eq!(
            details(&src),
            vec![
                Some("token `exec` at offset 4".into()),
                Some("token `(` at offset 2".into()),
                Some("token `x` at offset 2".into()),
                Some("program cannot be decoded".into()),
                Some("program cannot be decoded".into()),
                Some("function is not a stream".into()),
            ]
        );
    }

    #[test]
    fn truncated_program_is_checked_as_decoded() {
        let body: Vec<u8> = (0..400)
            .flat_map(|i| format!("{i} add {} mul ", i * 7 % 13).into_bytes())
            .collect();
        let program = [b"{ ".as_slice(), &body, b"exec }"].concat();
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&program, 6);
        // The tail (with `exec`) is cut: what decodes is unclosed.
        let src = function(1, "/FunctionType 4 /Filter /FlateDecode", &z[..z.len() / 2]);
        assert_eq!(details(&src), vec![Some("unclosed `{`".into())]);
    }
}
