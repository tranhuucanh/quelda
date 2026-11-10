//! Object parser: tokens → [`PdfObject`]. Parses direct objects (trailer
//! dicts, object stream members) and indirect objects `N G obj … endobj` at a
//! given offset, including stream data location.
//!
//! The parser is iterative (explicit stack), so nesting depth is bounded only
//! by [`Limits`] — malicious nesting cannot overflow the call stack.

use std::fmt;
use std::ops::Range;

use super::lexer::{Keyword, LexError, Lexer, Token, is_whitespace};
use super::object::{Dict, Name, ObjRef, PdfObject, PdfStream, StreamLength};
use crate::error::{EngineIssue, IssueCode};
use crate::limits::Limits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    Lex(super::lexer::LexErrorKind),
    UnexpectedEof,
    /// A token that cannot start or continue an object here.
    UnexpectedToken,
    /// A dictionary key that is not a name.
    DictKeyNotName,
    /// `>>` right after a key.
    DictMissingValue,
    /// Not `N G obj` with valid object number / generation.
    InvalidObjectHeader,
    /// `stream` without a following `endstream`.
    UnterminatedStream,
    /// More than `limit` arrays/dictionaries open at once.
    NestingDepth {
        limit: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub offset: usize,
}

impl ParseError {
    fn new(kind: ParseErrorKind, offset: usize) -> Self {
        ParseError { kind, offset }
    }

    pub fn issue_code(&self) -> IssueCode {
        match self.kind {
            ParseErrorKind::NestingDepth { .. } => IssueCode::LimitNestingDepth,
            _ => IssueCode::EngineParse,
        }
    }
}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError::new(ParseErrorKind::Lex(e.kind), e.offset)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ParseErrorKind::Lex(kind) => LexError {
                kind,
                offset: self.offset,
            }
            .fmt(f),
            ParseErrorKind::UnexpectedEof => f.write_str("unexpected end of input"),
            ParseErrorKind::UnexpectedToken => f.write_str("unexpected token"),
            ParseErrorKind::DictKeyNotName => f.write_str("dictionary key is not a name"),
            ParseErrorKind::DictMissingValue => f.write_str("dictionary key without value"),
            ParseErrorKind::InvalidObjectHeader => f.write_str("expected `N G obj`"),
            ParseErrorKind::UnterminatedStream => f.write_str("stream without endstream"),
            ParseErrorKind::NestingDepth { limit } => {
                write!(f, "arrays/dictionaries nested deeper than {limit}")
            }
        }
    }
}

impl From<ParseError> for EngineIssue {
    fn from(e: ParseError) -> Self {
        EngineIssue::new(e.issue_code(), Some(e.offset), e.to_string())
    }
}

/// An indirect object parsed at some offset.
#[derive(Clone, Debug, PartialEq)]
pub struct IndirectObject {
    pub id: ObjRef,
    /// Offset of `N` in `N G obj`.
    pub offset: usize,
    pub object: PdfObject,
    /// `endobj` was present.
    pub has_endobj: bool,
    /// End of the object: after `endobj`, or after the value/`endstream` when
    /// `endobj` is missing.
    pub end: usize,
}

/// Parses one direct object starting at `offset`. Returns the object and the
/// offset just after it.
pub fn parse_object(
    src: &[u8],
    offset: usize,
    limits: &Limits,
) -> Result<(PdfObject, usize), ParseError> {
    parse_object_extent(src, offset, limits).0
}

/// [`parse_object`], plus the furthest offset examined (the work done, also
/// when parsing fails).
pub fn parse_object_extent(
    src: &[u8],
    offset: usize,
    limits: &Limits,
) -> (Result<(PdfObject, usize), ParseError>, usize) {
    let mut p = Parser::new(src, offset, limits);
    let result = p.value().map(|obj| (obj, p.lex.pos()));
    (result, p.lex.furthest())
}

/// Parses `N G obj <value> [stream … endstream] [endobj]` starting at `offset`
/// (leading whitespace/comments allowed). A missing `endobj` is tolerated and
/// reported in [`IndirectObject::has_endobj`].
pub fn parse_indirect_object(
    src: &[u8],
    offset: usize,
    limits: &Limits,
) -> Result<IndirectObject, ParseError> {
    parse_indirect_object_extent(src, offset, limits).0
}

/// [`parse_indirect_object`], plus the furthest offset examined (the work
/// done, also when parsing fails; scanning for `endstream` included).
pub fn parse_indirect_object_extent(
    src: &[u8],
    offset: usize,
    limits: &Limits,
) -> (Result<IndirectObject, ParseError>, usize) {
    let mut p = Parser::new(src, offset, limits);
    let mut scanned = 0;
    let result = indirect_object(&mut p, src, &mut scanned);
    (result, p.lex.furthest().max(scanned))
}

fn indirect_object(
    p: &mut Parser<'_>,
    src: &[u8],
    scanned: &mut usize,
) -> Result<IndirectObject, ParseError> {
    let (start, id) = p.object_header()?;
    let mut object = p.value()?;
    if let PdfObject::Dict(dict) = object {
        object = match p.stream_keyword() {
            Some(after_kw) => {
                let (stream, end) = locate_stream(src, dict, after_kw, scanned)?;
                p.lex.set_pos(end);
                PdfObject::Stream(stream)
            }
            None => PdfObject::Dict(dict),
        };
    }
    let before = p.lex.pos();
    let has_endobj = matches!(
        p.lex.next_token(),
        Ok(Some((_, Token::Keyword(Keyword::EndObj))))
    );
    if !has_endobj {
        p.lex.set_pos(before);
    }
    Ok(IndirectObject {
        id,
        offset: start,
        object,
        has_endobj,
        end: p.lex.pos(),
    })
}

/// How many bytes [`object_header_at`] looks at: enough for `N G obj` with
/// some whitespace, small enough that checking many offsets stays cheap.
pub const HEADER_WINDOW: usize = 256;

/// `N G obj` at `offset` (after optional whitespace/comments, all within
/// [`HEADER_WINDOW`] bytes): the offset of `N` and the id. Cheap and bounded,
/// for checking where an xref entry points.
pub fn object_header_at(src: &[u8], offset: usize) -> Option<(usize, ObjRef)> {
    let window = src.get(..offset.saturating_add(HEADER_WINDOW).min(src.len()))?;
    let mut lex = Lexer::at(window, offset);
    let mut tok = || lex.next_token().ok().flatten();
    match (tok(), tok(), tok()) {
        (
            Some((start, Token::Int(num))),
            Some((_, Token::Int(generation))),
            Some((_, Token::Keyword(Keyword::Obj))),
        ) => ObjRef::from_ints(num, generation).map(|id| (start, id)),
        _ => None,
    }
}

/// Given stream data starting at `data_start` and a length, returns the data
/// range and the offset after `endstream` if `endstream` follows the data
/// (after optional whitespace). Used for direct and resolved indirect `/Length`.
pub fn stream_data_with_length(
    src: &[u8],
    data_start: usize,
    length: u64,
) -> Option<(Range<usize>, usize)> {
    let end = data_start.checked_add(usize::try_from(length).ok()?)?;
    if end > src.len() {
        return None;
    }
    let mut i = end;
    while src.get(i).copied().is_some_and(is_whitespace) {
        i += 1;
    }
    src.get(i..)?
        .starts_with(b"endstream")
        .then(|| (data_start..end, i + b"endstream".len()))
}

/// Data range found by scanning for the first `endstream` after `data_start`;
/// the EOL right before `endstream` is not data. Returns the offset after
/// `endstream` too.
pub fn stream_data_by_scan(src: &[u8], data_start: usize) -> Option<(Range<usize>, usize)> {
    let rest = src.get(data_start..)?;
    let at = data_start + find(rest, b"endstream")?;
    let mut end = at;
    if end > data_start && src[end - 1] == b'\n' {
        end -= 1;
    }
    if end > data_start && src[end - 1] == b'\r' {
        end -= 1;
    }
    Some((data_start..end, at + b"endstream".len()))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `after_kw` is the offset right after the `stream` keyword.
/// `scanned` is set to how far the search for `endstream` went.
fn locate_stream(
    src: &[u8],
    dict: Dict,
    after_kw: usize,
    scanned: &mut usize,
) -> Result<(PdfStream, usize), ParseError> {
    // `stream` is followed by CRLF or LF (CR alone tolerated).
    let data_start = match (src.get(after_kw), src.get(after_kw + 1)) {
        (Some(b'\r'), Some(b'\n')) => after_kw + 2,
        (Some(b'\r' | b'\n'), _) => after_kw + 1,
        _ => after_kw,
    };
    let declared = dict.get("Length");
    let direct = declared.and_then(PdfObject::as_int);
    if let Some(len) = direct.and_then(|l| u64::try_from(l).ok()) {
        if let Some((data, end)) = stream_data_with_length(src, data_start, len) {
            let stream = PdfStream {
                dict,
                data_start,
                data,
                length: StreamLength::Declared,
            };
            return Ok((stream, end));
        }
    }
    let length = match declared.and_then(PdfObject::as_reference) {
        Some(r) => StreamLength::Indirect(r),
        None => StreamLength::Scanned { declared: direct },
    };
    *scanned = src.len();
    let (data, end) = stream_data_by_scan(src, data_start).ok_or(ParseError::new(
        ParseErrorKind::UnterminatedStream,
        after_kw,
    ))?;
    *scanned = end;
    let stream = PdfStream {
        dict,
        data_start,
        data,
        length,
    };
    Ok((stream, end))
}

/// Container being built.
enum Frame {
    Array(Vec<PdfObject>),
    Dict {
        entries: Vec<(Name, PdfObject)>,
        key: Option<Name>,
    },
}

struct Parser<'a> {
    lex: Lexer<'a>,
    max_depth: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a [u8], offset: usize, limits: &Limits) -> Self {
        Parser {
            lex: Lexer::at(src, offset),
            max_depth: limits.nesting_depth(),
        }
    }

    fn next(&mut self) -> Result<(usize, Token<'a>), ParseError> {
        self.lex.next_token()?.ok_or(ParseError::new(
            ParseErrorKind::UnexpectedEof,
            self.lex.pos(),
        ))
    }

    /// `N G obj`; returns the offset of `N` and the id.
    fn object_header(&mut self) -> Result<(usize, ObjRef), ParseError> {
        let (start, num) = self.next()?;
        let bad = || ParseError::new(ParseErrorKind::InvalidObjectHeader, start);
        let (_, generation) = self.next().map_err(|_| bad())?;
        let (_, kw) = self.next().map_err(|_| bad())?;
        match (num, generation, kw) {
            (Token::Int(n), Token::Int(g), Token::Keyword(Keyword::Obj)) => ObjRef::from_ints(n, g)
                .map(|id| (start, id))
                .ok_or_else(bad),
            _ => Err(bad()),
        }
    }

    /// If the next token is `stream`, consumes it and returns the offset after it.
    fn stream_keyword(&mut self) -> Option<usize> {
        let before = self.lex.pos();
        match self.lex.next_token() {
            Ok(Some((_, Token::Keyword(Keyword::Stream)))) => Some(self.lex.pos()),
            _ => {
                self.lex.set_pos(before);
                None
            }
        }
    }

    /// After an integer: `G R` makes it a reference. Otherwise the lexer is
    /// rewound so the following tokens are read again normally.
    fn int_or_ref(&mut self, num: i64) -> PdfObject {
        let before = self.lex.pos();
        if let (Ok(Some((_, Token::Int(generation)))), Ok(Some((_, Token::Keyword(Keyword::R))))) =
            (self.lex.next_token(), self.lex.next_token())
        {
            if let Some(r) = ObjRef::from_ints(num, generation) {
                return PdfObject::Ref(r);
            }
        }
        self.lex.set_pos(before);
        PdfObject::Int(num)
    }

    fn push(&self, stack: &mut Vec<Frame>, frame: Frame, at: usize) -> Result<(), ParseError> {
        if stack.len() >= self.max_depth {
            return Err(ParseError::new(
                ParseErrorKind::NestingDepth {
                    limit: self.max_depth,
                },
                at,
            ));
        }
        stack.push(frame);
        Ok(())
    }

    fn value(&mut self) -> Result<PdfObject, ParseError> {
        let mut stack: Vec<Frame> = Vec::new();
        loop {
            let (start, tok) = self.next()?;
            let unexpected = |kind| ParseError::new(kind, start);
            let value = match tok {
                Token::ArrayOpen => {
                    self.push(&mut stack, Frame::Array(Vec::new()), start)?;
                    continue;
                }
                Token::DictOpen => {
                    let frame = Frame::Dict {
                        entries: Vec::new(),
                        key: None,
                    };
                    self.push(&mut stack, frame, start)?;
                    continue;
                }
                Token::ArrayClose => match stack.pop() {
                    Some(Frame::Array(items)) => PdfObject::Array(items),
                    _ => return Err(unexpected(ParseErrorKind::UnexpectedToken)),
                },
                Token::DictClose => match stack.pop() {
                    Some(Frame::Dict { entries, key: None }) => PdfObject::Dict(Dict::new(entries)),
                    Some(Frame::Dict { key: Some(_), .. }) => {
                        return Err(unexpected(ParseErrorKind::DictMissingValue));
                    }
                    _ => return Err(unexpected(ParseErrorKind::UnexpectedToken)),
                },
                Token::Int(n) => self.int_or_ref(n),
                Token::Real(r) => PdfObject::Real(r),
                Token::String(s) => PdfObject::String(s),
                Token::Name(n) => PdfObject::Name(n),
                Token::Keyword(Keyword::True) => PdfObject::Bool(true),
                Token::Keyword(Keyword::False) => PdfObject::Bool(false),
                Token::Keyword(Keyword::Null) => PdfObject::Null,
                Token::Keyword(_) | Token::Operator(_) | Token::BraceOpen | Token::BraceClose => {
                    return Err(unexpected(ParseErrorKind::UnexpectedToken));
                }
            };
            match stack.last_mut() {
                None => return Ok(value),
                Some(Frame::Array(items)) => items.push(value),
                Some(Frame::Dict { entries, key }) => match key.take() {
                    Some(k) => entries.push((k, value)),
                    None => match value {
                        PdfObject::Name(n) => *key = Some(n),
                        _ => return Err(unexpected(ParseErrorKind::DictKeyNotName)),
                    },
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::lexer::LexErrorKind;

    fn parse(src: &[u8]) -> PdfObject {
        parse_object(src, 0, &Limits::default()).unwrap().0
    }

    fn parse_err(src: &[u8]) -> ParseError {
        parse_object(src, 0, &Limits::default()).unwrap_err()
    }

    fn indirect(src: &[u8]) -> IndirectObject {
        parse_indirect_object(src, 0, &Limits::default()).unwrap()
    }

    fn name(s: &str) -> PdfObject {
        PdfObject::Name(Name::from(s))
    }

    fn r(num: u32, generation: u16) -> PdfObject {
        PdfObject::Ref(ObjRef::new(num, generation))
    }

    fn nested(depth: usize) -> Vec<u8> {
        let mut v = b"<< /A ".repeat(depth);
        v.extend(b"1 ");
        v.extend(b">> ".repeat(depth));
        v
    }

    #[test]
    fn scalars() {
        assert_eq!(parse(b"null"), PdfObject::Null);
        assert_eq!(parse(b"true"), PdfObject::Bool(true));
        assert_eq!(parse(b"false"), PdfObject::Bool(false));
        assert_eq!(parse(b"-12"), PdfObject::Int(-12));
        assert_eq!(parse(b".5"), PdfObject::Real(0.5));
        assert_eq!(parse(b"(a\\)b)"), PdfObject::String(b"a)b".to_vec()));
        assert_eq!(parse(b"<4A53>"), PdfObject::String(b"JS".to_vec()));
        assert_eq!(parse(b"/J#53"), name("JS"));
    }

    #[test]
    fn references() {
        assert_eq!(parse(b"12 0 R"), r(12, 0));
        assert_eq!(
            parse(b"[1 0 R 2 3 R 4 5]"),
            PdfObject::Array(vec![r(1, 0), r(2, 3), PdfObject::Int(4), PdfObject::Int(5)])
        );
        // Out-of-range ids are not references; the stray `R` is an error.
        assert_eq!(parse_err(b"[-1 0 R]").kind, ParseErrorKind::UnexpectedToken);
        assert_eq!(
            parse_err(b"[1 70000 R]").kind,
            ParseErrorKind::UnexpectedToken
        );
    }

    #[test]
    fn integer_followed_by_other_tokens_is_not_consumed() {
        let (obj, end) = parse_object(b"5 6 7", 0, &Limits::default()).unwrap();
        assert_eq!(obj, PdfObject::Int(5));
        assert_eq!(end, 1);
        // A lex error after the integer belongs to the next object, not this one.
        let (obj, end) = parse_object(b"5 )", 0, &Limits::default()).unwrap();
        assert_eq!((obj, end), (PdfObject::Int(5), 1));
    }

    #[test]
    fn dict_and_array() {
        let obj = parse(b"<< /Type /Page /Kids [3 0 R] /Count 1 /Sub << /A (x) >> >>");
        let d = obj.as_dict().unwrap();
        assert!(d.get("Type").unwrap().is_name("Page"));
        assert_eq!(d.get("Kids"), Some(&PdfObject::Array(vec![r(3, 0)])));
        assert_eq!(d.get("Count"), Some(&PdfObject::Int(1)));
        let sub = d.get("Sub").and_then(PdfObject::as_dict).unwrap();
        assert_eq!(sub.get("A"), Some(&PdfObject::String(b"x".to_vec())));
        assert_eq!(parse(b"[]"), PdfObject::Array(vec![]));
        assert_eq!(parse(b"<<>>"), PdfObject::Dict(Dict::default()));
    }

    #[test]
    fn dict_keys_are_decoded_and_duplicates_kept() {
        let obj = parse(b"<< /S /JavaScript /J#53 (app.alert\\(1\\)) /JS 5 0 R >>");
        let d = obj.as_dict().unwrap();
        assert!(d.has_duplicate_keys());
        let js: Vec<_> = d.get_all("JS").collect();
        assert_eq!(js.len(), 2);
        assert_eq!(js[1], &r(5, 0));
        assert_eq!(d.duplicate_keys(), vec![&Name::from("JS")]);
    }

    #[test]
    fn comments_inside_objects() {
        let obj = parse(b"<< /A % c1\n 1 %c2\r /B [2 %c3\n 3] >>");
        let d = obj.as_dict().unwrap();
        assert_eq!(d.get("A"), Some(&PdfObject::Int(1)));
        assert_eq!(
            d.get("B"),
            Some(&PdfObject::Array(vec![
                PdfObject::Int(2),
                PdfObject::Int(3)
            ]))
        );
    }

    #[test]
    fn syntax_errors() {
        assert_eq!(parse_err(b"").kind, ParseErrorKind::UnexpectedEof);
        assert_eq!(parse_err(b"[1 2").kind, ParseErrorKind::UnexpectedEof);
        assert_eq!(parse_err(b"<< /A 1").kind, ParseErrorKind::UnexpectedEof);
        assert_eq!(parse_err(b"]").kind, ParseErrorKind::UnexpectedToken);
        assert_eq!(parse_err(b"[1 >>").kind, ParseErrorKind::UnexpectedToken);
        assert_eq!(parse_err(b"<< /A ]").kind, ParseErrorKind::UnexpectedToken);
        assert_eq!(parse_err(b"<< 1 2 >>").kind, ParseErrorKind::DictKeyNotName);
        assert_eq!(
            parse_err(b"<< [1] 2 >>").kind,
            ParseErrorKind::DictKeyNotName
        );
        assert_eq!(
            parse_err(b"<< /A >>").kind,
            ParseErrorKind::DictMissingValue
        );
        assert_eq!(parse_err(b"[BT]").kind, ParseErrorKind::UnexpectedToken);
        assert_eq!(parse_err(b"{ 1 }").kind, ParseErrorKind::UnexpectedToken);
        assert_eq!(parse_err(b"endobj").kind, ParseErrorKind::UnexpectedToken);
        let e = parse_err(b"[(abc");
        assert_eq!(
            e,
            ParseError::new(ParseErrorKind::Lex(LexErrorKind::UnterminatedString), 1)
        );
        assert_eq!(e.issue_code(), IssueCode::EngineParse);
    }

    #[test]
    fn nesting_at_limit_is_ok() {
        let limits = Limits {
            max_nesting_depth: 5,
            ..Limits::default()
        };
        assert!(parse_object(&nested(5), 0, &limits).is_ok());
        let arrays = b"[[[[[1]]]]]";
        assert!(parse_object(arrays, 0, &limits).is_ok());
    }

    #[test]
    fn nesting_over_limit_is_limit_issue() {
        let limits = Limits {
            max_nesting_depth: 5,
            ..Limits::default()
        };
        let e = parse_object(&nested(6), 0, &limits).unwrap_err();
        assert_eq!(e.kind, ParseErrorKind::NestingDepth { limit: 5 });
        assert_eq!(e.offset, 5 * 6);
        assert_eq!(e.issue_code(), IssueCode::LimitNestingDepth);
        let issue = EngineIssue::from(e);
        assert_eq!(issue.code.as_str(), "LIMIT.NESTING_DEPTH");
        assert_eq!(issue.offset, Some(30));
        let e = parse_object(b"[[[[[[1]]]]]]", 0, &limits).unwrap_err();
        assert_eq!(e.kind, ParseErrorKind::NestingDepth { limit: 5 });
    }

    #[test]
    fn very_deep_nesting_does_not_overflow() {
        // 1 000 000 levels: iterative parser stops at the limit.
        let e = parse_object(&b"[".repeat(1_000_000), 0, &Limits::default()).unwrap_err();
        assert_eq!(e.issue_code(), IssueCode::LimitNestingDepth);
        let huge = Limits {
            max_nesting_depth: u32::MAX,
            ..Limits::default()
        };
        let e = parse_object(&nested(100_000), 0, &huge).unwrap_err();
        assert_eq!(
            e.kind,
            ParseErrorKind::NestingDepth {
                limit: crate::limits::HARD_MAX_NESTING_DEPTH as usize
            }
        );
    }

    #[test]
    fn hard_max_depth_object_can_be_dropped_and_compared() {
        // 1 MiB: the wasm32 default stack. Drop/clone/eq/debug recurse.
        std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(|| {
                let depth = crate::limits::HARD_MAX_NESTING_DEPTH as usize;
                let huge = Limits {
                    max_nesting_depth: u32::MAX,
                    ..Limits::default()
                };
                for src in [
                    nested(depth),
                    [b"[".repeat(depth), b"]".repeat(depth)].concat(),
                ] {
                    let a = parse_object(&src, 0, &huge).unwrap().0;
                    let b = a.clone();
                    assert_eq!(a, b);
                    assert!(!format!("{a:?}").is_empty());
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn indirect_object() {
        let o = indirect(b"  12 0 obj\n<< /S /Launch /F (quelda-test.txt) >>\nendobj\n");
        assert_eq!(o.id, ObjRef::new(12, 0));
        assert_eq!(o.offset, 2);
        assert!(o.has_endobj);
        assert_eq!(o.end, 55);
        assert!(
            o.object
                .as_dict()
                .unwrap()
                .get("S")
                .unwrap()
                .is_name("Launch")
        );
    }

    #[test]
    fn indirect_object_at_offset() {
        let src = b"junk 3 1 obj [1 2] endobj";
        let o = parse_indirect_object(src, 5, &Limits::default()).unwrap();
        assert_eq!(o.id, ObjRef::new(3, 1));
        assert_eq!(o.offset, 5);
        assert_eq!(o.end, src.len());
    }

    #[test]
    fn indirect_object_without_endobj() {
        let o = indirect(b"1 0 obj 42 2 0 obj");
        assert_eq!(o.object, PdfObject::Int(42));
        assert!(!o.has_endobj);
        assert_eq!(o.end, 10);
        let o = indirect(b"1 0 obj << /A 1 >>");
        assert!(!o.has_endobj);
        assert_eq!(o.end, 18);
    }

    #[test]
    fn invalid_headers() {
        for src in [
            &b"1 0 R"[..],
            b"1 obj",
            b"-1 0 obj null endobj",
            b"1 70000 obj null endobj",
            b"1.0 0 obj null endobj",
            b"/A 0 obj",
            b"1 0",
            b"",
        ] {
            let e = parse_indirect_object(src, 0, &Limits::default()).unwrap_err();
            assert!(
                matches!(
                    e.kind,
                    ParseErrorKind::InvalidObjectHeader | ParseErrorKind::UnexpectedEof
                ),
                "{src:?}: {e:?}"
            );
        }
    }

    #[test]
    fn stream_with_declared_length() {
        let src = b"4 0 obj\n<< /Length 5 >>\nstream\r\nhello\nendstream\nendobj\n";
        let o = indirect(src);
        let s = o.object.as_stream().unwrap();
        assert_eq!(&src[s.data.clone()], b"hello");
        assert_eq!(s.data_start, 32);
        assert_eq!(s.length, StreamLength::Declared);
        assert!(o.has_endobj);
        assert_eq!(o.end, src.len() - 1);
    }

    #[test]
    fn stream_data_may_contain_endstream_when_length_is_right() {
        let src = b"1 0 obj << /Length 9 >> stream\nendstream\nendstream endobj";
        let s = indirect(src).object.as_stream().cloned().unwrap();
        assert_eq!(&src[s.data], b"endstream");
        assert_eq!(s.length, StreamLength::Declared);
    }

    #[test]
    fn stream_with_wrong_length_falls_back_to_scan() {
        for (src, declared) in [
            (
                &b"1 0 obj << /Length 2 >> stream\nhello\nendstream endobj"[..],
                Some(2),
            ),
            (
                b"1 0 obj << /Length 999 >> stream\nhello\nendstream endobj",
                Some(999),
            ),
            (
                b"1 0 obj << /Length -3 >> stream\nhello\nendstream endobj",
                Some(-3),
            ),
            (
                b"1 0 obj << /Length (5) >> stream\nhello\nendstream endobj",
                None,
            ),
            (b"1 0 obj << >> stream\nhello\r\nendstream endobj", None),
        ] {
            let o = indirect(src);
            let s = o.object.as_stream().unwrap();
            assert_eq!(&src[s.data.clone()], b"hello", "{src:?}");
            assert_eq!(s.length, StreamLength::Scanned { declared });
            assert!(o.has_endobj);
        }
    }

    #[test]
    fn stream_with_indirect_length() {
        let src = b"1 0 obj << /Length 7 0 R >> stream\nhello\nendstream\nendobj";
        let s = indirect(src).object.as_stream().cloned().unwrap();
        assert_eq!(s.length, StreamLength::Indirect(ObjRef::new(7, 0)));
        assert_eq!(&src[s.data.clone()], b"hello");
        // Once resolved (Step 5), the declared length can be applied.
        let (data, end) = stream_data_with_length(src, s.data_start, 5).unwrap();
        assert_eq!(&src[data], b"hello");
        assert_eq!(&src[end..], b"\nendobj");
    }

    #[test]
    fn stream_eol_variants() {
        for (src, data) in [
            (
                &b"1 0 obj << /Length 2 >> stream\r\nab endstream endobj"[..],
                &b"ab"[..],
            ),
            (
                b"1 0 obj << /Length 2 >> stream\nab endstream endobj",
                b"ab",
            ),
            (
                b"1 0 obj << /Length 2 >> stream\rab endstream endobj",
                b"ab",
            ),
            (
                b"1 0 obj << /Length 3 >> stream ab endstream endobj",
                b" ab",
            ),
            (b"1 0 obj << /Length 0 >> stream\nendstream endobj", b""),
        ] {
            let s = indirect(src).object.as_stream().cloned().unwrap();
            assert_eq!(&src[s.data], data, "{src:?}");
        }
    }

    #[test]
    fn unterminated_stream() {
        let e = parse_indirect_object(
            b"1 0 obj << /Length 99 >> stream\nhello",
            0,
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(e.kind, ParseErrorKind::UnterminatedStream);
    }

    #[test]
    fn stream_keyword_only_after_dict() {
        // `stream` after a non-dict is not a stream; `endobj` is then missing.
        let o = indirect(b"1 0 obj [1] stream\nx\nendstream endobj");
        assert_eq!(o.object, PdfObject::Array(vec![PdfObject::Int(1)]));
        assert!(!o.has_endobj);
    }

    #[test]
    fn data_range_helpers() {
        assert_eq!(
            stream_data_with_length(b"abc endstream", 0, 3),
            Some((0..3, 13))
        );
        assert_eq!(stream_data_with_length(b"abc endstream", 0, 2), None);
        assert_eq!(stream_data_with_length(b"abc", 0, u64::MAX), None);
        assert_eq!(stream_data_with_length(b"abc", 10, 0), None);
        assert_eq!(stream_data_by_scan(b"ab\r\nendstream", 0), Some((0..2, 13)));
        assert_eq!(stream_data_by_scan(b"\nendstream", 0), Some((0..0, 10)));
        assert_eq!(stream_data_by_scan(b"abc", 0), None);
        assert_eq!(stream_data_by_scan(b"abc", 10), None);
    }
}
