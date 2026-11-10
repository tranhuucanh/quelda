//! PDF tokenizer (ISO 32000-2 §7.2–7.3). Shared by object parsing and, later,
//! content streams. Names and strings come out **decoded** (design §4.3):
//! `/J#53` is the name `JS`, `(\101)` and `<41>` are the bytes `A`.
//!
//! Every call to [`Lexer::next_token`] either advances, reports end of input,
//! or returns an error, so loops over tokens always terminate.

use std::fmt;

use super::object::Name;

/// Keywords the object parser and structure parser care about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyword {
    Obj,
    EndObj,
    Stream,
    EndStream,
    R,
    True,
    False,
    Null,
    Xref,
    Trailer,
    StartXref,
}

impl Keyword {
    fn from_bytes(b: &[u8]) -> Option<Keyword> {
        Some(match b {
            b"obj" => Keyword::Obj,
            b"endobj" => Keyword::EndObj,
            b"stream" => Keyword::Stream,
            b"endstream" => Keyword::EndStream,
            b"R" => Keyword::R,
            b"true" => Keyword::True,
            b"false" => Keyword::False,
            b"null" => Keyword::Null,
            b"xref" => Keyword::Xref,
            b"trailer" => Keyword::Trailer,
            b"startxref" => Keyword::StartXref,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Token<'a> {
    Int(i64),
    Real(f64),
    /// Literal or hex string, escapes decoded.
    String(Vec<u8>),
    /// Name with `#xx` escapes decoded (without the leading `/`).
    Name(Name),
    ArrayOpen,
    ArrayClose,
    DictOpen,
    DictClose,
    /// `{` / `}` (PostScript calculator functions).
    BraceOpen,
    BraceClose,
    Keyword(Keyword),
    /// Any other run of regular characters: content stream operators
    /// (`BT`, `Tj`, `PS`, …) and junk.
    Operator(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LexErrorKind {
    /// End of input inside `( … )`.
    UnterminatedString,
    /// End of input inside `< … >`.
    UnterminatedHexString,
    /// Character other than a hex digit or whitespace inside `< … >`.
    InvalidHexDigit,
    /// `)` or a single `>` outside any token.
    UnexpectedDelimiter(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LexError {
    pub kind: LexErrorKind,
    /// Offset of the token that failed.
    pub offset: usize,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            LexErrorKind::UnterminatedString => f.write_str("unterminated literal string"),
            LexErrorKind::UnterminatedHexString => f.write_str("unterminated hex string"),
            LexErrorKind::InvalidHexDigit => f.write_str("invalid character in hex string"),
            LexErrorKind::UnexpectedDelimiter(b) => {
                write!(f, "unexpected delimiter {:?}", char::from(b))
            }
        }
    }
}

/// PDF whitespace (Table 1): NUL, TAB, LF, FF, CR, SPACE.
pub fn is_whitespace(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// PDF delimiters (Table 2).
pub fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// Neither whitespace nor delimiter.
pub fn is_regular(b: u8) -> bool {
    !is_whitespace(b) && !is_delimiter(b)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
    /// Furthest position any token reached (rewinds do not lower it).
    furthest: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Lexer::at(data, 0)
    }

    /// Lexer starting at `pos` (clamped to the end of `data`).
    pub fn at(data: &'a [u8], pos: usize) -> Self {
        let pos = pos.min(data.len());
        Lexer {
            data,
            pos,
            furthest: pos,
        }
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Furthest offset read so far: how much input lexing has examined,
    /// including bytes consumed by failed tokens and later rewound.
    pub fn furthest(&self) -> usize {
        self.furthest.max(self.pos)
    }

    /// Moves to `pos` (clamped to the end of `data`).
    pub fn set_pos(&mut self, pos: usize) {
        self.furthest = self.furthest();
        self.pos = pos.min(self.data.len());
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.data.get(self.pos + ahead).copied()
    }

    /// Skips whitespace and comments.
    pub fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if is_whitespace(b) {
                self.pos += 1;
            } else if b == b'%' {
                while let Some(c) = self.peek() {
                    if c == b'\n' || c == b'\r' {
                        break;
                    }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    /// Next token with its start offset; `Ok(None)` at end of input.
    /// On error the position is left just past the offending byte(s).
    pub fn next_token(&mut self) -> Result<Option<(usize, Token<'a>)>, LexError> {
        self.skip_whitespace();
        let start = self.pos;
        let Some(b) = self.peek() else {
            return Ok(None);
        };
        let err = |kind| LexError {
            kind,
            offset: start,
        };
        let tok = match b {
            b'[' => {
                self.pos += 1;
                Token::ArrayOpen
            }
            b']' => {
                self.pos += 1;
                Token::ArrayClose
            }
            b'{' => {
                self.pos += 1;
                Token::BraceOpen
            }
            b'}' => {
                self.pos += 1;
                Token::BraceClose
            }
            b'<' if self.peek_at(1) == Some(b'<') => {
                self.pos += 2;
                Token::DictOpen
            }
            b'>' if self.peek_at(1) == Some(b'>') => {
                self.pos += 2;
                Token::DictClose
            }
            b'<' => {
                self.pos += 1;
                Token::String(self.hex_string().map_err(err)?)
            }
            b'(' => {
                self.pos += 1;
                Token::String(self.literal_string().map_err(err)?)
            }
            b'/' => {
                self.pos += 1;
                Token::Name(self.name())
            }
            b')' | b'>' => {
                self.pos += 1;
                return Err(err(LexErrorKind::UnexpectedDelimiter(b)));
            }
            _ => {
                let run = self.regular_run();
                classify(run)
            }
        };
        Ok(Some((start, tok)))
    }

    fn regular_run(&mut self) -> &'a [u8] {
        let start = self.pos;
        while self.peek().is_some_and(is_regular) {
            self.pos += 1;
        }
        &self.data[start..self.pos]
    }

    /// After `/`: name bytes up to whitespace/delimiter, `#xx` decoded.
    /// A `#` not followed by two hex digits is kept literally.
    fn name(&mut self) -> Name {
        let run = self.regular_run();
        let mut out = Vec::with_capacity(run.len());
        let mut i = 0;
        while let Some(&b) = run.get(i) {
            if b == b'#' {
                let h = run.get(i + 1).copied().and_then(hex_val);
                let l = run.get(i + 2).copied().and_then(hex_val);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
            }
            out.push(b);
            i += 1;
        }
        Name::new(out)
    }

    /// After `(`: balanced parentheses, escapes, EOL normalized to LF.
    fn literal_string(&mut self) -> Result<Vec<u8>, LexErrorKind> {
        let mut out = Vec::new();
        let mut depth = 1usize;
        loop {
            let b = self.peek().ok_or(LexErrorKind::UnterminatedString)?;
            self.pos += 1;
            match b {
                b'(' => {
                    depth += 1;
                    out.push(b);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(out);
                    }
                    out.push(b);
                }
                b'\\' => {
                    let c = self.peek().ok_or(LexErrorKind::UnterminatedString)?;
                    self.pos += 1;
                    match c {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'0'..=b'7' => {
                            let mut v = u32::from(c - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        v = v * 8 + u32::from(d - b'0');
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }
                            // High-order overflow is ignored (§7.3.4.2).
                            out.push((v & 0xFF) as u8);
                        }
                        // Line continuation: backslash + EOL produces nothing.
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.pos += 1;
                            }
                        }
                        b'\n' => {}
                        // `\(`, `\)`, `\\`, and unknown escapes: the backslash is dropped.
                        _ => out.push(c),
                    }
                }
                b'\r' => {
                    if self.peek() == Some(b'\n') {
                        self.pos += 1;
                    }
                    out.push(b'\n');
                }
                _ => out.push(b),
            }
        }
    }

    /// After `<`: hex digits and whitespace; an odd final digit is padded with 0.
    fn hex_string(&mut self) -> Result<Vec<u8>, LexErrorKind> {
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        loop {
            let b = self.peek().ok_or(LexErrorKind::UnterminatedHexString)?;
            self.pos += 1;
            if b == b'>' {
                if let Some(h) = high {
                    out.push(h << 4);
                }
                return Ok(out);
            }
            if is_whitespace(b) {
                continue;
            }
            let v = hex_val(b).ok_or(LexErrorKind::InvalidHexDigit)?;
            match high.take() {
                Some(h) => out.push(h << 4 | v),
                None => high = Some(v),
            }
        }
    }
}

/// Number, keyword or operator from a run of regular characters.
fn classify(run: &[u8]) -> Token<'_> {
    if let Some(tok) = number(run) {
        return tok;
    }
    match Keyword::from_bytes(run) {
        Some(k) => Token::Keyword(k),
        None => Token::Operator(run),
    }
}

/// `[+-]? digits [. digits]` or `[+-]? . digits` (at least one digit, no exponent).
fn number(run: &[u8]) -> Option<Token<'static>> {
    let body = match run.first() {
        Some(b'+' | b'-') => &run[1..],
        _ => run,
    };
    let mut digits = 0usize;
    let mut dots = 0usize;
    for &b in body {
        match b {
            b'0'..=b'9' => digits += 1,
            b'.' => dots += 1,
            _ => return None,
        }
    }
    if digits == 0 || dots > 1 {
        return None;
    }
    // Only ASCII digits, sign and dot here, so this is valid UTF-8.
    let s = std::str::from_utf8(run).ok()?;
    if dots == 0 {
        if let Ok(i) = s.parse::<i64>() {
            return Some(Token::Int(i));
        }
    }
    // Reals, and integers too large for i64.
    s.parse::<f64>().ok().map(Token::Real)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &[u8]) -> Vec<Token<'_>> {
        let mut lx = Lexer::new(src);
        let mut out = Vec::new();
        while let Some((_, t)) = lx.next_token().unwrap() {
            out.push(t);
        }
        out
    }

    fn one(src: &[u8]) -> Token<'_> {
        let t = toks(src);
        assert_eq!(t.len(), 1, "{t:?}");
        t.into_iter().next().unwrap()
    }

    fn err(src: &[u8]) -> LexError {
        let mut lx = Lexer::new(src);
        loop {
            match lx.next_token() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("no error for {:?}", String::from_utf8_lossy(src)),
                Err(e) => return e,
            }
        }
    }

    fn name(s: &str) -> Token<'static> {
        Token::Name(Name::new(s.as_bytes().to_vec()))
    }

    fn string(b: &[u8]) -> Token<'static> {
        Token::String(b.to_vec())
    }

    #[test]
    fn integers() {
        assert_eq!(one(b"0"), Token::Int(0));
        assert_eq!(one(b"123"), Token::Int(123));
        assert_eq!(one(b"+3"), Token::Int(3));
        assert_eq!(one(b"-17"), Token::Int(-17));
        assert_eq!(one(b"-0"), Token::Int(0));
        assert_eq!(one(b"007"), Token::Int(7));
    }

    #[test]
    fn reals() {
        assert_eq!(one(b".5"), Token::Real(0.5));
        assert_eq!(one(b"-.002"), Token::Real(-0.002));
        assert_eq!(one(b"+.5"), Token::Real(0.5));
        assert_eq!(one(b"4."), Token::Real(4.0));
        assert_eq!(one(b"34.5"), Token::Real(34.5));
        assert_eq!(one(b"-3.62"), Token::Real(-3.62));
    }

    #[test]
    fn huge_integer_becomes_real() {
        assert_eq!(one(b"99999999999999999999"), Token::Real(1e20));
    }

    #[test]
    fn non_numbers_are_operators() {
        assert_eq!(one(b"-"), Token::Operator(b"-"));
        assert_eq!(one(b"."), Token::Operator(b"."));
        assert_eq!(one(b"1.2.3"), Token::Operator(b"1.2.3"));
        assert_eq!(one(b"1e5"), Token::Operator(b"1e5"));
        assert_eq!(one(b"--5"), Token::Operator(b"--5"));
        assert_eq!(one(b"12abc"), Token::Operator(b"12abc"));
    }

    #[test]
    fn keywords_and_operators() {
        assert_eq!(
            toks(b"obj endobj stream endstream R true false null xref trailer startxref"),
            vec![
                Token::Keyword(Keyword::Obj),
                Token::Keyword(Keyword::EndObj),
                Token::Keyword(Keyword::Stream),
                Token::Keyword(Keyword::EndStream),
                Token::Keyword(Keyword::R),
                Token::Keyword(Keyword::True),
                Token::Keyword(Keyword::False),
                Token::Keyword(Keyword::Null),
                Token::Keyword(Keyword::Xref),
                Token::Keyword(Keyword::Trailer),
                Token::Keyword(Keyword::StartXref),
            ]
        );
        assert_eq!(
            toks(b"BT Tj PS T* ' \""),
            vec![
                Token::Operator(b"BT"),
                Token::Operator(b"Tj"),
                Token::Operator(b"PS"),
                Token::Operator(b"T*"),
                Token::Operator(b"'"),
                Token::Operator(b"\""),
            ]
        );
        // Keywords are case-sensitive and whole-token.
        assert_eq!(one(b"Obj"), Token::Operator(b"Obj"));
        assert_eq!(one(b"objx"), Token::Operator(b"objx"));
    }

    #[test]
    fn delimiters() {
        assert_eq!(
            toks(b"[]<<>>{}"),
            vec![
                Token::ArrayOpen,
                Token::ArrayClose,
                Token::DictOpen,
                Token::DictClose,
                Token::BraceOpen,
                Token::BraceClose,
            ]
        );
        // Delimiters end tokens without whitespace.
        assert_eq!(
            toks(b"[1/A(x)<41>]"),
            vec![
                Token::ArrayOpen,
                Token::Int(1),
                name("A"),
                string(b"x"),
                string(b"A"),
                Token::ArrayClose,
            ]
        );
    }

    #[test]
    fn names_are_decoded() {
        assert_eq!(one(b"/J#53"), name("JS"));
        assert_eq!(one(b"/#4A#53"), name("JS"));
        assert_eq!(one(b"/#6a#73"), name("js"));
        assert_eq!(one(b"/A#20B"), name("A B"));
        assert_eq!(one(b"/Launch"), name("Launch"));
        assert_eq!(one(b"/"), name(""));
        assert_eq!(one(b"/1.5"), name("1.5"));
        // Invalid escapes are kept literally.
        assert_eq!(one(b"/A#G1"), name("A#G1"));
        assert_eq!(one(b"/A#4"), name("A#4"));
        assert_eq!(one(b"/A#"), name("A#"));
        // Non-UTF-8 bytes survive.
        assert_eq!(one(b"/#FF"), Token::Name(Name::new(vec![0xFF])));
    }

    #[test]
    fn name_ends_at_delimiter() {
        assert_eq!(toks(b"/A/B"), vec![name("A"), name("B")]);
        assert_eq!(toks(b"/JS(x)"), vec![name("JS"), string(b"x")]);
    }

    #[test]
    fn literal_string_nesting() {
        assert_eq!(one(b"(a(b)c)"), string(b"a(b)c"));
        assert_eq!(one(b"(()())"), string(b"()()"));
        assert_eq!(one(b"()"), string(b""));
    }

    #[test]
    fn literal_string_escapes() {
        assert_eq!(one(br"(\n\r\t\b\f)"), string(b"\n\r\t\x08\x0C"));
        assert_eq!(one(br"(\(\)\\)"), string(b"()\\"));
        assert_eq!(one(br"(a\)b)"), string(b"a)b"));
        assert_eq!(one(br"(\q)"), string(b"q"));
    }

    #[test]
    fn literal_string_octal() {
        assert_eq!(one(br"(\101)"), string(b"A"));
        assert_eq!(one(br"(\53)"), string(b"+"));
        assert_eq!(one(br"(\0)"), string(b"\0"));
        assert_eq!(one(br"(\0053)"), string(b"\x053"));
        assert_eq!(one(br"(\1012)"), string(b"A2"));
        // Overflow: high-order bits ignored.
        assert_eq!(one(br"(\777)"), string(b"\xFF"));
        assert_eq!(one(br"(\8)"), string(b"8"));
    }

    #[test]
    fn literal_string_line_continuation_and_eol() {
        assert_eq!(one(b"(ab\\\ncd)"), string(b"abcd"));
        assert_eq!(one(b"(ab\\\r\ncd)"), string(b"abcd"));
        assert_eq!(one(b"(ab\\\rcd)"), string(b"abcd"));
        // Unescaped EOLs become LF.
        assert_eq!(one(b"(a\r\nb\rc\nd)"), string(b"a\nb\nc\nd"));
    }

    #[test]
    fn hex_strings() {
        assert_eq!(one(b"<4A53>"), string(b"JS"));
        assert_eq!(one(b"<4a 5 3>"), string(b"JS"));
        assert_eq!(one(b"<>"), string(b""));
        // Odd number of digits: last one padded with 0.
        assert_eq!(one(b"<901FA>"), string(b"\x90\x1F\xA0"));
        assert_eq!(one(b"<7>"), string(b"\x70"));
    }

    #[test]
    fn comments_between_tokens() {
        assert_eq!(
            toks(b"1 % comment ( [ <<\n2%x\r/A%\n"),
            vec![Token::Int(1), Token::Int(2), name("A")]
        );
        assert_eq!(toks(b"% only a comment"), vec![]);
        // `%` inside a string is not a comment.
        assert_eq!(one(b"(50%)"), string(b"50%"));
    }

    #[test]
    fn whitespace_kinds() {
        assert_eq!(
            toks(b"\x001\t2\n3\x0C4\r5 6"),
            (1..=6).map(Token::Int).collect::<Vec<_>>()
        );
    }

    #[test]
    fn token_offsets() {
        let mut lx = Lexer::new(b"  12 /A");
        assert_eq!(lx.next_token().unwrap(), Some((2, Token::Int(12))));
        assert_eq!(lx.pos(), 4);
        assert_eq!(lx.next_token().unwrap(), Some((5, name("A"))));
        assert_eq!(lx.next_token().unwrap(), None);
        assert_eq!(lx.next_token().unwrap(), None);
    }

    #[test]
    fn errors() {
        assert_eq!(
            err(b"(abc"),
            LexError {
                kind: LexErrorKind::UnterminatedString,
                offset: 0
            }
        );
        assert_eq!(err(b"(a\\").kind, LexErrorKind::UnterminatedString);
        assert_eq!(err(b"(a(b)").kind, LexErrorKind::UnterminatedString);
        assert_eq!(err(b"<4A").kind, LexErrorKind::UnterminatedHexString);
        assert_eq!(
            err(b"1 <4X>"),
            LexError {
                kind: LexErrorKind::InvalidHexDigit,
                offset: 2
            }
        );
        assert_eq!(err(b")").kind, LexErrorKind::UnexpectedDelimiter(b')'));
        assert_eq!(err(b"1 >").kind, LexErrorKind::UnexpectedDelimiter(b'>'));
    }

    #[test]
    fn error_advances_position() {
        let mut lx = Lexer::new(b") 1");
        assert!(lx.next_token().is_err());
        assert_eq!(lx.next_token().unwrap(), Some((2, Token::Int(1))));
    }

    #[test]
    fn at_and_set_pos_clamp() {
        let mut lx = Lexer::at(b"12", 100);
        assert_eq!(lx.pos(), 2);
        assert_eq!(lx.next_token().unwrap(), None);
        lx.set_pos(0);
        assert_eq!(lx.next_token().unwrap(), Some((0, Token::Int(12))));
    }
}
