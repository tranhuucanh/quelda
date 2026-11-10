//! Content stream tokenizer: decoded content → operators with operands.
//!
//! Lenient like a reader: a token that fails to lex or an operand that fails
//! to parse is skipped and tokenizing goes on (so an operator hidden inside a
//! broken array is still seen). Inline images (`BI … ID data EI`) are one
//! `BI` operation; their data is not tokenized, except where readers could
//! disagree on where the data ends (see [`tokenize`]).

use std::ops::Range;

use crate::error::IssueCode;
use crate::limits::Limits;
use crate::parser::lexer::{Keyword, Lexer, Token, is_delimiter, is_whitespace};
use crate::parser::{Dict, Name, PdfObject, parse_object_extent};

/// Operands kept per operator; more are dropped (a real operator takes at
/// most a few dozen; `TJ` takes one array).
pub const MAX_OPERANDS: usize = 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct ContentOp<'d> {
    pub operator: &'d [u8],
    pub operands: Vec<PdfObject>,
    /// Offset of the operator in the decoded stream (`BI` for inline images).
    pub offset: usize,
    /// For `BI`: the image dictionary and data.
    pub inline_image: Option<InlineImage>,
}

impl ContentOp<'_> {
    pub fn is(&self, operator: &str) -> bool {
        self.operator == operator.as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InlineImage {
    /// Keys as written (abbreviated or not).
    pub dict: Dict,
    /// Image data in the decoded stream (up to the `EI` that ends it).
    pub data: Range<usize>,
}

impl InlineImage {
    /// First value of the full or abbreviated key.
    pub fn get(&self, full: &str, abbrev: &str) -> Option<&PdfObject> {
        self.dict.get(full).or_else(|| self.dict.get(abbrev))
    }

    /// Data size an unfiltered image needs (`None` if filtered or unknown).
    pub fn expected_len(&self) -> Option<usize> {
        if self.get("Filter", "F").is_some() {
            return None;
        }
        let num = |full, abbrev| {
            self.get(full, abbrev)
                .and_then(PdfObject::as_int)
                .and_then(|i| u64::try_from(i).ok())
        };
        let (w, h) = (num("Width", "W")?, num("Height", "H")?);
        let mask = matches!(self.get("ImageMask", "IM"), Some(PdfObject::Bool(true)));
        let (bpc, comps) = if mask {
            (1, 1)
        } else {
            (
                num("BitsPerComponent", "BPC")?,
                components(self.get("ColorSpace", "CS")?)?,
            )
        };
        let row = w.checked_mul(bpc)?.checked_mul(comps)?.div_ceil(8);
        usize::try_from(row.checked_mul(h)?).ok()
    }
}

fn components(cs: &PdfObject) -> Option<u64> {
    let name = match cs {
        PdfObject::Name(n) => n,
        PdfObject::Array(a) => a.first()?.as_name()?,
        _ => return None,
    };
    Some(match name.as_bytes() {
        b"G" | b"DeviceGray" | b"CalGray" | b"I" | b"Indexed" => 1,
        b"RGB" | b"DeviceRGB" | b"CalRGB" | b"Lab" => 3,
        b"CMYK" | b"DeviceCMYK" => 4,
        _ => return None,
    })
}

/// Tokenizes `data`, calling `f` for each operator. Returns the limit hit,
/// if any (operands nested deeper than `max_nesting_depth`); tokenizing
/// stops there.
///
/// Inline image data ends at the first `EI` between whitespace (what most
/// readers do). An unfiltered image also has a size implied by its
/// dimensions; when that ends earlier, a reader counting bytes would execute
/// the rest as operators, so that part is tokenized too (union).
pub fn tokenize<'d>(
    data: &'d [u8],
    limits: &Limits,
    mut f: impl FnMut(&ContentOp<'d>),
) -> Result<(), IssueCode> {
    // Ranges still to tokenize: the whole stream, then inline image tails.
    let mut ranges: Vec<Range<usize>> = Vec::new();
    ranges.push(0..data.len());
    while let Some(r) = ranges.pop() {
        let Some(src) = data.get(..r.end) else {
            continue;
        };
        let mut lex = Lexer::at(src, r.start);
        let mut operands: Vec<PdfObject> = Vec::new();
        loop {
            let (start, tok) = match lex.next_token() {
                Ok(Some(t)) => t,
                Ok(None) => break,
                Err(_) => {
                    operands.clear();
                    continue;
                }
            };
            let operand = match tok {
                Token::Int(i) => Some(PdfObject::Int(i)),
                Token::Real(x) => Some(PdfObject::Real(x)),
                Token::String(s) => Some(PdfObject::String(s)),
                Token::Name(n) => Some(PdfObject::Name(n)),
                Token::Keyword(Keyword::True) => Some(PdfObject::Bool(true)),
                Token::Keyword(Keyword::False) => Some(PdfObject::Bool(false)),
                Token::Keyword(Keyword::Null) => Some(PdfObject::Null),
                Token::ArrayOpen | Token::DictOpen => {
                    match parse_object_extent(src, start, limits).0 {
                        Ok((o, end)) => {
                            lex.set_pos(end);
                            Some(o)
                        }
                        Err(e) if e.issue_code().is_limit() => return Err(e.issue_code()),
                        // Not a valid object: look inside it.
                        Err(_) => {
                            let open = if matches!(tok, Token::DictOpen) { 2 } else { 1 };
                            lex.set_pos(start + open);
                            operands.clear();
                            None
                        }
                    }
                }
                Token::ArrayClose | Token::DictClose | Token::BraceOpen | Token::BraceClose => {
                    operands.clear();
                    None
                }
                Token::Keyword(_) | Token::Operator(_) => {
                    let operator = src.get(start..lex.pos()).unwrap_or_default();
                    if operator == b"BI" {
                        let (img, resume) = inline_image(src, &mut lex, limits)?;
                        if let Some(n) = img.expected_len() {
                            let implied = img.data.start.saturating_add(n);
                            if implied < img.data.end {
                                ranges.push(implied..img.data.end);
                            }
                        }
                        f(&ContentOp {
                            operator,
                            operands: Vec::new(),
                            offset: start,
                            inline_image: Some(img),
                        });
                        lex.set_pos(resume);
                    } else {
                        let op = ContentOp {
                            operator,
                            operands: std::mem::take(&mut operands),
                            offset: start,
                            inline_image: None,
                        };
                        f(&op);
                        // Reuse the allocation for the next operator.
                        operands = op.operands;
                    }
                    operands.clear();
                    None
                }
            };
            if let Some(o) = operand {
                if operands.len() < MAX_OPERANDS {
                    operands.push(o);
                }
            }
        }
    }
    Ok(())
}

/// Reads an inline image after `BI`: key/value pairs up to `ID`, then the
/// data up to `EI`. Returns the image and where tokenizing resumes.
fn inline_image(
    src: &[u8],
    lex: &mut Lexer<'_>,
    limits: &Limits,
) -> Result<(InlineImage, usize), IssueCode> {
    let mut entries: Vec<(Name, PdfObject)> = Vec::new();
    let mut key: Option<Name> = None;
    let id_end = loop {
        let (start, tok) = match lex.next_token() {
            Ok(Some(t)) => t,
            Ok(None) => break src.len(),
            Err(_) => continue,
        };
        let value = match tok {
            Token::Operator(b"ID") => break lex.pos(),
            Token::Name(n) if key.is_none() => {
                key = Some(n);
                continue;
            }
            Token::Name(n) => PdfObject::Name(n),
            Token::Int(i) => PdfObject::Int(i),
            Token::Real(x) => PdfObject::Real(x),
            Token::String(s) => PdfObject::String(s),
            Token::Keyword(Keyword::True) => PdfObject::Bool(true),
            Token::Keyword(Keyword::False) => PdfObject::Bool(false),
            Token::Keyword(Keyword::Null) => PdfObject::Null,
            Token::ArrayOpen | Token::DictOpen => match parse_object_extent(src, start, limits).0 {
                Ok((o, end)) => {
                    lex.set_pos(end);
                    o
                }
                Err(e) if e.issue_code().is_limit() => return Err(e.issue_code()),
                Err(_) => continue,
            },
            // Anything else: not a well-formed image dictionary; the data
            // still starts at the next `ID`.
            _ => continue,
        };
        if let Some(k) = key.take() {
            entries.push((k, value));
        }
    };
    // One whitespace byte separates `ID` from the data.
    let data_start = match src.get(id_end) {
        Some(&b) if is_whitespace(b) => id_end + 1,
        _ => id_end,
    };
    let (data_end, resume) = match find_ei(src, data_start) {
        Some(ei) => {
            let end = if ei > data_start && src.get(ei - 1).is_some_and(|&b| is_whitespace(b)) {
                ei - 1
            } else {
                ei
            };
            (end, ei + 2)
        }
        None => (src.len(), src.len()),
    };
    Ok((
        InlineImage {
            dict: Dict::new(entries),
            data: data_start..data_end.max(data_start),
        },
        resume,
    ))
}

/// First `EI` at or after `from` preceded by whitespace (or at `from`) and
/// followed by whitespace, a delimiter or the end.
fn find_ei(src: &[u8], from: usize) -> Option<usize> {
    let rest = src.get(from..)?;
    rest.windows(2)
        .enumerate()
        .filter(|(_, w)| w == b"EI")
        .map(|(i, _)| from + i)
        .find(|&i| {
            let before = i == from || src.get(i - 1).is_some_and(|&b| is_whitespace(b));
            let after = src
                .get(i + 2)
                .is_none_or(|&b| is_whitespace(b) || is_delimiter(b));
            before && after
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops(data: &[u8]) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        tokenize(data, &Limits::default(), |op| {
            out.push((
                String::from_utf8_lossy(op.operator).into_owned(),
                op.operands.len(),
            ))
        })
        .unwrap();
        out
    }

    fn names(data: &[u8]) -> Vec<String> {
        ops(data).into_iter().map(|(n, _)| n).collect()
    }

    #[test]
    fn operators_with_operands() {
        let got =
            ops(b"q 1 0 0 1 72 72 cm BT /F1 12 Tf [(a) 2 (b)] TJ (x) Tj ET Q true false null d0");
        assert_eq!(
            got,
            vec![
                ("q".into(), 0),
                ("cm".into(), 6),
                ("BT".into(), 0),
                ("Tf".into(), 2),
                ("TJ".into(), 1),
                ("Tj".into(), 1),
                ("ET".into(), 0),
                ("Q".into(), 0),
                ("d0".into(), 3),
            ]
        );
    }

    #[test]
    fn operand_values() {
        let mut seen = Vec::new();
        tokenize(b"/GS1 gs << /A 1 >> BDC", &Limits::default(), |op| {
            seen.push(op.operands.clone())
        })
        .unwrap();
        assert_eq!(seen[0], vec![PdfObject::Name(Name::from("GS1"))]);
        assert!(seen[1][0].as_dict().is_some());
    }

    #[test]
    fn ps_operator_found_strings_and_names_are_not_operators() {
        assert_eq!(names(b"q PS Q"), vec!["q", "PS", "Q"]);
        assert_eq!(names(b"(PS) Tj"), vec!["Tj"]);
        assert_eq!(names(b"q /PS gs Q"), vec!["q", "gs", "Q"]);
        assert_eq!(names(b"% PS in a comment\nQ"), vec!["Q"]);
    }

    #[test]
    fn broken_array_is_looked_into() {
        assert_eq!(names(b"[1 2 PS"), vec!["PS"]);
        assert_eq!(names(b"<< /A PS >> x"), vec!["PS", "x"]);
    }

    #[test]
    fn lex_errors_are_skipped() {
        // The lexer resumes right after the bad byte: `z>` is then an operator.
        assert_eq!(names(b") q <zz> PS"), vec!["q", "z", "PS"]);
        assert_eq!(names(b"(unterminated PS"), Vec::<String>::new());
        assert_eq!(names(b""), Vec::<String>::new());
    }

    #[test]
    fn inline_image_data_is_not_tokenized() {
        let data = b"q BI /W 2 /H 1 /BPC 8 /CS /G ID PS EI Q";
        let mut imgs = Vec::new();
        let mut list = Vec::new();
        tokenize(data, &Limits::default(), |op| {
            list.push(String::from_utf8_lossy(op.operator).into_owned());
            if let Some(i) = &op.inline_image {
                imgs.push(i.clone());
            }
        })
        .unwrap();
        assert_eq!(list, vec!["q", "BI", "Q"]);
        let img = &imgs[0];
        assert_eq!(&data[img.data.clone()], b"PS");
        assert_eq!(img.expected_len(), Some(2));
        assert_eq!(img.get("Width", "W"), Some(&PdfObject::Int(2)));
    }

    #[test]
    fn bytes_past_implied_size_are_tokenized() {
        // 1×1 gray image = 1 byte; a byte-counting reader runs ` PS` as code.
        assert_eq!(
            names(b"BI /W 1 /H 1 /BPC 8 /CS /G ID X PS EI Q"),
            vec!["BI", "Q", "PS"]
        );
        // Filtered: size unknown, nothing extra.
        assert_eq!(
            names(b"BI /W 1 /H 1 /BPC 8 /CS /G /F /AHx ID X PS EI Q"),
            vec!["BI", "Q"]
        );
    }

    #[test]
    fn ei_needs_whitespace_around() {
        let mut data_seen = Vec::new();
        let src = b"BI /W 9 /H 1 /BPC 8 /CS /G ID aEIb EIx EI Q";
        tokenize(src, &Limits::default(), |op| {
            if let Some(i) = &op.inline_image {
                data_seen.push(src[i.data.clone()].to_vec());
            }
        })
        .unwrap();
        assert_eq!(data_seen, vec![b"aEIb EIx".to_vec()]);
        // No EI at all: data runs to the end.
        assert_eq!(names(b"BI /W 1 ID PS"), vec!["BI"]);
    }

    #[test]
    fn expected_len_variants() {
        let img = |d: &[u8]| {
            let mut out = None;
            tokenize(d, &Limits::default(), |op| out = op.inline_image.clone()).unwrap();
            out.unwrap()
        };
        assert_eq!(
            img(b"BI /W 10 /H 2 /IM true ID x EI").expected_len(),
            Some(4)
        );
        assert_eq!(
            img(b"BI /W 3 /H 2 /BPC 8 /CS /RGB ID x EI").expected_len(),
            Some(18)
        );
        assert_eq!(
            img(b"BI /W 3 /H 2 /BPC 8 /CS /CS0 ID x EI").expected_len(),
            None
        );
        assert_eq!(
            img(b"BI /W 3 /H 2 /BPC 8 /CS [/I /RGB 1 <00>] ID x EI").expected_len(),
            Some(6)
        );
        assert_eq!(
            img(b"BI /W -3 /H 2 /BPC 8 /CS /G ID x EI").expected_len(),
            None
        );
    }

    #[test]
    fn deep_operand_is_a_limit() {
        let mut data = vec![b'['; 1000];
        data.extend_from_slice(b" PS");
        let r = tokenize(&data, &Limits::default(), |_| {});
        assert_eq!(r, Err(IssueCode::LimitNestingDepth));
    }

    #[test]
    fn operand_count_is_capped() {
        let mut data = b"1 ".repeat(MAX_OPERANDS + 10);
        data.extend_from_slice(b"re");
        assert_eq!(ops(&data), vec![("re".into(), MAX_OPERANDS)]);
    }

    #[test]
    fn garbage_never_hangs() {
        let mut seed = 0x2545_f491_u32;
        for _ in 0..300 {
            let data: Vec<u8> = (0..200)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    b"BIDE []<>()/ \n0PS%"[(seed % 18) as usize]
                })
                .collect();
            let _ = tokenize(&data, &Limits::default(), |_| {});
        }
    }
}
