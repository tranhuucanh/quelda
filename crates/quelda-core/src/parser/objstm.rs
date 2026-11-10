//! Object streams (`/Type /ObjStm`): the header of `N` pairs `num offset`,
//! then the members, each a direct object at `/First + offset` of the
//! decoded data. Members are never streams and always have generation 0.

use super::lexer::{Lexer, Token};
use super::object::{Dict, PdfObject};
use super::parse::{ParseError, parse_object_extent};
use crate::limits::Limits;

/// Damage that hides members: the stream cannot be fully inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjStmProblem {
    /// `/First` missing, negative or past the data.
    InvalidFirst,
    /// `/N` missing or negative (the header is read as far as it goes).
    InvalidN,
    /// Fewer `num offset` pairs than `/N`, or a pair out of range.
    MalformedHeader,
    /// A member offset points past the data.
    MemberOutOfRange { index: u32 },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    pub num: u32,
    /// Position in the header (what a type-2 xref entry refers to).
    pub index: u32,
    /// Offset in the decoded data.
    pub offset: usize,
    pub object: Result<PdfObject, ParseError>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ObjStmContents {
    pub members: Vec<Member>,
    pub problems: Vec<ObjStmProblem>,
}

/// Parses the members of an object stream from its dictionary and decoded
/// data. `charge(n)` is called with the work (bytes examined) of each step
/// and returns `false` to stop early.
pub fn parse_members(
    dict: &Dict,
    data: &[u8],
    limits: &Limits,
    mut charge: impl FnMut(usize) -> bool,
) -> ObjStmContents {
    let mut out = ObjStmContents::default();
    let first = dict
        .get("First")
        .and_then(PdfObject::as_int)
        .and_then(|f| usize::try_from(f).ok())
        .filter(|&f| f <= data.len());
    let Some(first) = first else {
        out.problems.push(ObjStmProblem::InvalidFirst);
        return out;
    };
    let n = dict
        .get("N")
        .and_then(PdfObject::as_int)
        .and_then(|n| u64::try_from(n).ok());
    if n.is_none() {
        out.problems.push(ObjStmProblem::InvalidN);
    }

    // The header lies before `/First`; lexing it cannot run past it.
    let header = &data[..first];
    let mut lex = Lexer::new(header);
    let mut pairs: Vec<(u32, usize)> = Vec::new();
    while n.is_none_or(|n| (pairs.len() as u64) < n) {
        let num = lex.next_token();
        let off = lex.next_token();
        match (num, off) {
            (Ok(Some((_, Token::Int(num)))), Ok(Some((_, Token::Int(off))))) => {
                match (u32::try_from(num), usize::try_from(off)) {
                    (Ok(num), Ok(off)) => pairs.push((num, off)),
                    _ => {
                        out.problems.push(ObjStmProblem::MalformedHeader);
                        break;
                    }
                }
            }
            (Ok(None), _) if n.is_none() => break,
            _ => {
                out.problems.push(ObjStmProblem::MalformedHeader);
                break;
            }
        }
    }
    if !charge(lex.furthest()) {
        return out;
    }

    for (index, (num, rel)) in pairs.into_iter().enumerate() {
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        let Some(offset) = first.checked_add(rel).filter(|&o| o < data.len()) else {
            out.problems.push(ObjStmProblem::MemberOutOfRange { index });
            continue;
        };
        let (result, furthest) = parse_object_extent(data, offset, limits);
        out.members.push(Member {
            num,
            index,
            offset,
            object: result.map(|(o, _)| o),
        });
        if !charge(furthest.saturating_sub(offset)) {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ParseErrorKind;
    use crate::parser::object::Name;

    fn dict(n: Option<i64>, first: Option<i64>) -> Dict {
        let mut e = vec![(Name::from("Type"), PdfObject::Name(Name::from("ObjStm")))];
        if let Some(n) = n {
            e.push((Name::from("N"), PdfObject::Int(n)));
        }
        if let Some(f) = first {
            e.push((Name::from("First"), PdfObject::Int(f)));
        }
        Dict::new(e)
    }

    fn members(d: &Dict, data: &[u8]) -> ObjStmContents {
        parse_members(d, data, &Limits::default(), |_| true)
    }

    #[test]
    fn parses_members() {
        let data = b"10 0 11 11 <</A (x)>>\n[1 2 R]\n";
        let c = members(&dict(Some(2), Some(11)), data);
        assert!(c.problems.is_empty(), "{:?}", c.problems);
        assert_eq!(c.members.len(), 2);
        assert_eq!(c.members[0].num, 10);
        assert_eq!(c.members[0].index, 0);
        assert_eq!(c.members[0].offset, 11);
        assert!(matches!(c.members[0].object, Ok(PdfObject::Dict(_))));
        assert_eq!(c.members[1].num, 11);
        assert_eq!(c.members[1].index, 1);
        assert!(matches!(c.members[1].object, Ok(PdfObject::Array(_))));
    }

    #[test]
    fn invalid_first() {
        assert_eq!(
            members(&dict(Some(1), None), b"1 0 1").problems,
            vec![ObjStmProblem::InvalidFirst]
        );
        assert_eq!(
            members(&dict(Some(1), Some(99)), b"1 0 1").problems,
            vec![ObjStmProblem::InvalidFirst]
        );
    }

    #[test]
    fn missing_n_reads_whole_header() {
        let c = members(&dict(None, Some(8)), b"1 0 2 4 (a) (b)");
        assert_eq!(c.problems, vec![ObjStmProblem::InvalidN]);
        assert_eq!(c.members.len(), 2);
        assert!(c.members.iter().all(|m| m.object.is_ok()));
    }

    #[test]
    fn short_header() {
        let c = members(&dict(Some(3), Some(4)), b"1 0 (a)");
        assert_eq!(c.problems, vec![ObjStmProblem::MalformedHeader]);
        assert_eq!(c.members.len(), 1);
        let c = members(&dict(Some(1), Some(5)), b"-1 0 (a)");
        assert_eq!(c.problems, vec![ObjStmProblem::MalformedHeader]);
    }

    #[test]
    fn member_out_of_range_and_broken() {
        let c = members(&dict(Some(2), Some(8)), b"1 99 2 0 (unterminated");
        assert_eq!(
            c.problems,
            vec![ObjStmProblem::MemberOutOfRange { index: 0 }]
        );
        assert_eq!(c.members.len(), 1);
        let err = c.members[0].object.as_ref().unwrap_err();
        assert!(matches!(err.kind, ParseErrorKind::Lex(_)));
    }

    #[test]
    fn charge_can_stop() {
        let mut calls = 0;
        let c = parse_members(
            &dict(Some(2), Some(8)),
            b"1 0 2 4 (a) (b)",
            &Limits::default(),
            |_| {
                calls += 1;
                calls < 2
            },
        );
        assert_eq!(c.members.len(), 1);
    }
}
