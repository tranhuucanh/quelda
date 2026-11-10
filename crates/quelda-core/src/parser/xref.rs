//! Cross-reference sections: classic tables (`xref` … `trailer`) and xref
//! streams (`/Type /XRef`, `/W`, `/Index`). Parsing is lenient: whatever
//! rows are readable are kept and the rest is reported as a problem, since
//! xref damage is a structure fact, not a reason to stop.

use super::lexer::{Keyword, Lexer, Token};
use super::object::{Dict, ObjRef, PdfObject};
use super::parse::parse_object_extent;
use crate::limits::Limits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrefKind {
    Table,
    /// Xref stream object `id`.
    Stream(ObjRef),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Free {
        next: u64,
        generation: u64,
    },
    InUse {
        offset: u64,
        generation: u64,
    },
    /// Type 2 (xref streams only): member `index` of object stream `objstm`.
    Compressed {
        objstm: u64,
        index: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XrefEntry {
    pub num: u32,
    pub kind: EntryKind,
}

/// Damage found while reading a section (rows before it are kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrefProblem {
    /// Table: a token that is neither a subsection header, a row nor `trailer`.
    MalformedTable { offset: usize },
    /// Table: fewer rows than the subsection header announces.
    ShortSubsection { offset: usize },
    /// Table: no `trailer` dictionary after the rows.
    MissingTrailer,
    /// Stream: `/W` missing or invalid (not 3 integers in 0..=8, or all 0).
    InvalidW,
    /// Stream: `/Index` invalid; `[0 /Size]` used instead.
    InvalidIndex,
    /// Stream: data ends before the rows `/Index` announces.
    TruncatedRows,
    /// Stream: data could not be (fully) decoded.
    Undecodable,
    /// Object number out of range (> u32).
    NumberOverflow,
}

#[derive(Clone, Debug, PartialEq)]
pub struct XrefSection {
    /// Offset of `xref` (table) or of `N G obj` (stream).
    pub offset: usize,
    pub kind: XrefKind,
    pub entries: Vec<XrefEntry>,
    /// Table: the `trailer` dictionary; stream: the stream dictionary.
    pub trailer: Option<Dict>,
    /// Offset of the `trailer` keyword (tables).
    pub trailer_offset: Option<usize>,
    pub problems: Vec<XrefProblem>,
}

impl XrefSection {
    /// Every `/Prev` value (duplicate keys included) that is a valid offset.
    pub fn prevs(&self) -> Vec<usize> {
        self.offsets_of("Prev")
    }

    /// Every `/XRefStm` value (hybrid files) that is a valid offset.
    pub fn xref_stms(&self) -> Vec<usize> {
        self.offsets_of("XRefStm")
    }

    fn offsets_of(&self, key: &str) -> Vec<usize> {
        self.trailer
            .iter()
            .flat_map(|t| t.get_all(key))
            .filter_map(|o| usize::try_from(o.as_int()?).ok())
            .collect()
    }
}

fn int(tok: Option<(usize, Token<'_>)>) -> Option<i64> {
    match tok {
        Some((_, Token::Int(i))) => Some(i),
        _ => None,
    }
}

/// Parses a table whose `xref` keyword is at `offset` (leading whitespace
/// allowed). `None` if there is no `xref` keyword there. Also returns the
/// furthest offset examined (parse work).
pub fn parse_table(src: &[u8], offset: usize, limits: &Limits) -> (Option<XrefSection>, usize) {
    let mut lex = Lexer::at(src, offset);
    let start = match lex.next_token() {
        Ok(Some((start, Token::Keyword(Keyword::Xref)))) => start,
        _ => return (None, lex.furthest()),
    };
    let mut section = XrefSection {
        offset: start,
        kind: XrefKind::Table,
        entries: Vec::new(),
        trailer: None,
        trailer_offset: None,
        problems: Vec::new(),
    };
    let mut work = 0;
    loop {
        let tok = lex.next_token().ok().flatten();
        let first = match tok {
            Some((at, Token::Keyword(Keyword::Trailer))) => {
                section.trailer_offset = Some(at);
                let (result, furthest) = parse_object_extent(src, lex.pos(), limits);
                work = furthest;
                match result {
                    Ok((PdfObject::Dict(d), _)) => section.trailer = Some(d),
                    _ => section.problems.push(XrefProblem::MissingTrailer),
                }
                break;
            }
            Some((_, Token::Int(i))) => i,
            Some((at, _)) => {
                section
                    .problems
                    .push(XrefProblem::MalformedTable { offset: at });
                section.problems.push(XrefProblem::MissingTrailer);
                break;
            }
            None => {
                section.problems.push(XrefProblem::MissingTrailer);
                break;
            }
        };
        let header_at = lex.pos();
        let Some(count) = int(lex.next_token().ok().flatten()) else {
            section
                .problems
                .push(XrefProblem::MalformedTable { offset: header_at });
            section.problems.push(XrefProblem::MissingTrailer);
            break;
        };
        if !read_rows(&mut lex, &mut section, first, count) {
            break;
        }
    }
    (Some(section), lex.furthest().max(work))
}

/// Reads up to `count` rows numbered from `first`. Returns `false` if the
/// table cannot continue (number overflow).
fn read_rows(lex: &mut Lexer<'_>, section: &mut XrefSection, first: i64, count: i64) -> bool {
    let mut k: i64 = 0;
    while k < count {
        let before = lex.pos();
        let row = (
            int(lex.next_token().ok().flatten()),
            int(lex.next_token().ok().flatten()),
            lex.next_token().ok().flatten(),
        );
        let (Some(a), Some(b), Some((_, Token::Operator(t @ (b"n" | b"f"))))) = row else {
            lex.set_pos(before);
            section
                .problems
                .push(XrefProblem::ShortSubsection { offset: before });
            return true;
        };
        let Some(num) = first.checked_add(k).and_then(|n| u32::try_from(n).ok()) else {
            section.problems.push(XrefProblem::NumberOverflow);
            return false;
        };
        let (a, b) = (a.max(0) as u64, b.max(0) as u64);
        let kind = if t == b"n" {
            EntryKind::InUse {
                offset: a,
                generation: b,
            }
        } else {
            EntryKind::Free {
                next: a,
                generation: b,
            }
        };
        section.entries.push(XrefEntry { num, kind });
        k += 1;
    }
    true
}

/// Rows of an xref stream from its dictionary and decoded data.
pub fn parse_stream_rows(dict: &Dict, data: &[u8]) -> (Vec<XrefEntry>, Vec<XrefProblem>) {
    let mut problems = Vec::new();
    let w: Option<Vec<usize>> = dict.get("W").and_then(PdfObject::as_array).and_then(|a| {
        a.iter()
            .map(|o| {
                o.as_int()
                    .and_then(|i| usize::try_from(i).ok())
                    .filter(|&i| i <= 8)
            })
            .collect::<Option<Vec<_>>>()
    });
    let w = match w {
        Some(w) if w.len() == 3 && w.iter().sum::<usize>() > 0 => w,
        _ => return (Vec::new(), vec![XrefProblem::InvalidW]),
    };
    let width: usize = w.iter().sum();
    let size = dict
        .get("Size")
        .and_then(PdfObject::as_int)
        .unwrap_or(0)
        .max(0);
    let index: Option<Vec<(i64, i64)>> = match dict.get("Index") {
        None => Some(vec![(0, size)]),
        Some(o) => o.as_array().and_then(|a| {
            if a.len() % 2 != 0 {
                return None;
            }
            a.chunks(2)
                .map(|p| Some((p[0].as_int()?, p[1].as_int()?)))
                .collect()
        }),
    };
    let index = index.unwrap_or_else(|| {
        problems.push(XrefProblem::InvalidIndex);
        vec![(0, size)]
    });

    let mut entries = Vec::new();
    let mut rows = data.chunks_exact(width);
    'outer: for (first, count) in index {
        let mut k: i64 = 0;
        while k < count.max(0) {
            let Some(row) = rows.next() else {
                problems.push(XrefProblem::TruncatedRows);
                break 'outer;
            };
            let Some(num) = first.checked_add(k).and_then(|n| u32::try_from(n).ok()) else {
                problems.push(XrefProblem::NumberOverflow);
                break 'outer;
            };
            let (f1, rest) = row.split_at(w[0]);
            let (f2, f3) = rest.split_at(w[1]);
            let typ = if w[0] == 0 { 1 } else { be(f1) };
            let kind = match typ {
                0 => Some(EntryKind::Free {
                    next: be(f2),
                    generation: be(f3),
                }),
                1 => Some(EntryKind::InUse {
                    offset: be(f2),
                    generation: be(f3),
                }),
                2 => Some(EntryKind::Compressed {
                    objstm: be(f2),
                    index: be(f3),
                }),
                // Unknown types are null references (ISO 32000-1 §7.5.8.3).
                _ => None,
            };
            if let Some(kind) = kind {
                entries.push(XrefEntry { num, kind });
            }
            k += 1;
        }
    }
    (entries, problems)
}

/// Big-endian unsigned integer (empty → 0).
fn be(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::object::Name;

    fn table(src: &[u8]) -> XrefSection {
        parse_table(src, 0, &Limits::default()).0.unwrap()
    }

    #[test]
    fn classic_table() {
        let src = b"xref\n0 3\n0000000000 65535 f \n0000000015 00000 n \n0000000079 00001 n\r\n7 1\n0000000200 00000 n \ntrailer\n<< /Size 8 /Prev 123 /XRefStm 456 >>\nstartxref";
        let s = table(src);
        assert_eq!(s.offset, 0);
        assert_eq!(s.kind, XrefKind::Table);
        assert!(s.problems.is_empty(), "{:?}", s.problems);
        assert_eq!(s.entries.len(), 4);
        assert_eq!(
            s.entries[0],
            XrefEntry {
                num: 0,
                kind: EntryKind::Free {
                    next: 0,
                    generation: 65535
                }
            }
        );
        assert_eq!(
            s.entries[2],
            XrefEntry {
                num: 2,
                kind: EntryKind::InUse {
                    offset: 79,
                    generation: 1
                }
            }
        );
        assert_eq!(s.entries[3].num, 7);
        assert_eq!(s.prevs(), vec![123]);
        assert_eq!(s.xref_stms(), vec![456]);
        assert!(s.trailer_offset.is_some());
    }

    #[test]
    fn not_a_table() {
        let (s, _) = parse_table(b"  1 0 obj", 0, &Limits::default());
        assert!(s.is_none());
        let (s, _) = parse_table(b"", 0, &Limits::default());
        assert!(s.is_none());
    }

    #[test]
    fn short_subsection_and_missing_trailer() {
        let s =
            table(b"xref\n0 5\n0000000000 65535 f \n0000000015 00000 n \ntrailer\n<< /Size 2 >>");
        assert_eq!(s.entries.len(), 2);
        assert!(matches!(
            s.problems[..],
            [XrefProblem::ShortSubsection { .. }]
        ));
        assert!(s.trailer.is_some());

        let s = table(b"xref\n0 1\n0000000000 65535 f \n");
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.problems, vec![XrefProblem::MissingTrailer]);

        let s = table(b"xref\n0 1\n0000000000 65535 f \nfoo");
        assert!(matches!(
            s.problems[..],
            [
                XrefProblem::MalformedTable { .. },
                XrefProblem::MissingTrailer
            ]
        ));

        let s = table(b"xref\n0 1\n0000000000 65535 f \ntrailer\n[1]");
        assert_eq!(s.problems, vec![XrefProblem::MissingTrailer]);

        let s = table(b"xref\n7 trailer");
        assert!(matches!(
            s.problems[..],
            [
                XrefProblem::MalformedTable { .. },
                XrefProblem::MissingTrailer
            ]
        ));
    }

    #[test]
    fn huge_count_is_bounded_by_rows() {
        let s = table(b"xref\n0 4000000000\n0000000000 65535 f \ntrailer <<>>");
        assert_eq!(s.entries.len(), 1);
        assert!(s.trailer.is_some());
    }

    #[test]
    fn table_number_overflow() {
        let s =
            table(b"xref\n4294967295 2\n0000000000 00000 n \n0000000000 00000 n \ntrailer <<>>");
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.problems, vec![XrefProblem::NumberOverflow]);
    }

    fn dict(entries: Vec<(&str, PdfObject)>) -> Dict {
        Dict::new(
            entries
                .into_iter()
                .map(|(k, v)| (Name::from(k), v))
                .collect(),
        )
    }

    fn ints(v: &[i64]) -> PdfObject {
        PdfObject::Array(v.iter().map(|&i| PdfObject::Int(i)).collect())
    }

    #[test]
    fn stream_rows() {
        let d = dict(vec![
            ("Type", PdfObject::Name(Name::from("XRef"))),
            ("W", ints(&[1, 2, 1])),
            ("Index", ints(&[0, 2, 10, 2])),
            ("Size", PdfObject::Int(12)),
        ]);
        let data = [
            0, 0, 0, 255, // 0: free
            1, 0x01, 0x00, 0, // 1: in use at 256
            2, 0, 9, 3, // 10: compressed in 9, index 3
            7, 0, 0, 0, // 11: unknown type → skipped
        ];
        let (entries, problems) = parse_stream_rows(&d, &data);
        assert!(problems.is_empty());
        assert_eq!(
            entries,
            vec![
                XrefEntry {
                    num: 0,
                    kind: EntryKind::Free {
                        next: 0,
                        generation: 255
                    }
                },
                XrefEntry {
                    num: 1,
                    kind: EntryKind::InUse {
                        offset: 256,
                        generation: 0
                    }
                },
                XrefEntry {
                    num: 10,
                    kind: EntryKind::Compressed {
                        objstm: 9,
                        index: 3
                    }
                },
            ]
        );
    }

    #[test]
    fn stream_type_field_defaults_to_in_use() {
        let d = dict(vec![("W", ints(&[0, 1, 0])), ("Size", PdfObject::Int(2))]);
        let (entries, problems) = parse_stream_rows(&d, &[5, 6]);
        assert!(problems.is_empty());
        assert_eq!(
            entries[1],
            XrefEntry {
                num: 1,
                kind: EntryKind::InUse {
                    offset: 6,
                    generation: 0
                }
            }
        );
    }

    #[test]
    fn stream_problems() {
        let bad_w = |w: PdfObject| parse_stream_rows(&dict(vec![("W", w)]), &[0; 8]);
        assert_eq!(bad_w(ints(&[1, 2])).1, vec![XrefProblem::InvalidW]);
        assert_eq!(bad_w(ints(&[1, 9, 1])).1, vec![XrefProblem::InvalidW]);
        assert_eq!(bad_w(ints(&[0, 0, 0])).1, vec![XrefProblem::InvalidW]);
        assert_eq!(bad_w(ints(&[1, -1, 1])).1, vec![XrefProblem::InvalidW]);
        assert_eq!(bad_w(PdfObject::Null).1, vec![XrefProblem::InvalidW]);

        let d = dict(vec![
            ("W", ints(&[1, 1, 1])),
            ("Size", PdfObject::Int(5)),
            ("Index", ints(&[0])),
        ]);
        let (entries, problems) = parse_stream_rows(&d, &[1, 0, 0, 1, 3, 0]);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            problems,
            vec![XrefProblem::InvalidIndex, XrefProblem::TruncatedRows]
        );

        let d = dict(vec![
            ("W", ints(&[1, 1, 1])),
            ("Index", ints(&[4294967295, 2])),
        ]);
        let (entries, problems) = parse_stream_rows(&d, &[1, 0, 0, 1, 0, 0]);
        assert_eq!(entries.len(), 1);
        assert_eq!(problems, vec![XrefProblem::NumberOverflow]);
    }

    #[test]
    fn duplicate_prev_keys_all_kept() {
        let s = XrefSection {
            offset: 0,
            kind: XrefKind::Table,
            entries: vec![],
            trailer: Some(dict(vec![
                ("Prev", PdfObject::Int(10)),
                ("Prev", PdfObject::Int(20)),
                ("Prev", PdfObject::Int(-1)),
            ])),
            trailer_offset: None,
            problems: vec![],
        };
        assert_eq!(s.prevs(), vec![10, 20]);
        assert!(s.xref_stms().is_empty());
    }
}
