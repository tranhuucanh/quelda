//! Every dictionary in the union set (design §5.3 `check_dict`): top-level
//! objects, stream dictionaries, object stream members, and dictionaries
//! nested directly in arrays and dictionaries. Each definition is visited
//! once (see `parser::document`); references are not followed.

use crate::parser::document::{Location as Source, ObjectEntry};
use crate::parser::{Dict, Name, ObjRef, PdfObject};

/// One step from an object to a nested value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathSeg {
    Key(Name),
    Index(usize),
}

/// Where a dictionary is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// Index into `Document::objects`.
    pub object: usize,
    pub id: ObjRef,
    /// Top-level offset, or object stream container + member index.
    pub source: Source,
    /// From the object to the dictionary; empty for the object itself (or
    /// the dictionary of a stream object).
    pub path: Vec<PathSeg>,
}

impl Location {
    /// The location of object `objects[object]` itself.
    pub fn of(object: usize, entry: &ObjectEntry) -> Location {
        Location {
            object,
            id: entry.id,
            source: entry.location,
            path: Vec::new(),
        }
    }

    /// Offset of the object: in the file, or in the decoded object stream.
    pub fn offset(&self) -> usize {
        match self.source {
            Source::File { offset } | Source::ObjStm { offset, .. } => offset,
        }
    }

    /// The dictionary is the object itself, not a nested one.
    pub fn is_object(&self) -> bool {
        self.path.is_empty()
    }
}

/// Calls `f` for every dictionary in `objects`, depth-first in file order.
/// Iterative: nesting is bounded by the parser, not by the stack. One path
/// is shared by the whole walk (a step is pushed going down, popped coming
/// back), so deep nesting costs no copies.
pub fn visit_dicts<'a>(objects: &'a [ObjectEntry], mut f: impl FnMut(&'a Dict, &Location)) {
    enum Step<'a> {
        Enter(&'a PdfObject, Option<PathSeg>),
        Leave,
    }
    let mut stack: Vec<Step<'a>> = Vec::new();
    for (i, entry) in objects.iter().enumerate() {
        let mut loc = Location::of(i, entry);
        stack.push(Step::Enter(&entry.object, None));
        while let Some(step) = stack.pop() {
            let obj = match step {
                Step::Leave => {
                    loc.path.pop();
                    continue;
                }
                Step::Enter(obj, seg) => {
                    if let Some(seg) = seg {
                        loc.path.push(seg);
                        stack.push(Step::Leave);
                    }
                    obj
                }
            };
            let dict = match obj {
                PdfObject::Dict(d) => d,
                PdfObject::Stream(s) => &s.dict,
                PdfObject::Array(items) => {
                    for (k, item) in items.iter().enumerate().rev() {
                        if is_container(item) {
                            stack.push(Step::Enter(item, Some(PathSeg::Index(k))));
                        }
                    }
                    continue;
                }
                _ => continue,
            };
            for (k, v) in dict.entries().iter().rev() {
                if is_container(v) {
                    stack.push(Step::Enter(v, Some(PathSeg::Key(k.clone()))));
                }
            }
            f(dict, &loc);
        }
    }
}

fn is_container(o: &PdfObject) -> bool {
    matches!(o, PdfObject::Dict(_) | PdfObject::Array(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Budget, Limits};
    use crate::parser::Document;

    fn doc(src: &[u8]) -> Document {
        let limits = Limits::default();
        Document::parse(src, &limits, &mut Budget::new(&limits))
    }

    fn collect(d: &Document) -> Vec<(ObjRef, Vec<PathSeg>, Vec<String>)> {
        let mut out = Vec::new();
        visit_dicts(&d.objects, |dict, loc| {
            let keys = dict
                .entries()
                .iter()
                .map(|(k, _)| format!("{k:?}"))
                .collect();
            out.push((loc.id, loc.path.clone(), keys));
        });
        out
    }

    fn key(k: &str) -> PathSeg {
        PathSeg::Key(Name::from(k))
    }

    #[test]
    fn nested_three_levels_in_order() {
        let d = doc(b"1 0 obj << /A << /B [ 1 << /C << /D 1 >> >> ] >> /E 2 >> endobj");
        let got = collect(&d);
        let paths: Vec<_> = got.iter().map(|(_, p, _)| p.clone()).collect();
        assert_eq!(
            paths,
            vec![
                vec![],
                vec![key("A")],
                vec![key("A"), key("B"), PathSeg::Index(1)],
                vec![key("A"), key("B"), PathSeg::Index(1), key("C")],
            ]
        );
        assert_eq!(got[3].2, vec!["/D"]);
    }

    #[test]
    fn stream_dict_and_top_level_array() {
        let d = doc(
            b"1 0 obj << /Length 2 /N << /X 1 >> >> stream\nab\nendstream endobj\n2 0 obj [<< /Y 1 >>] endobj",
        );
        let got = collect(&d);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, ObjRef::new(1, 0));
        assert!(got[0].1.is_empty());
        assert_eq!(got[1].1, vec![key("N")]);
        assert_eq!(got[2].0, ObjRef::new(2, 0));
        assert_eq!(got[2].1, vec![PathSeg::Index(0)]);
    }

    #[test]
    fn location_helpers() {
        let d = doc(b"%PDF-1.7\n3 0 obj << >> endobj");
        let loc = Location::of(0, &d.objects[0]);
        assert_eq!(loc.offset(), 9);
        assert!(loc.is_object());
        assert_eq!(loc.id, ObjRef::new(3, 0));
    }
}
