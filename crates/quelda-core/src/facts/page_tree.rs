//! Page tree facts (ADR #13): pages reached from every catalog, inherited
//! page boxes, declared `/Count`s, cycles and nodes listed more than once.
//!
//! Union: roots are every trailer's `/Root` and every `/Type /Catalog`
//! dictionary; a reference leads to every definition of its id. Each
//! definition is expanded once, so the walk ends whatever the tree looks
//! like. Cycles and repeats are judged on the id graph (edges from every
//! definition).

use std::collections::{HashMap, HashSet};

use crate::parser::{Dict, Document, ObjRef, PdfObject};

/// A `/MediaBox` or `/CropBox` value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PageBox {
    /// `[llx lly urx ury]`.
    Rect([f64; 4]),
    /// Present but not an array of 4 numbers.
    Malformed,
}

impl PageBox {
    fn from_obj(o: &PdfObject) -> PageBox {
        let Some(a) = o.as_array() else {
            return PageBox::Malformed;
        };
        let nums: Vec<f64> = a.iter().filter_map(PdfObject::as_number).collect();
        match <[f64; 4]>::try_from(nums) {
            Ok(r) if a.len() == 4 => PageBox::Rect(r),
            _ => PageBox::Malformed,
        }
    }

    /// Width and height (absolute), if a rectangle.
    pub fn size(&self) -> Option<(f64, f64)> {
        match self {
            PageBox::Rect([x0, y0, x1, y1]) => Some(((x1 - x0).abs(), (y1 - y0).abs())),
            PageBox::Malformed => None,
        }
    }
}

/// A page (leaf) definition reached from a root.
#[derive(Clone, Debug, PartialEq)]
pub struct Page {
    /// Index into `Document::objects`.
    pub object: usize,
    pub id: ObjRef,
    /// Own value, else inherited from the nearest ancestor that has one.
    pub media_box: Option<PageBox>,
    pub crop_box: Option<PageBox>,
    /// Own `/UserUnit` (not inheritable), if a number.
    pub user_unit: Option<f64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PageTree {
    /// Page definitions reached (each once).
    pub pages: Vec<Page>,
    /// Distinct page ids reached.
    pub page_count: usize,
    /// `/Count` of every intermediate node definition reached: (object, value).
    pub declared_counts: Vec<(usize, i64)>,
    /// Nodes on a cycle of `/Kids` edges.
    pub cycle_nodes: Vec<ObjRef>,
    /// Nodes listed twice in one `/Kids`, or by two different parents.
    pub repeated_nodes: Vec<ObjRef>,
}

#[derive(Clone, Copy, Default)]
struct Inherited {
    media_box: Option<PageBox>,
    crop_box: Option<PageBox>,
}

pub fn page_tree(doc: &Document) -> PageTree {
    let first = |o: &PdfObject| -> Option<PdfObject> {
        match o {
            PdfObject::Ref(r) => doc.definitions(*r).next().map(|d| d.object.clone()),
            o => Some(o.clone()),
        }
    };
    let dict_of = |i: usize| doc.objects.get(i).and_then(|e| e.object.as_dict());

    // Root /Pages nodes.
    let mut catalogs: Vec<&Dict> = Vec::new();
    for t in &doc.trailers {
        for r in t.dict.get_all("Root").filter_map(PdfObject::as_reference) {
            catalogs.extend(doc.definitions(r).filter_map(|d| d.object.as_dict()));
        }
    }
    catalogs.extend(
        doc.objects
            .iter()
            .filter_map(|e| e.object.as_dict())
            .filter(|d| d.get_all("Type").any(|t| t.is_name("Catalog"))),
    );
    let mut stack: Vec<(usize, Inherited)> = Vec::new();
    for c in catalogs {
        for r in c.get_all("Pages").filter_map(PdfObject::as_reference) {
            stack.extend(doc.definition_indices(r).map(|i| (i, Inherited::default())));
        }
    }

    let mut tree = PageTree::default();
    let mut expanded: HashSet<usize> = HashSet::new();
    let mut page_ids: HashSet<ObjRef> = HashSet::new();
    let mut edges: HashMap<ObjRef, Vec<ObjRef>> = HashMap::new();
    let mut parents: HashMap<ObjRef, HashSet<ObjRef>> = HashMap::new();
    let mut repeated: HashSet<ObjRef> = HashSet::new();

    while let Some((i, inherited)) = stack.pop() {
        if !expanded.insert(i) {
            continue;
        }
        let (Some(dict), Some(id)) = (dict_of(i), doc.objects.get(i).map(|e| e.id)) else {
            continue;
        };
        let own = |key: &str| dict.get(key).and_then(first).map(|o| PageBox::from_obj(&o));
        let here = Inherited {
            media_box: own("MediaBox").or(inherited.media_box),
            crop_box: own("CropBox").or(inherited.crop_box),
        };
        let kids: Vec<PdfObject> = dict
            .get_all("Kids")
            .filter_map(first)
            .filter(|k| k.as_array().is_some())
            .collect();
        let is_page = dict.get_all("Type").any(|t| t.is_name("Page"));
        if kids.is_empty() || is_page {
            page_ids.insert(id);
            tree.pages.push(Page {
                object: i,
                id,
                media_box: here.media_box,
                crop_box: here.crop_box,
                user_unit: dict
                    .get("UserUnit")
                    .and_then(first)
                    .and_then(|u| u.as_number()),
            });
            continue;
        }
        if let Some(n) = dict.get("Count").and_then(first).and_then(|c| c.as_int()) {
            tree.declared_counts.push((i, n));
        }
        for kids in &kids {
            let refs: Vec<ObjRef> = kids
                .as_array()
                .unwrap_or_default()
                .iter()
                .filter_map(PdfObject::as_reference)
                .collect();
            let mut in_this: HashSet<ObjRef> = HashSet::new();
            for k in refs {
                if !in_this.insert(k) {
                    repeated.insert(k);
                }
                parents.entry(k).or_default().insert(id);
                edges.entry(id).or_default().push(k);
                stack.extend(doc.definition_indices(k).map(|j| (j, here)));
            }
        }
    }

    tree.page_count = page_ids.len();
    repeated.extend(parents.iter().filter(|(_, p)| p.len() > 1).map(|(k, _)| *k));
    tree.repeated_nodes = sorted(repeated);
    tree.cycle_nodes = sorted(cycle_nodes(&edges));
    tree.pages.sort_by_key(|p| p.object);
    tree
}

fn sorted(s: HashSet<ObjRef>) -> Vec<ObjRef> {
    let mut v: Vec<ObjRef> = s.into_iter().collect();
    v.sort_unstable();
    v
}

/// Targets of back edges in an iterative DFS: each is on a cycle.
fn cycle_nodes(edges: &HashMap<ObjRef, Vec<ObjRef>>) -> HashSet<ObjRef> {
    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        Gray,
        Black,
    }
    let mut color: HashMap<ObjRef, Color> = HashMap::new();
    let mut out = HashSet::new();
    let mut starts: Vec<&ObjRef> = edges.keys().collect();
    starts.sort_unstable();
    for &start in starts {
        if color.contains_key(&start) {
            continue;
        }
        // (node, next edge index)
        let mut stack: Vec<(ObjRef, usize)> = vec![(start, 0)];
        color.insert(start, Color::Gray);
        while let Some(&mut (node, ref mut next)) = stack.last_mut() {
            let kids = edges.get(&node).map(Vec::as_slice).unwrap_or_default();
            if let Some(&k) = kids.get(*next) {
                *next += 1;
                match color.get(&k) {
                    Some(Color::Gray) => {
                        out.insert(k);
                    }
                    Some(Color::Black) => {}
                    None => {
                        color.insert(k, Color::Gray);
                        stack.push((k, 0));
                    }
                }
            } else {
                color.insert(node, Color::Black);
                stack.pop();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Budget, Limits};

    fn tree(body: &str) -> PageTree {
        let src = format!("%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n{body}");
        let limits = Limits::default();
        page_tree(&Document::parse(
            src.as_bytes(),
            &limits,
            &mut Budget::new(&limits),
        ))
    }

    fn r(n: u32) -> ObjRef {
        ObjRef::new(n, 0)
    }

    #[test]
    fn inherits_media_box_from_parent() {
        let t = tree(
            "2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 100 200] >> endobj\n\
             3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n\
             4 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 5 6] /CropBox 9 0 R /UserUnit 2 >> endobj\n\
             9 0 obj [0 0 1 (x)] endobj",
        );
        assert_eq!(t.page_count, 2);
        assert_eq!(t.declared_counts.len(), 1);
        assert_eq!(t.declared_counts[0].1, 2);
        let p3 = t.pages.iter().find(|p| p.id == r(3)).unwrap();
        assert_eq!(p3.media_box, Some(PageBox::Rect([0.0, 0.0, 100.0, 200.0])));
        assert_eq!(p3.media_box.unwrap().size(), Some((100.0, 200.0)));
        assert_eq!(p3.user_unit, None);
        let p4 = t.pages.iter().find(|p| p.id == r(4)).unwrap();
        assert_eq!(p4.media_box, Some(PageBox::Rect([0.0, 0.0, 5.0, 6.0])));
        assert_eq!(p4.crop_box, Some(PageBox::Malformed));
        assert_eq!(p4.user_unit, Some(2.0));
        assert!(t.cycle_nodes.is_empty() && t.repeated_nodes.is_empty());
    }

    #[test]
    fn two_levels() {
        let t = tree(
            "2 0 obj << /Type /Pages /Kids [7 0 R] /Count 1 /MediaBox [0 0 1 1] >> endobj\n\
             7 0 obj << /Type /Pages /Parent 2 0 R /Kids [3 0 R] /Count 1 >> endobj\n\
             3 0 obj << /Type /Page /Parent 7 0 R >> endobj",
        );
        assert_eq!(t.page_count, 1);
        assert_eq!(
            t.pages[0].media_box,
            Some(PageBox::Rect([0.0, 0.0, 1.0, 1.0]))
        );
        assert!(t.cycle_nodes.is_empty() && t.repeated_nodes.is_empty());
    }

    #[test]
    fn self_cycle_terminates() {
        let t = tree(
            "2 0 obj << /Type /Pages /Kids [3 0 R 2 0 R] /Count 2 >> endobj\n\
             3 0 obj << /Type /Page >> endobj",
        );
        assert_eq!(t.cycle_nodes, vec![r(2)]);
        assert_eq!(t.page_count, 1);
    }

    #[test]
    fn mutual_cycle() {
        let t = tree(
            "2 0 obj << /Type /Pages /Kids [7 0 R] >> endobj\n\
             7 0 obj << /Type /Pages /Kids [2 0 R 3 0 R] >> endobj\n\
             3 0 obj << /Type /Page >> endobj",
        );
        assert_eq!(t.cycle_nodes, vec![r(2)]);
    }

    #[test]
    fn repeated_kids() {
        let t = tree(
            "2 0 obj << /Type /Pages /Kids [3 0 R 3 0 R 7 0 R] >> endobj\n\
             7 0 obj << /Type /Pages /Kids [8 0 R] >> endobj\n\
             8 0 obj << /Type /Page >> endobj\n\
             3 0 obj << /Type /Page >> endobj",
        );
        assert_eq!(t.repeated_nodes, vec![r(3)]);
        assert!(t.cycle_nodes.is_empty());
        assert_eq!(t.page_count, 2);
        let t = tree(
            "2 0 obj << /Type /Pages /Kids [7 0 R 9 0 R] >> endobj\n\
             7 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n\
             9 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n\
             3 0 obj << /Type /Page >> endobj",
        );
        assert_eq!(t.repeated_nodes, vec![r(3)]);
    }

    #[test]
    fn every_definition_of_a_node_is_walked() {
        // Two definitions of the root: one per revision-like copy.
        let t = tree(
            "2 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n\
             2 0 obj << /Type /Pages /Kids [4 0 R] >> endobj\n\
             3 0 obj << /Type /Page >> endobj\n4 0 obj << /Type /Page >> endobj",
        );
        assert_eq!(t.page_count, 2);
        assert!(t.repeated_nodes.is_empty());
    }

    #[test]
    fn no_catalog_no_pages() {
        let limits = Limits::default();
        let d = Document::parse(b"1 0 obj << >> endobj", &limits, &mut Budget::new(&limits));
        assert_eq!(page_tree(&d), PageTree::default());
    }

    #[test]
    fn page_box_parsing() {
        let b = |s: &str| {
            let limits = Limits::default();
            let (o, _) = crate::parser::parse_object(s.as_bytes(), 0, &limits).unwrap();
            PageBox::from_obj(&o)
        };
        assert_eq!(b("[0 0 1.5 2]"), PageBox::Rect([0.0, 0.0, 1.5, 2.0]));
        assert_eq!(b("[0 0 1]"), PageBox::Malformed);
        assert_eq!(b("[0 0 1 /x]"), PageBox::Malformed);
        assert_eq!(b("/x"), PageBox::Malformed);
        assert_eq!(b("[10 10 0 0]").size(), Some((10.0, 10.0)));
        assert_eq!(PageBox::Malformed.size(), None);
    }
}
