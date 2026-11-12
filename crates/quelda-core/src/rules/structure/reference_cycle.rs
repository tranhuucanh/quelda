//! `STRUCT.REFERENCE_CYCLE`: chains that readers follow until they end, made
//! to never end: outline items and actions linked by `/Next` (and outline
//! `/First`), object streams linked by `/Extends`, arrays that contain
//! themselves through other arrays.
//!
//! Only chains that are acyclic in every real file are checked. Ordinary
//! reference cycles (`/Parent` and `/Kids`, `/Prev`, article beads) are how
//! PDF works and are not reported. The page tree has its own rule
//! (`STRUCT.PAGE_TREE_CYCLE`), drawing loops `RESOURCE.DRAW_RECURSION`.

use std::collections::{BTreeMap, BTreeSet};

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, ObjRef, PdfObject};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Site, Stage};

pub struct ReferenceCycle;

static META: RuleMeta = RuleMeta {
    id: "STRUCT.REFERENCE_CYCLE",
    category: Category::Structure,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.4.0",
    message: "A chain of objects loops back on itself",
    description: "A loop in a chain that readers follow to its end: outline (bookmark) \
        items or actions linked by `/Next` and outline `/First`, object streams linked by \
        `/Extends`, or arrays that contain themselves through other arrays. Readers that \
        walk such a chain naively never stop (hang, memory exhaustion). Every definition \
        of every object counts (all revisions). Ordinary reference cycles such as \
        `/Parent` and `/Kids` are not reported.",
};

type Graph = BTreeMap<ObjRef, BTreeSet<ObjRef>>;

/// References a `/Next` or `/First` value stands for: itself, the items of
/// an array (an action's `/Next` may be an array of actions), and the same
/// keys of dictionaries written inline.
fn chain_targets(value: &PdfObject, out: &mut BTreeSet<ObjRef>) {
    let mut stack = vec![value];
    while let Some(o) = stack.pop() {
        match o {
            PdfObject::Ref(r) => {
                out.insert(*r);
            }
            PdfObject::Array(items) => stack.extend(items.iter()),
            PdfObject::Dict(d) => {
                for key in ["Next", "First"] {
                    stack.extend(d.get_all(key));
                }
            }
            _ => {}
        }
    }
}

fn dict_of(o: &PdfObject) -> Option<&Dict> {
    match o {
        PdfObject::Dict(d) => Some(d),
        PdfObject::Stream(s) => Some(&s.dict),
        _ => None,
    }
}

/// A node on a cycle of `g`, if any. Iterative depth-first search.
fn on_cycle(g: &Graph) -> Option<ObjRef> {
    // 1: on the current path; 2: finished.
    let mut state: BTreeMap<ObjRef, u8> = BTreeMap::new();
    for &start in g.keys() {
        if state.contains_key(&start) {
            continue;
        }
        let mut stack: Vec<(ObjRef, Vec<ObjRef>)> = Vec::new();
        state.insert(start, 1);
        stack.push((start, g[&start].iter().copied().collect()));
        while let Some((node, pending)) = stack.last_mut() {
            let Some(next) = pending.pop() else {
                state.insert(*node, 2);
                stack.pop();
                continue;
            };
            match state.get(&next) {
                Some(1) => return Some(next),
                Some(_) => {}
                None => {
                    state.insert(next, 1);
                    let edges = g.get(&next).map(|e| e.iter().copied().collect());
                    stack.push((next, edges.unwrap_or_default()));
                }
            }
        }
    }
    None
}

fn site(ctx: &Ctx, id: ObjRef) -> Site {
    ctx.document()
        .definition_indices(id)
        .next()
        .and_then(|i| Some(Location::of(i, ctx.objects().get(i)?)))
        .map_or(Site::Document, Site::Object)
}

impl Rule for ReferenceCycle {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let doc = ctx.document();
        let (mut chain, mut extends, mut arrays) = (Graph::new(), Graph::new(), Graph::new());
        for entry in ctx.objects() {
            if let Some(d) = dict_of(&entry.object) {
                let mut to = BTreeSet::new();
                for key in ["Next", "First"] {
                    for v in d.get_all(key) {
                        chain_targets(v, &mut to);
                    }
                }
                if !to.is_empty() {
                    chain.entry(entry.id).or_default().extend(to);
                }
                if d.get_all("Type").any(|t| t.is_name("ObjStm")) {
                    let to: BTreeSet<ObjRef> = d
                        .get_all("Extends")
                        .filter_map(PdfObject::as_reference)
                        .collect();
                    if !to.is_empty() {
                        extends.entry(entry.id).or_default().extend(to);
                    }
                }
            } else if let PdfObject::Array(items) = &entry.object {
                // Only edges to objects that are arrays themselves.
                let to: BTreeSet<ObjRef> = items
                    .iter()
                    .filter_map(PdfObject::as_reference)
                    .filter(|r| {
                        doc.definitions(*r)
                            .any(|e| matches!(e.object, PdfObject::Array(_)))
                    })
                    .collect();
                if !to.is_empty() {
                    arrays.entry(entry.id).or_default().extend(to);
                }
            }
        }
        for (g, what) in [
            (&chain, "/Next or /First chain"),
            (&extends, "object stream /Extends chain"),
            (&arrays, "array"),
        ] {
            if let Some(id) = on_cycle(g) {
                out.report(
                    &META,
                    site(ctx, id),
                    Some(format!("{what} loops through object {id}")),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::run;

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&ReferenceCycle])
            .iter()
            .map(|f| f.detail.clone().unwrap_or_default())
            .collect()
    }

    #[test]
    fn outline_and_action_chains() {
        // Sibling loop.
        let breadth = b"1 0 obj << /Type /Outlines /First 2 0 R /Last 3 0 R >> endobj\n\
            2 0 obj << /Title (a) /Parent 1 0 R /Next 3 0 R >> endobj\n\
            3 0 obj << /Title (b) /Parent 1 0 R /Next 2 0 R >> endobj\n";
        assert_eq!(hits(breadth).len(), 1, "{:?}", hits(breadth));
        assert!(hits(breadth)[0].starts_with("/Next or /First chain loops"));
        // A child's /Next leads back to its parent.
        let depth = b"1 0 obj << /Type /Outlines /First 2 0 R >> endobj\n\
            2 0 obj << /Title (a) /First 3 0 R /Parent 1 0 R >> endobj\n\
            3 0 obj << /Title (b) /Parent 2 0 R /Next 2 0 R >> endobj\n";
        assert_eq!(hits(depth).len(), 1);
        // Actions: /Next as a reference, an array, an inline dictionary.
        let action = b"1 0 obj << /S /GoTo /D [9 0 R /Fit] /Next [2 0 R] >> endobj\n\
            2 0 obj << /S /GoTo /D [9 0 R /Fit] /Next << /S /Named /N /NextPage /Next 1 0 R >> >> endobj\n";
        assert_eq!(hits(action).len(), 1);
        let own = b"1 0 obj << /S /GoTo /D [9 0 R /Fit] /Next 1 0 R >> endobj\n";
        assert_eq!(hits(own).len(), 1);
    }

    #[test]
    fn object_stream_extends_and_arrays() {
        let ext = b"1 0 obj << /Type /ObjStm /N 1 /First 3 /Length 9 /Extends 1 0 R >> stream\n2 0 (abc)\nendstream endobj\n";
        assert_eq!(hits(ext), vec!["object stream /Extends chain loops through object 1 0"]);
        let arr = b"5 0 obj [6 0 R] endobj\n6 0 obj [7 0 R] endobj\n7 0 obj [5 0 R] endobj\n";
        assert_eq!(hits(arr).len(), 1);
        assert!(hits(arr)[0].starts_with("array loops"));
    }

    #[test]
    fn ordinary_structures_do_not_fire() {
        // A real outline: /Next, /Prev, /Parent, /First, /Last.
        let outline = b"1 0 obj << /Type /Outlines /First 2 0 R /Last 3 0 R /Count 2 >> endobj\n\
            2 0 obj << /Title (a) /Parent 1 0 R /Next 3 0 R /First 4 0 R /Last 4 0 R >> endobj\n\
            3 0 obj << /Title (b) /Parent 1 0 R /Prev 2 0 R >> endobj\n\
            4 0 obj << /Title (c) /Parent 2 0 R >> endobj\n";
        assert!(hits(outline).is_empty(), "{:?}", hits(outline));
        // Page tree: /Parent and /Kids refer to each other; a /Kids array
        // stored as an object refers to dictionaries, not arrays.
        let pages = b"1 0 obj << /Type /Pages /Kids 2 0 R /Count 1 >> endobj\n\
            2 0 obj [3 0 R] endobj\n\
            3 0 obj << /Type /Page /Parent 1 0 R /Annots 4 0 R >> endobj\n\
            4 0 obj [5 0 R] endobj\n\
            5 0 obj << /Type /Annot /P 3 0 R /Dest [3 0 R /Fit] >> endobj\n";
        assert!(hits(pages).is_empty(), "{:?}", hits(pages));
        // Object streams extending each other in a line.
        let ext = b"1 0 obj << /Type /ObjStm /N 0 /First 0 /Length 0 /Extends 2 0 R >> stream\n\nendstream endobj\n\
            2 0 obj << /Type /ObjStm /N 0 /First 0 /Length 0 >> stream\n\nendstream endobj\n";
        assert!(hits(ext).is_empty(), "{:?}", hits(ext));
    }
}
