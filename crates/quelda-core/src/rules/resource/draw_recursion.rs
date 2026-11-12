//! `RESOURCE.DRAW_RECURSION`: something drawn draws itself, directly or
//! through others: a Form XObject (`Do`), a tiling pattern (`scn`), a soft
//! mask (`gs`) or a Type 3 glyph (`Tj` with a Type 3 font). Renderers follow
//! these calls, so a loop recurses until the stack overflows or the
//! renderer hangs.
//!
//! Judged on the calls content streams make, never on resource dictionaries
//! alone: a resource dictionary shared by a form and its page often lists
//! the form itself, which is fine as long as the form does not call it.

use std::collections::HashMap;
use std::rc::Rc;

use crate::facts::content_ops::tokenize;
use crate::facts::{Ctx, Location};
use crate::parser::{Dict, Name, PdfObject};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct DrawRecursion;

static META: RuleMeta = RuleMeta {
    id: "RESOURCE.DRAW_RECURSION",
    category: Category::Resource,
    severity: Severity::Medium,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.3.0",
    message: "Content draws itself in a loop",
    description: "A Form XObject, tiling pattern, soft mask group or Type 3 glyph whose \
        content calls itself, directly or through other forms, patterns, soft masks or \
        glyphs (names resolved in the resources that apply, inherited ones included; every \
        definition of a reference). Renderers (pdf.js, Poppler, MuPDF, Ghostscript, \
        printers) follow these calls and recurse until they crash or hang. Only calls \
        made by content count: resource dictionaries that merely list a form are not \
        reported.",
};

/// Calls a content stream makes by name.
#[derive(Default)]
struct Calls {
    xobjects: Vec<Name>,
    patterns: Vec<Name>,
    gstates: Vec<Name>,
    /// Text shown: (font name, character codes).
    text: Vec<(Name, Vec<u8>)>,
}

/// Bytes of text kept per stream (glyph loops need only one code).
const MAX_TEXT: usize = 1 << 16;

/// Graph nodes visited at most; a larger graph is not judged further.
const MAX_NODES: usize = 200_000;

fn last_name(op: &[PdfObject]) -> Option<Name> {
    op.last().and_then(PdfObject::as_name).cloned()
}

fn calls(ctx: &Ctx, object: usize) -> Calls {
    let mut c = Calls::default();
    // Images and other data never call anything; decoding them would cost
    // time and the scan's decode budget.
    if !ctx.stream_roles(object).content {
        return c;
    }
    let Some(outcome) = ctx.decode(object) else {
        return c;
    };
    let Some(data) = outcome.data() else {
        return c;
    };
    let mut font: Option<Name> = None;
    let mut text_len = 0;
    let _ = tokenize(data, ctx.limits(), |op| {
        let o = &op.operands;
        let mut show = |bytes: Vec<u8>| {
            if let Some(f) = &font {
                if text_len < MAX_TEXT && !bytes.is_empty() {
                    text_len += bytes.len();
                    c.text.push((f.clone(), bytes));
                }
            }
        };
        match op.operator {
            b"Do" => c.xobjects.extend(last_name(o)),
            b"scn" | b"SCN" => c.patterns.extend(last_name(o)),
            b"gs" => c.gstates.extend(last_name(o)),
            b"Tf" => font = o.first().and_then(PdfObject::as_name).cloned(),
            b"Tj" | b"'" | b"\"" => {
                if let Some(s) = o.last().and_then(PdfObject::as_string) {
                    show(s.to_vec());
                }
            }
            b"TJ" => {
                if let Some(items) = o.last().and_then(PdfObject::as_array) {
                    show(items.iter().filter_map(PdfObject::as_string).flatten().copied().collect());
                }
            }
            _ => {}
        }
    });
    c
}

/// Dictionaries `o` stands for (every definition).
fn dicts<'c>(ctx: &'c Ctx, o: &'c PdfObject) -> Vec<&'c Dict> {
    ctx.resolve(o).filter_map(PdfObject::as_dict).collect()
}

/// Dictionaries under `key` in resource dictionary `r`.
fn category<'c>(ctx: &'c Ctx, r: &'c Dict, key: &'static str) -> Vec<&'c Dict> {
    r.get_all(key).flat_map(|v| dicts(ctx, v)).collect()
}

/// Streams `o` stands for (every definition of a reference).
fn streams(ctx: &Ctx, o: &PdfObject) -> Vec<usize> {
    let doc = ctx.document();
    o.as_reference()
        .into_iter()
        .flat_map(|r| doc.definition_indices(r))
        .filter(|&i| doc.objects[i].object.as_stream().is_some())
        .collect()
}

struct Graph<'c, 'a> {
    ctx: &'c Ctx<'a>,
    calls: HashMap<usize, Rc<Calls>>,
    /// Resource sets (each a list of resource dictionaries), interned.
    sets: Vec<Vec<&'c Dict>>,
    set_ids: HashMap<Vec<*const Dict>, usize>,
    /// Keys of the dictionaries names are looked up in, indexed once:
    /// scanning a dictionary for every call is cubic in forms that call
    /// each other through one shared resource dictionary.
    keys: HashMap<*const Dict, HashMap<&'c [u8], Vec<&'c PdfObject>>>,
}

impl<'c, 'a> Graph<'c, 'a> {
    fn intern(&mut self, set: Vec<&'c Dict>) -> usize {
        let key: Vec<*const Dict> = set.iter().map(|d| *d as *const Dict).collect();
        if let Some(&id) = self.set_ids.get(&key) {
            return id;
        }
        self.sets.push(set);
        self.set_ids.insert(key, self.sets.len() - 1);
        self.sets.len() - 1
    }

    /// The values of key `name` in `d` (a name written in content).
    fn entry(&mut self, d: &'c Dict, name: &Name) -> Vec<&'c PdfObject> {
        let keys = self.keys.entry(d as *const Dict).or_insert_with(|| {
            let mut keys: HashMap<&'c [u8], Vec<&'c PdfObject>> = HashMap::new();
            for (k, v) in d.entries() {
                keys.entry(k.as_bytes()).or_default().push(v);
            }
            keys
        });
        keys.get(name.as_bytes()).cloned().unwrap_or_default()
    }

    /// The values `names` have under `key` in resource dictionary `r`.
    fn called(&mut self, r: &'c Dict, key: &'static str, names: &[Name]) -> Vec<&'c PdfObject> {
        let mut out = Vec::new();
        for d in category(self.ctx, r, key) {
            for n in names {
                out.extend(self.entry(d, n));
            }
        }
        out
    }

    /// The resources `d` sets with its own `/Resources`, if any.
    fn own(&mut self, d: &'c Dict) -> Option<usize> {
        let set = category(self.ctx, d, "Resources");
        (!set.is_empty()).then(|| self.intern(set))
    }

    /// A stream called with `inherited` resources: the node it runs as.
    fn node(&mut self, object: usize, inherited: usize) -> (usize, usize) {
        let ctx = self.ctx;
        let dict = ctx.objects()[object].object.as_dict();
        let set = dict.and_then(|d| self.own(d)).unwrap_or(inherited);
        (object, set)
    }

    fn calls_of(&mut self, object: usize) -> Rc<Calls> {
        let ctx = self.ctx;
        Rc::clone(
            self.calls
                .entry(object)
                .or_insert_with(|| Rc::new(calls(ctx, object))),
        )
    }

    /// Nodes `(object, resources)` calls.
    fn edges(&mut self, (object, set): (usize, usize)) -> Vec<(usize, usize)> {
        let ctx = self.ctx;
        let calls = self.calls_of(object);
        let resources = self.sets[set].clone();
        let mut targets: Vec<(usize, usize)> = Vec::new();
        for r in resources {
            let drawn = self.called(r, "XObject", &calls.xobjects);
            let painted = self.called(r, "Pattern", &calls.patterns);
            for v in drawn.into_iter().chain(painted) {
                targets.extend(streams(ctx, v).into_iter().map(|i| (i, set)));
            }
            for gs in self.called(r, "ExtGState", &calls.gstates) {
                for gs in dicts(ctx, gs) {
                    for mask in category(ctx, gs, "SMask") {
                        for g in mask.get_all("G") {
                            targets.extend(streams(ctx, g).into_iter().map(|i| (i, set)));
                        }
                    }
                }
            }
            for d in category(ctx, r, "Font") {
                for (n, codes) in &calls.text {
                    let fonts: Vec<&'c Dict> =
                        self.entry(d, n).into_iter().flat_map(|v| dicts(ctx, v)).collect();
                    for font in fonts {
                        targets.extend(self.glyphs(font, codes, set));
                    }
                }
            }
        }
        targets
            .into_iter()
            .map(|(i, inherited)| self.node(i, inherited))
            .collect()
    }

    /// Glyph procedures of Type 3 font `font` that `codes` show, with the
    /// resources they run with (the font's own, else `set`).
    fn glyphs(&mut self, font: &'c Dict, codes: &[u8], set: usize) -> Vec<(usize, usize)> {
        let ctx = self.ctx;
        if !font
            .get_all("Subtype")
            .flat_map(|v| ctx.resolve(v))
            .any(|s| s.is_name("Type3"))
        {
            return Vec::new();
        }
        let set = self.own(font).unwrap_or(set);
        let mut names: HashMap<u8, &'c Name> = HashMap::new();
        for enc in category(ctx, font, "Encoding") {
            for diffs in enc.get_all("Differences").flat_map(|v| ctx.resolve(v)) {
                let mut code: Option<i64> = None;
                for item in diffs.as_array().unwrap_or_default() {
                    match item {
                        PdfObject::Int(c) => code = Some(*c),
                        PdfObject::Name(n) => {
                            if let Some(c) = code.and_then(|c| u8::try_from(c).ok()) {
                                names.entry(c).or_insert(n);
                            }
                            code = code.map(|c| c + 1);
                        }
                        _ => {}
                    }
                }
            }
        }
        let mut out = Vec::new();
        for procs in category(ctx, font, "CharProcs") {
            let mut seen = [false; 256];
            for &c in codes {
                if std::mem::replace(&mut seen[usize::from(c)], true) {
                    continue;
                }
                if let Some(n) = names.get(&c) {
                    for v in self.entry(procs, n) {
                        out.extend(streams(ctx, v).into_iter().map(|i| (i, set)));
                    }
                }
            }
        }
        out
    }
}

/// Streams the resource set `set` lists as drawable (forms, patterns,
/// soft mask groups, Type 3 glyphs), each with the resources it runs with.
fn listed(g: &mut Graph, set: usize) -> Vec<(usize, usize)> {
    let ctx = g.ctx;
    let mut targets = Vec::new();
    for r in g.sets[set].clone() {
        for key in ["XObject", "Pattern"] {
            for d in category(ctx, r, key) {
                for (_, v) in d.entries() {
                    targets.extend(streams(ctx, v).into_iter().map(|i| (i, set)));
                }
            }
        }
        for d in category(ctx, r, "ExtGState") {
            for (_, v) in d.entries() {
                for gs in dicts(ctx, v) {
                    for mask in category(ctx, gs, "SMask") {
                        for gr in mask.get_all("G") {
                            targets.extend(streams(ctx, gr).into_iter().map(|i| (i, set)));
                        }
                    }
                }
            }
        }
        for d in category(ctx, r, "Font") {
            for (_, v) in d.entries() {
                for font in dicts(ctx, v) {
                    if !font.get_all("Subtype").any(|s| s.is_name("Type3")) {
                        continue;
                    }
                    let fs = g.own(font).unwrap_or(set);
                    for procs in category(ctx, font, "CharProcs") {
                        for (_, p) in procs.entries() {
                            targets.extend(streams(ctx, p).into_iter().map(|i| (i, fs)));
                        }
                    }
                }
            }
        }
    }
    targets
        .into_iter()
        .map(|(i, inherited)| g.node(i, inherited))
        .collect()
}

/// Starting points: what pages list in their resources (inherited through
/// `/Parent`), and what any other resource dictionary lists: a loop must
/// pass through something drawn by name, so page content itself (which
/// nothing calls) is never read.
fn roots(g: &mut Graph) -> Vec<(usize, usize)> {
    let ctx = g.ctx;
    let mut sets = Vec::new();
    crate::facts::visitor::visit_dicts(ctx.objects(), |d, _| {
        if d.contains_key("Resources") {
            sets.push(d);
        }
    });
    let mut sets: Vec<usize> = sets.into_iter().filter_map(|d| g.own(d)).collect();
    for page in &ctx.page_tree().pages {
        let mut node = ctx.objects()[page.object].object.as_dict();
        for _ in 0..64 {
            let Some(d) = node else { break };
            if let Some(set) = g.own(d) {
                sets.push(set);
                break;
            }
            node = d
                .get_all("Parent")
                .flat_map(|v| ctx.resolve(v))
                .find_map(PdfObject::as_dict);
        }
    }
    sets.sort_unstable();
    sets.dedup();
    let mut out = Vec::new();
    for set in sets {
        out.extend(listed(g, set));
    }
    out
}

impl Rule for DrawRecursion {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let mut g = Graph {
            ctx,
            calls: HashMap::new(),
            sets: Vec::new(),
            set_ids: HashMap::new(),
            keys: HashMap::new(),
        };
        // 1: on the current path, 2: done.
        let mut state: HashMap<(usize, usize), u8> = HashMap::new();
        let mut reported = std::collections::BTreeSet::new();
        for root in roots(&mut g) {
            if state.contains_key(&root) {
                continue;
            }
            // (node, its edges, next edge)
            let mut path: Vec<((usize, usize), Vec<(usize, usize)>, usize)> = Vec::new();
            state.insert(root, 1);
            let edges = g.edges(root);
            path.push((root, edges, 0));
            while let Some((node, edges, next)) = path.last_mut() {
                let Some(&to) = edges.get(*next) else {
                    state.insert(*node, 2);
                    path.pop();
                    continue;
                };
                *next += 1;
                match state.get(&to) {
                    // Each object is described once: finding and printing
                    // the loop for every back edge is cubic in forms that
                    // call each other.
                    Some(1) if reported.insert(to.0) => {
                        let at = path.iter().position(|(n, _, _)| *n == to).unwrap_or(0);
                        let ids: Vec<String> = path[at..]
                            .iter()
                            .chain(std::iter::once(&path[at]))
                            .map(|((o, _), _, _)| ctx.objects()[*o].id.to_string())
                            .collect();
                        let e = &ctx.objects()[to.0];
                        out.report(
                            &META,
                            &Location::of(to.0, e),
                            Some(format!("drawing loop: {}", ids.join(" → "))),
                        );
                    }
                    Some(_) => {}
                    None => {
                        if state.len() >= MAX_NODES {
                            return;
                        }
                        state.insert(to, 1);
                        let edges = g.edges(to);
                        path.push((to, edges, 0));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&DrawRecursion])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    fn stream(num: u32, dict: &str, data: &str) -> String {
        format!(
            "{num} 0 obj << {dict} /Length {} >> stream\n{data}\nendstream endobj\n",
            data.len()
        )
    }

    fn doc(page_resources: &str, objects: &str) -> Vec<u8> {
        format!(
            "%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n\
             2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n\
             3 0 obj << /Type /Page /Parent 2 0 R /Resources {page_resources} /Contents 4 0 R >> endobj\n\
             {}{objects}trailer << /Root 1 0 R >>\n%%EOF\n",
            stream(4, "", "/Fm0 Do")
        )
        .into_bytes()
    }

    #[test]
    fn form_calls_itself() {
        // Own resources.
        let src = doc(
            "<< /XObject << /Fm0 10 0 R >> >>",
            &stream(10, "/Subtype /Form /Resources << /XObject << /X 10 0 R >> >>", "/X Do"),
        );
        assert_eq!(hits(&src), vec!["10 0: drawing loop: 10 0 → 10 0"]);
        // Inherited from the page: the form has no resources.
        let src = doc("<< /XObject << /Fm0 10 0 R >> >>", &stream(10, "/Subtype /Form", "/Fm0 Do"));
        assert_eq!(hits(&src), vec!["10 0: drawing loop: 10 0 → 10 0"]);
        // Through another form.
        let src = doc(
            "<< /XObject << /Fm0 10 0 R >> >>",
            &(stream(10, "/Subtype /Form /Resources << /XObject << /B 11 0 R >> >>", "q /B Do Q")
                + &stream(11, "/Subtype /Form /Resources << /XObject << /A 10 0 R >> >>", "/A Do")),
        );
        assert_eq!(hits(&src), vec!["10 0: drawing loop: 10 0 → 11 0 → 10 0"]);
    }

    #[test]
    fn patterns_soft_masks_and_glyphs() {
        let src = doc(
            "<< /XObject << /Fm0 10 0 R >> >>",
            &(stream(10, "/Subtype /Form", "/Pattern cs /P0 scn 0 0 1 1 re f")
                + "5 0 obj << /Pattern << /P0 11 0 R >> >> endobj\n"
                + &stream(11, "/Type /Pattern /PatternType 1 /Resources 5 0 R", "/P0 scn 0 0 1 1 re f")),
        );
        assert_eq!(hits(&src), vec!["11 0: drawing loop: 11 0 → 11 0"]);
        let src = doc(
            "<< /XObject << /Fm0 10 0 R >> >>",
            &(stream(10, "/Subtype /Form /Resources 5 0 R", "/GS0 gs")
                + "5 0 obj << /ExtGState << /GS0 << /SMask << /S /Luminosity /G 10 0 R >> >> >> >> endobj\n"),
        );
        assert_eq!(hits(&src), vec!["10 0: drawing loop: 10 0 → 10 0"]);
        let font = "6 0 obj << /Type /Font /Subtype /Type3 /FontMatrix [1 0 0 1 0 0] /FontBBox [0 0 1 1] \
            /Encoding << /Differences [65 /a /b] >> /CharProcs << /a 12 0 R /b 13 0 R >> \
            /Resources << /Font << /T3 6 0 R >> >> /FirstChar 65 /LastChar 66 /Widths [1 1] >> endobj\n";
        let src = doc(
            "<< /Font << /T3 6 0 R >> >>",
            &(font.to_string()
                + &stream(12, "", "1 0 0 0 1 1 d1 BT /T3 1 Tf (A) Tj ET")
                + &stream(13, "", "1 0 0 0 1 1 d1 0 0 1 1 re f")),
        );
        assert_eq!(hits(&src), vec!["12 0: drawing loop: 12 0 → 12 0"]);
    }

    #[test]
    fn images_are_not_content() {
        // Image data that reads like `/Im0 Do` under resources naming the
        // image itself: an image calls nothing, and is not decoded.
        let src = doc(
            "<< /XObject << /Fm0 10 0 R >> >>",
            &stream(
                10,
                "/Subtype /Image /Width 1 /Height 7 /BitsPerComponent 8 /ColorSpace /DeviceGray \
                 /Resources << /XObject << /Im0 10 0 R >> >>",
                "/Im0 Do",
            ),
        );
        assert!(hits(&src).is_empty());
    }

    #[test]
    fn listing_is_not_calling() {
        // A shared resource dictionary lists the form; the form draws
        // another one, not itself.
        let src = doc(
            "5 0 R",
            &("5 0 obj << /XObject << /Fm0 10 0 R /Fm1 11 0 R >> >> endobj\n".to_string()
                + &stream(10, "/Subtype /Form /Resources 5 0 R", "/Fm1 Do")
                + &stream(11, "/Subtype /Form /Resources 5 0 R", "0 0 1 1 re f")),
        );
        assert!(hits(&src).is_empty());
        // A glyph showing other glyphs of its own font, without a loop.
        let font = "6 0 obj << /Type /Font /Subtype /Type3 /Encoding << /Differences [65 /a /b] >> \
            /CharProcs << /a 12 0 R /b 13 0 R >> /Resources << /Font << /T3 6 0 R >> >> >> endobj\n";
        let src = doc(
            "<< /Font << /T3 6 0 R >> >>",
            &(font.to_string()
                + &stream(12, "", "BT /T3 1 Tf (B) Tj ET")
                + &stream(13, "", "0 0 1 1 re f")),
        );
        assert!(hits(&src).is_empty());
        // `/Fm0 Do` in the page content: the page is not drawn by anything.
        let src = doc("<< /XObject << /Fm0 10 0 R >> >>", &stream(10, "/Subtype /Form", "0 0 1 1 re f"));
        assert!(hits(&src).is_empty());
    }

    #[test]
    fn forms_that_all_call_each_other() {
        // Found by fuzzing: the loop text was built for every back edge, and
        // the shared dictionary was scanned for every call: cubic in the
        // number of forms (1,600 forms: 36 s in release, now under 1 s).
        const N: u32 = 600;
        let names: String = (0..N).map(|i| format!("/Fm{i} {} 0 R ", 10 + i)).collect();
        let calls: String = (0..N).map(|i| format!("/Fm{i} Do ")).collect();
        let mut objects = format!("5 0 obj << /XObject << {names}>> >> endobj\n");
        for i in 0..N {
            objects += &stream(10 + i, "/Subtype /Form /Resources 5 0 R", &calls);
        }
        let src = doc("5 0 R", &objects);
        let start = std::time::Instant::now();
        let found = hits(&src);
        let took = start.elapsed();
        assert_eq!(found[0], "10 0: drawing loop: 10 0 → 10 0");
        assert_eq!(found[1], "11 0: drawing loop: 11 0 → 11 0");
        assert!(took.as_secs() < 5, "took {took:?}");
    }
}
