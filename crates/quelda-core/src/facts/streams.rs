//! What each stream is, and its filter chain with indirect references
//! resolved.
//!
//! Roles come from the stream's own dictionary (`/Subtype /Form`,
//! `/Type /Metadata`, …) and from every reference to it anywhere in the
//! union set (`/Contents`, `/AP`, `/CharProcs`, `/XFA`, `/JS`, …), all
//! definitions included. A stream can have several roles; any role that must
//! be inspected wins over "opaque" (an image referenced as page content is
//! content).

use super::visitor::visit_dicts;
use crate::parser::{Dict, Document, Name, PdfObject};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamRoles {
    /// Content stream: page `/Contents`, Form XObject, tiling pattern,
    /// Type 3 glyph procedure, appearance stream.
    pub content: bool,
    /// XML: XMP metadata or an XFA packet.
    pub xml: bool,
    /// JavaScript (`/JS` stream).
    pub script: bool,
    /// Never inspected: image, font program, embedded file, ICC profile,
    /// sampled function, object/xref stream (the parser handles those).
    pub opaque: bool,
}

impl StreamRoles {
    /// Must be decoded: if it cannot be, the scan is `ERROR`.
    pub fn must_inspect(self) -> bool {
        self.content || self.xml || self.script
    }

    /// No known role: decoded if possible and tokenized as content (union),
    /// but failing to decode it is not an issue.
    pub fn speculative(self) -> bool {
        !self.must_inspect() && !self.opaque
    }

    /// Tokenized as a content stream (known or speculative).
    pub fn tokenized(self) -> bool {
        self.content || self.speculative()
    }
}

#[derive(Clone, Copy)]
enum Role {
    Content,
    Xml,
    Script,
    Opaque,
}

/// Roles of every object (non-streams: default), indexed like
/// `Document::objects`.
pub fn classify(doc: &Document) -> Vec<StreamRoles> {
    let mut roles = vec![StreamRoles::default(); doc.objects.len()];
    let mut marks: Vec<(usize, Role)> = Vec::new();
    for (i, e) in doc.objects.iter().enumerate() {
        if let PdfObject::Stream(s) = &e.object {
            if let Some(r) = own_role(&s.dict) {
                marks.push((i, r));
            }
        }
    }
    visit_dicts(&doc.objects, |dict, _| {
        let mut mark = |o: &PdfObject, role: Role| {
            for r in refs(o) {
                marks.extend(doc.definition_indices(r).map(|i| (i, role)));
            }
        };
        for (k, v) in dict.entries() {
            match k.as_bytes() {
                b"Contents" => mark(v, Role::Content),
                b"CharProcs" => each_value(v, |x| mark(x, Role::Content)),
                b"AP" => each_value(v, |state| {
                    mark(state, Role::Content);
                    each_value(state, |x| mark(x, Role::Content));
                }),
                b"Metadata" | b"XFA" => mark(v, Role::Xml),
                b"JS" => mark(v, Role::Script),
                b"FontFile" | b"FontFile2" | b"FontFile3" | b"Thumb" => mark(v, Role::Opaque),
                b"EF" => each_value(v, |x| mark(x, Role::Opaque)),
                _ => {}
            }
            for r in icc_profiles(v) {
                mark(&PdfObject::Ref(r), Role::Opaque);
            }
        }
    });
    for (i, role) in marks {
        let Some(r) = roles.get_mut(i) else { continue };
        if !matches!(doc.objects[i].object, PdfObject::Stream(_)) {
            continue;
        }
        match role {
            Role::Content => r.content = true,
            Role::Xml => r.xml = true,
            Role::Script => r.script = true,
            Role::Opaque => r.opaque = true,
        }
    }
    roles
}

/// Role from the stream's own dictionary (any value of duplicate keys).
fn own_role(d: &Dict) -> Option<Role> {
    let any =
        |key: &str, names: &[&str]| d.get_all(key).any(|v| names.iter().any(|n| v.is_name(n)));
    let int = |key: &str, i: i64| d.get_all(key).any(|v| v.as_int() == Some(i));
    if any("Subtype", &["Form"]) || (any("Type", &["Pattern"]) && int("PatternType", 1)) {
        return Some(Role::Content);
    }
    if any("Type", &["Metadata"]) || any("Subtype", &["XML"]) {
        return Some(Role::Xml);
    }
    if any("Subtype", &["Image", "Type1C", "CIDFontType0C", "OpenType"])
        || any("Type", &["ObjStm", "XRef", "EmbeddedFile"])
        || d.contains_key("Length1")
        || d.contains_key("Length2")
        || d.contains_key("Length3")
        || int("FunctionType", 0)
    {
        return Some(Role::Opaque);
    }
    None
}

/// The reference, or every reference in an array.
fn refs(o: &PdfObject) -> Vec<crate::parser::ObjRef> {
    match o {
        PdfObject::Ref(r) => vec![*r],
        PdfObject::Array(items) => items.iter().filter_map(PdfObject::as_reference).collect(),
        _ => Vec::new(),
    }
}

fn each_value(o: &PdfObject, mut f: impl FnMut(&PdfObject)) {
    if let PdfObject::Dict(d) = o {
        for (_, v) in d.entries() {
            f(v);
        }
    }
}

/// Streams named by `[/ICCBased N G R]`, also inside nested arrays
/// (`[/Indexed [/ICCBased …] …]`).
fn icc_profiles(o: &PdfObject) -> Vec<crate::parser::ObjRef> {
    let mut out = Vec::new();
    let mut stack = vec![o];
    while let Some(o) = stack.pop() {
        let Some(items) = o.as_array() else { continue };
        if items.first().is_some_and(|n| n.is_name("ICCBased")) {
            out.extend(items.get(1).and_then(PdfObject::as_reference));
        }
        stack.extend(items.iter().filter(|i| i.as_array().is_some()));
    }
    out
}

/// Resolves a direct object or a reference (first definition), and the
/// references inside an array, one level deep.
fn resolve(doc: &Document, o: Option<&PdfObject>) -> Option<PdfObject> {
    let first = |r| doc.definitions(r).next().map(|d| d.object.clone());
    let o = match o? {
        PdfObject::Ref(r) => first(*r)?,
        o => o.clone(),
    };
    Some(match o {
        PdfObject::Array(items) => PdfObject::Array(
            items
                .into_iter()
                .map(|i| match i {
                    PdfObject::Ref(r) => first(r).unwrap_or(PdfObject::Null),
                    i => i,
                })
                .collect(),
        ),
        o => o,
    })
}

/// `/Filter` and `/DecodeParms` with references resolved. `Err` when a key
/// appears more than once: readers disagree on which one wins, so the data
/// has no single decoding.
pub fn resolved_chain(
    doc: &Document,
    dict: &Dict,
) -> Result<(Option<PdfObject>, Option<PdfObject>), &'static str> {
    if dict.get_all("Filter").nth(1).is_some() || dict.get_all("DecodeParms").nth(1).is_some() {
        return Err("duplicate /Filter or /DecodeParms");
    }
    Ok((
        resolve(doc, dict.get("Filter")),
        resolve(doc, dict.get("DecodeParms")),
    ))
}

/// Filter names of a (resolved) `/Filter` value, in order. Non-names are
/// skipped.
pub fn filter_names(filter: Option<&PdfObject>) -> Vec<Name> {
    match filter {
        Some(PdfObject::Name(n)) => vec![n.clone()],
        Some(PdfObject::Array(items)) => items
            .iter()
            .filter_map(PdfObject::as_name)
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Budget, Limits};

    fn doc(src: &[u8]) -> Document {
        let limits = Limits::default();
        Document::parse(src, &limits, &mut Budget::new(&limits))
    }

    fn stream(num: u32, dict: &str) -> String {
        format!("{num} 0 obj << {dict} /Length 1 >> stream\nx\nendstream endobj\n")
    }

    fn roles_of(src: &str) -> Vec<(u32, StreamRoles)> {
        let d = doc(src.as_bytes());
        let roles = classify(&d);
        d.objects
            .iter()
            .zip(roles)
            .filter(|(e, _)| matches!(e.object, PdfObject::Stream(_)))
            .map(|(e, r)| (e.id.num, r))
            .collect()
    }

    fn get(v: &[(u32, StreamRoles)], n: u32) -> StreamRoles {
        v.iter()
            .find(|(i, _)| *i == n)
            .map(|(_, r)| *r)
            .unwrap_or_default()
    }

    #[test]
    fn roles_from_references() {
        let src = [
            "1 0 obj << /Type /Page /Contents [2 0 R 3 0 R] /AP << /N << /On 4 0 R >> /D 5 0 R >> >> endobj\n",
            "6 0 obj << /CharProcs << /a 7 0 R >> /Metadata 8 0 R /XFA [(t) 9 0 R] /JS 10 0 R >> endobj\n",
            "11 0 obj << /FontFile2 12 0 R /EF << /F 13 0 R >> /CS [/Indexed [/ICCBased 14 0 R] 1 <00>] >> endobj\n",
        ]
        .concat();
        let mut src = src;
        for n in 2..=14 {
            if n != 6 && n != 11 {
                src.push_str(&stream(n, ""));
            }
        }
        let v = roles_of(&src);
        for n in [2, 3, 4, 5, 7] {
            assert!(get(&v, n).content, "{n}");
            assert!(get(&v, n).tokenized());
        }
        assert!(get(&v, 8).xml && get(&v, 9).xml);
        assert!(get(&v, 10).script && get(&v, 10).must_inspect());
        for n in [12, 13, 14] {
            assert!(get(&v, n).opaque && !get(&v, n).tokenized(), "{n}");
        }
    }

    #[test]
    fn roles_from_own_dict() {
        let src = [
            stream(1, "/Subtype /Form"),
            stream(2, "/Type /Pattern /PatternType 1"),
            stream(3, "/Type /Pattern /PatternType 2"),
            stream(4, "/Type /Metadata /Subtype /XML"),
            stream(5, "/Subtype /Image"),
            stream(6, "/Length1 5"),
            stream(7, "/FunctionType 0"),
            stream(8, "/Type /EmbeddedFile"),
            stream(9, ""),
        ]
        .concat();
        let v = roles_of(&src);
        assert!(get(&v, 1).content && get(&v, 2).content);
        assert!(get(&v, 3).speculative());
        assert!(get(&v, 4).xml);
        for n in 5..=8 {
            assert!(get(&v, n).opaque, "{n}");
        }
        assert!(get(&v, 9).speculative() && get(&v, 9).tokenized());
        assert!(!get(&v, 9).must_inspect());
    }

    #[test]
    fn inspect_role_beats_opaque() {
        let src = format!(
            "1 0 obj << /Contents 2 0 R >> endobj\n{}",
            stream(2, "/Subtype /Image")
        );
        let r = get(&roles_of(&src), 2);
        assert!(r.content && r.opaque && r.must_inspect() && r.tokenized());
    }

    #[test]
    fn every_definition_gets_the_role() {
        let src = format!(
            "1 0 obj << /Contents 2 0 R >> endobj\n{}{}",
            stream(2, ""),
            stream(2, "/Q 1")
        );
        let d = doc(src.as_bytes());
        let roles = classify(&d);
        assert_eq!(roles.iter().filter(|r| r.content).count(), 2);
    }

    #[test]
    fn chain_resolves_references() {
        let d = doc(b"1 0 obj /FlateDecode endobj\n2 0 obj [/AHx 1 0 R] endobj\n3 0 obj << /Predictor 12 >> endobj");
        let dict = Dict::new(vec![
            (
                Name::from("Filter"),
                PdfObject::Ref(crate::parser::ObjRef::new(2, 0)),
            ),
            (
                Name::from("DecodeParms"),
                PdfObject::Array(vec![
                    PdfObject::Null,
                    PdfObject::Ref(crate::parser::ObjRef::new(3, 0)),
                ]),
            ),
        ]);
        let (f, p) = resolved_chain(&d, &dict).unwrap();
        let names = filter_names(f.as_ref());
        assert_eq!(names, vec![Name::from("AHx"), Name::from("FlateDecode")]);
        let p = p.unwrap();
        assert!(p.as_array().unwrap()[1].as_dict().is_some());
    }

    #[test]
    fn duplicate_filter_is_ambiguous() {
        let d = doc(b"");
        let dict = Dict::new(vec![
            (
                Name::from("Filter"),
                PdfObject::Name(Name::from("FlateDecode")),
            ),
            (Name::from("Filter"), PdfObject::Name(Name::from("AHx"))),
        ]);
        assert!(resolved_chain(&d, &dict).is_err());
        assert!(filter_names(None).is_empty());
    }
}
