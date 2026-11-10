//! What each stream is, and its filter chain with indirect references
//! resolved.
//!
//! Roles come from the stream's own dictionary (`/Subtype /Form`,
//! `/Type /Metadata`, …) and from every reference to it anywhere in the
//! union set (`/Contents`, `/AP`, `/CharProcs`, `/XFA`, `/JS`, …), all
//! definitions included. A value that is itself a reference to an array or
//! a dictionary (`/Contents 30 0 R` → `[31 0 R 32 0 R]`) is followed one
//! level, through every definition. A stream can have several roles; any
//! role that must be inspected wins over "opaque" (an image referenced as
//! page content is content).

use super::visitor::visit_dicts;
use crate::parser::document::ObjectEntry;
use crate::parser::{Dict, Document, Name, ObjRef, PdfObject};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamRoles {
    /// Content stream: page `/Contents`, Form XObject, tiling pattern,
    /// Type 3 glyph procedure, appearance stream.
    pub content: bool,
    /// XML: XMP metadata or an XFA packet.
    pub xml: bool,
    /// JavaScript (`/JS` stream).
    pub script: bool,
    /// Never inspected: binary data of a known kind — image, font program,
    /// CID maps, embedded file, ICC profile, `Indexed` palette, sampled
    /// function, mesh shading, threshold halftone, sound, 3D, signature
    /// validation data, JBIG2 globals — or an object/xref stream (the parser
    /// handles those).
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
            for r in refs(doc, o) {
                marks.extend(doc.definition_indices(r).map(|i| (i, role)));
            }
        };
        for (k, v) in dict.entries() {
            match k.as_bytes() {
                b"Contents" => mark(v, Role::Content),
                b"CharProcs" => each_value(doc, v, |x| mark(x, Role::Content)),
                b"AP" => each_value(doc, v, |state| {
                    mark(state, Role::Content);
                    each_value(doc, state, |x| mark(x, Role::Content));
                }),
                b"Metadata" | b"XFA" => mark(v, Role::Xml),
                b"JS" => mark(v, Role::Script),
                b"FontFile" | b"FontFile2" | b"FontFile3" | b"Thumb" | b"CIDToGIDMap"
                | b"CIDSet" | b"DestOutputProfile" | b"JBIG2Globals" | b"Sound" | b"3DD"
                | b"Certs" | b"OCSPs" | b"CRLs" | b"Cert" | b"OCSP" | b"CRL" => {
                    mark(v, Role::Opaque);
                }
                b"EF" => each_value(doc, v, |x| mark(x, Role::Opaque)),
                _ => {}
            }
        }
    });
    // Colour spaces are arrays, possibly top-level objects of their own.
    visit_arrays(&doc.objects, |items| {
        if let Some(r) = colour_space_streams(items) {
            marks.extend(doc.definition_indices(r).map(|i| (i, Role::Opaque)));
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
    if any(
        "Subtype",
        &["Image", "Type1C", "CIDFontType0C", "OpenType", "U3D", "PRC"],
    ) || any("Type", &["ObjStm", "XRef", "EmbeddedFile"])
        || d.contains_key("Length1")
        || d.contains_key("Length2")
        || d.contains_key("Length3")
        || int("FunctionType", 0)
        || (4..=7).any(|t| int("ShadingType", t))
        || [6, 10, 16].into_iter().any(|t| int("HalftoneType", t))
    {
        return Some(Role::Opaque);
    }
    None
}

/// The reference, every reference in an array, and — when the reference
/// names an array (any definition) — every reference in that array.
fn refs(doc: &Document, o: &PdfObject) -> Vec<ObjRef> {
    let in_array = |items: &[PdfObject]| -> Vec<ObjRef> {
        items.iter().filter_map(PdfObject::as_reference).collect()
    };
    match o {
        PdfObject::Ref(r) => {
            let mut v = vec![*r];
            for d in doc.definitions(*r) {
                if let PdfObject::Array(items) = &d.object {
                    v.extend(in_array(items));
                }
            }
            v
        }
        PdfObject::Array(items) => in_array(items),
        _ => Vec::new(),
    }
}

/// Every value of a dictionary, or of every definition of the dictionary a
/// reference names.
fn each_value(doc: &Document, o: &PdfObject, mut f: impl FnMut(&PdfObject)) {
    let mut values = |d: &Dict| {
        for (_, v) in d.entries() {
            f(v);
        }
    };
    match o {
        PdfObject::Dict(d) => values(d),
        PdfObject::Ref(r) => {
            for d in doc.definitions(*r) {
                if let PdfObject::Dict(d) = &d.object {
                    values(d);
                }
            }
        }
        _ => {}
    }
}

/// Calls `f` for every array in `objects`: top-level, nested in arrays and
/// dictionaries, in stream dictionaries. Iterative.
fn visit_arrays<'a>(objects: &'a [ObjectEntry], mut f: impl FnMut(&'a [PdfObject])) {
    for entry in objects {
        let mut stack: Vec<&'a PdfObject> = vec![&entry.object];
        while let Some(o) = stack.pop() {
            match o {
                PdfObject::Array(items) => {
                    f(items);
                    stack.extend(items);
                }
                PdfObject::Dict(d) => stack.extend(d.entries().iter().map(|(_, v)| v)),
                PdfObject::Stream(s) => stack.extend(s.dict.entries().iter().map(|(_, v)| v)),
                _ => {}
            }
        }
    }
}

/// Binary streams a colour space array names: the ICC profile of
/// `[/ICCBased N G R]` and the palette of `[/Indexed base hival N G R]`.
/// Nested colour spaces are arrays of their own (see [`visit_arrays`]).
fn colour_space_streams(items: &[PdfObject]) -> Option<ObjRef> {
    let slot = match items.first() {
        Some(n) if n.is_name("ICCBased") => 1,
        Some(n) if n.is_name("Indexed") => 3,
        _ => return None,
    };
    items.get(slot).and_then(PdfObject::as_reference)
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
    fn roles_through_indirect_arrays_and_dicts() {
        let src = [
            "1 0 obj << /Type /Page /Contents 20 0 R /AP 21 0 R >> endobj\n",
            "20 0 obj [2 0 R 3 0 R] endobj\n",
            "21 0 obj << /N 22 0 R >> endobj\n",
            "22 0 obj << /On 4 0 R >> endobj\n",
            "6 0 obj << /CharProcs 23 0 R /XFA 24 0 R /EF 25 0 R >> endobj\n",
            "23 0 obj << /a 5 0 R >> endobj\n",
            "24 0 obj [(template) 7 0 R (datasets) 8 0 R] endobj\n",
            "25 0 obj << /F 9 0 R >> endobj\n",
            // A second definition of the array counts too (union).
            "20 0 obj [10 0 R] endobj\n",
        ]
        .concat();
        let mut src = src;
        for n in [2, 3, 4, 5, 7, 8, 9, 10] {
            src.push_str(&stream(n, ""));
        }
        let v = roles_of(&src);
        for n in [2, 3, 4, 5, 10] {
            assert!(get(&v, n).content, "{n}");
        }
        assert!(get(&v, 7).xml && get(&v, 8).xml);
        assert!(get(&v, 9).opaque);
    }

    #[test]
    fn binary_streams_are_opaque() {
        let src = [
            // Palettes: direct, nested in other colour spaces, and a colour
            // space that is a top-level array object.
            "1 0 obj << /ColorSpace << /C0 [/Indexed /DeviceCMYK 120 2 0 R] /C1 [/Pattern [/Indexed /DeviceRGB 1 3 0 R]] /C2 30 0 R >> >> endobj\n",
            "30 0 obj [/Indexed 31 0 R 255 4 0 R] endobj\n",
            "31 0 obj [/ICCBased 5 0 R] endobj\n",
            "6 0 obj << /Subtype /CIDFontType2 /CIDToGIDMap 7 0 R /FontDescriptor << /CIDSet 8 0 R >> >> endobj\n",
            "9 0 obj << /OutputIntents [<< /DestOutputProfile 10 0 R >>] /DSS << /Certs [11 0 R] /OCSPs 32 0 R /CRLs [12 0 R] >> >> endobj\n",
            "32 0 obj [13 0 R] endobj\n",
            "14 0 obj << /S /Sound /Sound 15 0 R >> endobj\n",
            "16 0 obj << /DecodeParms << /JBIG2Globals 17 0 R >> >> endobj\n",
        ]
        .concat();
        let mut src = src;
        for n in [2, 3, 4, 5, 7, 8, 10, 11, 12, 13, 15, 17] {
            src.push_str(&stream(n, ""));
        }
        src.push_str(&stream(18, "/ShadingType 4 /ColorSpace /DeviceRGB"));
        src.push_str(&stream(19, "/ShadingType 7"));
        src.push_str(&stream(20, "/ShadingType 2"));
        src.push_str(&stream(21, "/HalftoneType 6"));
        src.push_str(&stream(22, "/Subtype /U3D"));
        let v = roles_of(&src);
        for n in [2, 3, 4, 5, 7, 8, 10, 11, 12, 13, 15, 17, 18, 19, 21, 22] {
            assert!(get(&v, n).opaque && !get(&v, n).tokenized(), "{n}");
        }
        // Axial shading is a dictionary in real files; a stream with it is
        // still unknown.
        assert!(get(&v, 20).speculative());
        // A palette string is not a stream; an array of the wrong shape
        // marks nothing.
        let src = format!(
            "1 0 obj [/Indexed /DeviceRGB 2 0 R] endobj\n2 0 obj [/Foo 1 2 3 0 R] endobj\n{}",
            stream(3, "")
        );
        assert!(get(&roles_of(&src), 3).speculative());
    }

    #[test]
    fn inspect_role_beats_opaque() {
        let src = format!(
            "1 0 obj << /Contents 2 0 R >> endobj\n{}",
            stream(2, "/Subtype /Image")
        );
        let r = get(&roles_of(&src), 2);
        assert!(r.content && r.opaque && r.must_inspect() && r.tokenized());
        // A content stream also named as a palette is still content.
        let src = format!(
            "1 0 obj << /Contents 2 0 R /CS [/Indexed /DeviceRGB 1 2 0 R] >> endobj\n{}",
            stream(2, "")
        );
        let r = get(&roles_of(&src), 2);
        assert!(r.content && r.opaque && r.tokenized());
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
