//! `Ctx`: everything rules may read (design §5.3). Built once per scan from
//! the union object set; rules never parse bytes.
//!
//! Decoding is lazy and cached: a stream is decoded at most once, and the
//! decode budget is charged once. Streams that must be inspected (content,
//! XML, JavaScript) are decoded when the `Ctx` is built, so a stream that
//! cannot be decoded is an engine issue whether or not a rule asks for it.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::rc::Rc;

use super::content_ops::{ContentOp, tokenize};
use super::page_tree::{PageTree, page_tree};
use super::streams::{StreamRoles, classify, filter_names, resolved_chain};
use super::visitor::{Location, visit_dicts};
use crate::error::{EngineIssue, IssueCode};
use crate::filters::{DecodeOutcome, FilterKind, decode};
use crate::limits::{Budget, Limits, Thresholds};
use crate::parser::document::{Facts, ObjectEntry, Revision, Trailer};
use crate::parser::structure::Structure;
use crate::parser::{Dict, Document, Name, PdfObject};

/// Decoded data of a stream (complete, truncated, or partial for a
/// speculative stream).
#[derive(Clone, Debug)]
pub struct StreamData<'a>(Rc<DecodeOutcome<'a>>);

impl StreamData<'_> {
    /// Complete or truncated: every byte a reader would see.
    pub fn is_usable(&self) -> bool {
        self.0.is_usable()
    }
}

impl Deref for StreamData<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.data().unwrap_or_default()
    }
}

/// Where a content operator is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpLocation {
    /// The content stream.
    pub stream: Location,
    /// Offset of the operator in the decoded stream.
    pub offset: usize,
    /// The stream has no known content role; tokenized because it could be
    /// one (union).
    pub speculative: bool,
}

/// An Image XObject (any dictionary with `/Subtype /Image`).
#[derive(Clone, Debug, PartialEq)]
pub struct ImageFact {
    pub location: Location,
    /// `None`: missing or not a number.
    pub width: Option<f64>,
    pub height: Option<f64>,
}

/// Callbacks of [`Ctx::walk`].
pub trait Visitor {
    fn dict(&mut self, _dict: &Dict, _loc: &Location) {}
    fn content_op(&mut self, _op: &ContentOp<'_>, _loc: &OpLocation) {}
    /// `true`: the visitor wants nothing more; the walk stops early.
    fn done(&self) -> bool {
        false
    }
}

pub struct Ctx<'a> {
    src: &'a [u8],
    limits: Limits,
    thresholds: Thresholds,
    doc: Document,
    roles: Vec<StreamRoles>,
    page_tree: PageTree,
    images: Vec<ImageFact>,
    headers: Vec<usize>,
    budget: RefCell<Budget>,
    cache: RefCell<HashMap<usize, Rc<DecodeOutcome<'a>>>>,
    issues: RefCell<Vec<EngineIssue>>,
    /// Limit codes already reported (each once per scan).
    limits_hit: RefCell<HashSet<IssueCode>>,
}

impl<'a> Ctx<'a> {
    pub fn new(src: &'a [u8], limits: Limits, thresholds: Thresholds) -> Ctx<'a> {
        let mut budget = Budget::new(&limits);
        let doc = Document::parse(src, &limits, &mut budget);
        let limits_hit = doc
            .issues
            .iter()
            .map(|i| i.code)
            .filter(|c| c.is_limit())
            .collect();
        let roles = classify(&doc);
        let page_tree = page_tree(&doc);
        let images = images(&doc);
        let headers = headers_outside_streams(&doc);
        let ctx = Ctx {
            src,
            limits,
            thresholds,
            doc,
            roles,
            page_tree,
            images,
            headers,
            budget: RefCell::new(budget),
            cache: RefCell::new(HashMap::new()),
            issues: RefCell::new(Vec::new()),
            limits_hit: RefCell::new(limits_hit),
        };
        for i in 0..ctx.roles.len() {
            if ctx.roles[i].must_inspect() {
                ctx.decode(i);
            }
        }
        ctx
    }

    /// The input bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.src
    }

    pub fn document(&self) -> &Document {
        &self.doc
    }

    pub fn objects(&self) -> &[ObjectEntry] {
        &self.doc.objects
    }

    pub fn trailers(&self) -> &[Trailer] {
        &self.doc.trailers
    }

    pub fn revisions(&self) -> &[Revision] {
        &self.doc.revisions
    }

    pub fn structure(&self) -> &Structure {
        &self.doc.structure
    }

    pub fn structure_facts(&self) -> &Facts {
        &self.doc.facts
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn thresholds(&self) -> &Thresholds {
        &self.thresholds
    }

    pub fn page_tree(&self) -> &PageTree {
        &self.page_tree
    }

    /// Image XObjects (inline images: the `BI` content operator).
    pub fn images(&self) -> &[ImageFact] {
        &self.images
    }

    /// Offsets of every line starting with `%PDF-` outside stream data
    /// (the header included).
    pub fn header_lines(&self) -> &[usize] {
        &self.headers
    }

    /// Roles of stream `objects[object]` (default for non-streams).
    pub fn stream_roles(&self, object: usize) -> StreamRoles {
        self.roles.get(object).copied().unwrap_or_default()
    }

    /// Filter names of stream `objects[object]`, references resolved.
    pub fn filter_chain(&self, object: usize) -> Vec<Name> {
        let Some(s) = self
            .doc
            .objects
            .get(object)
            .and_then(|e| e.object.as_stream())
        else {
            return Vec::new();
        };
        match resolved_chain(&self.doc, &s.dict) {
            Ok((f, _)) => filter_names(f.as_ref()),
            Err(_) => filter_names(s.dict.get("Filter")),
        }
    }

    /// The values `o` stands for: `o` itself, or, if it is an indirect
    /// reference, every definition of the referenced object (one level; union).
    pub fn resolve<'s>(&'s self, o: &'s PdfObject) -> impl Iterator<Item = &'s PdfObject> + 's {
        let defs = o
            .as_reference()
            .map(|r| self.doc.definitions(r).map(|e| &e.object));
        let direct = if defs.is_none() { Some(o) } else { None };
        direct.into_iter().chain(defs.into_iter().flatten())
    }

    /// Decoded data of the stream whose dictionary is at `loc` (`None`: not
    /// a stream dictionary, or not decodable).
    pub fn decoded_stream(&self, loc: &Location) -> Option<StreamData<'a>> {
        if !loc.is_object() {
            return None;
        }
        let outcome = self.decode(loc.object)?;
        outcome.data()?;
        Some(StreamData(outcome))
    }

    /// Decodes stream `objects[object]` once (cached) and records issues.
    pub fn decode(&self, object: usize) -> Option<Rc<DecodeOutcome<'a>>> {
        if let Some(o) = self.cache.borrow().get(&object) {
            return Some(Rc::clone(o));
        }
        let entry = self.doc.objects.get(object)?;
        let stream = entry.object.as_stream()?;
        let roles = self.stream_roles(object);
        let outcome = match resolved_chain(&self.doc, &stream.dict) {
            Err(msg) => DecodeOutcome::Invalid(msg),
            Ok((filter, parms)) => match self.src.get(stream.data.clone()) {
                None => DecodeOutcome::Invalid("stream data out of range"),
                Some(raw) => decode(
                    raw,
                    filter.as_ref(),
                    parms.as_ref(),
                    &mut self.budget.borrow_mut(),
                ),
            },
        };
        let offset = Some(Location::of(object, entry).offset());
        let what = || {
            let kind = if roles.content {
                "content"
            } else if roles.xml {
                "XML"
            } else {
                "JavaScript"
            };
            format!("{kind} stream {}", entry.id)
        };
        match &outcome {
            DecodeOutcome::Limit(code) => {
                if self.limits_hit.borrow_mut().insert(*code) {
                    self.issue(*code, offset, format!("stream {}: decode limit", entry.id));
                }
            }
            // Truncated data is inspected as far as it decodes (what readers
            // render, ADR #26); `STRUCT.TRUNCATED_STREAM` reports it.
            DecodeOutcome::Complete(_) | DecodeOutcome::Truncated { .. } => {}
            other if roles.must_inspect() => {
                let why = match other {
                    DecodeOutcome::Partial { filter, .. } => {
                        format!("{} data corrupt", filter.name())
                    }
                    DecodeOutcome::NotInspected(k) => format!("filter {} not decoded", k.name()),
                    DecodeOutcome::Unknown(n) => format!("unknown filter {n:?}"),
                    DecodeOutcome::Invalid(m) => (*m).to_string(),
                    _ => String::new(),
                };
                self.issue(
                    IssueCode::EngineUndecodable,
                    offset,
                    format!("{}: {why}", what()),
                );
            }
            _ => {}
        }
        let outcome = Rc::new(outcome);
        self.cache.borrow_mut().insert(object, Rc::clone(&outcome));
        Some(outcome)
    }

    /// Streams whose data ends before the end marker of a filter (the
    /// filter named): object and xref streams found by the parser, and every
    /// stream that is inspected or tokenized (decoded here if not yet).
    /// Sorted by object index.
    pub fn truncated_streams(&self) -> Vec<(usize, FilterKind)> {
        let mut v = self.doc.facts.truncated_streams.clone();
        for i in 0..self.roles.len() {
            let roles = self.roles[i];
            if !(roles.must_inspect() || roles.tokenized()) {
                continue;
            }
            if let Some(o) = self.decode(i) {
                if let DecodeOutcome::Truncated { filter, .. } = *o {
                    v.push((i, filter));
                }
            }
        }
        v.sort_unstable_by_key(|&(i, _)| i);
        v.dedup_by_key(|&mut (i, _)| i);
        v
    }

    /// Decoded bytes charged to the budget so far.
    pub fn decoded_bytes(&self) -> u64 {
        self.budget.borrow().used()
    }

    /// Every engine issue so far: parser issues, then facts issues.
    pub fn issues(&self) -> Vec<EngineIssue> {
        let mut v = self.doc.issues.clone();
        v.extend(self.issues.borrow().iter().cloned());
        v
    }

    fn issue(&self, code: IssueCode, offset: Option<usize>, msg: String) {
        self.issues
            .borrow_mut()
            .push(EngineIssue::new(code, offset, msg));
    }

    /// The single traversal: every dictionary (file order), then every
    /// operator of every content stream (known and speculative). Stops
    /// between dictionaries / streams once [`Visitor::done`].
    pub fn walk(&self, v: &mut dyn Visitor) {
        visit_dicts(&self.doc.objects, |d, loc| {
            if !v.done() {
                v.dict(d, loc);
            }
        });
        for (i, entry) in self.doc.objects.iter().enumerate() {
            if v.done() {
                return;
            }
            let roles = self.stream_roles(i);
            if !roles.tokenized() {
                continue;
            }
            let Some(outcome) = self.decode(i) else {
                continue;
            };
            let Some(data) = outcome.data() else { continue };
            let loc = OpLocation {
                stream: Location::of(i, entry),
                offset: 0,
                speculative: !roles.content,
            };
            let result = tokenize(data, &self.limits, |op| {
                let loc = OpLocation {
                    offset: op.offset,
                    ..loc.clone()
                };
                v.content_op(op, &loc);
            });
            if let Err(code) = result {
                // A broken operand in a stream that may not be content is
                // not worth an error; in real content it hides operators.
                if roles.content && self.limits_hit.borrow_mut().insert(code) {
                    self.issue(
                        code,
                        Some(loc.stream.offset()),
                        format!("content stream {}: operand nested too deep", entry.id),
                    );
                }
            }
        }
    }
}

fn number(o: Option<&PdfObject>) -> Option<f64> {
    o?.as_number()
}

/// Every dictionary with `/Subtype /Image`, nested ones included.
fn images(doc: &Document) -> Vec<ImageFact> {
    let mut out = Vec::new();
    visit_dicts(&doc.objects, |d, loc| {
        if d.get_all("Subtype").any(|s| s.is_name("Image")) {
            let resolve = |key: &str| match d.get(key) {
                Some(PdfObject::Ref(r)) => doc
                    .definitions(*r)
                    .next()
                    .and_then(|e| e.object.as_number()),
                o => number(o),
            };
            out.push(ImageFact {
                location: loc.clone(),
                width: resolve("Width"),
                height: resolve("Height"),
            });
        }
    });
    out
}

/// `%PDF-` line starts not inside the raw data of any top-level stream.
fn headers_outside_streams(doc: &Document) -> Vec<usize> {
    let mut ranges: Vec<std::ops::Range<usize>> = doc
        .objects
        .iter()
        .filter(|e| e.is_top_level())
        .filter_map(|e| e.object.as_stream())
        .map(|s| s.data.clone())
        .filter(|r| !r.is_empty())
        .collect();
    ranges.sort_by_key(|r| r.start);
    doc.structure
        .header_lines
        .iter()
        .copied()
        .filter(|&h| {
            // Ranges may overlap (false streams in binary data): check every
            // range starting at or before `h`.
            let n = ranges.partition_point(|r| r.start <= h);
            !ranges[..n].iter().rev().any(|r| h < r.end)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(src: &[u8]) -> Ctx<'_> {
        Ctx::new(src, Limits::default(), Thresholds::default())
    }

    #[derive(Default)]
    struct Collect {
        dicts: usize,
        ops: Vec<(String, bool)>,
    }

    impl Visitor for Collect {
        fn dict(&mut self, _: &Dict, _: &Location) {
            self.dicts += 1;
        }
        fn content_op(&mut self, op: &ContentOp<'_>, loc: &OpLocation) {
            self.ops.push((
                String::from_utf8_lossy(op.operator).into_owned(),
                loc.speculative,
            ));
        }
    }

    #[test]
    fn decode_is_cached_and_charged_once() {
        let src = b"1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length 9 /Filter /AHx >> stream\n71205053>\nendstream endobj";
        let c = ctx(src);
        assert!(c.issues().is_empty(), "{:?}", c.issues());
        let used = c.decoded_bytes();
        assert_eq!(used, 4);
        let loc = Location::of(1, &c.objects()[1]);
        let a = c.decoded_stream(&loc).unwrap();
        let b = c.decoded_stream(&loc).unwrap();
        assert_eq!(&*a, b"q PS");
        assert!(Rc::ptr_eq(&a.0, &b.0));
        assert_eq!(c.decoded_bytes(), used);
        let mut v = Collect::default();
        c.walk(&mut v);
        assert_eq!(v.ops, vec![("q".into(), false), ("PS".into(), false)]);
        assert_eq!(c.decoded_bytes(), used);
        assert_eq!(c.filter_chain(1), vec![Name::from("AHx")]);
        assert!(c.filter_chain(0).is_empty());
    }

    #[test]
    fn content_with_unknown_filter_is_an_issue() {
        let src = b"1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length 2 /Filter /Bogus >> stream\nPS\nendstream endobj";
        let c = ctx(src);
        let issues = c.issues();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, IssueCode::EngineUndecodable);
        assert!(
            issues[0].message.contains("content stream 2 0"),
            "{}",
            issues[0].message
        );
    }

    #[test]
    fn speculative_stream_with_unknown_filter_is_not_an_issue() {
        let src = b"2 0 obj << /Length 2 /Filter /Bogus >> stream\nPS\nendstream endobj\n3 0 obj << /Length 4 >> stream\nq PS\nendstream endobj";
        let c = ctx(src);
        assert!(c.issues().is_empty());
        let mut v = Collect::default();
        c.walk(&mut v);
        assert_eq!(v.ops, vec![("q".into(), true), ("PS".into(), true)]);
    }

    #[test]
    fn opaque_streams_are_not_decoded() {
        let src = b"2 0 obj << /Subtype /Image /Width 1 /Height 1 /Length 2 >> stream\nPS\nendstream endobj";
        let c = ctx(src);
        let mut v = Collect::default();
        c.walk(&mut v);
        assert!(v.ops.is_empty());
        assert_eq!(c.decoded_bytes(), 0);
        assert_eq!(c.images().len(), 1);
        assert_eq!(c.images()[0].width, Some(1.0));
    }

    #[test]
    fn xml_and_script_must_decode() {
        let src = b"1 0 obj << /Metadata 2 0 R /JS 3 0 R >> endobj\n\
            2 0 obj << /Length 2 /Filter /DCTDecode >> stream\nxx\nendstream endobj\n\
            3 0 obj << /Length 2 /Filter /FlateDecode >> stream\n\xff\xff\nendstream endobj";
        let c = ctx(src);
        let codes: Vec<_> = c.issues().iter().map(|i| i.message.clone()).collect();
        assert_eq!(codes.len(), 2, "{codes:?}");
        assert!(codes[0].starts_with("XML stream 2 0: filter DCTDecode"));
        assert!(codes[1].starts_with("JavaScript stream 3 0: FlateDecode"));
    }

    #[test]
    fn duplicate_filter_in_content_is_an_issue() {
        let src = b"1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length 2 /Filter /AHx /Filter /A85 >> stream\nPS\nendstream endobj";
        let c = ctx(src);
        assert_eq!(c.issues()[0].code, IssueCode::EngineUndecodable);
        assert!(c.issues()[0].message.contains("duplicate"));
    }

    #[test]
    fn decode_limit_reported_once() {
        let limits = Limits {
            max_decoded_bytes_total: 2,
            ..Limits::default()
        };
        let src = b"2 0 obj << /Length 5 /Filter /AHx >> stream\n71205>\nendstream endobj\n3 0 obj << /Length 5 /Filter /AHx >> stream\n71205>\nendstream endobj";
        let c = Ctx::new(src, limits, Thresholds::default());
        c.walk(&mut Collect::default());
        let issues = c.issues();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, IssueCode::LimitDecodedBytes);
    }

    fn with_stream(dict: &str, data: &[u8]) -> Vec<u8> {
        [
            format!("1 0 obj << /Contents 2 0 R /Metadata 3 0 R >> endobj\n2 0 obj << {dict} /Length {} >> stream\n", data.len()).as_bytes(),
            data,
            b"\nendstream endobj\n3 0 obj << /Length 4 >> stream\n<x/>\nendstream endobj",
        ]
        .concat()
    }

    #[test]
    fn truncated_content_is_inspected() {
        let content: Vec<u8> = (0..400)
            .flat_map(|i| format!("q 1 0 0 1 {i} {} cm Q ", i * 7 % 13).into_bytes())
            .collect();
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&content, 6);
        let cut = &z[..z.len() * 2 / 3];
        let src = with_stream("/Filter /FlateDecode", cut);
        let c = ctx(&src);
        assert!(c.issues().is_empty(), "{:?}", c.issues());
        let data = c.decoded_stream(&Location::of(1, &c.objects()[1])).unwrap();
        assert!(data.is_usable() && data.len() > 100);
        assert!(content.starts_with(&data));
        assert!(matches!(
            *c.decode(1).unwrap(),
            DecodeOutcome::Truncated { .. }
        ));
        // Corrupt data in a content stream is still an issue.
        let src = with_stream(
            "/Filter /FlateDecode",
            &[&[0x78, 0x9C, 0xFF][..], &[0; 8]].concat(),
        );
        assert_eq!(ctx(&src).issues()[0].code, IssueCode::EngineUndecodable);
    }

    #[test]
    fn unfiltered_streams_are_not_limited_or_copied() {
        let limits = Limits {
            max_decoded_bytes_per_stream: 10,
            max_decoded_bytes_total: 10,
            ..Limits::default()
        };
        let data = b"q Q ".repeat(100);
        let src = with_stream("", &data);
        let c = Ctx::new(&src, limits.clone(), Thresholds::default());
        c.walk(&mut Collect::default());
        assert!(c.issues().is_empty(), "{:?}", c.issues());
        assert_eq!(c.decoded_bytes(), 0);
        let d = c.decoded_stream(&Location::of(1, &c.objects()[1])).unwrap();
        // The very bytes of the input.
        assert_eq!(
            d.as_ptr(),
            src[src.windows(4).position(|w| w == b"q Q ").unwrap()..].as_ptr()
        );
        // Filtered data still counts.
        let src = with_stream("/Filter /AHx", &b"20".repeat(11));
        let c = Ctx::new(&src, limits, Thresholds::default());
        assert_eq!(c.issues()[0].code, IssueCode::LimitStreamDecodedBytes);
    }

    #[test]
    fn deep_operand_in_content_is_a_limit() {
        let mut data = vec![b'['; 600];
        data.extend_from_slice(b" PS");
        let mut src = format!(
            "1 0 obj << /Contents 2 0 R >> endobj\n2 0 obj << /Length {} >> stream\n",
            data.len()
        )
        .into_bytes();
        src.extend_from_slice(&data);
        src.extend_from_slice(b"\nendstream endobj");
        let c = ctx(&src);
        c.walk(&mut Collect::default());
        assert_eq!(c.issues()[0].code, IssueCode::LimitNestingDepth);
    }

    #[test]
    fn headers_inside_stream_data_are_excluded() {
        let src =
            b"%PDF-1.7\n1 0 obj << /Length 9 >> stream\n%PDF-1.4\nendstream endobj\n%PDF-1.5\n";
        let c = ctx(src);
        let last = src.windows(5).rposition(|w| w == b"%PDF-").unwrap();
        assert_eq!(c.header_lines(), &[0, last]);
    }

    #[test]
    fn resolve_follows_one_level() {
        use crate::parser::ObjRef;
        let src = b"1 0 obj /A endobj\n1 0 obj /B endobj\n2 0 obj 1 0 R endobj";
        let c = ctx(src);
        let all = |o: &PdfObject| -> Vec<PdfObject> { c.resolve(o).cloned().collect() };
        let name = |n: &str| PdfObject::Name(Name::from(n));
        let r1 = PdfObject::Ref(ObjRef::new(1, 0));
        assert_eq!(all(&r1), vec![name("A"), name("B")]);
        assert_eq!(all(&PdfObject::Ref(ObjRef::new(2, 0))), vec![r1]);
        assert!(all(&PdfObject::Ref(ObjRef::new(9, 0))).is_empty());
        assert_eq!(all(&PdfObject::Int(3)), vec![PdfObject::Int(3)]);
    }

    #[test]
    fn walk_visits_every_dict() {
        let src = b"1 0 obj << /A << /B 1 >> >> endobj\n2 0 obj [<< >>] endobj";
        let c = ctx(src);
        let mut v = Collect::default();
        c.walk(&mut v);
        assert_eq!(v.dicts, 3);
        assert!(c.stream_roles(0) == StreamRoles::default());
        assert!(
            c.decoded_stream(&Location::of(0, &c.objects()[0]))
                .is_none()
        );
    }
}
