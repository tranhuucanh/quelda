//! The union object set (design §4.2): every object definition any reader
//! could pick — from every xref section (every revision), from a linear scan
//! of the whole file, and from every object stream — plus structure facts
//! about where they disagree. Nothing is repaired and no revision is chosen.
//!
//! One [`ObjectEntry`] per physical definition: a top-level object found by
//! both the linear scan and an xref is one entry listing both sources, so
//! rules see each definition once. Different definitions of the same id are
//! all kept.

use std::collections::{HashMap, HashSet};

use super::linear_scan::object_candidates;
use super::object::{Dict, ObjRef, PdfObject, PdfStream, StreamLength};
use super::objstm::parse_members;
use super::parse::{
    ParseError, object_header_at, parse_indirect_object_extent, parse_object_extent,
    stream_data_with_length,
};
use super::structure::Structure;
use super::xref::{EntryKind, XrefKind, XrefProblem, XrefSection, parse_stream_rows, parse_table};
use crate::error::{EngineIssue, IssueCode};
use crate::filters::{DecodeOutcome, decode};
use crate::limits::{Budget, Limits};

/// Parsing may examine at most `WORK_FACTOR` × (file size + decoded object
/// stream size) + [`WORK_SLACK`] bytes. Normal files need about 1×: each
/// object is parsed once. Crafted overlapping candidates (e.g. thousands of
/// `N 0 obj (` inside one string) would otherwise cost quadratic time.
pub const WORK_FACTOR: usize = 16;
pub const WORK_SLACK: usize = 1 << 20;

/// Where a definition lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Location {
    /// Top-level `N G obj` at `offset` (of `N`).
    File { offset: usize },
    /// Member `index` of the object stream `objects[container]`, at `offset`
    /// in its decoded data.
    ObjStm {
        container: usize,
        index: u32,
        offset: usize,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ObjectEntry {
    pub id: ObjRef,
    pub location: Location,
    pub object: PdfObject,
    /// Index into [`Document::revisions`]: the revision whose body holds the
    /// definition (object stream members: their container's). `None`: after
    /// the last xref section, or no xref at all.
    pub revision: Option<usize>,
    /// `endobj` present (always `true` for object stream members).
    pub has_endobj: bool,
    /// Found by the linear scan.
    pub linear: bool,
    /// Indices into [`Document::sections`] whose entry points at this
    /// definition.
    pub listed_in: Vec<usize>,
}

impl ObjectEntry {
    pub fn is_top_level(&self) -> bool {
        matches!(self.location, Location::File { .. })
    }
}

/// One revision: an xref section (table or stream) and, in a hybrid file,
/// the xref stream its trailer names in `/XRefStm`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    pub section: usize,
    pub hybrid: Vec<usize>,
}

/// A trailer dictionary: after a `trailer` keyword, or an xref stream's
/// dictionary.
#[derive(Clone, Debug, PartialEq)]
pub struct Trailer {
    /// Offset of `trailer`, or of the xref stream object.
    pub offset: usize,
    pub dict: Dict,
    /// The xref section it belongs to (`None`: orphan `trailer`).
    pub section: Option<usize>,
}

impl Trailer {
    pub fn encrypt(&self) -> Option<&PdfObject> {
        self.dict.get("Encrypt")
    }
    pub fn root(&self) -> Option<&PdfObject> {
        self.dict.get("Root")
    }
    pub fn info(&self) -> Option<&PdfObject> {
        self.dict.get("Info")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    /// Offset past the end of the file.
    OutOfRange,
    /// No `N G obj` at the offset.
    NoObject,
    /// `N G obj` with another number or generation.
    WrongId(ObjRef),
    /// Compressed entry: no object stream with that number.
    NoObjStm,
    /// Compressed entry: no member at that index, or one with another number.
    WrongMember,
}

/// An xref entry that does not point at the object it lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XrefMismatch {
    pub section: usize,
    pub num: u32,
    pub kind: MismatchKind,
}

/// Several definitions of one id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateGroup {
    pub id: ObjRef,
    /// Indices into [`Document::objects`].
    pub entries: Vec<usize>,
    /// Every definition has the same content.
    pub identical: bool,
    /// Two definitions in the same revision differ.
    pub conflict_in_revision: bool,
}

/// `N G obj` whose body could not be parsed (truncated, garbage, or a false
/// match inside binary data).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokenObject {
    pub offset: usize,
    pub id: ObjRef,
    pub error: ParseError,
}

/// Structure facts for `STRUCT.*` rules.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Facts {
    pub xref_mismatches: Vec<XrefMismatch>,
    /// Indices into [`Document::objects`] whose number no xref section lists.
    pub unlisted: Vec<usize>,
    pub duplicates: Vec<DuplicateGroup>,
    pub broken_objects: Vec<BrokenObject>,
    /// Sections reached from the last `startxref` through `/Prev`, in order.
    pub chain: Vec<usize>,
    /// The `/Prev` chain revisits a section.
    pub prev_loop: bool,
    /// No `startxref`, or the last one does not point at an xref section.
    pub startxref_invalid: bool,
    /// The first object is a linearization dictionary (its first-page xref
    /// section is then not an incremental update).
    pub linearized: bool,
    /// Streams (indices into `objects`) whose indirect `/Length` has several
    /// definitions giving different valid lengths; the longest is used.
    pub ambiguous_lengths: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Document {
    pub structure: Structure,
    /// Every xref section found, in discovery order.
    pub sections: Vec<XrefSection>,
    /// Revisions in file order (by xref section offset).
    pub revisions: Vec<Revision>,
    /// Every trailer dictionary (union, orphans included).
    pub trailers: Vec<Trailer>,
    pub objects: Vec<ObjectEntry>,
    pub facts: Facts,
    /// Problems that make the verdict `ERROR`.
    pub issues: Vec<EngineIssue>,
    by_id: HashMap<ObjRef, Vec<usize>>,
}

impl Document {
    /// Builds the union object set. Never fails: damage becomes facts, and
    /// whatever could not be inspected becomes an issue.
    pub fn parse(src: &[u8], limits: &Limits, budget: &mut Budget) -> Document {
        let mut b = Builder {
            src,
            limits,
            budget,
            work: Work::new(src.len()),
            doc: Document {
                structure: Structure::scan(src),
                sections: Vec::new(),
                revisions: Vec::new(),
                trailers: Vec::new(),
                objects: Vec::new(),
                facts: Facts::default(),
                issues: Vec::new(),
                by_id: HashMap::new(),
            },
            by_offset: HashMap::new(),
            attempted: HashSet::new(),
            section_at: HashMap::new(),
            full: false,
            issued: HashSet::new(),
        };
        b.linear_scan();
        b.resolve_lengths();
        b.load_sections();
        b.objects_from_xref_offsets();
        b.resolve_lengths();
        b.assign_revisions();
        b.expand_object_streams();
        b.resolve_lengths();
        b.collect_trailers();
        b.xref_facts();
        b.duplicate_facts();
        b.doc.facts.linearized = b.linearized();
        b.doc
    }

    /// Every definition of `id`.
    pub fn definitions(&self, id: ObjRef) -> impl Iterator<Item = &ObjectEntry> + '_ {
        self.by_id
            .get(&id)
            .into_iter()
            .flatten()
            .filter_map(|&i| self.objects.get(i))
    }

    /// Indices into [`Document::objects`] of every definition of `id`.
    pub fn definition_indices(&self, id: ObjRef) -> impl Iterator<Item = usize> + '_ {
        self.by_id.get(&id).into_iter().flatten().copied()
    }

    /// The trailer dictionary of revision `r`.
    pub fn revision_trailer(&self, r: usize) -> Option<&Dict> {
        let s = self.revisions.get(r)?.section;
        self.sections.get(s)?.trailer.as_ref()
    }
}

/// Bytes examined by parsing, against a cap that grows with decoded data.
struct Work {
    used: usize,
    cap: usize,
}

impl Work {
    fn new(len: usize) -> Self {
        Work {
            used: 0,
            cap: len.saturating_mul(WORK_FACTOR).saturating_add(WORK_SLACK),
        }
    }

    fn grow(&mut self, len: usize) {
        self.cap = self.cap.saturating_add(len.saturating_mul(WORK_FACTOR));
    }

    /// `false` once the cap is exceeded.
    fn charge(&mut self, n: usize) -> bool {
        self.used = self.used.saturating_add(n);
        self.used <= self.cap
    }
}

struct Builder<'a, 'b> {
    src: &'a [u8],
    limits: &'a Limits,
    budget: &'b mut Budget,
    work: Work,
    doc: Document,
    /// Top-level definitions by offset of `N`.
    by_offset: HashMap<usize, usize>,
    /// Offsets already given to the object parser (each is parsed once).
    attempted: HashSet<usize>,
    /// Requested section offset → section index (`None`: no section there).
    section_at: HashMap<usize, Option<usize>>,
    /// `max_objects` reached.
    full: bool,
    /// Limit codes already reported once.
    issued: HashSet<IssueCode>,
}

impl Builder<'_, '_> {
    fn issue(&mut self, code: IssueCode, offset: Option<usize>, msg: impl Into<String>) {
        self.doc.issues.push(EngineIssue::new(code, offset, msg));
    }

    /// Reports a limit once per scan.
    fn limit(&mut self, code: IssueCode, msg: &str) {
        if self.issued.insert(code) {
            self.issue(code, None, msg);
        }
    }

    fn charge(&mut self, n: usize) -> bool {
        if self.work.charge(n) {
            return true;
        }
        self.limit(
            IssueCode::LimitParseWork,
            "parsing examined the input too many times over; rest not parsed",
        );
        false
    }

    fn out_of_work(&self) -> bool {
        self.issued.contains(&IssueCode::LimitParseWork)
    }

    /// Adds a definition unless `max_objects` is reached.
    fn push(&mut self, entry: ObjectEntry) -> Option<usize> {
        if self.full || self.doc.objects.len() as u64 >= self.limits.max_objects {
            self.full = true;
            self.limit(
                IssueCode::LimitObjects,
                &format!("more than {} objects", self.limits.max_objects),
            );
            return None;
        }
        let i = self.doc.objects.len();
        if let Location::File { offset } = entry.location {
            self.by_offset.insert(offset, i);
        }
        self.doc.by_id.entry(entry.id).or_default().push(i);
        self.doc.objects.push(entry);
        Some(i)
    }

    /// Parses the top-level object at `offset`; records failures.
    fn parse_top_level(&mut self, offset: usize, linear: bool) -> Option<usize> {
        if self.full || self.out_of_work() || !self.attempted.insert(offset) {
            return self.by_offset.get(&offset).copied();
        }
        let (result, furthest) = parse_indirect_object_extent(self.src, offset, self.limits);
        if !self.charge(furthest.saturating_sub(offset)) {
            return None;
        }
        match result {
            Ok(o) => {
                if let Some(&i) = self.by_offset.get(&o.offset) {
                    return Some(i);
                }
                self.push(ObjectEntry {
                    id: o.id,
                    location: Location::File { offset: o.offset },
                    object: o.object,
                    revision: None,
                    has_endobj: o.has_endobj,
                    linear,
                    listed_in: Vec::new(),
                })
            }
            Err(e) => {
                if e.issue_code().is_limit() {
                    self.doc.issues.push(e.into());
                } else if let Some((start, id)) = object_header_at(self.src, offset) {
                    self.doc.facts.broken_objects.push(BrokenObject {
                        offset: start,
                        id,
                        error: e,
                    });
                }
                None
            }
        }
    }

    fn linear_scan(&mut self) {
        for offset in object_candidates(self.src) {
            if self.full || self.out_of_work() {
                break;
            }
            self.parse_top_level(offset, true);
        }
    }

    /// Resolves indirect `/Length` of every stream still using the scanned
    /// range: each definition of the length object that is a non-negative
    /// integer with `endstream` right after the data it gives is a candidate;
    /// the longest wins (inspect the most bytes).
    fn resolve_lengths(&mut self) {
        let src = self.src;
        let mut updates: Vec<(usize, PdfStream, bool)> = Vec::new();
        for (i, e) in self.doc.objects.iter().enumerate() {
            let PdfObject::Stream(s) = &e.object else {
                continue;
            };
            let StreamLength::Indirect(r) = s.length else {
                continue;
            };
            let mut ranges: Vec<std::ops::Range<usize>> = self
                .doc
                .definitions(r)
                .filter_map(|d| u64::try_from(d.object.as_int()?).ok())
                .filter_map(|len| stream_data_with_length(src, s.data_start, len))
                .map(|(range, _)| range)
                .collect();
            ranges.sort_by_key(|r| r.end);
            ranges.dedup();
            if let Some(longest) = ranges.last() {
                let mut s = s.clone();
                s.data = longest.clone();
                s.length = StreamLength::ResolvedIndirect(r);
                updates.push((i, s, ranges.len() > 1));
            }
        }
        for (i, s, ambiguous) in updates {
            if ambiguous {
                self.doc.facts.ambiguous_lengths.push(i);
            }
            if let Some(e) = self.doc.objects.get_mut(i) {
                e.object = PdfObject::Stream(s);
            }
        }
    }

    /// Loads every xref section: the `/Prev` chain from the last
    /// `startxref`, every other `startxref` target, every `xref` table and
    /// every xref stream in the file.
    fn load_sections(&mut self) {
        // The chain a reader follows.
        let last = self.doc.structure.last_startxref();
        match last {
            Some(off) => {
                let mut stack = vec![off];
                let mut visited = HashSet::new();
                let mut first = true;
                while let Some(off) = stack.pop() {
                    if !visited.insert(off) {
                        self.doc.facts.prev_loop = true;
                        continue;
                    }
                    let Some(s) = self.load_section(off) else {
                        if first {
                            self.doc.facts.startxref_invalid = true;
                        }
                        first = false;
                        continue;
                    };
                    first = false;
                    self.doc.facts.chain.push(s);
                    for stm in self.doc.sections[s].xref_stms() {
                        self.load_section(stm);
                    }
                    stack.extend(self.doc.sections[s].prevs().into_iter().rev());
                }
            }
            None => self.doc.facts.startxref_invalid = true,
        }

        // Everything else, for the union.
        let mut offsets: Vec<usize> = self
            .doc
            .structure
            .startxrefs
            .iter()
            .filter_map(|s| s.target)
            .collect();
        offsets.extend(self.doc.structure.xref_tables.iter().copied());
        offsets.extend(
            self.doc
                .objects
                .iter()
                .filter_map(|e| match (&e.object, e.location) {
                    (PdfObject::Stream(s), Location::File { offset })
                        if is_xref_stream(&s.dict) =>
                    {
                        Some(offset)
                    }
                    _ => None,
                }),
        );
        let mut tried: HashSet<usize> = HashSet::new();
        let mut i = 0;
        while let Some(&off) = offsets.get(i) {
            i += 1;
            if !tried.insert(off) {
                continue;
            }
            if let Some(s) = self.load_section(off) {
                offsets.extend(self.doc.sections[s].prevs());
                offsets.extend(self.doc.sections[s].xref_stms());
            }
        }
    }

    fn load_section(&mut self, offset: usize) -> Option<usize> {
        if let Some(&s) = self.section_at.get(&offset) {
            return s;
        }
        let s = self.read_section(offset);
        self.section_at.insert(offset, s);
        s
    }

    fn read_section(&mut self, offset: usize) -> Option<usize> {
        if offset >= self.src.len() || self.out_of_work() {
            return None;
        }
        let (table, furthest) = parse_table(self.src, offset, self.limits);
        if !self.charge(furthest.saturating_sub(offset)) {
            return None;
        }
        let section = match table {
            Some(t) => t,
            None => {
                let (start, _) = object_header_at(self.src, offset)?;
                let i = match self.by_offset.get(&start) {
                    Some(&i) => i,
                    None => self.parse_top_level(start, false)?,
                };
                self.stream_section(i)?
            }
        };
        if let Some(&existing) = self
            .section_at
            .values()
            .flatten()
            .find(|&&s| self.doc.sections[s].offset == section.offset)
        {
            return Some(existing);
        }
        if self.doc.sections.len() as u64 >= u64::from(self.limits.max_revisions) {
            self.limit(
                IssueCode::LimitRevisions,
                &format!("more than {} xref sections", self.limits.max_revisions),
            );
            return None;
        }
        self.doc.sections.push(section);
        Some(self.doc.sections.len() - 1)
    }

    /// The xref section of stream object `objects[i]`, if it is one.
    fn stream_section(&mut self, i: usize) -> Option<XrefSection> {
        let e = self.doc.objects.get(i)?;
        let PdfObject::Stream(s) = &e.object else {
            return None;
        };
        if !is_xref_stream(&s.dict) {
            return None;
        }
        let (id, offset) = (e.id, e.location);
        let Location::File { offset } = offset else {
            return None;
        };
        let s = s.clone();
        let mut problems = Vec::new();
        let entries = match self.decode_stream(&s) {
            DecodeOutcome::Complete(data) => {
                let (entries, p) = parse_stream_rows(&s.dict, &data);
                problems = p;
                entries
            }
            DecodeOutcome::Partial { data, .. } => {
                let (entries, p) = parse_stream_rows(&s.dict, &data);
                problems.push(XrefProblem::Undecodable);
                problems.extend(p);
                entries
            }
            DecodeOutcome::Limit(code) => {
                self.issue(
                    code,
                    Some(offset),
                    format!("xref stream {id}: decode limit"),
                );
                problems.push(XrefProblem::Undecodable);
                Vec::new()
            }
            _ => {
                problems.push(XrefProblem::Undecodable);
                Vec::new()
            }
        };
        Some(XrefSection {
            offset,
            kind: XrefKind::Stream(id),
            entries,
            trailer: Some(s.dict),
            trailer_offset: None,
            problems,
        })
    }

    /// Decodes a stream, resolving an indirect `/Filter` / `/DecodeParms`.
    fn decode_stream(&mut self, s: &PdfStream) -> DecodeOutcome {
        let Some(raw) = self.src.get(s.data.clone()) else {
            return DecodeOutcome::Invalid("stream data out of range");
        };
        let resolve = |o: Option<&PdfObject>| -> Option<PdfObject> {
            match o? {
                PdfObject::Ref(r) => self.doc.definitions(*r).next().map(|d| d.object.clone()),
                o => Some(o.clone()),
            }
        };
        let filter = resolve(s.dict.get("Filter"));
        let parms = resolve(s.dict.get("DecodeParms"));
        decode(raw, filter.as_ref(), parms.as_ref(), self.budget)
    }

    /// Top-level objects only an xref offset finds (e.g. a comment between
    /// `N G` and `obj` hides them from the pattern search).
    fn objects_from_xref_offsets(&mut self) {
        let mut offsets = Vec::new();
        for section in &self.doc.sections {
            for e in &section.entries {
                if let EntryKind::InUse { offset, .. } = e.kind {
                    if let Ok(o) = usize::try_from(offset) {
                        offsets.push(o);
                    }
                }
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        for off in offsets {
            if self.full || self.out_of_work() {
                break;
            }
            if let Some((start, _)) = object_header_at(self.src, off) {
                if !self.by_offset.contains_key(&start) {
                    self.parse_top_level(start, false);
                }
            }
        }
    }

    /// Revisions in file order; each top-level definition belongs to the
    /// first revision whose xref section starts at or after it.
    fn assign_revisions(&mut self) {
        let mut hybrid_of: HashMap<usize, usize> = HashMap::new();
        for (t, section) in self.doc.sections.iter().enumerate() {
            if section.kind != XrefKind::Table {
                continue;
            }
            for off in section.xref_stms() {
                if let Some(&Some(s)) = self.section_at.get(&off) {
                    if s != t {
                        hybrid_of.insert(s, t);
                    }
                }
            }
        }
        let mut primary: Vec<usize> = (0..self.doc.sections.len())
            .filter(|s| !hybrid_of.contains_key(s))
            .collect();
        primary.sort_by_key(|&s| self.doc.sections[s].offset);
        self.doc.revisions = primary
            .iter()
            .map(|&s| Revision {
                section: s,
                hybrid: hybrid_of
                    .iter()
                    .filter(|&(_, &t)| t == s)
                    .map(|(&h, _)| h)
                    .collect(),
            })
            .collect();
        for r in &mut self.doc.revisions {
            r.hybrid.sort_unstable();
        }
        let ends: Vec<usize> = primary
            .iter()
            .map(|&s| self.doc.sections[s].offset)
            .collect();
        for e in &mut self.doc.objects {
            if let Location::File { offset } = e.location {
                let r = ends.partition_point(|&end| end < offset);
                e.revision = (r < ends.len()).then_some(r);
            }
        }
    }

    /// Decodes every object stream — `/Type /ObjStm`, or named by a
    /// compressed xref entry or an `/Extends` — and adds its members.
    fn expand_object_streams(&mut self) {
        let mut queue: Vec<usize> = Vec::new();
        let mut referenced: HashSet<u32> = HashSet::new();
        for section in &self.doc.sections {
            for e in &section.entries {
                if let EntryKind::Compressed { objstm, .. } = e.kind {
                    if let Ok(n) = u32::try_from(objstm) {
                        referenced.insert(n);
                    }
                }
            }
        }
        for (i, e) in self.doc.objects.iter().enumerate() {
            if let PdfObject::Stream(s) = &e.object {
                if is_objstm(&s.dict) || referenced.contains(&e.id.num) {
                    queue.push(i);
                }
            }
        }
        let mut done: HashSet<usize> = HashSet::new();
        while let Some(c) = queue.pop() {
            if !done.insert(c) || self.full || self.out_of_work() {
                continue;
            }
            for r in self.expand(c) {
                queue.extend(
                    self.doc
                        .by_id
                        .get(&r)
                        .into_iter()
                        .flatten()
                        .copied()
                        .filter(|&i| matches!(self.doc.objects[i].object, PdfObject::Stream(_))),
                );
            }
        }
    }

    /// Adds the members of object stream `objects[c]`; returns its `/Extends`.
    fn expand(&mut self, c: usize) -> Vec<ObjRef> {
        let (id, location, revision) = {
            let e = &self.doc.objects[c];
            (e.id, e.location, e.revision)
        };
        let PdfObject::Stream(s) = &self.doc.objects[c].object else {
            return Vec::new();
        };
        let s = s.clone();
        let offset = match location {
            Location::File { offset } => Some(offset),
            Location::ObjStm { .. } => None,
        };
        let extends: Vec<ObjRef> = s
            .dict
            .get_all("Extends")
            .filter_map(PdfObject::as_reference)
            .collect();
        let data = match self.decode_stream(&s) {
            DecodeOutcome::Complete(d) => d,
            DecodeOutcome::Partial { data, filter } => {
                self.issue(
                    IssueCode::EngineUndecodable,
                    offset,
                    format!(
                        "object stream {id}: {} data corrupt or truncated",
                        filter.name()
                    ),
                );
                data
            }
            DecodeOutcome::Limit(code) => {
                self.issue(code, offset, format!("object stream {id}: decode limit"));
                return extends;
            }
            other => {
                let why = match other {
                    DecodeOutcome::NotInspected(k) => format!("filter {} not decoded", k.name()),
                    DecodeOutcome::Unknown(n) => format!("unknown filter {n:?}"),
                    DecodeOutcome::Invalid(m) => m.to_string(),
                    _ => String::new(),
                };
                self.issue(
                    IssueCode::EngineUndecodable,
                    offset,
                    format!("object stream {id}: {why}"),
                );
                return extends;
            }
        };
        self.work.grow(data.len());
        let work = &mut self.work;
        let mut over = false;
        let contents = parse_members(&s.dict, &data, self.limits, |n| {
            let ok = work.charge(n);
            over |= !ok;
            ok
        });
        if over {
            self.charge(0);
        }
        for p in &contents.problems {
            self.issue(
                IssueCode::EngineParse,
                offset,
                format!("object stream {id}: {p:?}"),
            );
        }
        for m in contents.members {
            match m.object {
                Ok(object) => {
                    self.push(ObjectEntry {
                        id: ObjRef::new(m.num, 0),
                        location: Location::ObjStm {
                            container: c,
                            index: m.index,
                            offset: m.offset,
                        },
                        object,
                        revision,
                        has_endobj: true,
                        linear: false,
                        listed_in: Vec::new(),
                    });
                }
                Err(e) => {
                    let code = e.issue_code();
                    self.issue(
                        code,
                        offset,
                        format!("object stream {id}, member {} ({}): {e}", m.index, m.num),
                    );
                }
            }
        }
        extends
    }

    fn collect_trailers(&mut self) {
        let mut seen: HashSet<usize> = HashSet::new();
        for (i, s) in self.doc.sections.iter().enumerate() {
            let Some(dict) = &s.trailer else { continue };
            let offset = s.trailer_offset.unwrap_or(s.offset);
            seen.insert(offset);
            self.doc.trailers.push(Trailer {
                offset,
                dict: dict.clone(),
                section: Some(i),
            });
        }
        for off in self.doc.structure.trailers.clone() {
            if seen.contains(&off) || self.out_of_work() {
                continue;
            }
            let after = off + b"trailer".len();
            let (result, furthest) = parse_object_extent(self.src, after, self.limits);
            if !self.charge(furthest.saturating_sub(after)) {
                break;
            }
            match result {
                Ok((PdfObject::Dict(dict), _)) => self.doc.trailers.push(Trailer {
                    offset: off,
                    dict,
                    section: None,
                }),
                Err(e) if e.issue_code().is_limit() => self.doc.issues.push(e.into()),
                _ => {}
            }
        }
    }

    /// Which definitions each xref entry points at, and which it misses;
    /// definitions no xref lists.
    fn xref_facts(&mut self) {
        let mut members: HashMap<(u32, u32), Vec<usize>> = HashMap::new();
        let mut containers: HashSet<u32> = HashSet::new();
        for (i, e) in self.doc.objects.iter().enumerate() {
            if let Location::ObjStm {
                container, index, ..
            } = e.location
            {
                let num = self.doc.objects[container].id.num;
                containers.insert(num);
                members.entry((num, index)).or_default().push(i);
            }
        }
        let mut listed: HashSet<u32> = HashSet::new();
        let mut hits: Vec<(usize, usize)> = Vec::new();
        let mut mismatches = Vec::new();
        for (si, section) in self.doc.sections.iter().enumerate() {
            for e in &section.entries {
                let miss = |kind| XrefMismatch {
                    section: si,
                    num: e.num,
                    kind,
                };
                match e.kind {
                    EntryKind::Free { .. } => {}
                    EntryKind::InUse { offset, generation } => {
                        listed.insert(e.num);
                        let Some(off) =
                            usize::try_from(offset).ok().filter(|&o| o < self.src.len())
                        else {
                            mismatches.push(miss(MismatchKind::OutOfRange));
                            continue;
                        };
                        match object_header_at(self.src, off) {
                            None => mismatches.push(miss(MismatchKind::NoObject)),
                            Some((start, id)) => {
                                if id.num != e.num || u64::from(id.generation) != generation {
                                    mismatches.push(miss(MismatchKind::WrongId(id)));
                                } else if let Some(&i) = self.by_offset.get(&start) {
                                    hits.push((i, si));
                                }
                            }
                        }
                    }
                    EntryKind::Compressed { objstm, index } => {
                        listed.insert(e.num);
                        let key = u32::try_from(objstm).ok().zip(u32::try_from(index).ok());
                        let found: Vec<usize> = key
                            .and_then(|k| members.get(&k))
                            .into_iter()
                            .flatten()
                            .copied()
                            .filter(|&i| self.doc.objects[i].id.num == e.num)
                            .collect();
                        if found.is_empty() {
                            let has_stm = key.is_some_and(|(n, _)| containers.contains(&n));
                            mismatches.push(miss(if has_stm {
                                MismatchKind::WrongMember
                            } else {
                                MismatchKind::NoObjStm
                            }));
                        }
                        hits.extend(found.into_iter().map(|i| (i, si)));
                    }
                }
            }
        }
        for (i, s) in hits {
            let l = &mut self.doc.objects[i].listed_in;
            if !l.contains(&s) {
                l.push(s);
            }
        }
        self.doc.facts.xref_mismatches = mismatches;
        self.doc.facts.unlisted = self
            .doc
            .objects
            .iter()
            .enumerate()
            .filter(|(_, e)| !listed.contains(&e.id.num))
            .map(|(i, _)| i)
            .collect();
    }

    fn duplicate_facts(&mut self) {
        let mut groups: Vec<(ObjRef, Vec<usize>)> = self
            .doc
            .by_id
            .iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(id, v)| (*id, v.clone()))
            .collect();
        groups.sort_unstable();
        let objects = &self.doc.objects;
        let same =
            |a: usize, b: usize| same_content(self.src, &objects[a].object, &objects[b].object);
        self.doc.facts.duplicates = groups
            .into_iter()
            .map(|(id, entries)| {
                let identical = entries[1..].iter().all(|&e| same(entries[0], e));
                // Equality is transitive: compare with the first of each revision.
                let mut first_of: HashMap<Option<usize>, usize> = HashMap::new();
                let mut conflict_in_revision = false;
                for &e in &entries {
                    match first_of.get(&objects[e].revision) {
                        Some(&f) => conflict_in_revision |= !same(f, e),
                        None => {
                            first_of.insert(objects[e].revision, e);
                        }
                    }
                }
                DuplicateGroup {
                    id,
                    entries,
                    identical,
                    conflict_in_revision,
                }
            })
            .collect();
    }

    fn linearized(&self) -> bool {
        self.doc
            .objects
            .iter()
            .filter_map(|e| match e.location {
                Location::File { offset } => Some((offset, e)),
                Location::ObjStm { .. } => None,
            })
            .min_by_key(|(o, _)| *o)
            .and_then(|(_, e)| e.object.as_dict())
            .is_some_and(|d| d.contains_key("Linearized"))
    }
}

fn has_type(dict: &Dict, t: &str) -> bool {
    dict.get_all("Type").any(|v| v.is_name(t))
}

/// `/Type /XRef`, or (lenient, as a reader at `startxref` would be) `/W`.
fn is_xref_stream(dict: &Dict) -> bool {
    has_type(dict, "XRef") || dict.contains_key("W")
}

fn is_objstm(dict: &Dict) -> bool {
    has_type(dict, "ObjStm")
}

/// Same content: equal objects; for streams, equal dictionaries and equal
/// raw data (not equal positions).
fn same_content(src: &[u8], a: &PdfObject, b: &PdfObject) -> bool {
    match (a, b) {
        (PdfObject::Stream(x), PdfObject::Stream(y)) => {
            x.dict == y.dict && src.get(x.data.clone()) == src.get(y.data.clone())
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::object::Name;

    fn dict(entries: &[(&str, &str)]) -> Dict {
        Dict::new(
            entries
                .iter()
                .map(|(k, v)| (Name::from(*k), PdfObject::Name(Name::from(*v))))
                .collect(),
        )
    }

    #[test]
    fn work_cap_grows_with_decoded_data() {
        let mut w = Work::new(10);
        assert_eq!(w.cap, 10 * WORK_FACTOR + WORK_SLACK);
        assert!(w.charge(w.cap));
        assert!(!w.charge(1));
        w.grow(1);
        assert!(w.charge(0));
        let mut w = Work::new(usize::MAX);
        w.grow(usize::MAX);
        assert!(w.charge(usize::MAX));
    }

    #[test]
    fn stream_kinds() {
        assert!(is_xref_stream(&dict(&[("Type", "XRef")])));
        assert!(is_xref_stream(&dict(&[("W", "x")])));
        assert!(!is_xref_stream(&dict(&[("Type", "ObjStm")])));
        // Duplicate /Type keys: any value counts.
        assert!(is_objstm(&dict(&[("Type", "XObject"), ("Type", "ObjStm")])));
        assert!(!is_objstm(&Dict::default()));
    }

    #[test]
    fn same_content_compares_stream_bytes_not_positions() {
        let src = b"abcXabc";
        let stream = |r: std::ops::Range<usize>| {
            PdfObject::Stream(PdfStream {
                dict: Dict::default(),
                data_start: r.start,
                data: r,
                length: StreamLength::Declared,
            })
        };
        assert!(same_content(src, &stream(0..3), &stream(4..7)));
        assert!(!same_content(src, &stream(0..3), &stream(3..6)));
        assert!(same_content(src, &PdfObject::Int(1), &PdfObject::Int(1)));
        assert!(!same_content(src, &PdfObject::Int(1), &stream(0..3)));
    }

    #[test]
    fn empty_input() {
        let limits = Limits::default();
        let d = Document::parse(b"", &limits, &mut Budget::new(&limits));
        assert!(d.objects.is_empty() && d.issues.is_empty());
        assert!(d.facts.startxref_invalid);
        assert_eq!(d.revision_trailer(0), None);
    }

    #[test]
    fn startxref_to_nowhere() {
        let limits = Limits::default();
        let src = b"%PDF-1.7\n1 0 obj 1 endobj\nstartxref\n9999\n%%EOF";
        let d = Document::parse(src, &limits, &mut Budget::new(&limits));
        assert!(d.facts.startxref_invalid);
        assert!(d.sections.is_empty());
        assert_eq!(d.facts.unlisted, vec![0]);
    }

    #[test]
    fn startxref_to_non_xref_object() {
        let limits = Limits::default();
        let src = b"%PDF-1.7\n1 0 obj << >> endobj\nstartxref\n9\n%%EOF";
        let d = Document::parse(src, &limits, &mut Budget::new(&limits));
        assert!(d.facts.startxref_invalid);
        assert!(d.sections.is_empty());
        assert_eq!(d.objects.len(), 1);
    }
}
