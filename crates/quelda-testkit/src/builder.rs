//! `PdfBuilder`: writes PDFs byte-for-byte, including deliberately broken
//! ones. Independent of `quelda-core`; output is fully deterministic.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::filters::{Filter, encode_chain, filter_entry};

/// How a revision's cross-reference section is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xref {
    /// Classic `xref` table + `trailer`.
    Table,
    /// PDF 1.5 cross-reference stream (needed to index object-stream members).
    Stream,
    /// No xref and no trailer at all: readers must reconstruct.
    None,
}

enum Item {
    Obj {
        num: u32,
        generation: u16,
        body: Vec<u8>,
        listed: bool,
        is_stream: bool,
    },
    Raw(Vec<u8>),
}

struct ObjStm {
    num: u32,
    members: Vec<u32>,
    filters: Vec<Filter>,
}

struct Revision {
    items: Vec<Item>,
    objstms: Vec<ObjStm>,
    xref: Xref,
    trailer: String,
    wrong_offsets: bool,
    prev_loop: bool,
}

impl Revision {
    fn new() -> Self {
        Revision {
            items: Vec::new(),
            objstms: Vec::new(),
            xref: Xref::Table,
            trailer: String::new(),
            wrong_offsets: false,
            prev_loop: false,
        }
    }
}

enum Entry {
    InUse { offset: usize, generation: u16 },
    Compressed { objstm: u32, index: u16 },
}

/// Builds a PDF file. Objects are written in insertion order; each call to
/// [`PdfBuilder::revision`] starts an incremental update.
pub struct PdfBuilder {
    version: String,
    prefix: Vec<u8>,
    trailing: Vec<u8>,
    omit_eof: bool,
    root: u32,
    revs: Vec<Revision>,
}

/// Formats a stream object body: dict (with `/Filter` and `/Length`) + data.
pub fn stream_body(dict: &str, data: &[u8], filters: &[Filter]) -> Vec<u8> {
    let encoded = encode_chain(filters, data);
    raw_stream_body(&join_entries(dict, &filter_entry(filters)), &encoded)
}

/// Like [`stream_body`] but `data` is written as-is (only `/Length` is added).
pub fn raw_stream_body(dict: &str, data: &[u8]) -> Vec<u8> {
    let dict = join_entries(dict, &format!("/Length {}", data.len()));
    let mut body = format!("<< {dict} >>\nstream\n").into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(b"\nendstream");
    body
}

fn join_entries(a: &str, b: &str) -> String {
    match (a.trim(), b.trim()) {
        ("", b) => b.to_string(),
        (a, "") => a.to_string(),
        (a, b) => format!("{a} {b}"),
    }
}

/// Groups sorted object numbers into contiguous `(start, count)` runs.
fn runs(nums: &[u32]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for &n in nums {
        match out.last_mut() {
            Some((start, count)) if *start + *count == n => *count += 1,
            _ => out.push((n, 1)),
        }
    }
    out
}

impl PdfBuilder {
    /// Starts a file with header `%PDF-<version>` and a binary comment line.
    pub fn new(version: &str) -> Self {
        PdfBuilder {
            version: version.to_string(),
            prefix: Vec::new(),
            trailing: Vec::new(),
            omit_eof: false,
            root: 1,
            revs: vec![Revision::new()],
        }
    }

    fn rev(&mut self) -> &mut Revision {
        let last = self.revs.len() - 1;
        &mut self.revs[last]
    }

    /// Bytes written before `%PDF-` (offsets stay absolute).
    pub fn prefix_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.prefix.extend_from_slice(bytes);
        self
    }

    /// Bytes written after the final `%%EOF`.
    pub fn trailing_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.trailing.extend_from_slice(bytes);
        self
    }

    /// Drops the final `%%EOF` line.
    pub fn omit_eof(&mut self) -> &mut Self {
        self.omit_eof = true;
        self
    }

    /// Object number of the catalog (`/Root`), default 1.
    pub fn root(&mut self, num: u32) -> &mut Self {
        self.root = num;
        self
    }

    /// Adds `num 0 obj <body> endobj`, listed in the xref.
    pub fn object(&mut self, num: u32, body: impl AsRef<[u8]>) -> &mut Self {
        self.object_gen(num, 0, body)
    }

    /// Adds an object with an explicit generation number.
    pub fn object_gen(&mut self, num: u32, generation: u16, body: impl AsRef<[u8]>) -> &mut Self {
        self.push_obj(num, generation, body.as_ref().to_vec(), true, false)
    }

    /// Adds an object that no xref entry points to (only a linear scan finds it).
    pub fn unlisted_object(&mut self, num: u32, body: impl AsRef<[u8]>) -> &mut Self {
        self.push_obj(num, 0, body.as_ref().to_vec(), false, false)
    }

    /// Adds a stream object; `data` is encoded through `filters` (decode order).
    pub fn stream(&mut self, num: u32, dict: &str, data: &[u8], filters: &[Filter]) -> &mut Self {
        let body = stream_body(dict, data, filters);
        self.push_obj(num, 0, body, true, true)
    }

    /// Adds a stream object whose `data` is written unencoded (dict may name any filter).
    pub fn stream_raw(&mut self, num: u32, dict: &str, data: &[u8]) -> &mut Self {
        let body = raw_stream_body(dict, data);
        self.push_obj(num, 0, body, true, true)
    }

    fn push_obj(
        &mut self,
        num: u32,
        generation: u16,
        body: Vec<u8>,
        listed: bool,
        is_stream: bool,
    ) -> &mut Self {
        self.rev().items.push(Item::Obj {
            num,
            generation,
            body,
            listed,
            is_stream,
        });
        self
    }

    /// Writes raw bytes between objects (comments, junk, a second header…).
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.rev().items.push(Item::Raw(bytes.to_vec()));
        self
    }

    /// Packs `members` (non-stream objects of this revision) into object stream `num`.
    /// Members are only indexed by an [`Xref::Stream`]; a table cannot point into an ObjStm.
    pub fn objstm(&mut self, num: u32, members: &[u32], filters: &[Filter]) -> &mut Self {
        self.rev().objstms.push(ObjStm {
            num,
            members: members.to_vec(),
            filters: filters.to_vec(),
        });
        self
    }

    /// Cross-reference form of the current revision (default [`Xref::Table`]).
    pub fn xref(&mut self, xref: Xref) -> &mut Self {
        self.rev().xref = xref;
        self
    }

    /// Extra trailer entries for the current revision, e.g. `/Encrypt 9 0 R`.
    pub fn trailer(&mut self, extra: &str) -> &mut Self {
        let rev = self.rev();
        rev.trailer = join_entries(&rev.trailer, extra);
        self
    }

    /// Shifts every in-use offset of the current revision's xref by +3 bytes.
    pub fn wrong_offsets(&mut self) -> &mut Self {
        self.rev().wrong_offsets = true;
        self
    }

    /// Points the current revision's `/Prev` at its own xref (an infinite loop).
    pub fn prev_loop(&mut self) -> &mut Self {
        self.rev().prev_loop = true;
        self
    }

    /// Starts an incremental update: following objects go into a new revision.
    pub fn revision(&mut self) -> &mut Self {
        self.revs.push(Revision::new());
        self
    }

    /// Serializes the file.
    ///
    /// # Panics
    /// If an ObjStm member is missing from its revision or is a stream (a bug in the fixture).
    pub fn build(&self) -> Vec<u8> {
        let mut out = self.prefix.clone();
        out.extend_from_slice(format!("%PDF-{}\n", self.version).as_bytes());
        // Binary comment (raw high bytes) so transfer tools treat the file as binary.
        out.extend_from_slice(&[b'%', 0xE2, 0xE3, 0xCF, 0xD3, b'\n']);

        let mut max_num = self
            .revs
            .iter()
            .flat_map(|r| {
                r.items
                    .iter()
                    .filter_map(|i| match i {
                        Item::Obj { num, .. } => Some(*num),
                        Item::Raw(_) => None,
                    })
                    .chain(r.objstms.iter().map(|s| s.num))
            })
            .max()
            .unwrap_or(0);

        let mut prev_xref: Option<usize> = None;
        let last = self.revs.len() - 1;
        for (ri, rev) in self.revs.iter().enumerate() {
            let members: BTreeSet<u32> = rev
                .objstms
                .iter()
                .flat_map(|s| s.members.iter().copied())
                .collect();
            let mut bodies: HashMap<u32, &[u8]> = HashMap::new();
            let mut entries: BTreeMap<u32, Entry> = BTreeMap::new();

            for item in &rev.items {
                match item {
                    Item::Raw(bytes) => out.extend_from_slice(bytes),
                    Item::Obj {
                        num,
                        generation,
                        body,
                        listed,
                        is_stream,
                    } => {
                        if members.contains(num) {
                            assert!(
                                !is_stream,
                                "object {num} is a stream; it cannot go into an ObjStm"
                            );
                            bodies.insert(*num, body);
                            continue;
                        }
                        let offset = out.len();
                        write_obj(&mut out, *num, *generation, body);
                        if *listed {
                            entries.insert(
                                *num,
                                Entry::InUse {
                                    offset,
                                    generation: *generation,
                                },
                            );
                        }
                    }
                }
            }

            for stm in &rev.objstms {
                let mut header = String::new();
                let mut content: Vec<u8> = Vec::new();
                for (index, m) in stm.members.iter().enumerate() {
                    let body = bodies.get(m).unwrap_or_else(|| {
                        panic!("ObjStm {} member {m} not in this revision", stm.num)
                    });
                    header.push_str(&format!("{m} {} ", content.len()));
                    content.extend_from_slice(body);
                    content.push(b'\n');
                    entries.insert(
                        *m,
                        Entry::Compressed {
                            objstm: stm.num,
                            index: index as u16,
                        },
                    );
                }
                let mut data = header.clone().into_bytes();
                data.extend_from_slice(&content);
                let dict = format!(
                    "/Type /ObjStm /N {} /First {}",
                    stm.members.len(),
                    header.len()
                );
                let offset = out.len();
                write_obj(
                    &mut out,
                    stm.num,
                    0,
                    &stream_body(&dict, &data, &stm.filters),
                );
                entries.insert(
                    stm.num,
                    Entry::InUse {
                        offset,
                        generation: 0,
                    },
                );
            }

            let shift = if rev.wrong_offsets { 3 } else { 0 };
            let first = ri == 0;
            let xref_offset = match rev.xref {
                Xref::None => None,
                Xref::Table => {
                    let offset = out.len();
                    let prev = if rev.prev_loop {
                        Some(offset)
                    } else {
                        prev_xref
                    };
                    write_table(&mut out, &entries, first, shift);
                    let mut dict = format!("/Size {} /Root {} 0 R", max_num + 1, self.root);
                    if let Some(p) = prev {
                        dict.push_str(&format!(" /Prev {p}"));
                    }
                    let dict = join_entries(&dict, &rev.trailer);
                    out.extend_from_slice(format!("trailer\n<< {dict} >>\n").as_bytes());
                    Some(offset)
                }
                Xref::Stream => {
                    max_num += 1;
                    let num = max_num;
                    let offset = out.len();
                    entries.insert(
                        num,
                        Entry::InUse {
                            offset,
                            generation: 0,
                        },
                    );
                    let prev = if rev.prev_loop {
                        Some(offset)
                    } else {
                        prev_xref
                    };
                    let (index, rows) = xref_stream_rows(&entries, first, shift);
                    let mut dict = format!(
                        "/Type /XRef /Size {} /W [1 4 2] /Index [{index}] /Root {} 0 R",
                        max_num + 1,
                        self.root
                    );
                    if let Some(p) = prev {
                        dict.push_str(&format!(" /Prev {p}"));
                    }
                    let dict = join_entries(&dict, &rev.trailer);
                    write_obj(&mut out, num, 0, &raw_stream_body(&dict, &rows));
                    Some(offset)
                }
            };
            if let Some(offset) = xref_offset {
                out.extend_from_slice(format!("startxref\n{offset}\n").as_bytes());
                prev_xref = Some(offset);
            }
            if !(ri == last && self.omit_eof) {
                out.extend_from_slice(b"%%EOF\n");
            }
        }
        out.extend_from_slice(&self.trailing);
        out
    }
}

fn write_obj(out: &mut Vec<u8>, num: u32, generation: u16, body: &[u8]) {
    out.extend_from_slice(format!("{num} {generation} obj\n").as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\nendobj\n");
}

fn write_table(out: &mut Vec<u8>, entries: &BTreeMap<u32, Entry>, first: bool, shift: usize) {
    let mut nums: Vec<u32> = entries
        .iter()
        .filter(|(_, e)| matches!(e, Entry::InUse { .. }))
        .map(|(n, _)| *n)
        .collect();
    if first {
        nums.insert(0, 0);
    }
    out.extend_from_slice(b"xref\n");
    for (start, count) in runs(&nums) {
        out.extend_from_slice(format!("{start} {count}\n").as_bytes());
        for n in start..start + count {
            match entries.get(&n) {
                Some(Entry::InUse { offset, generation }) => {
                    out.extend_from_slice(
                        format!("{:010} {generation:05} n\r\n", offset + shift).as_bytes(),
                    );
                }
                _ => out.extend_from_slice(b"0000000000 65535 f\r\n"),
            }
        }
    }
}

fn xref_stream_rows(
    entries: &BTreeMap<u32, Entry>,
    first: bool,
    shift: usize,
) -> (String, Vec<u8>) {
    let mut nums: Vec<u32> = entries.keys().copied().collect();
    if first {
        nums.insert(0, 0);
    }
    let runs = runs(&nums);
    let index: Vec<String> = runs.iter().map(|(s, c)| format!("{s} {c}")).collect();
    let mut rows = Vec::new();
    for n in nums {
        let (kind, f2, f3): (u8, u32, u16) = match entries.get(&n) {
            Some(Entry::InUse { offset, generation }) => (1, (offset + shift) as u32, *generation),
            Some(Entry::Compressed { objstm, index }) => (2, *objstm, *index),
            None => (0, 0, 0xFFFF),
        };
        rows.push(kind);
        rows.extend_from_slice(&f2.to_be_bytes());
        rows.extend_from_slice(&f3.to_be_bytes());
    }
    (index.join(" "), rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).rposition(|w| w == needle)
    }

    fn int_after(hay: &[u8], at: usize) -> usize {
        let digits: String = hay[at..]
            .iter()
            .skip_while(|b| b.is_ascii_whitespace())
            .take_while(|b| b.is_ascii_digit())
            .map(|&b| char::from(b))
            .collect();
        digits.parse().unwrap()
    }

    fn startxrefs(pdf: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(p) = find(&pdf[from..], b"startxref\n") {
            let at = from + p + b"startxref\n".len();
            out.push(int_after(pdf, at));
            from = at;
        }
        out
    }

    /// Parses a classic xref table at `offset` into (num, offset, generation) entries in use.
    fn table_entries(pdf: &[u8], offset: usize) -> Vec<(u32, usize, u16)> {
        assert!(
            pdf[offset..].starts_with(b"xref\n"),
            "startxref does not point at `xref`"
        );
        let text = std::str::from_utf8(&pdf[offset + 5..]).unwrap_or_else(|e| {
            std::str::from_utf8(&pdf[offset + 5..offset + 5 + e.valid_up_to()]).unwrap()
        });
        let mut lines = text.lines();
        let mut out = Vec::new();
        while let Some(line) = lines.next() {
            if line.starts_with("trailer") {
                break;
            }
            let mut it = line.split_whitespace();
            let start: u32 = it.next().unwrap().parse().unwrap();
            let count: u32 = it.next().unwrap().parse().unwrap();
            for n in start..start + count {
                let e = lines.next().unwrap();
                // 20 bytes per entry: `lines()` strips the 2-byte "\r\n" EOL.
                assert_eq!(e.len(), 18, "bad xref entry: {e:?}");
                if e.ends_with('n') {
                    out.push((n, e[..10].parse().unwrap(), e[11..16].parse().unwrap()));
                }
            }
        }
        out
    }

    fn assert_obj_at(pdf: &[u8], offset: usize, num: u32, generation: u16) {
        let want = format!("{num} {generation} obj");
        assert!(
            pdf[offset..].starts_with(want.as_bytes()),
            "offset {offset} should start `{want}`, found {:?}",
            String::from_utf8_lossy(&pdf[offset..(offset + 20).min(pdf.len())])
        );
    }

    fn simple() -> PdfBuilder {
        let mut b = PdfBuilder::new("1.7");
        b.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .object(
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>",
            )
            .stream(4, "", b"BT ET", &[]);
        b
    }

    #[test]
    fn header_and_eof() {
        let pdf = simple().build();
        assert!(pdf.starts_with(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"));
        assert!(pdf.ends_with(b"%%EOF\n"));
    }

    #[test]
    fn table_offsets_point_at_objects() {
        let pdf = simple().build();
        let sx = startxrefs(&pdf);
        assert_eq!(sx.len(), 1);
        let entries = table_entries(&pdf, sx[0]);
        assert_eq!(entries.len(), 4);
        for (n, off, g) in entries {
            assert_obj_at(&pdf, off, n, g);
        }
        assert_eq!(rfind(&pdf, b"\nxref\n").map(|p| p + 1), Some(sx[0]));
    }

    #[test]
    fn prefix_keeps_offsets_absolute() {
        let mut b = simple();
        b.prefix_bytes(b"JUNK BEFORE HEADER\n");
        let pdf = b.build();
        assert!(pdf.starts_with(b"JUNK BEFORE HEADER\n%PDF-1.7"));
        let sx = startxrefs(&pdf)[0];
        for (n, off, g) in table_entries(&pdf, sx) {
            assert_obj_at(&pdf, off, n, g);
        }
    }

    #[test]
    fn stream_length_matches_data() {
        let data = b"q 1 0 0 1 0 0 cm Q";
        let mut b = PdfBuilder::new("1.4");
        b.stream(7, "/QueldaKey 1", data, &[]);
        let pdf = b.build();
        let len_at = find(&pdf, b"/Length ").unwrap() + 8;
        let len = int_after(&pdf, len_at);
        assert_eq!(len, data.len());
        let data_at = find(&pdf, b">>\nstream\n").unwrap() + b">>\nstream\n".len();
        assert_eq!(&pdf[data_at..data_at + len], data);
        assert!(pdf[data_at + len..].starts_with(b"\nendstream\nendobj"));
    }

    #[test]
    fn filtered_stream_declares_filters() {
        let mut b = PdfBuilder::new("1.4");
        b.stream(7, "", b"data", &[Filter::Ascii85, Filter::Flate]);
        let pdf = b.build();
        assert!(find(&pdf, b"/Filter [/ASCII85Decode /FlateDecode] /Length").is_some());
    }

    #[test]
    fn objstm_header_matches_n_and_first() {
        let mut b = PdfBuilder::new("1.5");
        b.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .object(10, "<< /QueldaA 1 >>")
            .object(11, "<< /QueldaB 2 >>")
            .objstm(9, &[10, 11], &[])
            .xref(Xref::Stream);
        let pdf = b.build();
        let at = find(&pdf, b"/Type /ObjStm").unwrap();
        assert_eq!(
            int_after(&pdf, find(&pdf[at..], b"/N ").unwrap() + at + 3),
            2
        );
        let first = int_after(&pdf, find(&pdf[at..], b"/First ").unwrap() + at + 7);
        let data_at = find(&pdf[at..], b"stream\n").unwrap() + at + 7;
        let header = std::str::from_utf8(&pdf[data_at..data_at + first]).unwrap();
        let nums: Vec<usize> = header
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(nums.len(), 4);
        assert_eq!((nums[0], nums[2]), (10, 11));
        let objs = &pdf[data_at + first..];
        assert!(objs[nums[1]..].starts_with(b"<< /QueldaA 1 >>"));
        assert!(objs[nums[3]..].starts_with(b"<< /QueldaB 2 >>"));
        // Members are not written as top-level objects.
        assert!(find(&pdf, b"10 0 obj").is_none());
    }

    #[test]
    fn xref_stream_rows_resolve() {
        let mut b = PdfBuilder::new("1.5");
        b.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .object(10, "<< /QueldaA 1 >>")
            .objstm(9, &[10], &[])
            .xref(Xref::Stream);
        let pdf = b.build();
        let sx = startxrefs(&pdf)[0];
        assert_obj_at(&pdf, sx, 11, 0);
        let data_at = find(&pdf[sx..], b"stream\n").unwrap() + sx + 7;
        let len = int_after(&pdf, find(&pdf[sx..], b"/Length ").unwrap() + sx + 8);
        let rows = &pdf[data_at..data_at + len];
        let index_at = find(&pdf[sx..], b"/Index [").unwrap() + sx + 8;
        let index_end = find(&pdf[index_at..], b"]").unwrap() + index_at;
        let index: Vec<u32> = std::str::from_utf8(&pdf[index_at..index_end])
            .unwrap()
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        let mut nums = Vec::new();
        for pair in index.chunks(2) {
            nums.extend(pair[0]..pair[0] + pair[1]);
        }
        assert_eq!(rows.len(), nums.len() * 7);
        for (n, row) in nums.iter().zip(rows.chunks(7)) {
            let f2 = u32::from_be_bytes(row[1..5].try_into().unwrap()) as usize;
            let f3 = u16::from_be_bytes(row[5..7].try_into().unwrap());
            match row[0] {
                0 => assert_eq!(*n, 0),
                1 => assert_obj_at(&pdf, f2, *n, f3),
                2 => assert_eq!((*n, f2, f3), (10, 9, 0)),
                k => panic!("bad type {k}"),
            }
        }
    }

    #[test]
    fn incremental_update_chains_prev() {
        let mut b = simple();
        b.revision()
            .object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>");
        let pdf = b.build();
        let sx = startxrefs(&pdf);
        assert_eq!(sx.len(), 2);
        let trailer2 = find(&pdf[sx[1]..], b"trailer").unwrap() + sx[1];
        let prev = int_after(
            &pdf,
            find(&pdf[trailer2..], b"/Prev ").unwrap() + trailer2 + 6,
        );
        assert_eq!(prev, sx[0]);
        let e2 = table_entries(&pdf, sx[1]);
        assert_eq!(e2.len(), 1);
        assert_eq!(e2[0].0, 3);
        assert_obj_at(&pdf, e2[0].1, 3, 0);
        assert_eq!(pdf.windows(5).filter(|w| w == b"%%EOF").count(), 2);
    }

    #[test]
    fn prev_loop_points_to_itself() {
        let mut b = simple();
        b.revision().object(3, "<< >>").prev_loop();
        let pdf = b.build();
        let sx = startxrefs(&pdf);
        let trailer2 = find(&pdf[sx[1]..], b"trailer").unwrap() + sx[1];
        let prev = int_after(
            &pdf,
            find(&pdf[trailer2..], b"/Prev ").unwrap() + trailer2 + 6,
        );
        assert_eq!(prev, sx[1]);
    }

    #[test]
    fn wrong_offsets_are_off_by_three() {
        let mut b = simple();
        b.wrong_offsets();
        let pdf = b.build();
        for (n, off, g) in table_entries(&pdf, startxrefs(&pdf)[0]) {
            assert_obj_at(&pdf, off - 3, n, g);
        }
    }

    #[test]
    fn unlisted_object_is_not_in_xref() {
        let mut b = simple();
        b.unlisted_object(20, "<< /QueldaHidden 1 >>");
        let pdf = b.build();
        assert!(find(&pdf, b"20 0 obj").is_some());
        let nums: Vec<u32> = table_entries(&pdf, startxrefs(&pdf)[0])
            .iter()
            .map(|e| e.0)
            .collect();
        assert!(!nums.contains(&20));
    }

    #[test]
    fn no_xref_and_no_eof_options() {
        let mut b = simple();
        b.xref(Xref::None).omit_eof().trailing_bytes(b"TAIL");
        let pdf = b.build();
        assert!(find(&pdf, b"startxref").is_none());
        assert!(find(&pdf, b"%%EOF").is_none());
        assert!(pdf.ends_with(b"endobj\nTAIL"));
    }

    #[test]
    fn deterministic() {
        assert_eq!(simple().build(), simple().build());
    }

    #[test]
    fn runs_groups_contiguous() {
        assert_eq!(runs(&[0, 1, 2, 5, 6, 9]), vec![(0, 3), (5, 2), (9, 1)]);
        assert_eq!(runs(&[]), vec![]);
    }
}
