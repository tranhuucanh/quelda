//! The bytes the parser reads (plan Step 16 Phase B): a slice (the whole
//! file in memory, zero-copy — the parser functions run on it unchanged), or
//! a [`Source`] read on demand through a small page cache.
//!
//! Over a source, an object is parsed in a *window* of the file: the
//! parser functions run on the window as if it were the file, and the
//! result is kept only if they read nothing past its end (lexing never reads
//! beyond the furthest offset it reports). Otherwise the window doubles and
//! the parse runs again. Results are therefore the same as on the whole
//! file; the differential tests check it with windows of a few bytes.

use std::borrow::Cow;
use std::cell::{OnceCell, RefCell};
use std::ops::{Deref, Range};
use std::rc::Rc;

use super::object::{ObjRef, PdfObject};
use super::parse::{
    Bytes, HEADER_WINDOW, Head, IndirectObject, ParseError, ParseErrorKind, data_with_length,
    endobj_at, indirect_head, locate_stream, object_header_at, parse_indirect_object_extent,
    parse_object_extent,
};
use super::xref::{XrefProblem, XrefSection, parse_table};
use crate::limits::Limits;
use crate::source::Source;

/// Sizes used over a source (tests make them tiny).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tuning {
    /// Page of the cache.
    pub page: usize,
    /// Pages kept.
    pub pages: usize,
    /// Bytes read per step of the sequential pass.
    pub block: usize,
    /// First window for parsing an object.
    pub window: usize,
}

impl Tuning {
    pub const DEFAULT: Tuning = Tuning {
        page: 64 << 10,
        pages: 16,
        block: 1 << 20,
        window: 4 << 10,
    };
}

enum Kind<'a> {
    Slice(&'a [u8]),
    Source(&'a (dyn Source + 'a)),
}

pub(crate) struct Input<'a> {
    kind: Kind<'a>,
    len: usize,
    tuning: Tuning,
    /// Most recently used last.
    pages: RefCell<Vec<(usize, Rc<[u8]>)>>,
    /// Every `endstream` (sources only; from the sequential pass).
    endstreams: OnceCell<Vec<usize>>,
    /// The first read error (offset, message); nothing is read after it.
    failed: RefCell<Option<(usize, String)>>,
}

/// Bytes of a window.
pub(crate) enum WindowData<'a> {
    Borrowed(&'a [u8]),
    Page(Rc<[u8]>),
    Owned(Vec<u8>),
}

impl Deref for WindowData<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            WindowData::Borrowed(b) => b,
            WindowData::Page(p) => p,
            WindowData::Owned(v) => v,
        }
    }
}

/// `data` is the file from offset `base`.
pub(crate) struct Window<'a> {
    pub base: usize,
    pub data: WindowData<'a>,
}

impl<'a> Input<'a> {
    pub fn slice(src: &'a [u8]) -> Input<'a> {
        Input::new(Kind::Slice(src), src.len(), Tuning::DEFAULT)
    }

    /// `Err`: the source is too large to address on this platform.
    pub fn source(src: &'a (dyn Source + 'a), tuning: Tuning) -> Result<Input<'a>, String> {
        let len = usize::try_from(src.len())
            .map_err(|_| format!("input of {} bytes is too large here", src.len()))?;
        Ok(Input::new(Kind::Source(src), len, tuning))
    }

    fn new(kind: Kind<'a>, len: usize, tuning: Tuning) -> Input<'a> {
        let tuning = Tuning {
            page: tuning.page.max(1),
            pages: tuning.pages.max(1),
            block: tuning.block.max(1),
            window: tuning.window.max(1),
        };
        Input {
            kind,
            len,
            tuning,
            pages: RefCell::new(Vec::new()),
            endstreams: OnceCell::new(),
            failed: RefCell::new(None),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn tuning(&self) -> Tuning {
        self.tuning
    }

    /// The whole input, when it is a slice.
    pub fn as_slice(&self) -> Option<&'a [u8]> {
        match self.kind {
            Kind::Slice(s) => Some(s),
            Kind::Source(_) => None,
        }
    }

    /// The first read error: offset and message.
    pub fn failure(&self) -> Option<(usize, String)> {
        self.failed.borrow().clone()
    }

    pub fn set_endstreams(&self, offsets: Vec<usize>) {
        let _ = self.endstreams.set(offsets);
    }

    /// Reads `buf.len()` bytes at `offset` from the source (`false`: read
    /// error, recorded; every later read fails at once).
    pub fn fetch(&self, offset: usize, buf: &mut [u8]) -> bool {
        if self.failed.borrow().is_some() {
            return false;
        }
        let end = offset.checked_add(buf.len());
        let result = match self.kind {
            _ if end.is_none_or(|e| e > self.len) => Err("read past the end".to_string()),
            Kind::Slice(s) => {
                buf.copy_from_slice(&s[offset..offset + buf.len()]);
                Ok(())
            }
            Kind::Source(src) => src.read_at(offset as u64, buf).map_err(|e| e.0),
        };
        match result {
            Ok(()) => true,
            Err(msg) => {
                *self.failed.borrow_mut() = Some((offset, msg));
                false
            }
        }
    }

    /// Cached page `n` (sources only).
    fn page(&self, n: usize) -> Option<Rc<[u8]>> {
        let mut pages = self.pages.borrow_mut();
        if let Some(i) = pages.iter().position(|(p, _)| *p == n) {
            let hit = pages.remove(i);
            let data = Rc::clone(&hit.1);
            pages.push(hit);
            return Some(data);
        }
        let start = n.checked_mul(self.tuning.page)?;
        if start >= self.len {
            return None;
        }
        let end = start.saturating_add(self.tuning.page).min(self.len);
        let mut buf = vec![0u8; end - start];
        if !self.fetch(start, &mut buf) {
            return None;
        }
        let data: Rc<[u8]> = buf.into();
        if pages.len() >= self.tuning.pages {
            pages.remove(0);
        }
        pages.push((n, Rc::clone(&data)));
        Some(data)
    }

    /// Bytes `range` (`None`: out of range, or read error).
    pub fn read(&self, range: Range<usize>) -> Option<Cow<'a, [u8]>> {
        if range.start > range.end || range.end > self.len {
            return None;
        }
        if let Kind::Slice(s) = self.kind {
            return s.get(range).map(Cow::Borrowed);
        }
        let page = self.tuning.page;
        if range.start < range.end && range.start / page == (range.end - 1) / page {
            let p = self.page(range.start / page)?;
            let at = range.start % page;
            return Some(Cow::Owned(p[at..at + range.len()].to_vec()));
        }
        let mut buf = vec![0u8; range.len()];
        self.fetch(range.start, &mut buf).then_some(Cow::Owned(buf))
    }

    /// The file from about `offset`, at least `want` bytes of it (fewer at
    /// the end). A slice gives the whole file.
    pub fn window(&self, offset: usize, want: usize) -> Option<Window<'a>> {
        if offset > self.len {
            return None;
        }
        if let Kind::Slice(s) = self.kind {
            return Some(Window {
                base: 0,
                data: WindowData::Borrowed(s),
            });
        }
        let end = offset.saturating_add(want.max(1)).min(self.len);
        let page = self.tuning.page;
        if offset < end && offset / page == (end - 1) / page {
            let n = offset / page;
            return Some(Window {
                base: n * page,
                data: WindowData::Page(self.page(n)?),
            });
        }
        let mut buf = vec![0u8; end - offset];
        self.fetch(offset, &mut buf).then_some(Window {
            base: offset,
            data: WindowData::Owned(buf),
        })
    }

    /// Runs `f(window, offset in window)` → `(result, furthest offset read
    /// in window)` on growing windows until it reads nothing past the end
    /// of one (or the window reaches the end of the file). Returns the
    /// result, the window's base and the absolute furthest offset.
    pub fn windowed<T>(
        &self,
        offset: usize,
        mut f: impl FnMut(&[u8], usize) -> (T, usize),
    ) -> Option<(T, usize, usize)> {
        let mut want = self.tuning.window;
        loop {
            let w = self.window(offset, want)?;
            let (t, furthest) = f(&w.data, offset - w.base);
            let end = w.base + w.data.len();
            if end >= self.len || furthest < w.data.len() {
                return Some((t, w.base, w.base + furthest));
            }
            want = want.max(end - offset).saturating_mul(2);
        }
    }

    /// [`object_header_at`] (reads at most [`HEADER_WINDOW`] bytes).
    pub fn object_header_at(&self, offset: usize) -> Option<(usize, ObjRef)> {
        if let Some(src) = self.as_slice() {
            return object_header_at(src, offset);
        }
        if offset >= self.len {
            return None;
        }
        let (r, base, _) = self.windowed(offset, |w, at| {
            (object_header_at(w, at), at + HEADER_WINDOW - 1)
        })?;
        r.map(|(start, id)| (start + base, id))
    }

    /// [`parse_indirect_object_extent`].
    pub fn parse_indirect(
        &self,
        offset: usize,
        limits: &Limits,
    ) -> (Result<IndirectObject, ParseError>, usize) {
        if let Some(src) = self.as_slice() {
            return parse_indirect_object_extent(src, offset, limits);
        }
        let failed = || {
            let e = ParseError {
                kind: ParseErrorKind::UnexpectedEof,
                offset,
            };
            (Err(e), offset)
        };
        let Some((head, base, furthest)) =
            self.windowed(offset, |w, at| indirect_head(w, at, limits))
        else {
            return failed();
        };
        let head = match head {
            Err(e) => return (Err(shift_err(e, base)), furthest),
            Ok(Head::Done(mut o)) => {
                o.offset += base;
                o.end += base;
                return (Ok(o), furthest);
            }
            Ok(Head::Stream(h)) => h,
        };
        let mut scanned = 0;
        let after_kw = head.after_kw + base;
        match locate_stream(self, head.dict, after_kw, &mut scanned) {
            Err(e) => (Err(e), furthest.max(scanned)),
            Ok((stream, end)) => {
                let Some(((has_endobj, end_rel, _), base2, f2)) = self.windowed(end, |w, at| {
                    let r = endobj_at(w, at);
                    (r, r.2)
                }) else {
                    return failed();
                };
                let o = IndirectObject {
                    id: head.id,
                    offset: head.start + base,
                    object: PdfObject::Stream(Box::new(stream)),
                    has_endobj,
                    end: end_rel + base2,
                };
                (Ok(o), furthest.max(f2).max(scanned))
            }
        }
    }

    /// [`parse_object_extent`].
    pub fn parse_object(
        &self,
        offset: usize,
        limits: &Limits,
    ) -> (Result<(PdfObject, usize), ParseError>, usize) {
        if let Some(src) = self.as_slice() {
            return parse_object_extent(src, offset, limits);
        }
        match self.windowed(offset, |w, at| parse_object_extent(w, at, limits)) {
            Some((r, base, furthest)) => (
                r.map(|(o, end)| (o, end + base))
                    .map_err(|e| shift_err(e, base)),
                furthest,
            ),
            None => (
                Err(ParseError {
                    kind: ParseErrorKind::UnexpectedEof,
                    offset,
                }),
                offset,
            ),
        }
    }

    /// [`parse_table`].
    pub fn parse_table(&self, offset: usize, limits: &Limits) -> (Option<XrefSection>, usize) {
        if let Some(src) = self.as_slice() {
            return parse_table(src, offset, limits);
        }
        match self.windowed(offset, |w, at| parse_table(w, at, limits)) {
            Some((section, base, furthest)) => (section.map(|s| shift_section(s, base)), furthest),
            None => (None, offset),
        }
    }

    /// [`super::parse::stream_data_with_length`].
    pub fn data_with_length(
        &self,
        data_start: usize,
        length: u64,
    ) -> Option<(Range<usize>, usize)> {
        data_with_length(self, data_start, length)
    }

    /// Bytes `a` and `b` are equal (read in pieces).
    pub fn same_bytes(&self, a: Range<usize>, b: Range<usize>) -> bool {
        if let Some(src) = self.as_slice() {
            return src.get(a) == src.get(b);
        }
        // As `src.get(a) == src.get(b)`: out of range is `None`.
        let valid = |r: &Range<usize>| r.start <= r.end && r.end <= self.len;
        if !valid(&a) || !valid(&b) {
            return valid(&a) == valid(&b);
        }
        if a.len() != b.len() {
            return false;
        }
        let step = self.tuning.page;
        let mut k = 0;
        while k < a.len() {
            let n = step.min(a.len() - k);
            match (
                self.read(a.start + k..a.start + k + n),
                self.read(b.start + k..b.start + k + n),
            ) {
                (Some(x), Some(y)) if x == y => k += n,
                _ => return false,
            }
        }
        true
    }
}

impl Bytes for Input<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn byte(&self, i: usize) -> Option<u8> {
        if let Kind::Slice(s) = self.kind {
            return s.get(i).copied();
        }
        if i >= self.len {
            return None;
        }
        self.page(i / self.tuning.page)
            .and_then(|p| p.get(i % self.tuning.page).copied())
    }

    fn find_endstream(&self, from: usize) -> Option<usize> {
        if let Kind::Slice(s) = self.kind {
            return s.find_endstream(from);
        }
        let all = self.endstreams.get()?;
        all.get(all.partition_point(|&o| o < from)).copied()
    }
}

fn shift_err(mut e: ParseError, base: usize) -> ParseError {
    e.offset += base;
    e
}

fn shift_section(mut s: XrefSection, base: usize) -> XrefSection {
    s.offset += base;
    if let Some(t) = &mut s.trailer_offset {
        *t += base;
    }
    for p in &mut s.problems {
        match p {
            XrefProblem::MalformedTable { offset } | XrefProblem::ShortSubsection { offset } => {
                *offset += base;
            }
            _ => {}
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Tuning {
        Tuning {
            page: 4,
            pages: 2,
            block: 3,
            window: 1,
        }
    }

    #[test]
    fn reads_and_windows() {
        let src: &[u8] = b"0123456789";
        let i = Input::source(&src, tiny()).unwrap();
        assert_eq!(i.read(2..9).as_deref(), Some(&b"2345678"[..]));
        assert_eq!(i.read(4..6).as_deref(), Some(&b"45"[..]));
        assert_eq!(i.read(5..5).as_deref(), Some(&b""[..]));
        assert_eq!(i.read(5..11), None);
        assert_eq!(i.byte(9), Some(b'9'));
        assert_eq!(i.byte(10), None);
        // Within one page: the page itself.
        let w = i.window(5, 2).unwrap();
        assert_eq!((w.base, &*w.data), (4, &b"4567"[..]));
        let w = i.window(3, 4).unwrap();
        assert_eq!((w.base, &*w.data), (3, &b"3456"[..]));
        assert_eq!(i.window(10, 4).map(|w| w.data.len()), Some(0));
        assert!(i.window(11, 4).is_none());
        // Pages kept: at most 2.
        assert!(i.pages.borrow().len() <= 2);
        assert!(i.failure().is_none());
        let s = Input::slice(src);
        assert_eq!(
            s.window(7, 1).map(|w| (w.base, w.data.len())),
            Some((0, 10))
        );
    }

    #[test]
    fn windowed_grows_until_nothing_is_read_past_the_end() {
        let src = b"1 0 obj << /A [1 2 3 4 5 6 7 8 9] /B (long string here) >> endobj 2 0 obj";
        let s: &[u8] = src;
        let limits = Limits::default();
        for window in 1..20 {
            for page in [1, 3, 8, 100] {
                let t = Tuning {
                    page,
                    pages: 2,
                    block: 1,
                    window,
                };
                let i = Input::source(&s, t).unwrap();
                assert_eq!(
                    i.parse_indirect(0, &limits),
                    parse_indirect_object_extent(src, 0, &limits),
                    "window {window} page {page}"
                );
                assert_eq!(i.object_header_at(1), object_header_at(src, 1));
                assert_eq!(i.object_header_at(66), object_header_at(src, 66));
                assert_eq!(
                    i.parse_object(8, &limits),
                    parse_object_extent(src, 8, &limits)
                );
            }
        }
    }

    #[test]
    fn same_bytes_like_slices() {
        let src: &[u8] = b"abcXabcabc";
        let i = Input::source(&src, tiny()).unwrap();
        for (a, b) in [
            (0..3, 4..7),
            (0..3, 3..6),
            (4..7, 7..10),
            (0..3, 8..11),
            (8..11, 9..12),
        ] {
            assert_eq!(
                i.same_bytes(a.clone(), b.clone()),
                src.get(a.clone()) == src.get(b.clone()),
                "{a:?} {b:?}"
            );
        }
    }

    #[test]
    fn nothing_is_read_after_an_error() {
        struct Fails;
        impl Source for Fails {
            fn len(&self) -> u64 {
                100
            }
            fn read_at(&self, _: u64, _: &mut [u8]) -> Result<(), crate::source::ReadError> {
                Err(crate::source::ReadError("no".to_string()))
            }
        }
        let i = Input::source(&Fails, tiny()).unwrap();
        assert_eq!(i.byte(50), None);
        assert_eq!(i.failure(), Some((48, "no".to_string())));
        assert_eq!(i.read(0..1), None);
        assert_eq!(i.failure().map(|f| f.0), Some(48));
    }
}
