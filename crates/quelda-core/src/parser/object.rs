//! Normalized PDF objects (design §4.3). Rules only ever see this form:
//! names and strings decoded, dictionaries in file order with duplicate keys
//! kept (duplicates are a structure fact, not something to silently resolve).

use std::fmt;
use std::ops::Range;

/// Indirect object identifier `N G`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjRef {
    pub num: u32,
    pub generation: u16,
}

impl ObjRef {
    pub fn new(num: u32, generation: u16) -> Self {
        ObjRef { num, generation }
    }

    /// `N G` from parsed integers; `None` if out of range for a PDF object id.
    pub fn from_ints(num: i64, generation: i64) -> Option<Self> {
        Some(ObjRef {
            num: u32::try_from(num).ok()?,
            generation: u16::try_from(generation).ok()?,
        })
    }
}

impl fmt::Display for ObjRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.num, self.generation)
    }
}

/// A name with `#xx` escapes decoded. Stored as bytes: names are byte strings
/// and may be invalid UTF-8; compare with `name == "JS"`. Names of up to
/// [`INLINE_NAME`] bytes (nearly all of them) live inline, without a heap
/// allocation.
#[derive(Clone)]
pub struct Name(NameRepr);

/// Longest name stored inline (keeps `Name` as small as a `Vec`).
const INLINE_NAME: usize = 22;

#[derive(Clone)]
enum NameRepr {
    Inline(u8, [u8; INLINE_NAME]),
    Heap(Box<[u8]>),
}

impl Name {
    pub fn new(bytes: Vec<u8>) -> Self {
        if bytes.len() <= INLINE_NAME {
            Name::from_slice(&bytes)
        } else {
            Name(NameRepr::Heap(bytes.into_boxed_slice()))
        }
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut buf = [0u8; INLINE_NAME];
        match buf.get_mut(..bytes.len()) {
            Some(head) => {
                head.copy_from_slice(bytes);
                Name(NameRepr::Inline(bytes.len() as u8, buf))
            }
            None => Name(NameRepr::Heap(bytes.into())),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            NameRepr::Inline(len, buf) => &buf[..usize::from(*len)],
            NameRepr::Heap(b) => b,
        }
    }

    /// The name as text, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }
}

impl Default for Name {
    fn default() -> Self {
        Name::from_slice(b"")
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Name {}

impl std::hash::Hash for Name {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl From<&str> for Name {
    fn from(s: &str) -> Self {
        Name::from_slice(s.as_bytes())
    }
}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl PartialEq<&str> for Name {
    fn eq(&self, other: &&str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", String::from_utf8_lossy(self.as_bytes()))
    }
}

/// Dictionary in file order. Duplicate keys are kept: use [`Dict::get_all`]
/// when every value matters (readers disagree on which duplicate wins).
#[derive(Clone, PartialEq, Default)]
pub struct Dict {
    entries: Vec<(Name, PdfObject)>,
    has_duplicate_keys: bool,
}

impl Dict {
    pub fn new(entries: Vec<(Name, PdfObject)>) -> Self {
        let has_duplicate_keys = has_duplicates(&entries);
        Dict {
            entries,
            has_duplicate_keys,
        }
    }

    pub fn entries(&self) -> &[(Name, PdfObject)] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// First value for `key`.
    pub fn get(&self, key: &str) -> Option<&PdfObject> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Every value for `key`, in file order.
    pub fn get_all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a PdfObject> + 'a {
        self.entries
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Some key appears more than once.
    pub fn has_duplicate_keys(&self) -> bool {
        self.has_duplicate_keys
    }

    /// Keys that appear more than once, sorted, each listed once.
    pub fn duplicate_keys(&self) -> Vec<&Name> {
        if !self.has_duplicate_keys {
            return Vec::new();
        }
        duplicates(&self.entries)
    }
}

/// Small dictionaries (nearly all) are compared pairwise, without allocating.
fn has_duplicates(entries: &[(Name, PdfObject)]) -> bool {
    if entries.len() > 16 {
        return !duplicates(entries).is_empty();
    }
    entries
        .iter()
        .enumerate()
        .any(|(i, (k, _))| entries[i + 1..].iter().any(|(k2, _)| k == k2))
}

/// O(n log n): sort key references, report equal neighbours.
fn duplicates(entries: &[(Name, PdfObject)]) -> Vec<&Name> {
    if entries.len() < 2 {
        return Vec::new();
    }
    let mut keys: Vec<&Name> = entries.iter().map(|(k, _)| k).collect();
    keys.sort_unstable();
    let mut out: Vec<&Name> = Vec::new();
    for w in keys.windows(2) {
        if w[0] == w[1] && out.last() != Some(&w[0]) {
            out.push(w[0]);
        }
    }
    out
}

impl fmt::Debug for Dict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.entries.iter().map(|(k, v)| (k, v)))
            .finish()
    }
}

/// How the data range of a stream was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamLength {
    /// Direct `/Length`, and `endstream` follows the declared data.
    Declared,
    /// `/Length` is an indirect reference not (yet) resolved to a length
    /// that `endstream` follows: `data` comes from scanning for `endstream`.
    Indirect(ObjRef),
    /// `/Length` is an indirect reference, resolved (see
    /// `parser::document`), and `endstream` follows the data it gives.
    ResolvedIndirect(ObjRef),
    /// `/Length` missing, not a non-negative integer, or wrong (`endstream`
    /// not where it points): `data` comes from scanning for `endstream`.
    Scanned { declared: Option<i64> },
}

/// Stream object: dictionary + location of its raw (still encoded) data.
#[derive(Clone, Debug, PartialEq)]
pub struct PdfStream {
    pub dict: Dict,
    /// First byte after `stream` + EOL.
    pub data_start: usize,
    /// Raw data in the input.
    pub data: Range<usize>,
    pub length: StreamLength,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PdfObject {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    /// Decoded bytes (literal escapes / hex resolved).
    String(Vec<u8>),
    Name(Name),
    Array(Vec<PdfObject>),
    Dict(Dict),
    /// Boxed: streams are few, and this keeps every other value small.
    Stream(Box<PdfStream>),
    Ref(ObjRef),
}

impl PdfObject {
    /// PDF type name, for messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            PdfObject::Null => "null",
            PdfObject::Bool(_) => "boolean",
            PdfObject::Int(_) => "integer",
            PdfObject::Real(_) => "real",
            PdfObject::String(_) => "string",
            PdfObject::Name(_) => "name",
            PdfObject::Array(_) => "array",
            PdfObject::Dict(_) => "dictionary",
            PdfObject::Stream(_) => "stream",
            PdfObject::Ref(_) => "reference",
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            PdfObject::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Integer or real as `f64`.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            PdfObject::Int(i) => Some(*i as f64),
            PdfObject::Real(r) => Some(*r),
            _ => None,
        }
    }

    pub fn as_name(&self) -> Option<&Name> {
        match self {
            PdfObject::Name(n) => Some(n),
            _ => None,
        }
    }

    /// `true` if this is the name `name`.
    pub fn is_name(&self, name: &str) -> bool {
        self.as_name().is_some_and(|n| n == name)
    }

    pub fn as_string(&self) -> Option<&[u8]> {
        match self {
            PdfObject::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[PdfObject]> {
        match self {
            PdfObject::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The dictionary of a dict or of a stream.
    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            PdfObject::Dict(d) => Some(d),
            PdfObject::Stream(s) => Some(&s.dict),
            _ => None,
        }
    }

    pub fn as_stream(&self) -> Option<&PdfStream> {
        match self {
            PdfObject::Stream(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_reference(&self) -> Option<ObjRef> {
        match self {
            PdfObject::Ref(r) => Some(*r),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from(s)
    }

    #[test]
    fn objref_from_ints() {
        assert_eq!(ObjRef::from_ints(12, 0), Some(ObjRef::new(12, 0)));
        assert_eq!(ObjRef::from_ints(-1, 0), None);
        assert_eq!(ObjRef::from_ints(1, 65536), None);
        assert_eq!(ObjRef::from_ints(1 << 32, 0), None);
        assert_eq!(ObjRef::new(7, 1).to_string(), "7 1");
    }

    #[test]
    fn name_compares_with_str() {
        let js = Name::new(b"JS".to_vec());
        assert!(js == "JS");
        assert!(js != "JSX");
        assert_eq!(js.as_str(), Some("JS"));
        assert_eq!(Name::new(vec![0xFF]).as_str(), None);
        assert_eq!(format!("{js:?}"), "/JS");
    }

    #[test]
    fn dict_keeps_order_and_duplicates() {
        let d = Dict::new(vec![
            (n("S"), PdfObject::Name(n("URI"))),
            (n("A"), PdfObject::Int(1)),
            (n("S"), PdfObject::Name(n("Launch"))),
        ]);
        assert_eq!(d.len(), 3);
        assert!(!d.is_empty());
        assert_eq!(d.entries()[1].0, n("A"));
        assert_eq!(d.get("S"), Some(&PdfObject::Name(n("URI"))));
        let all: Vec<_> = d.get_all("S").collect();
        assert_eq!(
            all,
            vec![&PdfObject::Name(n("URI")), &PdfObject::Name(n("Launch"))]
        );
        assert!(d.has_duplicate_keys());
        assert_eq!(d.duplicate_keys(), vec![&n("S")]);
        assert!(d.contains_key("A"));
        assert!(!d.contains_key("B"));
    }

    #[test]
    fn dict_without_duplicates() {
        let d = Dict::new(vec![(n("A"), PdfObject::Null), (n("B"), PdfObject::Null)]);
        assert!(!d.has_duplicate_keys());
        assert!(d.duplicate_keys().is_empty());
        assert!(!Dict::default().has_duplicate_keys());
    }

    #[test]
    fn duplicate_keys_listed_once() {
        let d = Dict::new(vec![
            (n("B"), PdfObject::Null),
            (n("A"), PdfObject::Null),
            (n("B"), PdfObject::Null),
            (n("A"), PdfObject::Null),
            (n("B"), PdfObject::Null),
        ]);
        assert_eq!(d.duplicate_keys(), vec![&n("A"), &n("B")]);
    }

    #[test]
    fn accessors() {
        let r = ObjRef::new(4, 0);
        assert_eq!(PdfObject::Int(3).as_int(), Some(3));
        assert_eq!(PdfObject::Int(3).as_number(), Some(3.0));
        assert_eq!(PdfObject::Real(0.5).as_number(), Some(0.5));
        assert_eq!(PdfObject::Real(0.5).as_int(), None);
        assert!(PdfObject::Name(n("Launch")).is_name("Launch"));
        assert!(!PdfObject::String(b"Launch".to_vec()).is_name("Launch"));
        assert_eq!(
            PdfObject::String(b"x".to_vec()).as_string(),
            Some(&b"x"[..])
        );
        assert_eq!(PdfObject::Ref(r).as_reference(), Some(r));
        assert_eq!(PdfObject::Array(vec![]).as_array(), Some(&[][..]));
        let s = PdfStream {
            dict: Dict::new(vec![(n("Length"), PdfObject::Int(0))]),
            data_start: 10,
            data: 10..10,
            length: StreamLength::Declared,
        };
        let so = PdfObject::Stream(Box::new(s.clone()));
        assert_eq!(so.as_dict(), Some(&s.dict));
        assert_eq!(so.as_stream(), Some(&s));
        assert_eq!(so.type_name(), "stream");
        assert_eq!(PdfObject::Null.type_name(), "null");
        assert_eq!(PdfObject::Null.as_dict(), None);
    }
}
