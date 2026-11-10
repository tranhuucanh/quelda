//! Stream decoding (design §4.4): filter chains with a decode budget checked
//! **while** decoding, so bombs stop early instead of filling memory.
//!
//! Decoded: Flate, LZW (both with PNG/TIFF predictors), ASCIIHex, ASCII85,
//! RunLength. Image codecs and Crypt are never decoded (`NotInspected`);
//! unrecognized filters are `Unknown`. Whether either is an engine issue
//! depends on what the stream is, which the facts layer (Step 6) decides.

mod ascii85;
mod asciihex;
mod flate;
mod lzw;
pub mod predictor;
mod runlength;

use std::borrow::Cow;

use crate::error::IssueCode;
use crate::limits::{Budget, Cap};
use crate::parser::{Dict, Name, PdfObject, PdfStream};

/// Hard cap on filters per stream. Real files use at most 2–3; each stage
/// may allocate up to the per-stream budget, so long chains would multiply work.
pub const MAX_FILTER_CHAIN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FilterKind {
    Flate,
    Lzw,
    AsciiHex,
    Ascii85,
    RunLength,
    Ccitt,
    Dct,
    Jpx,
    Jbig2,
    Crypt,
}

impl FilterKind {
    /// Full name or the inline-image abbreviation (§8.9.7, Table 92).
    pub fn from_name(name: &Name) -> Option<FilterKind> {
        Some(match name.as_bytes() {
            b"FlateDecode" | b"Fl" => FilterKind::Flate,
            b"LZWDecode" | b"LZW" => FilterKind::Lzw,
            b"ASCIIHexDecode" | b"AHx" => FilterKind::AsciiHex,
            b"ASCII85Decode" | b"A85" => FilterKind::Ascii85,
            b"RunLengthDecode" | b"RL" => FilterKind::RunLength,
            b"CCITTFaxDecode" | b"CCF" => FilterKind::Ccitt,
            b"DCTDecode" | b"DCT" => FilterKind::Dct,
            b"JPXDecode" => FilterKind::Jpx,
            b"JBIG2Decode" => FilterKind::Jbig2,
            b"Crypt" => FilterKind::Crypt,
            _ => return None,
        })
    }

    /// Canonical (full) filter name.
    pub fn name(self) -> &'static str {
        match self {
            FilterKind::Flate => "FlateDecode",
            FilterKind::Lzw => "LZWDecode",
            FilterKind::AsciiHex => "ASCIIHexDecode",
            FilterKind::Ascii85 => "ASCII85Decode",
            FilterKind::RunLength => "RunLengthDecode",
            FilterKind::Ccitt => "CCITTFaxDecode",
            FilterKind::Dct => "DCTDecode",
            FilterKind::Jpx => "JPXDecode",
            FilterKind::Jbig2 => "JBIG2Decode",
            FilterKind::Crypt => "Crypt",
        }
    }

    /// `false` for image codecs and Crypt (not decoded in v0.1).
    pub fn is_decodable(self) -> bool {
        matches!(
            self,
            FilterKind::Flate
                | FilterKind::Lzw
                | FilterKind::AsciiHex
                | FilterKind::Ascii85
                | FilterKind::RunLength
        )
    }
}

/// One filter of a stream's chain, with its `/DecodeParms` entry.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainEntry<'a> {
    pub name: &'a Name,
    /// `None`: unrecognized filter name.
    pub kind: Option<FilterKind>,
    pub parms: Option<&'a Dict>,
}

/// Reads `/Filter` + `/DecodeParms` (or `/F` + `/DP` of inline images).
/// Indirect references must be resolved by the caller; one here is an error.
pub fn parse_chain<'a>(
    filter: Option<&'a PdfObject>,
    parms: Option<&'a PdfObject>,
) -> Result<Vec<ChainEntry<'a>>, &'static str> {
    let names: Vec<&Name> = match filter {
        None | Some(PdfObject::Null) => Vec::new(),
        Some(PdfObject::Name(n)) => vec![n],
        Some(PdfObject::Array(items)) => items
            .iter()
            .map(|o| o.as_name().ok_or("/Filter array contains a non-name"))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err("/Filter is not a name or an array"),
    };
    let parms: Vec<Option<&Dict>> = match parms {
        None | Some(PdfObject::Null) => Vec::new(),
        Some(PdfObject::Dict(d)) => vec![Some(d)],
        Some(PdfObject::Array(items)) => items
            .iter()
            .map(|o| match o {
                PdfObject::Dict(d) => Ok(Some(d)),
                PdfObject::Null => Ok(None),
                _ => Err("/DecodeParms array contains a non-dictionary"),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err("/DecodeParms is not a dictionary or an array"),
    };
    Ok(names
        .into_iter()
        .enumerate()
        .map(|(i, name)| ChainEntry {
            name,
            kind: FilterKind::from_name(name),
            parms: parms.get(i).copied().flatten(),
        })
        .collect())
}

#[derive(Clone, Debug, PartialEq)]
pub enum DecodeOutcome<'a> {
    /// Every filter decoded its whole input. Unfiltered data is borrowed
    /// from the input, not copied.
    Complete(Cow<'a, [u8]>),
    /// `filter` (the first that was cut short) ran out of input before its
    /// end marker; `data` is everything it decoded up to there, which is
    /// what readers render. Only Flate reports this (other filters treat a
    /// missing end marker as a clean end).
    Truncated { data: Vec<u8>, filter: FilterKind },
    /// `filter` (the first that failed) hit corrupt data; `data` is what the
    /// chain produced anyway.
    Partial { data: Vec<u8>, filter: FilterKind },
    /// The chain contains a filter v0.1 never decodes (image codec, Crypt).
    NotInspected(FilterKind),
    /// The chain contains an unrecognized filter name.
    Unknown(Name),
    /// `/Filter` / `/DecodeParms` malformed (or unresolved reference).
    Invalid(&'static str),
    /// A decode limit was hit; decoding stopped.
    Limit(IssueCode),
}

impl DecodeOutcome<'_> {
    /// Decoded bytes, if any were produced.
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            DecodeOutcome::Complete(d) => Some(d),
            DecodeOutcome::Truncated { data: d, .. } | DecodeOutcome::Partial { data: d, .. } => {
                Some(d)
            }
            _ => None,
        }
    }

    /// The same outcome, owning its data.
    pub fn into_owned(self) -> DecodeOutcome<'static> {
        match self {
            DecodeOutcome::Complete(d) => DecodeOutcome::Complete(Cow::Owned(d.into_owned())),
            DecodeOutcome::Truncated { data, filter } => DecodeOutcome::Truncated { data, filter },
            DecodeOutcome::Partial { data, filter } => DecodeOutcome::Partial { data, filter },
            DecodeOutcome::NotInspected(k) => DecodeOutcome::NotInspected(k),
            DecodeOutcome::Unknown(n) => DecodeOutcome::Unknown(n),
            DecodeOutcome::Invalid(m) => DecodeOutcome::Invalid(m),
            DecodeOutcome::Limit(c) => DecodeOutcome::Limit(c),
        }
    }

    /// The whole data was decoded: complete, or truncated (every byte up to
    /// the end of the input, as readers see it).
    pub fn is_usable(&self) -> bool {
        matches!(
            self,
            DecodeOutcome::Complete(_) | DecodeOutcome::Truncated { .. }
        )
    }
}

/// Decodes the raw data of `stream` (located in `src`) with its own
/// `/Filter` and `/DecodeParms`.
pub fn decode_stream<'a>(
    src: &'a [u8],
    stream: &PdfStream,
    budget: &mut Budget,
) -> DecodeOutcome<'a> {
    let Some(raw) = src.get(stream.data.clone()) else {
        return DecodeOutcome::Invalid("stream data out of range");
    };
    decode(
        raw,
        stream.dict.get("Filter"),
        stream.dict.get("DecodeParms"),
        budget,
    )
}

/// Decodes `raw` through the chain given by `filter` / `parms`. The decoded
/// size is charged to `budget` (once, on success or partial success).
/// Unfiltered data is returned as is and charged nothing: decode limits
/// stop decompression bombs, and raw data is already bounded by the file
/// size limit.
pub fn decode<'a>(
    raw: &'a [u8],
    filter: Option<&PdfObject>,
    parms: Option<&PdfObject>,
    budget: &mut Budget,
) -> DecodeOutcome<'a> {
    let chain = match parse_chain(filter, parms) {
        Ok(c) => c,
        Err(msg) => return DecodeOutcome::Invalid(msg),
    };
    if chain.len() > MAX_FILTER_CHAIN {
        return DecodeOutcome::Limit(IssueCode::LimitFilterChain);
    }
    if let Some(e) = chain.iter().find(|e| e.kind.is_none()) {
        return DecodeOutcome::Unknown(e.name.clone());
    }
    if let Some(k) = chain
        .iter()
        .filter_map(|e| e.kind)
        .find(|k| !k.is_decodable())
    {
        return DecodeOutcome::NotInspected(k);
    }
    if chain.is_empty() {
        return DecodeOutcome::Complete(Cow::Borrowed(raw));
    }
    let cap = budget.cap_for(raw.len() as u64);
    let mut data: Cow<[u8]> = Cow::Borrowed(raw);
    let mut corrupt: Option<FilterKind> = None;
    let mut truncated: Option<FilterKind> = None;
    for e in &chain {
        let Some(kind) = e.kind else {
            return DecodeOutcome::Unknown(e.name.clone());
        };
        match run_stage(kind, &data, e.parms, cap) {
            Ok((out, end)) => {
                match end {
                    End::Complete => {}
                    End::Truncated => {
                        truncated.get_or_insert(kind);
                    }
                    End::Corrupt => {
                        corrupt.get_or_insert(kind);
                    }
                }
                data = Cow::Owned(out);
            }
            Err(StageError::Limit(code)) => return DecodeOutcome::Limit(code),
            Err(StageError::Invalid(msg)) => return DecodeOutcome::Invalid(msg),
        }
    }
    let data = data.into_owned();
    budget.charge(data.len() as u64);
    match (corrupt, truncated) {
        (Some(filter), _) => DecodeOutcome::Partial { data, filter },
        (None, Some(filter)) => DecodeOutcome::Truncated { data, filter },
        (None, None) => DecodeOutcome::Complete(Cow::Owned(data)),
    }
}

/// How a filter's input ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// End marker reached, or a clean end of input.
    Complete,
    /// Input ran out before the end marker; everything before it decoded.
    Truncated,
    /// Invalid data.
    Corrupt,
}

impl From<bool> for End {
    fn from(complete: bool) -> End {
        if complete {
            End::Complete
        } else {
            End::Corrupt
        }
    }
}

#[derive(Debug)]
enum StageError {
    Limit(IssueCode),
    Invalid(&'static str),
}

impl From<LimitHit> for StageError {
    fn from(l: LimitHit) -> Self {
        StageError::Limit(l.0)
    }
}

/// One filter (+ predictor). Returns the output and how the input ended.
fn run_stage(
    kind: FilterKind,
    input: &[u8],
    parms: Option<&Dict>,
    cap: Cap,
) -> Result<(Vec<u8>, End), StageError> {
    let mut sink = Sink::new(cap);
    let end = match kind {
        FilterKind::Flate => flate::decode(input, &mut sink)?,
        FilterKind::Lzw => lzw::decode(input, lzw::early_change(parms)?, &mut sink)?.into(),
        FilterKind::AsciiHex => asciihex::decode(input, &mut sink)?.into(),
        FilterKind::Ascii85 => ascii85::decode(input, &mut sink)?.into(),
        FilterKind::RunLength => runlength::decode(input, &mut sink)?.into(),
        _ => return Err(StageError::Invalid("filter is not decodable")),
    };
    let out = sink.into_inner();
    if matches!(kind, FilterKind::Flate | FilterKind::Lzw) {
        if let Some(p) = predictor::Params::from_dict(parms).map_err(StageError::Invalid)? {
            // A partial last row has no single decoding: corrupt.
            let (out, rows_ok) = p.apply(&out);
            return Ok((out, if rows_ok { end } else { End::Corrupt }));
        }
    }
    Ok((out, end))
}

/// A decode limit was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LimitHit(pub IssueCode);

/// Decoder output that refuses to grow past its cap. Checked before every
/// write, so memory never exceeds the cap (plus `Vec` slack).
pub(crate) struct Sink {
    buf: Vec<u8>,
    cap: Cap,
}

impl Sink {
    pub(crate) fn new(cap: Cap) -> Self {
        Sink {
            buf: Vec::new(),
            cap,
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<(), LimitHit> {
        let need = self.buf.len().saturating_add(bytes.len());
        if need as u64 > self.cap.bytes {
            return Err(LimitHit(self.cap.code));
        }
        if need > self.buf.capacity() {
            // Grow geometrically, but never reserve past the cap.
            let cap = usize::try_from(self.cap.bytes).unwrap_or(usize::MAX);
            let target = need.max(self.buf.capacity().saturating_mul(2)).min(cap);
            self.buf.reserve_exact(target - self.buf.len());
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn push(&mut self, b: u8) -> Result<(), LimitHit> {
        self.write(&[b])
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    #[cfg(test)]
    pub(crate) fn unlimited() -> Self {
        Sink::new(Cap {
            bytes: u64::MAX,
            code: IssueCode::LimitStreamDecodedBytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use quelda_testkit::Filter;

    fn name(s: &str) -> PdfObject {
        PdfObject::Name(Name::from(s))
    }

    fn names(list: &[&str]) -> PdfObject {
        PdfObject::Array(list.iter().map(|s| name(s)).collect())
    }

    fn dict(entries: &[(&str, i64)]) -> PdfObject {
        PdfObject::Dict(Dict::new(
            entries
                .iter()
                .map(|(k, v)| (Name::from(*k), PdfObject::Int(*v)))
                .collect(),
        ))
    }

    fn run<'a>(raw: &'a [u8], filter: &PdfObject, parms: Option<&PdfObject>) -> DecodeOutcome<'a> {
        decode(
            raw,
            Some(filter),
            parms,
            &mut Budget::new(&Limits::default()),
        )
    }

    /// Encodes with testkit (applied in reverse order, like a writer would).
    fn encode(data: &[u8], filters: &[Filter]) -> Vec<u8> {
        filters
            .iter()
            .rev()
            .fold(data.to_vec(), |acc, f| f.encode(&acc))
    }

    const TEXT: &[u8] = b"BT /F1 24 Tf 72 720 Td (quelda test) Tj ET\nq 1 0 0 1 0 0 cm Q\n";

    #[test]
    fn filter_names_and_abbreviations() {
        for (full, abbr, kind) in [
            ("FlateDecode", "Fl", FilterKind::Flate),
            ("LZWDecode", "LZW", FilterKind::Lzw),
            ("ASCIIHexDecode", "AHx", FilterKind::AsciiHex),
            ("ASCII85Decode", "A85", FilterKind::Ascii85),
            ("RunLengthDecode", "RL", FilterKind::RunLength),
            ("CCITTFaxDecode", "CCF", FilterKind::Ccitt),
            ("DCTDecode", "DCT", FilterKind::Dct),
        ] {
            assert_eq!(FilterKind::from_name(&Name::from(full)), Some(kind));
            assert_eq!(FilterKind::from_name(&Name::from(abbr)), Some(kind));
            assert_eq!(kind.name(), full);
        }
        assert_eq!(
            FilterKind::from_name(&Name::from("JBIG2Decode")),
            Some(FilterKind::Jbig2)
        );
        assert_eq!(FilterKind::from_name(&Name::from("flatedecode")), None);
        assert!(FilterKind::Flate.is_decodable());
        assert!(!FilterKind::Jpx.is_decodable());
        assert!(!FilterKind::Crypt.is_decodable());
    }

    #[test]
    fn round_trip_each_filter() {
        for f in [
            Filter::Flate,
            Filter::Lzw,
            Filter::AsciiHex,
            Filter::Ascii85,
            Filter::RunLength,
        ] {
            let raw = f.encode(TEXT);
            assert_eq!(
                run(&raw, &name(f.name()), None),
                DecodeOutcome::Complete(TEXT.to_vec().into()),
                "{}",
                f.name()
            );
        }
    }

    #[test]
    fn chains_of_two_and_three() {
        let chain3 = [Filter::Ascii85, Filter::AsciiHex, Filter::Flate];
        let raw = encode(TEXT, &chain3);
        let filter = names(&["ASCII85Decode", "ASCIIHexDecode", "FlateDecode"]);
        assert_eq!(
            run(&raw, &filter, None),
            DecodeOutcome::Complete(TEXT.to_vec().into())
        );
        let raw = encode(TEXT, &[Filter::Ascii85, Filter::Flate]);
        let filter = names(&["A85", "Fl"]);
        assert_eq!(
            run(&raw, &filter, None),
            DecodeOutcome::Complete(TEXT.to_vec().into())
        );
        let raw = encode(TEXT, &[Filter::Flate, Filter::Flate]);
        let filter = names(&["FlateDecode", "FlateDecode"]);
        assert_eq!(
            run(&raw, &filter, None),
            DecodeOutcome::Complete(TEXT.to_vec().into())
        );
    }

    #[test]
    fn no_filter_is_identity() {
        let mut b = Budget::new(&Limits::default());
        assert_eq!(
            decode(b"abc", None, None, &mut b),
            DecodeOutcome::Complete(b"abc".to_vec().into())
        );
        // Unfiltered data is borrowed, not copied, and not charged.
        assert!(matches!(
            decode(b"abc", None, None, &mut b),
            DecodeOutcome::Complete(Cow::Borrowed(_))
        ));
        assert_eq!(b.used(), 0);
        assert_eq!(
            decode(b"abc", Some(&PdfObject::Null), None, &mut b),
            DecodeOutcome::Complete(b"abc".to_vec().into())
        );
        assert_eq!(run(b"abc", &names(&[]), None).data(), Some(&b"abc"[..]));
    }

    #[test]
    fn unknown_and_not_inspected() {
        assert_eq!(
            run(b"x", &name("QueldaUnknownDecode"), None),
            DecodeOutcome::Unknown(Name::from("QueldaUnknownDecode"))
        );
        assert_eq!(
            run(b"x", &name("DCTDecode"), None),
            DecodeOutcome::NotInspected(FilterKind::Dct)
        );
        assert_eq!(
            run(b"x", &names(&["FlateDecode", "JBIG2Decode"]), None),
            DecodeOutcome::NotInspected(FilterKind::Jbig2)
        );
        // Unknown wins over not-inspected anywhere in the chain.
        assert_eq!(
            run(b"x", &names(&["DCT", "Foo"]), None),
            DecodeOutcome::Unknown(Name::from("Foo"))
        );
        assert_eq!(
            run(b"x", &name("Crypt"), None),
            DecodeOutcome::NotInspected(FilterKind::Crypt)
        );
        assert_eq!(run(b"x", &name("DCT"), None).data(), None);
    }

    #[test]
    fn invalid_chain_specs() {
        let r = PdfObject::Ref(crate::parser::ObjRef::new(5, 0));
        assert!(matches!(run(b"x", &r, None), DecodeOutcome::Invalid(_)));
        assert!(matches!(
            run(b"x", &PdfObject::Int(1), None),
            DecodeOutcome::Invalid(_)
        ));
        let mixed = PdfObject::Array(vec![name("Fl"), PdfObject::Int(1)]);
        assert!(matches!(run(b"x", &mixed, None), DecodeOutcome::Invalid(_)));
        assert!(matches!(
            run(b"x", &name("Fl"), Some(&r)),
            DecodeOutcome::Invalid(_)
        ));
        let bad_parms = PdfObject::Array(vec![PdfObject::Int(3)]);
        assert!(matches!(
            run(b"x", &name("Fl"), Some(&bad_parms)),
            DecodeOutcome::Invalid(_)
        ));
    }

    #[test]
    fn parms_align_with_filters() {
        let filter = names(&["AHx", "Fl", "LZW"]);
        let parms = PdfObject::Array(vec![PdfObject::Null, dict(&[("Predictor", 12)])]);
        let chain = parse_chain(Some(&filter), Some(&parms)).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].parms, None);
        assert!(chain[1].parms.unwrap().contains_key("Predictor"));
        assert_eq!(chain[2].parms, None);
        // A single dictionary applies to the first filter.
        let single = dict(&[("Columns", 4)]);
        let chain = parse_chain(Some(&filter), Some(&single)).unwrap();
        assert!(chain[0].parms.is_some());
        assert!(chain[1].parms.is_none());
        assert!(parse_chain(None, Some(&single)).unwrap().is_empty());
    }

    #[test]
    fn flate_with_png_predictor_via_parms() {
        // 2 rows × 3 columns, 1 byte/pixel, PNG Up predictor on row 2.
        let encoded = [2u8, 1, 2, 3, 2, 1, 1, 1];
        let raw = Filter::Flate.encode(&encoded);
        let parms = dict(&[("Predictor", 12), ("Columns", 3)]);
        assert_eq!(
            run(&raw, &name("FlateDecode"), Some(&parms)),
            DecodeOutcome::Complete(vec![1, 2, 3, 2, 3, 4].into())
        );
        let bad = dict(&[("Predictor", 7)]);
        assert!(matches!(
            run(&raw, &name("FlateDecode"), Some(&bad)),
            DecodeOutcome::Invalid(_)
        ));
        // Predictors only apply to Flate/LZW.
        let raw = Filter::AsciiHex.encode(&encoded);
        assert_eq!(
            run(&raw, &name("AHx"), Some(&parms)),
            DecodeOutcome::Complete(encoded.to_vec().into())
        );
    }

    #[test]
    fn partial_reports_first_failing_filter_and_keeps_data() {
        let raw = Filter::Flate.encode(&TEXT.repeat(50));
        let cut = &raw[..raw.len() / 2];
        match run(cut, &name("FlateDecode"), None) {
            DecodeOutcome::Truncated { data, filter } => {
                assert_eq!(filter, FilterKind::Flate);
                assert!(!data.is_empty());
                assert!(TEXT.repeat(50).starts_with(&data));
            }
            other => panic!("{other:?}"),
        }
        // Corrupt Flate (stored block with a bad length check).
        assert!(matches!(
            run(b"\x78\x9c\x00\x05\x00\x00\x00", &name("FlateDecode"), None),
            DecodeOutcome::Partial {
                filter: FilterKind::Flate,
                ..
            }
        ));
        // Truncated then corrupt in a chain: corrupt wins.
        let hex_of_cut: Vec<u8> = cut
            .iter()
            .flat_map(|b| format!("{b:02X}").into_bytes())
            .chain(*b"ZZ")
            .collect();
        assert!(matches!(
            run(&hex_of_cut, &names(&["AHx", "Fl"]), None),
            DecodeOutcome::Partial {
                filter: FilterKind::AsciiHex,
                ..
            }
        ));
        let hex_of_cut = &hex_of_cut[..hex_of_cut.len() - 2];
        assert!(matches!(
            run(hex_of_cut, &names(&["AHx", "Fl"]), None),
            DecodeOutcome::Truncated {
                filter: FilterKind::Flate,
                ..
            }
        ));
        // Corrupt hex ("A B C" then junk) feeding RunLength: the first
        // failing filter is reported, the chain still runs on what decoded.
        // RL reads 0x41 = copy 66 bytes, only "BC" left (also partial).
        let hex = b"414243ZZ";
        assert_eq!(
            run(hex, &names(&["AHx", "RL"]), None),
            DecodeOutcome::Partial {
                data: b"BC".to_vec(),
                filter: FilterKind::AsciiHex
            }
        );
    }

    #[test]
    fn chain_longer_than_cap_is_limit() {
        let long: Vec<&str> = vec!["AHx"; MAX_FILTER_CHAIN + 1];
        assert_eq!(
            run(b"", &names(&long), None),
            DecodeOutcome::Limit(IssueCode::LimitFilterChain)
        );
        let ok: Vec<&str> = vec!["RL"; MAX_FILTER_CHAIN];
        assert!(matches!(
            run(b"\x80", &names(&ok), None),
            DecodeOutcome::Complete(_)
        ));
    }

    fn small_budget(per_stream: u64, total: u64, ratio: u32) -> Budget {
        Budget::new(&Limits {
            max_decoded_bytes_per_stream: per_stream,
            max_decoded_bytes_total: total,
            max_compression_ratio: ratio,
            ..Limits::default()
        })
    }

    #[test]
    fn per_stream_limit() {
        let raw = Filter::Flate.encode(&[b'a'; 5000]);
        let mut b = small_budget(4000, 1 << 30, 1_000_000);
        assert_eq!(
            decode(&raw, Some(&name("Fl")), None, &mut b),
            DecodeOutcome::Limit(IssueCode::LimitStreamDecodedBytes)
        );
        assert_eq!(b.used(), 0);
        // Unfiltered data is not decoded: no limit applies (ADR #26).
        assert!(matches!(
            decode(&[0; 4001], None, None, &mut b),
            DecodeOutcome::Complete(_)
        ));
        assert_eq!(b.used(), 0);
        let mut b = small_budget(5000, 1 << 30, 1_000_000);
        assert!(matches!(
            decode(&raw, Some(&name("Fl")), None, &mut b),
            DecodeOutcome::Complete(_)
        ));
        assert_eq!(b.used(), 5000);
    }

    #[test]
    fn total_limit_across_streams() {
        let raw = Filter::Flate.encode(&[b'a'; 3000]);
        let mut b = small_budget(1 << 20, 7000, 1_000_000);
        for _ in 0..2 {
            assert!(matches!(
                decode(&raw, Some(&name("Fl")), None, &mut b),
                DecodeOutcome::Complete(_)
            ));
        }
        assert_eq!(
            decode(&raw, Some(&name("Fl")), None, &mut b),
            DecodeOutcome::Limit(IssueCode::LimitDecodedBytes)
        );
        assert_eq!(b.used(), 6000);
    }

    #[test]
    fn ratio_limit_applies_above_floor() {
        let mb = 1usize << 20;
        let raw = Filter::Flate.encode(&vec![0u8; 3 * mb]);
        let mut b = small_budget(1 << 30, 1 << 30, 100);
        assert_eq!(
            decode(&raw, Some(&name("Fl")), None, &mut b),
            DecodeOutcome::Limit(IssueCode::LimitCompressionRatio)
        );
        // Below the floor a high ratio is fine.
        let raw = Filter::Flate.encode(&vec![0u8; mb / 2]);
        assert!(matches!(
            decode(&raw, Some(&name("Fl")), None, &mut b),
            DecodeOutcome::Complete(_)
        ));
    }

    #[test]
    fn decode_stream_uses_dict() {
        let raw = Filter::AsciiHex.encode(TEXT);
        let mut src = b"xx".to_vec();
        src.extend(&raw);
        let stream = PdfStream {
            dict: Dict::new(vec![(Name::from("Filter"), name("AHx"))]),
            data_start: 2,
            data: 2..src.len(),
            length: crate::parser::StreamLength::Declared,
        };
        let mut b = Budget::new(&Limits::default());
        assert_eq!(
            decode_stream(&src, &stream, &mut b),
            DecodeOutcome::Complete(TEXT.to_vec().into())
        );
        let bad = PdfStream {
            data: 2..src.len() + 1,
            ..stream
        };
        assert!(matches!(
            decode_stream(&src, &bad, &mut b),
            DecodeOutcome::Invalid(_)
        ));
    }

    #[test]
    fn sink_caps_before_writing() {
        let mut s = Sink::new(Cap {
            bytes: 3,
            code: IssueCode::LimitDecodedBytes,
        });
        assert!(s.write(b"ab").is_ok());
        assert_eq!(s.write(b"cd"), Err(LimitHit(IssueCode::LimitDecodedBytes)));
        assert!(s.push(b'c').is_ok());
        assert!(s.push(b'd').is_err());
        assert_eq!(s.into_inner(), b"abc");
    }
}
