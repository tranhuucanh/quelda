//! LZWDecode (§7.4.4): 9–12 bit codes, MSB first, 256 = clear table,
//! 257 = end of data; `/EarlyChange` 1 (default) widens codes one entry early.

use super::{LimitHit, Sink, StageError};
use crate::parser::{Dict, PdfObject};

const CLEAR: u16 = 256;
const EOD: u16 = 257;
const FIRST_FREE: u16 = 258;
const MAX_CODES: usize = 4096;

/// `/EarlyChange` from the decode parameters (default 1).
pub(super) fn early_change(parms: Option<&Dict>) -> Result<bool, StageError> {
    match parms.and_then(|d| d.get("EarlyChange")) {
        None | Some(PdfObject::Null) => Ok(true),
        Some(PdfObject::Int(1)) => Ok(true),
        Some(PdfObject::Int(0)) => Ok(false),
        Some(_) => Err(StageError::Invalid("/EarlyChange is not 0 or 1")),
    }
}

struct Entry {
    /// Previous code in the string (`u16::MAX` for single bytes).
    prefix: u16,
    last: u8,
    first: u8,
    len: u16,
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    n: u32,
}

impl Bits<'_> {
    fn read(&mut self, width: u32) -> Option<u16> {
        while self.n < width {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            self.acc = (self.acc << 8) | u32::from(b);
            self.n += 8;
        }
        self.n -= width;
        let v = (self.acc >> self.n) & ((1 << width) - 1);
        self.acc &= (1 << self.n) - 1;
        Some(v as u16)
    }
}

/// `Ok(true)`: reached EOD or a clean end of input. `Ok(false)`: invalid code.
pub(crate) fn decode(input: &[u8], early: bool, out: &mut Sink) -> Result<bool, LimitHit> {
    let mut table: Vec<Entry> = (0..=255u8)
        .map(|b| Entry {
            prefix: u16::MAX,
            last: b,
            first: b,
            len: 1,
        })
        .chain((0..2).map(|_| Entry {
            prefix: u16::MAX,
            last: 0,
            first: 0,
            len: 0,
        }))
        .collect();
    let mut bits = Bits {
        data: input,
        pos: 0,
        acc: 0,
        n: 0,
    };
    let mut scratch = Vec::with_capacity(MAX_CODES);
    let mut width = 9;
    let mut prev: Option<u16> = None;
    while let Some(code) = bits.read(width) {
        match code {
            CLEAR => {
                table.truncate(FIRST_FREE as usize);
                width = 9;
                prev = None;
                continue;
            }
            EOD => return Ok(true),
            _ => {}
        }
        let next = table.len() as u16;
        let first = match (prev, code) {
            (_, c) if c < next && c != CLEAR && c != EOD => {
                emit(&table, c, &mut scratch);
                out.write(&scratch)?;
                table[c as usize].first
            }
            // KwKwK: the code being defined right now.
            (Some(p), c) if c == next => {
                emit(&table, p, &mut scratch);
                let f = table[p as usize].first;
                scratch.push(f);
                out.write(&scratch)?;
                f
            }
            _ => return Ok(false),
        };
        if let Some(p) = prev {
            if table.len() < MAX_CODES {
                let pe = &table[p as usize];
                table.push(Entry {
                    prefix: p,
                    last: first,
                    first: pe.first,
                    len: pe.len.saturating_add(1),
                });
            }
        }
        prev = Some(code);
        let n = table.len() + usize::from(early);
        width = match n {
            ..512 => 9,
            512..1024 => 10,
            1024..2048 => 11,
            _ => 12,
        };
    }
    // Missing EOD: common, and the data decoded so far is all there is.
    Ok(true)
}

/// Writes the string for `code` into `scratch` (replacing its contents).
fn emit(table: &[Entry], code: u16, scratch: &mut Vec<u8>) {
    let len = table.get(code as usize).map_or(0, |e| e.len as usize);
    scratch.clear();
    scratch.resize(len, 0);
    let mut c = code;
    for slot in scratch.iter_mut().rev() {
        let Some(e) = table.get(c as usize) else {
            break;
        };
        *slot = e.last;
        c = e.prefix;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quelda_testkit::Filter;

    /// Reference encoder for both EarlyChange values (testkit only does 1).
    /// Code widths follow the decoder: a code is read with the width of the
    /// table size *before* the entry it implies is added.
    fn encode(data: &[u8], early: bool) -> Vec<u8> {
        struct W {
            out: Vec<u8>,
            acc: u32,
            n: u32,
            dec_len: u32,
            first: bool,
            early: u32,
        }
        impl W {
            fn put(&mut self, code: u32) {
                let width = match self.dec_len + self.early {
                    ..512 => 9,
                    512..1024 => 10,
                    1024..2048 => 11,
                    _ => 12,
                };
                self.acc = (self.acc << width) | code;
                self.n += width;
                while self.n >= 8 {
                    self.n -= 8;
                    self.out.push((self.acc >> self.n) as u8);
                    self.acc &= (1 << self.n) - 1;
                }
            }
            fn code(&mut self, code: u32) {
                self.put(code);
                if self.first {
                    self.first = false;
                } else {
                    self.dec_len = (self.dec_len + 1).min(4096);
                }
            }
            fn clear(&mut self) {
                self.put(256);
                self.dec_len = 258;
                self.first = true;
            }
        }
        let mut w = W {
            out: Vec::new(),
            acc: 0,
            n: 0,
            dec_len: 258,
            first: true,
            early: u32::from(early),
        };
        let mut dict: std::collections::HashMap<Vec<u8>, u32> = std::collections::HashMap::new();
        let mut next = 258u32;
        let code_of = |s: &[u8], dict: &std::collections::HashMap<Vec<u8>, u32>| {
            if s.len() == 1 {
                u32::from(s[0])
            } else {
                dict[s]
            }
        };
        w.clear();
        let mut cur: Vec<u8> = Vec::new();
        for &b in data {
            let mut wc = cur.clone();
            wc.push(b);
            if wc.len() == 1 || dict.contains_key(&wc) {
                cur = wc;
                continue;
            }
            w.code(code_of(&cur, &dict));
            dict.insert(wc, next);
            next += 1;
            if next == 4096 {
                w.clear();
                dict.clear();
                next = 258;
            }
            cur = vec![b];
        }
        if !cur.is_empty() {
            w.code(code_of(&cur, &dict));
        }
        w.put(257);
        if w.n > 0 {
            w.out.push((w.acc << (8 - w.n)) as u8);
        }
        w.out
    }

    fn lzw(input: &[u8], early: bool) -> (Vec<u8>, bool) {
        let mut s = Sink::unlimited();
        let ok = decode(input, early, &mut s).unwrap();
        (s.into_inner(), ok)
    }

    fn sample(len: usize) -> Vec<u8> {
        // Repetitive enough to fill the table (codes up to 12 bits).
        (0..len)
            .map(|i| ((i / 3) % 97) as u8 ^ (i % 5) as u8)
            .collect()
    }

    #[test]
    fn early_change_1_round_trip() {
        for len in [0, 1, 2, 3, 100, 5000, 60_000] {
            let data = sample(len);
            assert_eq!(
                lzw(&encode(&data, true), true),
                (data.clone(), true),
                "{len}"
            );
            // Also the testkit encoder (independent implementation).
            assert_eq!(lzw(&Filter::Lzw.encode(&data), true), (data, true), "{len}");
        }
    }

    #[test]
    fn early_change_0_round_trip() {
        for len in [0, 1, 100, 5000, 60_000] {
            let data = sample(len);
            assert_eq!(lzw(&encode(&data, false), false), (data, true), "{len}");
        }
    }

    #[test]
    fn wrong_early_change_does_not_round_trip() {
        let data = sample(5000);
        assert_ne!(lzw(&encode(&data, true), false).0, data);
    }

    #[test]
    fn spec_example() {
        // ISO 32000 §7.4.4.2 example: 45 45 45 45 45 65 45 45 45 66.
        let enc = [0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        assert_eq!(
            lzw(&enc, true),
            (vec![45, 45, 45, 45, 45, 65, 45, 45, 45, 66], true)
        );
    }

    #[test]
    fn invalid_code_is_partial() {
        // 9-bit code 300 with an empty table.
        let (out, ok) = lzw(&[0x96, 0x00], true);
        assert!(!ok);
        assert!(out.is_empty());
    }

    #[test]
    fn missing_eod_is_complete() {
        let data = b"hello hello hello".to_vec();
        let enc = encode(&data, true);
        let (out, ok) = lzw(&enc[..enc.len() - 2], true);
        assert!(ok);
        assert!(data.starts_with(&out));
    }

    #[test]
    fn early_change_parms() {
        let d = |v: PdfObject| Dict::new(vec![("EarlyChange".into(), v)]);
        assert!(early_change(None).unwrap());
        assert!(early_change(Some(&d(PdfObject::Int(1)))).unwrap());
        assert!(!early_change(Some(&d(PdfObject::Int(0)))).unwrap());
        assert!(early_change(Some(&d(PdfObject::Int(2)))).is_err());
        assert!(early_change(Some(&Dict::default())).unwrap());
    }

    #[test]
    fn respects_cap() {
        let enc = encode(&vec![7u8; 100_000], true);
        let mut s = Sink::new(crate::limits::Cap {
            bytes: 1000,
            code: crate::error::IssueCode::LimitStreamDecodedBytes,
        });
        assert!(decode(&enc, true, &mut s).is_err());
    }
}
