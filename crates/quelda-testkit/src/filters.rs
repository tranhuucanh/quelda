//! Stream filter encoders. A filter list is given in *decode* order (the order
//! it appears in `/Filter`), so encoding applies it in reverse.

use std::collections::HashMap;

use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::deflate::core::{
    CompressionStrategy, CompressorOxide, TDEFLFlush, TDEFLStatus, compress,
    create_comp_flags_from_zip_params,
};

/// A PDF stream filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    Flate,
    AsciiHex,
    Ascii85,
    /// `LZWDecode` with the default `/EarlyChange 1`.
    Lzw,
    RunLength,
    /// Written into `/Filter` as-is; data is NOT encoded (JBIG2, JPX, unknown filters…).
    Declared(&'static str),
}

impl Filter {
    /// The filter's PDF name, without the leading `/`.
    pub fn name(self) -> &'static str {
        match self {
            Filter::Flate => "FlateDecode",
            Filter::AsciiHex => "ASCIIHexDecode",
            Filter::Ascii85 => "ASCII85Decode",
            Filter::Lzw => "LZWDecode",
            Filter::RunLength => "RunLengthDecode",
            Filter::Declared(name) => name,
        }
    }

    /// Encodes `data` so that this filter decodes it back.
    pub fn encode(self, data: &[u8]) -> Vec<u8> {
        match self {
            Filter::Flate => flate(data),
            Filter::AsciiHex => ascii_hex(data),
            Filter::Ascii85 => ascii85(data),
            Filter::Lzw => lzw(data),
            Filter::RunLength => run_length(data),
            Filter::Declared(_) => data.to_vec(),
        }
    }
}

/// Encodes `data` through a filter list given in decode order.
pub fn encode_chain(filters: &[Filter], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for f in filters.iter().rev() {
        out = f.encode(&out);
    }
    out
}

/// The `/Filter` dictionary entry for a filter list ("" when there is none).
pub fn filter_entry(filters: &[Filter]) -> String {
    match filters {
        [] => String::new(),
        [one] => format!("/Filter /{}", one.name()),
        many => {
            let names: Vec<String> = many.iter().map(|f| format!("/{}", f.name())).collect();
            format!("/Filter [{}]", names.join(" "))
        }
    }
}

/// Small inputs use fixed-Huffman literals: deflate would otherwise pick a
/// *stored* block for short text, leaving the payload readable as plain bytes
/// and defeating the point of a "hidden in a compressed stream" fixture.
fn flate(data: &[u8]) -> Vec<u8> {
    if data.len() <= 4096 {
        zlib_fixed_literals(data)
    } else {
        compress_to_vec_zlib(data, 9)
    }
}

fn zlib_fixed_literals(data: &[u8]) -> Vec<u8> {
    let mut w = LsbWriter::default();
    w.put(1, 1); // BFINAL
    w.put(1, 2); // BTYPE = 01, fixed Huffman
    for &b in data {
        let (code, len) = if b < 144 {
            (0x30 + u32::from(b), 8)
        } else {
            (0x190 + u32::from(b) - 144, 9)
        };
        w.put(reverse_bits(code, len), len);
    }
    w.put(0, 7); // end of block (symbol 256)
    let mut out = vec![0x78, 0x01];
    out.extend(w.finish());
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// Deflate packs bits LSB-first; Huffman codes are stored MSB-first.
fn reverse_bits(code: u32, len: u32) -> u32 {
    (0..len).fold(0, |acc, i| (acc << 1) | ((code >> i) & 1))
}

#[derive(Default)]
struct LsbWriter {
    out: Vec<u8>,
    acc: u64,
    bits: u32,
}

impl LsbWriter {
    fn put(&mut self, value: u32, len: u32) {
        self.acc |= u64::from(value) << self.bits;
        self.bits += len;
        while self.bits >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.bits -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn ascii_hex(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2 + 1);
    for (i, b) in data.iter().enumerate() {
        if i > 0 && i % 32 == 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(format!("{b:02X}").as_bytes());
    }
    out.push(b'>');
    out
}

fn ascii85(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 5 / 4 + 4);
    for chunk in data.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        let mut n = u32::from_be_bytes(word);
        if chunk.len() == 4 && n == 0 {
            out.push(b'z');
            continue;
        }
        let mut digits = [0u8; 5];
        for d in digits.iter_mut().rev() {
            *d = (n % 85) as u8 + b'!';
            n /= 85;
        }
        out.extend_from_slice(&digits[..chunk.len() + 1]);
    }
    out.extend_from_slice(b"~>");
    out
}

const LZW_CLEAR: u16 = 256;
const LZW_EOD: u16 = 257;

struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    bits: u32,
}

impl BitWriter {
    fn put(&mut self, code: u16, width: u32) {
        self.acc = (self.acc << width) | u32::from(code);
        self.bits += width;
        while self.bits >= 8 {
            self.bits -= 8;
            self.out.push((self.acc >> self.bits) as u8);
        }
        self.acc &= (1 << self.bits) - 1;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.out.push((self.acc << (8 - self.bits)) as u8);
        }
        self.out
    }
}

/// LZW with `EarlyChange 1`: the code width grows one code early.
fn lzw(data: &[u8]) -> Vec<u8> {
    let mut w = BitWriter {
        out: Vec::new(),
        acc: 0,
        bits: 0,
    };
    let mut dict: HashMap<(u16, u8), u16> = HashMap::new();
    let mut width = 9;
    let mut next: u16 = 258;
    w.put(LZW_CLEAR, width);
    let Some((&first, rest)) = data.split_first() else {
        w.put(LZW_EOD, width);
        return w.finish();
    };
    let mut cur = u16::from(first);
    for &c in rest {
        if let Some(&code) = dict.get(&(cur, c)) {
            cur = code;
            continue;
        }
        w.put(cur, width);
        if next == 4094 {
            w.put(LZW_CLEAR, width);
            dict.clear();
            width = 9;
            next = 258;
        } else {
            dict.insert((cur, c), next);
            next += 1;
            if next == (1 << width) && width < 12 {
                width += 1;
            }
        }
        cur = u16::from(c);
    }
    w.put(cur, width);
    w.put(LZW_EOD, width);
    w.finish()
}

fn run_length(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut run = 1;
        while i + run < data.len() && data[i + run] == data[i] && run < 128 {
            run += 1;
        }
        if run >= 2 {
            out.push((257 - run) as u8);
            out.push(data[i]);
            i += run;
            continue;
        }
        let start = i;
        while i < data.len() && i - start < 128 {
            if i + 1 < data.len() && data[i + 1] == data[i] {
                break;
            }
            i += 1;
        }
        if i == start {
            i += 1;
        }
        out.push((i - start - 1) as u8);
        out.extend_from_slice(&data[start..i]);
    }
    out.push(128);
    out
}

/// zlib stream of `total` zero bytes, produced with fixed 64 KiB buffers so a
/// multi-GB bomb never sits in memory. Deflate tops out near 1032:1.
pub fn flate_zeros(total: u64) -> Vec<u8> {
    const CHUNK: usize = 64 * 1024;
    let flags = create_comp_flags_from_zip_params(9, 15, CompressionStrategy::RLE as i32);
    let mut comp = CompressorOxide::new(flags);
    let zeros = vec![0u8; CHUNK];
    let mut buf = vec![0u8; CHUNK];
    let mut out = Vec::new();
    let mut remaining = total;
    loop {
        let take = remaining.min(CHUNK as u64) as usize;
        let flush = if remaining <= CHUNK as u64 {
            TDEFLFlush::Finish
        } else {
            TDEFLFlush::None
        };
        let mut input = &zeros[..take];
        loop {
            let (status, used, written) = compress(&mut comp, input, &mut buf, flush);
            out.extend_from_slice(&buf[..written]);
            input = &input[used..];
            match status {
                TDEFLStatus::Done => return out,
                TDEFLStatus::Okay if input.is_empty() && written < buf.len() => break,
                TDEFLStatus::Okay => {}
                other => panic!("deflate failed: {other:?}"),
            }
        }
        remaining -= take as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::inflate::decompress_to_vec_zlib;

    fn sample(len: usize) -> Vec<u8> {
        // Deterministic LCG, mixed with runs so every encoder path is hit.
        let mut x: u32 = 12345;
        (0..len)
            .map(|i| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                if (i / 300) % 3 == 0 {
                    b'A'
                } else {
                    (x >> 16) as u8
                }
            })
            .collect()
    }

    fn un_hex(data: &[u8]) -> Vec<u8> {
        let digits: Vec<u8> = data
            .iter()
            .copied()
            .take_while(|&b| b != b'>')
            .filter(u8::is_ascii_hexdigit)
            .collect();
        digits
            .chunks(2)
            .map(|p| {
                let s = std::str::from_utf8(p).unwrap();
                u8::from_str_radix(&format!("{s:0<2}"), 16).unwrap()
            })
            .collect()
    }

    fn un_85(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut group = Vec::new();
        for &b in data {
            match b {
                b'~' => break,
                b'z' => out.extend_from_slice(&[0; 4]),
                b'!'..=b'u' => {
                    group.push(b - b'!');
                    if group.len() == 5 {
                        let n = group.iter().fold(0u32, |n, &d| n * 85 + u32::from(d));
                        out.extend_from_slice(&n.to_be_bytes());
                        group.clear();
                    }
                }
                _ => {}
            }
        }
        if !group.is_empty() {
            let keep = group.len() - 1;
            group.resize(5, 84);
            let n = group.iter().fold(0u32, |n, &d| n * 85 + u32::from(d));
            out.extend_from_slice(&n.to_be_bytes()[..keep]);
        }
        out
    }

    // Mirrors the pdf.js LZW decoder (EarlyChange 1).
    fn un_lzw(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut table: Vec<Vec<u8>> = Vec::new();
        let reset = |t: &mut Vec<Vec<u8>>| {
            t.clear();
            t.extend((0..=255u8).map(|b| vec![b]));
            t.push(Vec::new());
            t.push(Vec::new());
        };
        reset(&mut table);
        let (mut width, mut acc, mut bits, mut pos) = (9u32, 0u32, 0u32, 0usize);
        let mut prev: Option<Vec<u8>> = None;
        loop {
            while bits < width {
                let Some(&b) = data.get(pos) else { return out };
                acc = (acc << 8) | u32::from(b);
                bits += 8;
                pos += 1;
            }
            bits -= width;
            let code = ((acc >> bits) & ((1 << width) - 1)) as usize;
            acc &= (1 << bits) - 1;
            match code {
                256 => {
                    reset(&mut table);
                    width = 9;
                    prev = None;
                    continue;
                }
                257 => return out,
                _ => {}
            }
            let entry = match (&prev, table.get(code)) {
                (_, Some(e)) if code < table.len() => e.clone(),
                (Some(p), _) => {
                    let mut e = p.clone();
                    e.push(p[0]);
                    e
                }
                (None, _) => panic!("bad first code"),
            };
            if let Some(p) = prev.take() {
                let mut e = p;
                e.push(entry[0]);
                table.push(e);
                if table.len() + 1 >= (1 << width) && width < 12 {
                    width += 1;
                }
            }
            out.extend_from_slice(&entry);
            prev = Some(entry);
        }
    }

    fn un_rl(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let len = data[i] as usize;
            i += 1;
            match len {
                128 => break,
                0..=127 => {
                    out.extend_from_slice(&data[i..i + len + 1]);
                    i += len + 1;
                }
                _ => {
                    out.extend(std::iter::repeat_n(data[i], 257 - len));
                    i += 1;
                }
            }
        }
        out
    }

    #[test]
    fn roundtrip_each_filter() {
        for len in [0, 1, 3, 4, 5, 1000, 70_000] {
            let data = sample(len);
            assert_eq!(
                decompress_to_vec_zlib(&Filter::Flate.encode(&data)).unwrap(),
                data
            );
            assert_eq!(un_hex(&Filter::AsciiHex.encode(&data)), data, "hex {len}");
            assert_eq!(un_85(&Filter::Ascii85.encode(&data)), data, "a85 {len}");
            assert_eq!(un_lzw(&Filter::Lzw.encode(&data)), data, "lzw {len}");
            assert_eq!(un_rl(&Filter::RunLength.encode(&data)), data, "rl {len}");
        }
    }

    #[test]
    fn small_flate_never_leaks_plaintext() {
        for payload in [
            &b"<< /S /Launch /F (quelda-test.txt) >>"[..],
            b"q (% quelda-test) PS Q\n",
        ] {
            let enc = Filter::Flate.encode(payload);
            assert!(
                !enc.windows(6).any(|w| payload.windows(6).any(|p| p == w)),
                "plaintext leaked"
            );
            assert_eq!(decompress_to_vec_zlib(&enc).unwrap(), payload);
        }
    }

    #[test]
    fn adler32_known_value() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn ascii85_zero_group_uses_z() {
        assert_eq!(Filter::Ascii85.encode(&[0, 0, 0, 0]), b"z~>");
    }

    #[test]
    fn chain_encodes_in_reverse_decode_order() {
        let data = b"BT (quelda) Tj ET".to_vec();
        let chain = [Filter::Ascii85, Filter::AsciiHex, Filter::Flate];
        let enc = encode_chain(&chain, &data);
        let dec = decompress_to_vec_zlib(&un_hex(&un_85(&enc))).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn declared_filter_is_not_encoded() {
        assert_eq!(Filter::Declared("JBIG2Decode").encode(b"xyz"), b"xyz");
    }

    #[test]
    fn filter_entry_forms() {
        assert_eq!(filter_entry(&[]), "");
        assert_eq!(filter_entry(&[Filter::Flate]), "/Filter /FlateDecode");
        assert_eq!(
            filter_entry(&[Filter::Ascii85, Filter::Flate]),
            "/Filter [/ASCII85Decode /FlateDecode]"
        );
    }

    #[test]
    fn flate_zeros_is_valid_and_small() {
        let total = 10 * 1024 * 1024;
        let z = flate_zeros(total);
        assert!(z.len() < 20_000, "{} bytes", z.len());
        let back = decompress_to_vec_zlib(&z).unwrap();
        assert_eq!(back.len() as u64, total);
        assert!(back.iter().all(|&b| b == 0));
    }
}
