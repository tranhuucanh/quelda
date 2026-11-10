//! FlateDecode via `miniz_oxide`, streamed through a 32 KiB window so the
//! output budget is checked every chunk (a bomb never materializes).
//! Tolerant like common readers: Adler-32 is not verified, data without a
//! valid zlib header is inflated as raw deflate, and data that ends before
//! the final block (truncated) yields everything decoded up to its end — the
//! same bytes zlib produces, which is what renderers use.

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

use super::{End, LimitHit, Sink};

/// Deflate window; the wrapping output buffer must be this size (power of two).
const WINDOW: usize = 32 * 1024;

/// zlib header: CM = 8 (deflate), CINFO ≤ 7, FCHECK makes it a multiple of 31.
fn has_zlib_header(data: &[u8]) -> bool {
    match data {
        [cmf, flg, ..] => {
            cmf & 0x0F == 8 && cmf >> 4 <= 7 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0
        }
        _ => false,
    }
}

/// How the deflate stream ended; on `Truncated` and `Corrupt` the output so
/// far is kept.
pub(crate) fn decode(input: &[u8], out: &mut Sink) -> Result<End, LimitHit> {
    if input.is_empty() {
        return Ok(End::Complete);
    }
    // The zlib header is skipped and the rest inflated as raw deflate: the
    // data is complete once the final block ends, with or without the
    // Adler-32 trailer (never checked). A preset dictionary (FDICT) cannot
    // be honoured, as by readers.
    let input = match input {
        [_, flg, rest @ ..] if has_zlib_header(input) => {
            if flg & 0x20 != 0 {
                return Ok(End::Corrupt);
            }
            rest
        }
        _ => input,
    };
    let flags = 0;
    let mut state = Box::<DecompressorOxide>::default();
    let mut window = vec![0u8; WINDOW];
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;
    loop {
        let rest = input.get(in_pos..).unwrap_or_default();
        let (status, consumed, written) = decompress(&mut state, rest, &mut window, out_pos, flags);
        in_pos += consumed;
        if let Some(chunk) = window.get(out_pos..out_pos + written) {
            out.write(chunk)?;
        }
        out_pos = (out_pos + written) & (WINDOW - 1);
        match status {
            TINFLStatus::Done => return Ok(End::Complete),
            TINFLStatus::HasMoreOutput if consumed > 0 || written > 0 => {}
            // Every input byte was used and the decoder wants more: the data
            // was cut short, not malformed.
            TINFLStatus::FailedCannotMakeProgress | TINFLStatus::NeedsMoreInput
                if in_pos == input.len() =>
            {
                return Ok(End::Truncated);
            }
            // Corrupt data, or no progress.
            _ => return Ok(End::Corrupt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IssueCode;
    use crate::limits::Cap;
    use miniz_oxide::deflate::{compress_to_vec, compress_to_vec_zlib};

    fn inflate(input: &[u8]) -> (Vec<u8>, End) {
        let mut s = Sink::unlimited();
        let end = decode(input, &mut s).unwrap();
        (s.into_inner(), end)
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// Text-like data: compresses with matches and dynamic Huffman blocks.
    fn text(len: usize) -> Vec<u8> {
        let words = [
            &b"q 1 0 0 1 "[..],
            b"72 720 cm ",
            b"BT /F1 12 Tf ",
            b"(quelda) Tj ",
            b"ET Q\n",
        ];
        let mut v = Vec::new();
        let mut i = 0usize;
        while v.len() < len {
            v.extend_from_slice(words[i * 7 % words.len()]);
            v.extend(format!("{} ", i % 97).bytes());
            i += 1;
        }
        v.truncate(len);
        v
    }

    /// What zlib (zlib-rs, a port of zlib 1.3) inflates from `input` before
    /// it runs out: `None` if zlib reports an error.
    fn zlib_output(input: &[u8], zlib_header: bool) -> Option<Vec<u8>> {
        use flate2::{Decompress, FlushDecompress, Status};
        let mut d = Decompress::new(zlib_header);
        let mut out = Vec::with_capacity(input.len() * 8 + 64);
        loop {
            let before = (d.total_in(), d.total_out());
            let rest = &input[usize::try_from(d.total_in()).ok()?..];
            if out.capacity() == out.len() {
                out.reserve(64 * 1024);
            }
            match d.decompress_vec(rest, &mut out, FlushDecompress::None) {
                Ok(Status::StreamEnd) => return Some(out),
                Ok(_) if (d.total_in(), d.total_out()) == before => return Some(out),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
    }

    #[test]
    fn zlib_round_trip_many_sizes() {
        for len in [0, 1, 100, WINDOW - 1, WINDOW, WINDOW + 1, 5 * WINDOW + 17] {
            let data = sample(len);
            assert_eq!(
                inflate(&compress_to_vec_zlib(&data, 6)),
                (data, End::Complete),
                "{len}"
            );
        }
    }

    #[test]
    fn raw_deflate_without_header() {
        let data = sample(1000);
        assert_eq!(inflate(&compress_to_vec(&data, 6)), (data, End::Complete));
    }

    #[test]
    fn bad_adler_is_ignored() {
        let data = sample(500);
        let mut z = compress_to_vec_zlib(&data, 6);
        let n = z.len();
        z[n - 1] ^= 0xFF;
        assert_eq!(inflate(&z), (data, End::Complete));
    }

    #[test]
    fn truncated_keeps_prefix() {
        let data = sample(20 * WINDOW);
        let z = compress_to_vec_zlib(&data, 1);
        let (out, end) = inflate(&z[..z.len() / 2]);
        assert_eq!(end, End::Truncated);
        assert!(!out.is_empty());
        assert!(data.starts_with(&out));
        // Missing (part of) the Adler-32 trailer: all the data is there.
        for cut in 1..=4 {
            assert_eq!(inflate(&z[..z.len() - cut]), (data.clone(), End::Complete));
        }
    }

    /// ADR #26: a truncated stream is scanned as far as it decodes, so the
    /// decoder must yield every byte zlib (what renderers use) yields — a
    /// shorter output would hide the tail from the rules. Checked at every
    /// cut point, for stored, fixed and dynamic Huffman blocks, with and
    /// without the zlib header.
    #[test]
    fn truncated_output_equals_zlib_at_every_cut() {
        let inputs: Vec<(&str, Vec<u8>, bool)> = vec![
            ("text level 6", compress_to_vec_zlib(&text(6000), 6), true),
            ("text level 1", compress_to_vec_zlib(&text(3000), 1), true),
            ("stored", compress_to_vec_zlib(&sample(2000), 0), true),
            (
                "fixed huffman",
                compress_to_vec_zlib(b"BT (quelda) Tj ET", 6),
                true,
            ),
            ("raw deflate", compress_to_vec(&text(3000), 9), false),
            ("binary", compress_to_vec_zlib(&sample(3 * WINDOW), 9), true),
            (
                "long matches",
                compress_to_vec_zlib(&[&vec![b'a'; 3 * WINDOW][..], &text(500)].concat(), 9),
                true,
            ),
        ];
        for (what, z, header) in inputs {
            for cut in 0..=z.len() {
                let input = &z[..cut];
                let (out, end) = inflate(input);
                let reference = zlib_output(input, header)
                    .unwrap_or_else(|| panic!("{what}: zlib error at cut {cut}"));
                assert_eq!(out.len(), reference.len(), "{what}: cut {cut}");
                assert_eq!(out, reference, "{what}: cut {cut}");
                // Empty input is empty data; the Adler-32 is not needed.
                let complete = cut == 0 || cut == z.len() || header && cut + 4 >= z.len();
                let expected = if complete {
                    End::Complete
                } else {
                    End::Truncated
                };
                assert_eq!(end, expected, "{what}: cut {cut}");
            }
        }
    }

    #[test]
    fn garbage_is_corrupt() {
        let (out, end) = inflate(b"\x78\x9c\xff\xff\xff\xff garbage");
        assert_eq!(end, End::Corrupt);
        assert!(out.len() < 100);
        // A stored block whose length check fails.
        assert_eq!(inflate(b"\x01\x05\x00\x00\x00abcde").1, End::Corrupt);
        // An invalid block type.
        assert_eq!(inflate(b"\x07\x00").1, End::Corrupt);
    }

    #[test]
    fn one_byte_is_truncated() {
        assert_eq!(inflate(b"x"), (vec![], End::Truncated));
        assert_eq!(inflate(b"\x78\x9c"), (vec![], End::Truncated));
    }

    #[test]
    fn preset_dictionary_is_corrupt() {
        // FLG with FDICT set (and FCHECK making the header valid).
        assert!(has_zlib_header(&[0x78, 0xBB]));
        assert_eq!(inflate(b"\x78\xbb\x00\x00\x00\x01\x03\x00").1, End::Corrupt);
    }

    #[test]
    fn trailing_bytes_after_end_ignored() {
        let data = sample(300);
        let mut z = compress_to_vec_zlib(&data, 6);
        z.extend_from_slice(b"\r\njunk");
        assert_eq!(inflate(&z), (data, End::Complete));
    }

    #[test]
    fn header_detection() {
        assert!(has_zlib_header(&[0x78, 0x9C]));
        assert!(has_zlib_header(&[0x78, 0x01]));
        assert!(has_zlib_header(&[0x78, 0xDA]));
        assert!(!has_zlib_header(&[0x78, 0x9D]));
        assert!(!has_zlib_header(&[0x79, 0x9C]));
        assert!(!has_zlib_header(&[0x78]));
    }

    #[test]
    fn stops_at_cap_without_decoding_everything() {
        let z = compress_to_vec_zlib(&vec![0u8; 10 * WINDOW], 9);
        let mut s = Sink::new(Cap {
            bytes: 2 * WINDOW as u64,
            code: IssueCode::LimitStreamDecodedBytes,
        });
        assert_eq!(
            decode(&z, &mut s),
            Err(LimitHit(IssueCode::LimitStreamDecodedBytes))
        );
        assert!(s.into_inner().len() <= 2 * WINDOW);
    }
}
