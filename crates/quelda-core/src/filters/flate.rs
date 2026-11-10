//! FlateDecode via `miniz_oxide`, streamed through a 32 KiB window so the
//! output budget is checked every chunk (a bomb never materializes).
//! Tolerant like common readers: Adler-32 is not verified, and data without
//! a valid zlib header is inflated as raw deflate.

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::{
    TINFL_FLAG_IGNORE_ADLER32, TINFL_FLAG_PARSE_ZLIB_HEADER,
};
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

use super::{LimitHit, Sink};

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

/// Returns `Ok(true)` if the deflate stream ended properly, `Ok(false)` if it
/// is corrupt or truncated (output so far is kept).
pub(crate) fn decode(input: &[u8], out: &mut Sink) -> Result<bool, LimitHit> {
    if input.is_empty() {
        return Ok(true);
    }
    let mut flags = TINFL_FLAG_IGNORE_ADLER32;
    if has_zlib_header(input) {
        flags |= TINFL_FLAG_PARSE_ZLIB_HEADER;
    }
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
            TINFLStatus::Done => return Ok(true),
            TINFLStatus::HasMoreOutput if consumed > 0 || written > 0 => {}
            // Truncated input, corrupt data, or no progress.
            _ => return Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IssueCode;
    use crate::limits::Cap;
    use miniz_oxide::deflate::{compress_to_vec, compress_to_vec_zlib};

    fn inflate(input: &[u8]) -> (Vec<u8>, bool) {
        let mut s = Sink::unlimited();
        let ok = decode(input, &mut s).unwrap();
        (s.into_inner(), ok)
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn zlib_round_trip_many_sizes() {
        for len in [0, 1, 100, WINDOW - 1, WINDOW, WINDOW + 1, 5 * WINDOW + 17] {
            let data = sample(len);
            assert_eq!(
                inflate(&compress_to_vec_zlib(&data, 6)),
                (data, true),
                "{len}"
            );
        }
    }

    #[test]
    fn raw_deflate_without_header() {
        let data = sample(1000);
        assert_eq!(inflate(&compress_to_vec(&data, 6)), (data, true));
    }

    #[test]
    fn bad_adler_is_ignored() {
        let data = sample(500);
        let mut z = compress_to_vec_zlib(&data, 6);
        let n = z.len();
        z[n - 1] ^= 0xFF;
        assert_eq!(inflate(&z), (data, true));
    }

    #[test]
    fn truncated_keeps_prefix() {
        let data = sample(20 * WINDOW);
        let z = compress_to_vec_zlib(&data, 1);
        let (out, ok) = inflate(&z[..z.len() / 2]);
        assert!(!ok);
        assert!(!out.is_empty());
        assert!(data.starts_with(&out));
    }

    #[test]
    fn garbage_is_partial() {
        let (out, ok) = inflate(b"\x78\x9c\xff\xff\xff\xff garbage");
        assert!(!ok);
        assert!(out.len() < 100);
        assert_eq!(inflate(b"x"), (vec![], false));
    }

    #[test]
    fn trailing_bytes_after_end_ignored() {
        let data = sample(300);
        let mut z = compress_to_vec_zlib(&data, 6);
        z.extend_from_slice(b"\r\njunk");
        assert_eq!(inflate(&z), (data, true));
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
