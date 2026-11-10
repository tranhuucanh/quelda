//! ASCII85Decode (§7.4.3): groups of 5 chars `!`..`u` → 4 bytes, `z` = 4
//! zero bytes, whitespace ignored, `~>` ends the data, a final group of
//! 2–4 chars yields 1–3 bytes.

use super::{LimitHit, Sink};
use crate::parser::lexer::is_whitespace;

/// `Ok(false)` on invalid input (bad char, misplaced `z`, overflowing group,
/// lone final char). A missing `~>` is tolerated.
pub(crate) fn decode(input: &[u8], out: &mut Sink) -> Result<bool, LimitHit> {
    let mut group = [0u8; 5];
    let mut n = 0usize;
    for &b in input {
        match b {
            b'~' => break,
            b'z' if n == 0 => out.write(&[0; 4])?,
            b'!'..=b'u' => {
                group[n] = b - b'!';
                n += 1;
                if n == 5 {
                    let Some(v) = value(&group) else {
                        return Ok(false);
                    };
                    out.write(&v.to_be_bytes())?;
                    n = 0;
                }
            }
            _ if is_whitespace(b) => {}
            // Invalid character: the pending group is not trustworthy.
            _ => return Ok(false),
        }
    }
    let mut complete = true;
    match n {
        0 => {}
        1 => complete = false,
        _ => {
            // Pad with `u` (84), keep n - 1 bytes.
            group[n..].fill(84);
            let Some(v) = value(&group) else {
                return Ok(false);
            };
            out.write(&v.to_be_bytes()[..n - 1])?;
        }
    }
    Ok(complete)
}

fn value(group: &[u8; 5]) -> Option<u32> {
    let v = group.iter().fold(0u64, |acc, &d| acc * 85 + u64::from(d));
    u32::try_from(v).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quelda_testkit::Filter;

    fn a85(input: &[u8]) -> (Vec<u8>, bool) {
        let mut s = Sink::unlimited();
        let ok = decode(input, &mut s).unwrap();
        (s.into_inner(), ok)
    }

    #[test]
    fn known_vectors() {
        assert_eq!(a85(b"87cURD]i,\"Ebo80~>"), (b"Hello World!".to_vec(), true));
        assert_eq!(a85(b"z~>"), (vec![0; 4], true));
        assert_eq!(a85(b"zz~>"), (vec![0; 8], true));
        assert_eq!(a85(b"s8W-!~>"), (vec![0xFF; 4], true));
        assert_eq!(a85(b"~>"), (vec![], true));
    }

    #[test]
    fn final_partial_groups() {
        for len in 0..=9 {
            let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(a85(&Filter::Ascii85.encode(&data)), (data, true), "{len}");
        }
    }

    #[test]
    fn whitespace_anywhere() {
        assert_eq!(
            a85(b" 87cU\nRD]i ,\"Eb\r\to80 ~>"),
            (b"Hello World!".to_vec(), true)
        );
    }

    #[test]
    fn missing_eod_tolerated() {
        assert_eq!(a85(b"87cURD]i,\"Ebo80"), (b"Hello World!".to_vec(), true));
    }

    #[test]
    fn invalid_input_is_partial() {
        // `z` inside a group: the pending group is dropped.
        assert_eq!(a85(b"87czURD~>"), (vec![], false));
        assert_eq!(a85(b"87cURD]z"), (b"Hell".to_vec(), false));
        // Character outside the alphabet.
        assert_eq!(a85(b"87cUR{D]i~>"), (b"Hell".to_vec(), false));
        // Group value > 2^32 - 1.
        assert_eq!(a85(b"uuuuu~>"), (vec![], false));
        // A lone final char cannot encode a byte.
        assert_eq!(a85(b"87cURD~>"), (b"Hell".to_vec(), false));
    }
}
