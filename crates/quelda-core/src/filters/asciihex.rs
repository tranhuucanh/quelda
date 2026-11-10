//! ASCIIHexDecode (§7.4.2): hex digits, whitespace ignored, `>` ends the
//! data, an odd final digit is followed by an implied 0.

use super::{LimitHit, Sink};
use crate::parser::lexer::is_whitespace;

/// `Ok(false)` on a character that is neither hex digit nor whitespace.
/// A missing `>` is tolerated.
pub(crate) fn decode(input: &[u8], out: &mut Sink) -> Result<bool, LimitHit> {
    let mut high: Option<u8> = None;
    for &b in input {
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b'>' => break,
            _ if is_whitespace(b) => continue,
            // Invalid character: a pending half byte is not trustworthy.
            _ => return Ok(false),
        };
        match high.take() {
            Some(h) => out.push(h << 4 | v)?,
            None => high = Some(v),
        }
    }
    if let Some(h) = high {
        out.push(h << 4)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(input: &[u8]) -> (Vec<u8>, bool) {
        let mut s = Sink::unlimited();
        let ok = decode(input, &mut s).unwrap();
        (s.into_inner(), ok)
    }

    #[test]
    fn decodes() {
        assert_eq!(hex(b"4A53>"), (b"JS".to_vec(), true));
        assert_eq!(hex(b"4a 5\n3\r\t>"), (b"JS".to_vec(), true));
        assert_eq!(hex(b"901FA>"), (vec![0x90, 0x1F, 0xA0], true));
        assert_eq!(hex(b">"), (vec![], true));
        assert_eq!(hex(b""), (vec![], true));
    }

    #[test]
    fn missing_eod_tolerated_and_data_after_eod_ignored() {
        assert_eq!(hex(b"4A53"), (b"JS".to_vec(), true));
        assert_eq!(hex(b"4A>53"), (b"J".to_vec(), true));
    }

    #[test]
    fn invalid_char_is_partial() {
        assert_eq!(hex(b"4A5Z3>"), (vec![0x4A], false));
    }
}
