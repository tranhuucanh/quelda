//! RunLengthDecode (§7.4.5): length byte 0–127 → copy the next n+1 bytes;
//! 129–255 → repeat the next byte 257−n times; 128 → end of data.

use super::{LimitHit, Sink};

/// `Ok(false)` if a run is cut off by the end of input. A missing EOD
/// marker is tolerated.
pub(crate) fn decode(input: &[u8], out: &mut Sink) -> Result<bool, LimitHit> {
    let mut i = 0usize;
    while let Some(&len) = input.get(i) {
        i += 1;
        match len {
            128 => return Ok(true),
            0..=127 => {
                let n = usize::from(len) + 1;
                let Some(lit) = input.get(i..i + n) else {
                    out.write(input.get(i..).unwrap_or_default())?;
                    return Ok(false);
                };
                out.write(lit)?;
                i += n;
            }
            _ => {
                let Some(&b) = input.get(i) else {
                    return Ok(false);
                };
                out.write(&[b; 128][..257 - usize::from(len)])?;
                i += 1;
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl(input: &[u8]) -> (Vec<u8>, bool) {
        let mut s = Sink::unlimited();
        let ok = decode(input, &mut s).unwrap();
        (s.into_inner(), ok)
    }

    #[test]
    fn literal_and_repeat_runs() {
        assert_eq!(rl(b"\x02abc\x80"), (b"abc".to_vec(), true));
        assert_eq!(rl(b"\xFEx\x80"), (b"xxx".to_vec(), true));
        assert_eq!(rl(b"\x81z\x80"), (vec![b'z'; 128], true));
        assert_eq!(rl(b"\x00a\xFFb\x80"), (b"abb".to_vec(), true));
        assert_eq!(rl(b"\x80ignored"), (vec![], true));
        assert_eq!(rl(b""), (vec![], true));
    }

    #[test]
    fn missing_eod_tolerated() {
        assert_eq!(rl(b"\x01ab"), (b"ab".to_vec(), true));
    }

    #[test]
    fn truncated_runs_are_partial() {
        assert_eq!(rl(b"\x05abc"), (b"abc".to_vec(), false));
        assert_eq!(rl(b"\x00a\xFE"), (b"a".to_vec(), false));
    }

    #[test]
    fn round_trip_testkit() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i / 10) as u8).collect();
        let enc = quelda_testkit::Filter::RunLength.encode(&data);
        assert_eq!(rl(&enc), (data, true));
    }
}
