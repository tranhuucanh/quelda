//! Predictors for Flate/LZW (§7.4.4.4): TIFF Predictor 2 and PNG
//! predictors 10–15 (per-row tag: None, Sub, Up, Average, Paeth).
//! Output is never larger than the input, so no budget check is needed here.

use crate::parser::{Dict, PdfObject};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// 2 (TIFF) or 10–15 (PNG; the tag in each row decides).
    pub predictor: u8,
    pub colors: usize,
    pub bits_per_component: usize,
    pub columns: usize,
}

fn int_param(d: &Dict, key: &str, default: i64) -> Result<i64, &'static str> {
    match d.get(key) {
        None | Some(PdfObject::Null) => Ok(default),
        Some(PdfObject::Int(v)) => Ok(*v),
        Some(_) => Err("predictor parameter is not an integer"),
    }
}

impl Params {
    /// `Ok(None)` when no predictor applies (missing or `/Predictor 1`).
    pub fn from_dict(parms: Option<&Dict>) -> Result<Option<Params>, &'static str> {
        let Some(d) = parms else {
            return Ok(None);
        };
        let predictor = match int_param(d, "Predictor", 1)? {
            1 => return Ok(None),
            p @ (2 | 10..=15) => p as u8,
            _ => return Err("unsupported /Predictor"),
        };
        let colors = int_param(d, "Colors", 1)?;
        let bpc = int_param(d, "BitsPerComponent", 8)?;
        let columns = int_param(d, "Columns", 1)?;
        if !(1..=32).contains(&colors) {
            return Err("/Colors out of range");
        }
        if ![1, 2, 4, 8, 16].contains(&bpc) {
            return Err("/BitsPerComponent out of range");
        }
        if !(1..=1 << 24).contains(&columns) {
            return Err("/Columns out of range");
        }
        Ok(Some(Params {
            predictor,
            colors: colors as usize,
            bits_per_component: bpc as usize,
            columns: columns as usize,
        }))
    }

    /// Bytes per row of decoded data (without the PNG tag byte).
    pub fn row_bytes(&self) -> usize {
        (self.colors * self.bits_per_component * self.columns).div_ceil(8)
    }

    /// Bytes per complete pixel, at least 1 (PNG "bpp").
    fn pixel_bytes(&self) -> usize {
        (self.colors * self.bits_per_component).div_ceil(8)
    }

    /// Undoes the predictor. The flag is `false` if a row tag is invalid or
    /// the last row is incomplete (decoded as far as possible).
    pub fn apply(&self, data: &[u8]) -> (Vec<u8>, bool) {
        if self.predictor == 2 {
            self.tiff(data)
        } else {
            self.png(data)
        }
    }

    fn png(&self, data: &[u8]) -> (Vec<u8>, bool) {
        let rb = self.row_bytes();
        let bpp = self.pixel_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(data.len());
        for chunk in data.chunks(rb + 1) {
            let Some((&tag, row)) = chunk.split_first() else {
                break;
            };
            if tag > 4 {
                return (out, false);
            }
            let start = out.len();
            let has_up = start >= rb;
            for (i, &x) in row.iter().enumerate() {
                let left = if i >= bpp { out[start + i - bpp] } else { 0 };
                let up = if has_up { out[start - rb + i] } else { 0 };
                let up_left = if has_up && i >= bpp {
                    out[start - rb + i - bpp]
                } else {
                    0
                };
                let pred = match tag {
                    0 => 0,
                    1 => left,
                    2 => up,
                    3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                    _ => paeth(left, up, up_left),
                };
                out.push(x.wrapping_add(pred));
            }
            if row.len() < rb {
                return (out, false);
            }
        }
        (out, true)
    }

    fn tiff(&self, data: &[u8]) -> (Vec<u8>, bool) {
        let rb = self.row_bytes();
        let bpc = self.bits_per_component;
        let samples = self.colors * self.columns;
        let mut out = data.to_vec();
        let mut complete = true;
        for row in out.chunks_mut(rb) {
            // Samples that fit entirely in this (possibly short) row.
            let fit = (row.len() * 8 / bpc).min(samples);
            if fit < samples {
                complete = false;
            }
            for s in self.colors..fit {
                let v = sample(row, s, bpc).wrapping_add(sample(row, s - self.colors, bpc));
                set_sample(row, s, bpc, v);
            }
        }
        (out, complete)
    }
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let (pa, pb, pc) = (
        (p - i16::from(a)).abs(),
        (p - i16::from(b)).abs(),
        (p - i16::from(c)).abs(),
    );
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Sample `s` of width `bpc` (1, 2, 4, 8 or 16 bits; never straddles bytes
/// unaligned). Callers keep `s` within the row.
fn sample(row: &[u8], s: usize, bpc: usize) -> u32 {
    if bpc == 16 {
        return u32::from(row[2 * s]) << 8 | u32::from(row[2 * s + 1]);
    }
    let bit = s * bpc;
    let shift = 8 - bpc - bit % 8;
    u32::from(row[bit / 8] >> shift) & ((1 << bpc) - 1)
}

fn set_sample(row: &mut [u8], s: usize, bpc: usize, v: u32) {
    if bpc == 16 {
        row[2 * s] = (v >> 8) as u8;
        row[2 * s + 1] = v as u8;
        return;
    }
    let bit = s * bpc;
    let shift = 8 - bpc - bit % 8;
    let mask = (((1u32 << bpc) - 1) << shift) as u8;
    row[bit / 8] = (row[bit / 8] & !mask) | (((v << shift) as u8) & mask);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Name;

    fn params(predictor: u8, colors: usize, bpc: usize, columns: usize) -> Params {
        Params {
            predictor,
            colors,
            bits_per_component: bpc,
            columns,
        }
    }

    fn dict(entries: &[(&str, PdfObject)]) -> Dict {
        Dict::new(
            entries
                .iter()
                .map(|(k, v)| (Name::from(*k), v.clone()))
                .collect(),
        )
    }

    /// Reference PNG encoder: every row with the given tag.
    fn png_encode(p: &Params, data: &[u8], tag: u8) -> Vec<u8> {
        let rb = p.row_bytes();
        let bpp = p.pixel_bytes();
        let mut out = Vec::new();
        for (r, row) in data.chunks(rb).enumerate() {
            out.push(tag);
            for i in 0..row.len() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                let up = if r > 0 { data[(r - 1) * rb + i] } else { 0 };
                let ul = if r > 0 && i >= bpp {
                    data[(r - 1) * rb + i - bpp]
                } else {
                    0
                };
                let pred = match tag {
                    0 => 0,
                    1 => left,
                    2 => up,
                    3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                    _ => paeth(left, up, ul),
                };
                out.push(row[i].wrapping_sub(pred));
            }
        }
        out
    }

    /// Reference TIFF encoder (right to left so earlier samples stay raw).
    fn tiff_encode(p: &Params, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        let samples = p.colors * p.columns;
        for row in out.chunks_mut(p.row_bytes()) {
            for s in (p.colors..samples).rev() {
                let v = sample(row, s, p.bits_per_component).wrapping_sub(sample(
                    row,
                    s - p.colors,
                    p.bits_per_component,
                ));
                set_sample(row, s, p.bits_per_component, v);
            }
        }
        out
    }

    fn image(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i * 31 % 256) as u8 ^ (i / 7) as u8)
            .collect()
    }

    #[test]
    fn png_each_tag_round_trips() {
        for (colors, bpc) in [(1, 8), (3, 8), (4, 8), (1, 1), (3, 16)] {
            let p = params(15, colors, bpc, 13);
            let data = image(p.row_bytes() * 5);
            for tag in 0..=4 {
                let enc = png_encode(&p, &data, tag);
                assert_eq!(
                    p.apply(&enc),
                    (data.clone(), true),
                    "tag {tag} colors {colors} bpc {bpc}"
                );
            }
        }
    }

    #[test]
    fn png_bad_tag_and_short_row() {
        let p = params(12, 1, 8, 3);
        assert_eq!(p.apply(&[0, 1, 2, 3, 9, 1, 1, 1]), (vec![1, 2, 3], false));
        assert_eq!(p.apply(&[0, 1, 2, 3, 2, 1]), (vec![1, 2, 3, 2], false));
        assert_eq!(p.apply(&[]), (vec![], true));
    }

    #[test]
    fn tiff_round_trips_all_bit_depths() {
        for (colors, bpc) in [(1, 1), (1, 2), (3, 4), (1, 8), (3, 8), (2, 16)] {
            let p = params(2, colors, bpc, 9);
            let data = image(p.row_bytes() * 4);
            let enc = tiff_encode(&p, &data);
            assert_ne!(enc, data, "colors {colors} bpc {bpc}");
            assert_eq!(p.apply(&enc), (data, true), "colors {colors} bpc {bpc}");
        }
    }

    #[test]
    fn tiff_known_vector() {
        // 8-bit gray: deltas 10, +1, +1, +1 → 10 11 12 13.
        let p = params(2, 1, 8, 4);
        assert_eq!(p.apply(&[10, 1, 1, 1]), (vec![10, 11, 12, 13], true));
        // Short last row is decoded as far as possible.
        assert_eq!(
            p.apply(&[10, 1, 1, 1, 5, 1]),
            (vec![10, 11, 12, 13, 5, 6], false)
        );
    }

    #[test]
    fn params_from_dict() {
        assert_eq!(Params::from_dict(None), Ok(None));
        assert_eq!(Params::from_dict(Some(&Dict::default())), Ok(None));
        let d = dict(&[("Predictor", PdfObject::Int(1))]);
        assert_eq!(Params::from_dict(Some(&d)), Ok(None));
        let d = dict(&[
            ("Predictor", PdfObject::Int(12)),
            ("Columns", PdfObject::Int(5)),
        ]);
        assert_eq!(Params::from_dict(Some(&d)), Ok(Some(params(12, 1, 8, 5))));
        for bad in [
            dict(&[("Predictor", PdfObject::Int(3))]),
            dict(&[("Predictor", PdfObject::Real(2.0))]),
            dict(&[
                ("Predictor", PdfObject::Int(2)),
                ("Colors", PdfObject::Int(0)),
            ]),
            dict(&[
                ("Predictor", PdfObject::Int(2)),
                ("BitsPerComponent", PdfObject::Int(3)),
            ]),
            dict(&[
                ("Predictor", PdfObject::Int(10)),
                ("Columns", PdfObject::Int(1 << 30)),
            ]),
        ] {
            assert!(Params::from_dict(Some(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn huge_columns_with_tiny_data_does_not_allocate_rows() {
        let p = params(12, 32, 16, 1 << 24);
        assert_eq!(p.row_bytes(), 1 << 30);
        assert_eq!(p.apply(&[0, 1, 2]), (vec![1, 2], false));
        let p = params(2, 32, 16, 1 << 24);
        assert!(!p.apply(&[0, 1, 2]).1);
    }

    #[test]
    fn paeth_matches_spec() {
        assert_eq!(paeth(10, 20, 10), 20);
        assert_eq!(paeth(20, 10, 10), 20);
        assert_eq!(paeth(10, 10, 20), 10);
        assert_eq!(paeth(0, 0, 0), 0);
    }
}
