//! Files that are not (only) PDF but carry a `.pdf` name: the main way attackers
//! reach Ghostscript/ImageMagick. All scripts are inert (`showpage`, one red pixel…).

use super::{Doc, Fixture, Kind, group};

pub(crate) const NOT_PDF: &str = "FILETYPE.NOT_PDF_HEADER";
pub(crate) const PS_MAGIC: &str = "FILETYPE.POSTSCRIPT_MAGIC";
pub(crate) const FOREIGN: &str = "FILETYPE.FOREIGN_MAGIC";
pub(crate) const POLYGLOT: &str = "FILETYPE.POLYGLOT";

pub(crate) fn ps_adobe() -> Vec<u8> {
    b"%!PS-Adobe-3.0\n%%Title: quelda-test\n% quelda-test: inert PostScript\nshowpage\n%%EOF\n"
        .to_vec()
}

pub(crate) fn eps_ascii() -> Vec<u8> {
    b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 1 1\n% quelda-test\nshowpage\n%%EOF\n".to_vec()
}

/// DOS EPS binary: 30-byte header (`C5 D0 D3 C6`, PS offset/length, no WMF/TIFF) + PS section.
pub(crate) fn eps_binary() -> Vec<u8> {
    let ps = eps_ascii();
    let mut out = vec![0xC5, 0xD0, 0xD3, 0xC6];
    out.extend_from_slice(&30u32.to_le_bytes());
    out.extend_from_slice(&(ps.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&ps);
    out
}

pub(crate) fn svg() -> Vec<u8> {
    b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"><!-- quelda-test --><rect width=\"1\" height=\"1\"/></svg>\n".to_vec()
}

/// ImageMagick Vector Graphics: draws one point, reads nothing.
pub(crate) fn mvg() -> Vec<u8> {
    b"push graphic-context\nviewbox 0 0 1 1\n# quelda-test\nfill red\npoint 0,0\npop graphic-context\n".to_vec()
}

/// ImageMagick Scripting Language: creates a 1x1 image, reads no file.
pub(crate) fn msl() -> Vec<u8> {
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<image size=\"1x1\"><!-- quelda-test --></image>\n".to_vec()
}

pub(crate) fn html() -> Vec<u8> {
    b"<!DOCTYPE html>\n<html><body><script>/* quelda-test */</script></body></html>\n".to_vec()
}

/// Smallest valid (empty) ZIP: end-of-central-directory record only.
pub(crate) fn zip_eocd() -> Vec<u8> {
    let mut z = b"PK\x05\x06".to_vec();
    z.extend_from_slice(&[0; 18]);
    z
}

/// ZIP with one stored file `quelda-test.txt` (local header, central directory, EOCD).
pub(crate) fn zip_one_file() -> Vec<u8> {
    let name = b"quelda-test.txt";
    let data = b"quelda-test\n";
    let crc = crc32(data);
    let mut z = Vec::new();
    z.extend_from_slice(b"PK\x03\x04");
    z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&(name.len() as u16).to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z.extend_from_slice(name);
    z.extend_from_slice(data);
    let cd_offset = z.len() as u32;
    z.extend_from_slice(b"PK\x01\x02");
    z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&(name.len() as u16).to_le_bytes());
    z.extend_from_slice(&[0; 12]);
    z.extend_from_slice(&0u32.to_le_bytes());
    z.extend_from_slice(name);
    let cd_len = z.len() as u32 - cd_offset;
    z.extend_from_slice(b"PK\x05\x06");
    z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    z.extend_from_slice(&cd_len.to_le_bytes());
    z.extend_from_slice(&cd_offset.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub(crate) fn with_prefix(prefix: &[u8]) -> Vec<u8> {
    let mut b = Doc::new().builder();
    b.prefix_bytes(prefix);
    b.build()
}

pub(crate) fn pdf_then(tail: &[u8]) -> Vec<u8> {
    let mut b = Doc::new().builder();
    b.trailing_bytes(tail);
    b.build()
}

fn ft(name: &str, bytes: Vec<u8>, fires: &[&'static str], note: &str) -> Fixture {
    group(Kind::Filetype, name, bytes, fires, note)
}

pub(crate) fn all() -> Vec<Fixture> {
    vec![
        ft(
            "ps-renamed",
            ps_adobe(),
            &[NOT_PDF, PS_MAGIC],
            "PostScript saved as .pdf",
        )
        .at_least(),
        ft(
            "eps-ascii",
            eps_ascii(),
            &[NOT_PDF, PS_MAGIC],
            "EPS (text) saved as .pdf",
        )
        .at_least(),
        ft(
            "eps-binary",
            eps_binary(),
            &[NOT_PDF, PS_MAGIC],
            "DOS EPS binary header C5 D0 D3 C6",
        )
        .at_least(),
        ft("svg", svg(), &[NOT_PDF, FOREIGN], "SVG saved as .pdf").at_least(),
        ft(
            "mvg",
            mvg(),
            &[NOT_PDF, FOREIGN],
            "ImageMagick MVG saved as .pdf",
        )
        .at_least(),
        ft(
            "msl",
            msl(),
            &[NOT_PDF, FOREIGN],
            "ImageMagick MSL saved as .pdf",
        )
        .at_least(),
        ft("html", html(), &[NOT_PDF, FOREIGN], "HTML saved as .pdf").at_least(),
        ft(
            "zip",
            zip_one_file(),
            &[NOT_PDF, FOREIGN],
            "ZIP saved as .pdf",
        )
        .at_least(),
        ft(
            "junk-before-header",
            with_prefix(b"QUELDA-JUNK\n"),
            &[NOT_PDF],
            "Valid PDF preceded by junk bytes (readers tolerate, magic sniffers do not)",
        ),
        ft(
            "pdf-zip-polyglot",
            pdf_then(&zip_eocd()),
            &[POLYGLOT],
            "Valid PDF + empty ZIP appended after %%EOF (22 bytes, under max_trailing_bytes)",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn eps_binary_header_points_at_ps() {
        let e = eps_binary();
        assert_eq!(&e[..4], &[0xC5, 0xD0, 0xD3, 0xC6]);
        let off = u32::from_le_bytes(e[4..8].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(e[8..12].try_into().unwrap()) as usize;
        assert!(e[off..].starts_with(b"%!PS-Adobe-3.0 EPSF-3.0"));
        assert_eq!(off + len, e.len());
    }

    #[test]
    fn zip_records_are_consistent() {
        let z = zip_one_file();
        let eocd = z.len() - 22;
        assert_eq!(&z[eocd..eocd + 4], b"PK\x05\x06");
        let cd_off = u32::from_le_bytes(z[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        assert_eq!(&z[cd_off..cd_off + 4], b"PK\x01\x02");
    }
}
