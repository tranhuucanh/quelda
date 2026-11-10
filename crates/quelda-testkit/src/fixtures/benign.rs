//! Clean documents. They must not trip any rule except the ones listed
//! (a link `/URI`, an AcroForm and an incremental update are benign but are cases of rules).

use super::{Doc, Fixture, Kind, group};
use crate::builder::Xref;
use crate::filters::{Filter, flate_zeros};

fn benign(name: &str, bytes: Vec<u8>, fires: &[&'static str], note: &str) -> Fixture {
    group(Kind::Benign, name, bytes, fires, note)
}

pub(crate) fn rgb_image(w: u32, h: u32) -> Vec<u8> {
    (0..w * h)
        .flat_map(|i| {
            [
                (i * 7 % 256) as u8,
                (i * 13 % 256) as u8,
                (i * 29 % 256) as u8,
            ]
        })
        .collect()
}

pub(crate) fn all() -> Vec<Fixture> {
    let mut out = Vec::new();

    out.push(benign(
        "minimal",
        Doc::new().build(),
        &[],
        "One page, base-14 font, classic xref",
    ));

    let mut d = Doc::new();
    d.version = "2.0";
    out.push(benign("pdf-2.0", d.build(), &[], "PDF 2.0 header"));

    let mut d = Doc::new();
    d.kids = "3 0 R 6 0 R 7 0 R".into();
    d.count = 3;
    let mut b = d.builder();
    for (n, c) in [(6, 8), (7, 9)] {
        b.object(
            n,
            format!("<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents {c} 0 R >>"),
        );
        b.stream(
            c,
            "",
            format!("BT /F1 18 Tf 72 720 Td (quelda page {n}) Tj ET\n").as_bytes(),
            &[],
        );
    }
    out.push(benign(
        "multipage-text",
        b.build(),
        &[],
        "Three pages of text",
    ));

    let mut d = Doc::new();
    d.content_filters = vec![Filter::Flate];
    out.push(benign(
        "content-flate",
        d.build(),
        &[],
        "Flate-compressed content stream",
    ));

    let mut d = Doc::new();
    d.content_filters = vec![Filter::Ascii85, Filter::Flate];
    out.push(benign(
        "content-two-filters",
        d.build(),
        &[],
        "Common two-filter chain [/ASCII85Decode /FlateDecode]: below max_filter_chain",
    ));

    let mut d = Doc::new();
    d.xobjects.push(("Im1", 10));
    d.content = b"q 200 0 0 200 72 400 cm /Im1 Do Q\n".to_vec();
    let mut b = d.builder();
    b.stream(
        10,
        "/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceRGB /BitsPerComponent 8",
        &rgb_image(16, 16),
        &[Filter::Flate],
    );
    out.push(benign(
        "image-rgb-flate",
        b.build(),
        &[],
        "16x16 RGB image, Flate",
    ));

    let mut d = Doc::new();
    d.version = "1.5";
    let mut b = d.builder();
    b.object(10, "<< /Title (quelda benign) >>")
        .objstm(9, &[1, 2, 3, 5, 10], &[Filter::Flate])
        .xref(Xref::Stream)
        .trailer("/Info 10 0 R");
    out.push(benign(
        "xref-stream-objstm",
        b.build(),
        &[],
        "PDF 1.5 style: catalog, pages, page, font and Info inside a Flate ObjStm; xref stream",
    ));

    let mut b = Doc::new().builder();
    b.revision().stream(
        4,
        "",
        b"BT /F1 24 Tf 72 720 Td (quelda test, edited) Tj ET\n",
        &[],
    );
    out.push(benign(
        "incremental-update",
        b.build(),
        &["STRUCT.INCREMENTAL_UPDATE"],
        "Harmless incremental update replacing the content stream",
    ));

    let mut d = Doc::new();
    d.annots.push(6);
    let mut b = d.builder();
    b.object(6, super::LINK_TO_10)
        .object(10, "<< /S /URI /URI (https://example.invalid/quelda) >>");
    out.push(benign(
        "link-uri",
        b.build(),
        &["EXTERNAL.URI"],
        "Ordinary hyperlink: warn in balanced, block in strict",
    ));

    let mut d = Doc::new();
    d.catalog_extra = "/AcroForm << /Fields [10 0 R] /DA (/Helv 0 Tf 0 g) >>".into();
    d.annots.push(10);
    let mut b = d.builder();
    b.object(
        10,
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (name) /V (quelda) /Rect [72 600 300 620] /P 3 0 R >>",
    );
    out.push(benign(
        "acroform-text-field",
        b.build(),
        &["FORMS.ACROFORM"],
        "AcroForm with one text field",
    ));

    let mut d = Doc::new();
    d.pages_extra = "/MediaBox [0 0 2384 3370]".into();
    d.xobjects.push(("Im1", 10));
    d.content = b"q 2384 0 0 3370 0 0 cm /Im1 Do Q\n".to_vec();
    let mut b = d.builder();
    b.stream_raw(
        10,
        "/Type /XObject /Subtype /Image /Width 14043 /Height 9933 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode",
        &flate_zeros(14043 * 9933),
    );
    out.push(benign(
        "a0-large-image",
        b.build(),
        &[],
        "A0 page with a full 14043x9933 (~1.4e8 px, A0 @300dpi) grayscale image: under every threshold",
    ));

    out
}
