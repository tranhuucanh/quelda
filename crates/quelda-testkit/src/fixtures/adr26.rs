//! Fixtures of the Step 13 corpus fixes (ADR #26): truncated Flate, binary
//! streams that are never tokenized, stream roles through indirect arrays,
//! `ACTIVE.OPEN_ACTION` limited to real actions, unfiltered streams outside
//! the decode limits, and the `POSTSCRIPT.TYPE4_FUNCTION` allowlist.

use super::{BASE_CONTENT, Doc, Fixture, Kind, bad, good, group};
use crate::builder::PdfBuilder;
use crate::filters::Filter;

const TRUNC: &str = "STRUCT.TRUNCATED_STREAM";
const TYPE4: &str = "POSTSCRIPT.TYPE4_FUNCTION";
const OPEN: &str = "ACTIVE.OPEN_ACTION";
const PS_OP: &str = "POSTSCRIPT.CONTENT_OP";
const DOCTYPE: &str = "XML.DOCTYPE";
const CHAIN: &str = "STRUCT.FILTER_CHAIN";
const CHAIN3: [Filter; 3] = [Filter::Ascii85, Filter::AsciiHex, Filter::Flate];

/// Real Type 4 programs (Illustrator → ilovepdf colour conversion, and a
/// tint transform with `if` from a print file).
const TYPE4_ILLUSTRATOR: &[u8] = b"{2 index 1.000000 cvr exch sub 4 1 roll 1 index 1.000000 cvr exch sub \n4 1 roll 0 index 1.000000 cvr exch sub 4 1 roll 1.000000 4 1 \nroll 7 -1 roll 1.000000 cvr exch sub 7 1 roll 6 -1 roll 1.000000 \ncvr exch sub 6 1 roll 5 -1 roll 1.000000 cvr exch sub 5 1 \nroll 4 -1 roll 1.000000 cvr exch sub 4 1 roll pop pop pop }\n";
const TYPE4_WITH_IF: &[u8] = b"{  1.000000 exch dup 0.000000 gt { exch pop dup 0.000000 sub -1.000000 mul 1.000000 add exch } if dup 1.000000 gt { exch pop 0.000000 exch } if pop }\n";

/// Content that survives a cut of the last [`PAD_CUT`] encoded bytes: the
/// visible operators, then a comment long enough to absorb the cut.
fn padded(data: &[u8]) -> Vec<u8> {
    let pad: String = (0..40).map(|i| format!(" pad{i}")).collect();
    [data, b"\n%", pad.as_bytes(), b"\n"].concat()
}

/// Encoded bytes dropped from the end (Adler-32 + end of the final block).
const PAD_CUT: usize = 40;

/// `data` Flate-encoded, cut before the end of the final block.
fn truncated_flate(data: &[u8]) -> Vec<u8> {
    let z = Filter::Flate.encode(&padded(data));
    z[..z.len() - PAD_CUT].to_vec()
}

/// The base document whose page content (object 4) is written by `body`.
fn with_content(dict: &str, data: &[u8]) -> Vec<u8> {
    let d = Doc::new();
    let mut b = PdfBuilder::new(d.version);
    b.object(1, d.catalog_body())
        .object(2, d.pages_body())
        .object(3, d.page_body())
        .stream_raw(4, dict, data)
        .object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    b.build()
}

/// Base doc + extra objects.
fn doc_with(f: impl FnOnce(&mut PdfBuilder), d: Doc) -> Vec<u8> {
    let mut b = d.builder();
    f(&mut b);
    b.build()
}

fn function(data: &[u8], filters: &[Filter], dict: &str) -> Vec<u8> {
    doc_with(
        |b| {
            b.stream(
                10,
                &format!("/FunctionType 4 /Domain [0 1] /Range [0 1 0 1 0 1 0 1] {dict}"),
                data,
                filters,
            );
        },
        Doc::new(),
    )
}

fn truncated_rule() -> Vec<Fixture> {
    let xmp = b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?><x:xmpmeta xmlns:x='adobe:ns:meta/'/><?xpacket end='w'?>";
    // A hand-made object stream whose Flate data is cut after its member.
    let objstm = {
        let member = b"<< /QueldaTruncated (member of a truncated object stream) >>";
        let header = b"10 0 ";
        let data = [&header[..], member].concat();
        let z = truncated_flate(&data);
        let mut d = Doc::new();
        d.version = "1.5";
        doc_with(
            |b| {
                b.stream_raw(
                    9,
                    &format!(
                        "/Type /ObjStm /N 1 /First {} /Filter /FlateDecode",
                        header.len()
                    ),
                    &z,
                );
            },
            d,
        )
    };
    let no_adler = {
        let z = Filter::Flate.encode(BASE_CONTENT);
        with_content("/Filter /FlateDecode", &z[..z.len() - 4])
    };
    let hex_of_truncated: Vec<u8> = truncated_flate(BASE_CONTENT)
        .iter()
        .flat_map(|b| format!("{b:02X}").into_bytes())
        .chain(*b">")
        .collect();
    vec![
        bad(
            TRUNC,
            "plain",
            with_content("/Filter /FlateDecode", &truncated_flate(BASE_CONTENT)),
            &[],
            "Page content whose Flate data stops before the end of the final block (inspected as far as it decodes, no ERROR)",
        ),
        bad(
            TRUNC,
            "filter-chain",
            with_content("/Filter [/ASCIIHexDecode /FlateDecode]", &hex_of_truncated),
            &[],
            "Truncated Flate data inside an ASCIIHex layer",
        ),
        bad(
            TRUNC,
            "objstm",
            objstm,
            &["STRUCT.XREF_MISMATCH"],
            "Object stream whose Flate data is cut after its only member (member still parsed; not in the xref table)",
        ),
        bad(
            TRUNC,
            "xmp",
            doc_with(
                |b| {
                    b.stream_raw(
                        20,
                        "/Type /Metadata /Subtype /XML /Filter /FlateDecode",
                        &truncated_flate(xmp),
                    );
                },
                Doc {
                    catalog_extra: "/Metadata 20 0 R".to_string(),
                    ..Doc::new()
                },
            ),
            &[],
            "Truncated XMP metadata stream",
        ),
        bad(
            TRUNC,
            "unknown-role",
            doc_with(
                |b| {
                    b.stream_raw(20, "/Filter /FlateDecode", &truncated_flate(b"q Q"));
                },
                Doc::new(),
            ),
            &[],
            "Truncated stream of unknown role (decoded speculatively)",
        ),
        good(
            TRUNC,
            "complete",
            {
                let mut d = Doc::new();
                d.content_filters = vec![Filter::Flate];
                d.build()
            },
            &[],
            "Complete Flate content",
        ),
        good(
            TRUNC,
            "no-adler",
            no_adler,
            &[],
            "Final block complete, Adler-32 trailer missing (never checked)",
        ),
        good(
            TRUNC,
            "image",
            doc_with(
                |b| {
                    b.stream_raw(
                        10,
                        "/Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode",
                        &truncated_flate(&[0, 255, 255, 0]),
                    );
                },
                Doc {
                    xobjects: vec![("Im1", 10)],
                    ..Doc::new()
                },
            ),
            &[],
            "Truncated image data: images are never decoded",
        ),
    ]
}

fn binary_streams() -> Vec<Fixture> {
    // Bytes that tokenize as the `PS` operator (NUL is whitespace).
    let palette: Vec<u8> = [&[0x10u8, 0x20, 0x30, 0x00][..], b"\0\0PS\0\0", &[0x40; 6]].concat();
    let indexed = |cs: &str, extra: &str| {
        doc_with(
            |b| {
                b.stream(20, "", &palette, &[]);
                if !extra.is_empty() {
                    b.object(21, extra);
                }
                b.stream(
                    10,
                    &format!("/Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace {cs} /BitsPerComponent 8"),
                    &[0, 1, 2, 3],
                    &[],
                );
            },
            Doc {
                xobjects: vec![("Im1", 10)],
                ..Doc::new()
            },
        )
    };
    let indirect_contents = |data: &[u8], filters: &[Filter]| {
        doc_with(
            |b| {
                b.object(20, "[4 0 R 21 0 R]");
                b.stream(21, "", data, filters);
            },
            Doc {
                page_extra: "/Contents 20 0 R".to_string(),
                ..Doc::new()
            },
        )
    };
    vec![
        good(
            PS_OP,
            "indexed-palette",
            indexed("[/Indexed /DeviceCMYK 2 20 0 R]", ""),
            &[],
            "Indexed palette (binary) containing the bytes \\0\\0PS\\0\\0: never tokenized",
        ),
        good(
            PS_OP,
            "indexed-palette-indirect",
            indexed("21 0 R", "[/Indexed [/ICCBased 22 0 R] 2 20 0 R]"),
            &[],
            "Indexed colour space as its own object, palette with PS bytes",
        ),
        good(
            PS_OP,
            "cidtogidmap",
            doc_with(
                |b| {
                    b.stream(20, "", &palette, &[Filter::Flate]);
                    b.object(
                        10,
                        "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /QueldaTest /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /CIDToGIDMap 20 0 R >>",
                    );
                },
                Doc::new(),
            ),
            &[],
            "CIDToGIDMap (binary) containing PS bytes",
        ),
        good(
            PS_OP,
            "mesh-shading",
            doc_with(
                |b| {
                    b.stream(
                        10,
                        "/ShadingType 4 /ColorSpace /DeviceGray /BitsPerCoordinate 8 /BitsPerComponent 8 /BitsPerFlag 8 /Decode [0 1 0 1 0 1]",
                        &palette,
                        &[],
                    );
                },
                Doc::new(),
            ),
            &[],
            "Free-form mesh shading (binary vertex data) containing PS bytes",
        ),
        bad(
            PS_OP,
            "contents-indirect-array",
            indirect_contents(b"q (quelda-test) PS Q\n", &[Filter::Flate]),
            &[],
            "/Contents 20 0 R → [4 0 R 21 0 R]: the second stream is content (PS operator)",
        ),
        group(
            Kind::Malformed,
            "contents-indirect-array-corrupt",
            indirect_contents(b"\xff\xff quelda-test", &[Filter::Declared("FlateDecode")]),
            &[],
            "Content stream reached through an indirect /Contents array, Flate data corrupt: must be ERROR (fail-closed)",
        )
        .at_least()
        .error("ENGINE.UNDECODABLE"),
    ]
}

fn unfiltered_limit() -> Vec<Fixture> {
    // 4 KiB of unfiltered XMP padding, then a DOCTYPE at the very end.
    let xmp = [
        &b"<?xpacket begin=''?><x:xmpmeta xmlns:x='adobe:ns:meta/'>"[..],
        &b" ".repeat(4096),
        b"<!DOCTYPE x [<!ENTITY a 'quelda-test'>]></x:xmpmeta>",
    ]
    .concat();
    let with = |filters: &[Filter]| {
        doc_with(
            |b| {
                b.stream(20, "/Type /Metadata /Subtype /XML", &xmp, filters);
            },
            Doc {
                catalog_extra: "/Metadata 20 0 R".to_string(),
                ..Doc::new()
            },
        )
    };
    vec![
        bad(
            DOCTYPE,
            "unfiltered-large",
            with(&[]),
            &[],
            "4 KiB unfiltered XMP, DOCTYPE at the end (conformance: still found with a 1 KiB decode limit)",
        ),
        bad(
            DOCTYPE,
            "flate-large",
            with(&[Filter::Flate]),
            &[],
            "Same XMP, Flate-encoded (conformance: a 1 KiB decode limit is an ERROR)",
        ),
    ]
}

fn open_action_rule() -> Vec<Fixture> {
    let catalog = |entry: &str, extra: &[(u32, &str)]| {
        let extra: Vec<(u32, String)> = extra.iter().map(|(n, s)| (*n, s.to_string())).collect();
        doc_with(
            |b| {
                for (n, body) in &extra {
                    b.object(*n, body);
                }
            },
            Doc {
                catalog_extra: entry.to_string(),
                ..Doc::new()
            },
        )
    };
    vec![
        good(
            OPEN,
            "destination",
            catalog("/OpenAction [3 0 R /Fit]", &[]),
            &[],
            "Destination array: open at page 1",
        ),
        good(
            OPEN,
            "destination-fith",
            catalog("/OpenAction [3 0 R /FitH -32768]", &[]),
            &[],
            "Destination array as written by LaTeX/hyperref",
        ),
        good(
            OPEN,
            "goto",
            catalog("/OpenAction << /S /GoTo /D [3 0 R /FitH 0] >>", &[]),
            &[],
            "Plain GoTo action",
        ),
        good(
            OPEN,
            "goto-name-encoded",
            catalog("/Open#41ction << /#53 /G#6fTo /D [3 0 R /Fit] >>", &[]),
            &[],
            "GoTo action with #xx-encoded names",
        ),
        good(
            OPEN,
            "indirect-destination",
            catalog("/OpenAction 20 0 R", &[(20, "[3 0 R /XYZ 0 842 0]")]),
            &[],
            "Indirect destination array",
        ),
        good(
            OPEN,
            "indirect-goto",
            catalog(
                "/OpenAction 20 0 R",
                &[(20, "<< /S /GoTo /D [3 0 R /Fit] >>")],
            ),
            &[],
            "Indirect GoTo action",
        ),
        bad(
            OPEN,
            "next-javascript",
            catalog(
                "/OpenAction << /S /GoTo /D [3 0 R /Fit] /Next << /S /JavaScript /JS (app.alert('quelda-test')) >> >>",
                &[],
            ),
            &["ACTIVE.JAVASCRIPT"],
            "GoTo whose /Next chain runs JavaScript",
        ),
        bad(
            OPEN,
            "next-indirect",
            catalog(
                "/OpenAction << /S /GoTo /D [3 0 R /Fit] /Next 20 0 R >>",
                &[(20, "<< /S /Thread /D 0 >>")],
            ),
            &[],
            "GoTo with an indirect /Next",
        ),
        bad(
            OPEN,
            "indirect-subtype",
            catalog("/OpenAction << /S 20 0 R /D 0 >>", &[(20, "/Thread")]),
            &[],
            "Action whose /S is an indirect name",
        ),
        bad(
            OPEN,
            "unresolved",
            catalog("/OpenAction 99 0 R", &[]),
            &[],
            "/OpenAction pointing at a missing object",
        ),
        bad(
            OPEN,
            "string",
            catalog("/OpenAction (quelda-test)", &[]),
            &[],
            "/OpenAction is a string (named destination): not an array or action",
        ),
        bad(
            OPEN,
            "goto-and-other-definition",
            {
                let mut b = Doc {
                    catalog_extra: "/OpenAction 20 0 R".to_string(),
                    ..Doc::new()
                }
                .builder();
                b.object(20, "[3 0 R /Fit]");
                b.revision().object(20, "<< /S /Thread /D 0 >>");
                b.build()
            },
            &["STRUCT.INCREMENTAL_UPDATE"],
            "Indirect value redefined by an update: destination, then a Thread action (union)",
        ),
    ]
}

fn type4_rule() -> Vec<Fixture> {
    let deep = format!("{{ {}{}}}", "true { ".repeat(101), "} if ".repeat(101));
    let long = [b"{ ".as_slice(), &b"dup pop ".repeat(8200), b"}"].concat();
    let bad_programs: Vec<(&str, Vec<u8>, &str)> = vec![
        ("exec", b"{ 1 exec }".to_vec(), "`exec`"),
        (
            "file",
            b"{ (quelda-test) (r) file }".to_vec(),
            "`file` with strings",
        ),
        ("run", b"{ run }".to_vec(), "`run`"),
        (
            "currentfile",
            b"{ currentfile pop }".to_vec(),
            "`currentfile`",
        ),
        (
            "literal-name",
            b"{ /x 1 def }".to_vec(),
            "literal name and `def`",
        ),
        (
            "procedure-exec",
            b"{ { pop } exec }".to_vec(),
            "procedure executed with `exec`",
        ),
        (
            "stray-procedure",
            b"{ { pop } }".to_vec(),
            "procedure not used by if/ifelse",
        ),
        ("unbalanced", b"{ dup } } pop".to_vec(), "unbalanced braces"),
        (
            "unclosed",
            b"{ dup { pop } if".to_vec(),
            "unclosed procedure",
        ),
        (
            "two-procedures",
            b"{ } { }".to_vec(),
            "program is not one procedure",
        ),
        ("too-long", long, "program over 64 KiB"),
        ("too-deep", deep.into_bytes(), "procedures nested 102 deep"),
        (
            "huge-index",
            b"{ 100000 index }".to_vec(),
            "index with a literal count of 100000",
        ),
        (
            "negative-copy",
            b"{ -1 copy }".to_vec(),
            "copy with a negative count",
        ),
    ];
    let mut v: Vec<Fixture> = bad_programs
        .into_iter()
        .map(|(name, p, note)| {
            bad(
                TYPE4,
                name,
                function(&p, &[], ""),
                &[],
                &format!("Type 4 program outside the allowlist: {note}"),
            )
        })
        .collect();
    v.extend([
        bad(
            TYPE4,
            "flate",
            function(b"{ 1 exec }", &[Filter::Flate], ""),
            &[],
            "Flate-encoded program using `exec`",
        ),
        bad(
            TYPE4,
            "filter-chain",
            function(b"{ 1 exec }", &CHAIN3, ""),
            &[CHAIN],
            "Program using `exec` behind Flate → ASCIIHex → ASCII85",
        ),
        bad(
            TYPE4,
            "undecodable",
            function(b"{ dup }", &[Filter::Declared("QueldaUnknownDecode")], ""),
            &[],
            "Program behind an unknown filter: cannot be checked",
        ),
        bad(
            TYPE4,
            "in-shading",
            doc_with(
                |b| {
                    b.object(
                        11,
                        "<< /ShadingType 2 /ColorSpace /DeviceCMYK /Coords [0 0 1 0] /Function 10 0 R >>",
                    );
                    b.stream(10, "/FunctionType 4 /Domain [0 1] /Range [0 1 0 1 0 1 0 1]", b"{ 1 exec }", &[]);
                },
                Doc::new(),
            ),
            &[],
            "Program using `exec` in a function referenced by an axial shading",
        ),
        good(
            TYPE4,
            "illustrator",
            function(TYPE4_ILLUSTRATOR, &[], ""),
            &[],
            "Colour conversion program written by Illustrator/ilovepdf",
        ),
        good(
            TYPE4,
            "illustrator-flate",
            function(TYPE4_ILLUSTRATOR, &[Filter::Flate], ""),
            &[],
            "Same, Flate-encoded",
        ),
        good(
            TYPE4,
            "illustrator-filter-chain",
            function(TYPE4_ILLUSTRATOR, &CHAIN3, ""),
            &[CHAIN],
            "Same, behind three filters",
        ),
        good(
            TYPE4,
            "tint-with-if",
            function(TYPE4_WITH_IF, &[], ""),
            &[],
            "Tint transform with if procedures (print file)",
        ),
        good(
            TYPE4,
            "every-operator",
            function(
                b"{ abs add atan ceiling cos cvi cvr div exp floor idiv ln log mod mul neg round sin sqrt sub truncate and bitshift eq false ge gt le lt ne not or true xor copy dup exch index pop roll { } if { } { } ifelse }",
                &[],
                "",
            ),
            &[],
            "All 42 operators of the spec",
        ),
        good(
            TYPE4,
            "numbers-and-comments",
            function(
                b"% leading comment\r\n{ 1 -2 +3 .5 5. -0.0 1.0E-5 1e5 -.5e+3 16#FF 2#1010 % comment\n pop }\n% trailing comment",
                &[],
                "",
            ),
            &[],
            "Every number syntax, comments and odd whitespace",
        ),
        good(
            TYPE4,
            "nul-whitespace",
            function(b"\0{\0dup\x0Cpop\t}\0", &[], ""),
            &[],
            "NUL and form feed as whitespace",
        ),
        good(
            TYPE4,
            "indirect-function-type",
            doc_with(
                |b| {
                    b.object(30, "4");
                    b.stream(10, "/FunctionType 30 0 R /Domain [0 1] /Range [0 1]", b"{ dup mul }", &[]);
                },
                Doc::new(),
            ),
            &[],
            "Indirect /FunctionType, valid program",
        ),
    ]);
    v
}

pub(crate) fn all() -> Vec<Fixture> {
    let mut out = Vec::new();
    out.extend(truncated_rule());
    out.extend(binary_streams());
    out.extend(unfiltered_limit());
    out.extend(open_action_rule());
    out.extend(type4_rule());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::inflate::decompress_to_vec_zlib;

    #[test]
    fn truncated_flate_keeps_the_content() {
        let z = truncated_flate(BASE_CONTENT);
        // Not a complete zlib stream any more, but the content is all in
        // what decodes.
        let e = decompress_to_vec_zlib(&z).unwrap_err();
        assert!(e.output.starts_with(BASE_CONTENT));
    }
}
