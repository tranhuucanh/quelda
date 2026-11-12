//! Rules added in 0.4.0: objects that cannot be parsed, chains that loop,
//! and the thread action that opens another file.

use super::{Doc, Fixture, LINK_TO_10, bad, good};
use crate::builder::PdfBuilder;

const BROKEN: &str = "STRUCT.BROKEN_OBJECT";
const CYCLE: &str = "STRUCT.REFERENCE_CYCLE";
const REMOTE: &str = "EXTERNAL.REMOTE_GOTO";
const EOF: &str = "STRUCT.MISSING_EOF";
const XREF: &str = "STRUCT.XREF_MISMATCH";

/// The base document plus `objects`.
fn with(catalog_extra: &str, objects: &[(u32, &str)]) -> Vec<u8> {
    builder(catalog_extra, objects).build()
}

fn builder(catalog_extra: &str, objects: &[(u32, &str)]) -> PdfBuilder {
    let mut d = Doc::new();
    d.catalog_extra = catalog_extra.to_string();
    let mut b = d.builder();
    for (n, body) in objects {
        b.object(*n, body);
    }
    b
}

/// The base document with `raw` written between its objects and the xref.
fn with_raw(raw: &[u8]) -> Vec<u8> {
    let mut b = Doc::new().builder();
    b.raw(raw);
    b.build()
}

/// A link annotation whose action is `action`.
fn link(action: &str) -> Vec<u8> {
    let mut d = Doc::new();
    d.annots.push(6);
    let mut b = d.builder();
    b.object(6, LINK_TO_10).object(10, action);
    b.build()
}

fn broken_object() -> Vec<Fixture> {
    // The file ends in the middle of a script: nothing after it (no xref).
    let truncated = {
        let mut v =
            b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R >>\nendobj\n\
            2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
                .to_vec();
        v.extend_from_slice(b"7 0 obj\n<< /S /JavaScript /JS (app.alert\\(1");
        v
    };
    let in_stream = {
        let mut d = Doc::new();
        d.content
            .extend_from_slice(b"% 9 0 obj << /S /JavaScript /JS >\n");
        d.build()
    };
    vec![
        bad(
            BROKEN,
            "key-without-value",
            with_raw(b"9 0 obj\n<< /S /JavaScript /JS >>\nendobj\n"),
            &[],
            "A dictionary key without a value",
        ),
        bad(
            BROKEN,
            "garbage-body",
            with_raw(b"9 0 obj\n]] >> what\nendobj\n"),
            &[],
            "The body is not an object",
        ),
        bad(
            BROKEN,
            "unbalanced-dict",
            with_raw(b"9 0 obj\n<< /S /Launch /F (calc.exe)\nendobj\n"),
            &[],
            "A dictionary that is never closed",
        ),
        bad(
            BROKEN,
            "truncated-file",
            truncated,
            &[EOF, XREF, "ACTIVE.OPEN_ACTION"],
            "The file is cut off inside an object",
        ),
        good(
            BROKEN,
            "valid",
            Doc::new().build(),
            &[],
            "Every object parses",
        ),
        good(
            BROKEN,
            "header-in-string",
            with("", &[(9, "<< /Note (was 30 0 obj << /Bad >) >>")]),
            &[],
            "`N G obj` is text inside a string",
        ),
        good(
            BROKEN,
            "header-in-object-comment",
            with("", &[(9, "<< /Note 1 % 30 0 obj << /Bad >\n>>")]),
            &[],
            "`N G obj` is in a comment inside an object",
        ),
        good(
            BROKEN,
            "header-in-comment-line",
            with_raw(b"% removed: 30 0 obj << /Bad >\n"),
            &[],
            "`N G obj` is on a comment line between objects",
        ),
        good(
            BROKEN,
            "header-in-stream-data",
            in_stream,
            &[],
            "`N G obj` is inside the data of a stream",
        ),
    ]
}

fn reference_cycle() -> Vec<Fixture> {
    const OUTLINES: &str = "/Outlines 7 0 R";
    let objstm = |a: &str, b: &str| {
        let mut d = Doc::new().builder();
        d.stream_raw(8, &format!("/Type /ObjStm /N 0 /First 0 {a}"), b"")
            .stream_raw(9, &format!("/Type /ObjStm /N 0 /First 0 {b}"), b"");
        d.build()
    };
    let across_revisions = {
        let mut b = builder(
            OUTLINES,
            &[
                (7, "<< /Type /Outlines /First 8 0 R /Last 9 0 R /Count 2 >>"),
                (8, "<< /Title (a) /Parent 7 0 R /Next 9 0 R >>"),
                (9, "<< /Title (b) /Parent 7 0 R /Prev 8 0 R >>"),
            ],
        );
        b.revision()
            .object(9, "<< /Title (b) /Parent 7 0 R /Prev 8 0 R /Next 8 0 R >>");
        b.build()
    };
    vec![
        bad(
            CYCLE,
            "outline-siblings",
            with(
                OUTLINES,
                &[
                    (7, "<< /Type /Outlines /First 8 0 R /Last 9 0 R /Count 2 >>"),
                    (8, "<< /Title (a) /Parent 7 0 R /Next 9 0 R >>"),
                    (9, "<< /Title (b) /Parent 7 0 R /Next 8 0 R >>"),
                ],
            ),
            &[],
            "Outline items whose /Next links form a loop",
        ),
        bad(
            CYCLE,
            "outline-self",
            with(
                OUTLINES,
                &[
                    (7, "<< /Type /Outlines /First 8 0 R /Last 8 0 R /Count 1 >>"),
                    (8, "<< /Title (a) /Parent 7 0 R /Next 8 0 R >>"),
                ],
            ),
            &[],
            "An outline item that is its own /Next",
        ),
        bad(
            CYCLE,
            "outline-child-to-parent",
            with(
                OUTLINES,
                &[
                    (7, "<< /Type /Outlines /First 8 0 R /Last 8 0 R /Count 1 >>"),
                    (8, "<< /Title (a) /Parent 7 0 R /First 9 0 R /Last 9 0 R >>"),
                    (9, "<< /Title (b) /Parent 8 0 R /Next 8 0 R >>"),
                ],
            ),
            &[],
            "A child item whose /Next is its parent",
        ),
        bad(
            CYCLE,
            "action-next",
            link("<< /S /GoTo /D [3 0 R /Fit] /Next 10 0 R >>"),
            &[],
            "An action that is its own /Next",
        ),
        bad(
            CYCLE,
            "action-next-array",
            {
                let mut d = Doc::new();
                d.annots.push(6);
                let mut b = d.builder();
                b.object(6, LINK_TO_10)
                    .object(10, "<< /S /GoTo /D [3 0 R /Fit] /Next [11 0 R] >>")
                    .object(
                        11,
                        "<< /S /GoTo /D [3 0 R /Fit] /Next << /S /GoTo /D [3 0 R /FitH 0] /Next 10 0 R >> >>",
                    );
                b.build()
            },
            &[],
            "Actions chained through an array and an inline dictionary",
        ),
        bad(
            CYCLE,
            "objstm-extends",
            objstm("/Extends 9 0 R", "/Extends 8 0 R"),
            &[],
            "Object streams that extend each other",
        ),
        bad(
            CYCLE,
            "arrays",
            with("", &[(8, "[1 9 0 R]"), (9, "[2 8 0 R]")]),
            &[],
            "Two arrays that contain each other",
        ),
        bad(
            CYCLE,
            "across-revisions",
            across_revisions,
            &["STRUCT.INCREMENTAL_UPDATE"],
            "The loop only exists with an older and a newer definition together",
        ),
        good(
            CYCLE,
            "page-tree",
            Doc::new().build(),
            &[],
            "/Parent and /Kids point at each other: ordinary",
        ),
        good(
            CYCLE,
            "outline",
            with(
                OUTLINES,
                &[
                    (7, "<< /Type /Outlines /First 8 0 R /Last 9 0 R /Count 2 >>"),
                    (
                        8,
                        "<< /Title (a) /Parent 7 0 R /Next 9 0 R /First 11 0 R /Last 11 0 R /Count 1 >>",
                    ),
                    (9, "<< /Title (b) /Parent 7 0 R /Prev 8 0 R >>"),
                    (11, "<< /Title (c) /Parent 8 0 R >>"),
                ],
            ),
            &[],
            "A well-formed outline (/Prev and /Parent point back)",
        ),
        good(
            CYCLE,
            "action-chain",
            {
                let mut d = Doc::new();
                d.annots.push(6);
                let mut b = d.builder();
                b.object(6, LINK_TO_10)
                    .object(10, "<< /S /GoTo /D [3 0 R /Fit] /Next [11 0 R 12 0 R] >>")
                    .object(11, "<< /S /GoTo /D [3 0 R /FitH 0] /Next 12 0 R >>")
                    .object(12, "<< /S /GoTo /D [3 0 R /FitB] >>");
                b.build()
            },
            &[],
            "Actions that share a successor, without a loop",
        ),
        good(
            CYCLE,
            "objstm-extends-chain",
            objstm("/Extends 9 0 R", ""),
            &[],
            "An object stream that extends another",
        ),
        good(
            CYCLE,
            "arrays",
            with("", &[(8, "[1 9 0 R 9 0 R]"), (9, "[2 3 0 R]")]),
            &[],
            "Arrays that share an item, without a loop",
        ),
    ]
}

fn thread_action() -> Vec<Fixture> {
    vec![
        bad(
            REMOTE,
            "thread-in-file",
            link("<< /S /Thread /F (other.pdf) /D 0 >>"),
            &[],
            "Thread action into another file",
        ),
        bad(
            REMOTE,
            "thread-in-filespec",
            link("<< /S /Thread /F << /Type /Filespec /F (other.pdf) >> /D 0 >>"),
            &[],
            "Thread action into another file (file specification)",
        ),
        good(
            REMOTE,
            "thread-local",
            link("<< /S /Thread /D 0 >>"),
            &[],
            "Thread action inside this document",
        ),
    ]
}

pub fn all() -> Vec<Fixture> {
    [broken_object(), reference_cycle(), thread_action()].concat()
}
