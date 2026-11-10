//! Facts layer on the testkit fixtures (Step 6).

mod common;

use common::{fixture, fixtures};
use quelda_core::facts::{ContentOp, Ctx, Location, OpLocation, PageBox, PathSeg, Visitor};
use quelda_core::limits::{Limits, Thresholds};
use quelda_core::parser::document::Location as Source;
use quelda_core::parser::{Dict, Name, ObjRef};

fn ctx(bytes: &[u8]) -> Ctx<'_> {
    Ctx::new(bytes, Limits::default(), Thresholds::default())
}

#[derive(Default)]
struct Collect {
    dicts: Vec<(Location, Dict)>,
    ops: Vec<(Vec<u8>, OpLocation)>,
}

impl Visitor for Collect {
    fn dict(&mut self, dict: &Dict, loc: &Location) {
        self.dicts.push((loc.clone(), dict.clone()));
    }
    fn content_op(&mut self, op: &ContentOp<'_>, loc: &OpLocation) {
        self.ops.push((op.operator.to_vec(), loc.clone()));
    }
}

fn walk(c: &Ctx<'_>) -> Collect {
    let mut v = Collect::default();
    c.walk(&mut v);
    v
}

fn ps_ops(c: &Ctx<'_>) -> Vec<OpLocation> {
    walk(c)
        .ops
        .into_iter()
        .filter(|(o, _)| o == b"PS")
        .map(|(_, l)| l)
        .collect()
}

fn launch_dicts(v: &Collect) -> Vec<&Location> {
    v.dicts
        .iter()
        .filter(|(_, d)| d.get_all("S").any(|s| s.is_name("Launch")))
        .map(|(l, _)| l)
        .collect()
}

#[test]
fn issues_match_manifest_for_every_fixture() {
    for f in fixtures() {
        let c = ctx(&f.bytes);
        walk(&c);
        let issues = c.issues();
        match f.engine_error {
            None => assert!(issues.is_empty(), "{}: {issues:?}", f.path),
            Some(prefix) => assert!(
                issues.iter().any(|i| i.code.as_str().starts_with(prefix)),
                "{}: want {prefix}, got {issues:?}",
                f.path
            ),
        }
    }
}

#[test]
fn visitor_sees_nested_dict() {
    let c = ctx(&fixture("rules/ACTIVE.LAUNCH/bad/nested-dict.pdf").bytes);
    let v = walk(&c);
    let found = launch_dicts(&v);
    assert_eq!(found.len(), 1);
    let path: Vec<PathSeg> = ["QueldaNest", "L2", "L3"]
        .iter()
        .map(|k| PathSeg::Key(Name::from(*k)))
        .collect();
    assert_eq!(found[0].path, path);
    assert_eq!(found[0].id, ObjRef::new(3, 0));
}

#[test]
fn visitor_sees_dict_in_object_stream() {
    let c = ctx(&fixture("rules/ACTIVE.LAUNCH/bad/in-objstm.pdf").bytes);
    let v = walk(&c);
    let found = launch_dicts(&v);
    assert_eq!(found.len(), 1);
    assert!(matches!(found[0].source, Source::ObjStm { .. }));
    assert!(found[0].is_object());
}

#[test]
fn visitor_sees_dict_in_old_revision_once() {
    let c = ctx(&fixture("rules/ACTIVE.LAUNCH/bad/old-revision.pdf").bytes);
    let v = walk(&c);
    let found = launch_dicts(&v);
    assert_eq!(found.len(), 1);
    assert_eq!(c.objects()[found[0].object].revision, Some(0));
    assert_eq!(c.revisions().len(), 2);
    // Every definition is visited exactly once.
    let roots = v.dicts.iter().filter(|(l, _)| l.is_object()).count();
    let dict_objects = c
        .objects()
        .iter()
        .filter(|e| e.object.as_dict().is_some())
        .count();
    assert_eq!(roots, dict_objects);
}

#[test]
fn page_tree_cycles_and_repeats() {
    for (name, cycle, repeated) in [
        ("kids-self", true, false),
        ("mutual", true, false),
        ("kids-duplicate", false, true),
    ] {
        let f = fixture(&format!("rules/STRUCT.PAGE_TREE_CYCLE/bad/{name}.pdf"));
        let t = ctx(&f.bytes).page_tree().clone();
        assert_eq!(!t.cycle_nodes.is_empty(), cycle, "{name}: {t:?}");
        assert_eq!(!t.repeated_nodes.is_empty(), repeated, "{name}: {t:?}");
        assert_eq!(t.page_count, 1, "{name}");
    }
    let t = ctx(&fixture("rules/STRUCT.PAGE_TREE_CYCLE/good/two-level.pdf").bytes)
        .page_tree()
        .clone();
    assert!(t.cycle_nodes.is_empty() && t.repeated_nodes.is_empty());
    assert_eq!(t.page_count, 1);
}

#[test]
fn page_tree_has_no_problem_in_benign_files() {
    for f in fixtures().iter().filter(|f| f.path.starts_with("benign/")) {
        let c = ctx(&f.bytes);
        let t = c.page_tree();
        assert!(t.page_count >= 1, "{}", f.path);
        assert!(
            t.cycle_nodes.is_empty() && t.repeated_nodes.is_empty(),
            "{}",
            f.path
        );
        for p in &t.pages {
            assert!(
                matches!(p.media_box, Some(PageBox::Rect(_))),
                "{}: {p:?}",
                f.path
            );
        }
    }
    assert_eq!(
        ctx(&fixture("benign/multipage-text.pdf").bytes)
            .page_tree()
            .page_count,
        ctx(&fixture("benign/multipage-text.pdf").bytes)
            .page_tree()
            .pages
            .len()
    );
}

#[test]
fn media_box_inherited_from_pages() {
    let c = ctx(&fixture("rules/RESOURCE.PAGE_SIZE/bad/inherited.pdf").bytes);
    let pages = &c.page_tree().pages;
    assert_eq!(pages.len(), 1);
    // The page dict has no /MediaBox: the /Pages node's applies.
    let own = c.objects()[pages[0].object]
        .object
        .as_dict()
        .unwrap()
        .contains_key("MediaBox");
    assert!(!own);
    assert_eq!(
        pages[0].media_box.and_then(|b| b.size()),
        Some((100000.0, 100000.0))
    );
}

#[test]
fn page_counts() {
    let t = |p: &str| ctx(&fixture(p).bytes).page_tree().clone();
    assert_eq!(
        t("rules/RESOURCE.PAGE_COUNT/bad/many-pages.pdf").page_count,
        10_001
    );
    assert_eq!(
        t("rules/RESOURCE.PAGE_COUNT/good/hundred-pages.pdf").page_count,
        100
    );
    for name in ["declared-count", "name-encoded"] {
        let tree = t(&format!("rules/RESOURCE.PAGE_COUNT/bad/{name}.pdf"));
        assert_eq!(tree.page_count, 1);
        assert!(
            tree.declared_counts.iter().any(|&(_, n)| n == 1_000_000),
            "{name}"
        );
    }
}

#[test]
fn ps_operator_found_in_every_bad_content_fixture() {
    for f in fixtures()
        .iter()
        .filter(|f| f.path.starts_with("rules/POSTSCRIPT.CONTENT_OP/bad/"))
    {
        let found = ps_ops(&ctx(&f.bytes));
        assert!(!found.is_empty(), "{}", f.path);
        // Each variant puts `PS` in a stream with a known content role.
        assert!(found.iter().any(|l| !l.speculative), "{}", f.path);
    }
}

#[test]
fn ps_in_flate_form_xobject() {
    let c = ctx(&fixture("rules/POSTSCRIPT.CONTENT_OP/bad/form-xobject.pdf").bytes);
    let found = ps_ops(&c);
    assert_eq!(found.len(), 1);
    let s = &c.objects()[found[0].stream.object];
    assert_eq!(s.id, ObjRef::new(10, 0));
    assert!(c.stream_roles(found[0].stream.object).content);
    assert_eq!(
        c.filter_chain(found[0].stream.object),
        vec![Name::from("FlateDecode")]
    );
}

#[test]
fn no_ps_operator_in_near_misses_or_benign_files() {
    for f in fixtures().iter().filter(|f| {
        f.path.starts_with("benign/") || f.path.starts_with("rules/POSTSCRIPT.CONTENT_OP/good/")
    }) {
        assert!(ps_ops(&ctx(&f.bytes)).is_empty(), "{}", f.path);
    }
}

#[test]
fn inline_image_with_ps_bytes() {
    let f = fixture("rules/POSTSCRIPT.CONTENT_OP/good/inline-image-ps-bytes.pdf");
    let c = ctx(&f.bytes);
    let mut v = Collect::default();
    c.walk(&mut v);
    let ops: Vec<&[u8]> = v.ops.iter().map(|(o, _)| o.as_slice()).collect();
    assert!(ops.contains(&b"BI".as_slice()));
    assert!(!ops.contains(&b"PS".as_slice()));
}

#[test]
fn image_dimensions() {
    let dims = |p: &str| {
        ctx(&fixture(p).bytes)
            .images()
            .iter()
            .map(|i| (i.width, i.height))
            .collect::<Vec<_>>()
    };
    for v in [
        "plain",
        "name-encoded",
        "in-objstm",
        "nested-dict",
        "old-revision",
    ] {
        let d = dims(&format!("rules/RESOURCE.IMAGE_DIMENSIONS/bad/{v}.pdf"));
        assert!(d.contains(&(Some(100000.0), Some(100000.0))), "{v}: {d:?}");
    }
    assert_eq!(
        dims("rules/RESOURCE.IMAGE_DIMENSIONS/bad/non-numeric.pdf"),
        vec![(None, Some(8.0))]
    );
    assert_eq!(
        dims("rules/RESOURCE.IMAGE_DIMENSIONS/good/below-threshold.pdf"),
        vec![(Some(30000.0), Some(30000.0))]
    );
}

#[test]
fn inline_image_dimensions() {
    let c = ctx(&fixture("rules/RESOURCE.IMAGE_DIMENSIONS/bad/inline-image.pdf").bytes);
    struct Dims(Vec<(Option<i64>, Option<i64>)>);
    impl Visitor for Dims {
        fn content_op(&mut self, op: &ContentOp<'_>, _: &OpLocation) {
            if let Some(i) = &op.inline_image {
                let n = |a, b| i.get(a, b).and_then(|o| o.as_int());
                self.0.push((n("Width", "W"), n("Height", "H")));
            }
        }
    }
    let mut d = Dims(Vec::new());
    c.walk(&mut d);
    assert_eq!(d.0, vec![(Some(100000), Some(100000))]);
}

#[test]
fn filter_chains() {
    let longest = |p: &str| {
        let c = ctx(&fixture(p).bytes);
        (0..c.objects().len())
            .map(|i| c.filter_chain(i).len())
            .max()
            .unwrap_or(0)
    };
    assert_eq!(
        longest("rules/STRUCT.FILTER_CHAIN/bad/three-filters.pdf"),
        3
    );
    assert_eq!(longest("rules/STRUCT.FILTER_CHAIN/bad/name-encoded.pdf"), 3);
    assert_eq!(longest("rules/STRUCT.FILTER_CHAIN/good/two-filters.pdf"), 2);
    let c = ctx(&fixture("rules/STRUCT.FILTER_CHAIN/bad/repeated.pdf").bytes);
    let repeated = (0..c.objects().len()).any(|i| {
        let mut ch = c.filter_chain(i);
        let n = ch.len();
        ch.sort();
        ch.dedup();
        ch.len() < n
    });
    assert!(repeated);
}

#[test]
fn header_lines_outside_streams() {
    let n = |p: &str| ctx(&fixture(p).bytes).header_lines().len();
    assert_eq!(n("rules/STRUCT.MULTIPLE_HEADERS/bad/second-header.pdf"), 2);
    assert!(n("rules/STRUCT.MULTIPLE_HEADERS/bad/concatenated.pdf") >= 2);
    assert_eq!(
        n("rules/STRUCT.MULTIPLE_HEADERS/good/header-in-stream.pdf"),
        1
    );
    assert_eq!(
        n("rules/STRUCT.MULTIPLE_HEADERS/good/header-in-string.pdf"),
        1
    );
    for f in fixtures().iter().filter(|f| f.path.starts_with("benign/")) {
        assert_eq!(ctx(&f.bytes).header_lines().len(), 1, "{}", f.path);
    }
}

#[test]
fn xml_streams_decoded_for_rules() {
    for v in [
        "plain",
        "flate",
        "filter-chain",
        "lzw",
        "old-revision",
        "in-xfa",
    ] {
        let c = ctx(&fixture(&format!("rules/XML.DOCTYPE/bad/{v}.pdf")).bytes);
        let hit = (0..c.objects().len()).any(|i| {
            c.stream_roles(i).xml
                && c.decoded_stream(&Location::of(i, &c.objects()[i]))
                    .is_some_and(|d| d.windows(8).any(|w| w == b"<!ENTITY"))
        });
        assert!(hit, "{v}");
    }
}

#[test]
fn javascript_stream_is_script() {
    let c = ctx(&fixture("rules/ACTIVE.JAVASCRIPT/bad/js-stream.pdf").bytes);
    let hit = (0..c.objects().len()).any(|i| {
        c.stream_roles(i).script
            && c.decoded_stream(&Location::of(i, &c.objects()[i]))
                .is_some_and(|d| d.windows(9).any(|w| w == b"app.alert"))
    });
    assert!(hit);
}

#[test]
fn large_image_is_not_decoded() {
    let c = ctx(&fixture("benign/a0-large-image.pdf").bytes);
    walk(&c);
    assert!(c.issues().is_empty());
    assert!(c.decoded_bytes() < 1 << 20, "{}", c.decoded_bytes());
}

#[test]
fn truncated_inputs_never_panic() {
    for f in fixtures().iter().filter(|f| {
        f.path.starts_with("benign/") || f.path.starts_with("rules/POSTSCRIPT.CONTENT_OP/")
    }) {
        let step = (f.bytes.len() / 40).max(1);
        for end in (0..f.bytes.len()).step_by(step) {
            let c = ctx(&f.bytes[..end]);
            walk(&c);
            let _ = c.issues();
        }
    }
}
