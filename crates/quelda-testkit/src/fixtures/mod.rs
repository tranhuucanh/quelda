//! The fixture set written by `gen-fixtures`. Every fixture states which
//! rules must fire (`fires`), so `manifest.json` doubles as the spec for the
//! rule steps and the conformance suite.
//!
//! Object numbers used by [`Doc`]: 1 catalog, 2 pages, 3 page, 4 content,
//! 5 font, 6 link annotation (carrier), 7 extra page-tree node, 9 ObjStm,
//! 10–19 payload, 20+ helper objects.

mod benign;
mod dict_cases;
mod filetype;
mod malformed;
mod special;

use crate::builder::PdfBuilder;
use crate::filters::Filter;

/// Fixture group, also the top-level directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Benign,
    Filetype,
    Malformed,
    /// `rules/<ID>/bad/`: the rule must fire.
    Bad,
    /// `rules/<ID>/good/`: near-miss, the rule must not fire.
    Good,
}

impl Kind {
    pub fn key(self) -> &'static str {
        match self {
            Kind::Benign => "benign",
            Kind::Filetype => "filetype",
            Kind::Malformed => "malformed",
            Kind::Bad => "bad",
            Kind::Good => "good",
        }
    }
}

/// One generated file and its expected outcome.
#[derive(Clone, Debug)]
pub struct Fixture {
    /// Path relative to the fixtures root, e.g. `rules/ACTIVE.LAUNCH/bad/plain.pdf`.
    pub path: String,
    pub bytes: Vec<u8>,
    pub kind: Kind,
    /// Rule under test (bad/good fixtures).
    pub rule: Option<&'static str>,
    pub variant: String,
    /// Every rule that must fire on this file.
    pub fires: Vec<&'static str>,
    /// `true`: exactly `fires`. `false`: at least `fires` (engine behavior past
    /// the first problem is unspecified, e.g. non-PDF input).
    pub exact: bool,
    /// The engine must stop with `ERROR` and an issue code with this prefix.
    pub engine_error: Option<&'static str>,
    pub note: String,
}

impl Fixture {
    fn new(
        kind: Kind,
        path: String,
        variant: &str,
        bytes: Vec<u8>,
        fires: &[&'static str],
        note: &str,
    ) -> Self {
        let mut fires = fires.to_vec();
        fires.sort_unstable();
        fires.dedup();
        Fixture {
            path,
            bytes,
            kind,
            rule: None,
            variant: variant.to_string(),
            fires,
            exact: true,
            engine_error: None,
            note: note.to_string(),
        }
    }

    fn at_least(mut self) -> Self {
        self.exact = false;
        self
    }

    fn error(mut self, code_prefix: &'static str) -> Self {
        self.engine_error = Some(code_prefix);
        self
    }
}

fn group(kind: Kind, name: &str, bytes: Vec<u8>, fires: &[&'static str], note: &str) -> Fixture {
    Fixture::new(
        kind,
        format!("{}/{name}.pdf", kind.key()),
        name,
        bytes,
        fires,
        note,
    )
}

/// `rules/<rule>/bad/<variant>.pdf`; `rule` is added to `fires`.
fn bad(
    rule: &'static str,
    variant: &str,
    bytes: Vec<u8>,
    also: &[&'static str],
    note: &str,
) -> Fixture {
    let mut fires = vec![rule];
    fires.extend_from_slice(also);
    let mut f = Fixture::new(
        Kind::Bad,
        format!("rules/{rule}/bad/{variant}.pdf"),
        variant,
        bytes,
        &fires,
        note,
    );
    f.rule = Some(rule);
    f
}

/// `rules/<rule>/good/<variant>.pdf`; `fires` must not contain `rule`.
fn good(
    rule: &'static str,
    variant: &str,
    bytes: Vec<u8>,
    fires: &[&'static str],
    note: &str,
) -> Fixture {
    assert!(
        !fires.contains(&rule),
        "good fixture {rule}/{variant} fires its own rule"
    );
    let mut f = Fixture::new(
        Kind::Good,
        format!("rules/{rule}/good/{variant}.pdf"),
        variant,
        bytes,
        fires,
        note,
    );
    f.rule = Some(rule);
    f
}

pub(crate) const BASE_CONTENT: &[u8] = b"BT /F1 24 Tf 72 720 Td (quelda test) Tj ET\n";

/// A clean one-page document whose parts fixtures override.
#[derive(Clone, Debug)]
pub(crate) struct Doc {
    pub version: &'static str,
    pub catalog_extra: String,
    pub pages_extra: String,
    pub kids: String,
    pub count: u64,
    pub page_parent: u32,
    pub page_extra: String,
    pub xobjects: Vec<(&'static str, u32)>,
    pub annots: Vec<u32>,
    pub content: Vec<u8>,
    pub content_filters: Vec<Filter>,
}

impl Doc {
    pub fn new() -> Self {
        Doc {
            version: "1.7",
            catalog_extra: String::new(),
            pages_extra: "/MediaBox [0 0 595 842]".to_string(),
            kids: "3 0 R".to_string(),
            count: 1,
            page_parent: 2,
            page_extra: String::new(),
            xobjects: Vec::new(),
            annots: Vec::new(),
            content: BASE_CONTENT.to_vec(),
            content_filters: Vec::new(),
        }
    }

    pub fn catalog_body(&self) -> String {
        join(&["<< /Type /Catalog /Pages 2 0 R", &self.catalog_extra, ">>"])
    }

    pub fn pages_body(&self) -> String {
        join(&[
            &format!(
                "<< /Type /Pages /Kids [{}] /Count {}",
                self.kids, self.count
            ),
            &self.pages_extra,
            ">>",
        ])
    }

    pub fn page_body(&self) -> String {
        let xobj = if self.xobjects.is_empty() {
            String::new()
        } else {
            let e: Vec<String> = self
                .xobjects
                .iter()
                .map(|(k, n)| format!("/{k} {n} 0 R"))
                .collect();
            format!(" /XObject << {} >>", e.join(" "))
        };
        let annots = if self.annots.is_empty() {
            String::new()
        } else {
            let e: Vec<String> = self.annots.iter().map(|n| format!("{n} 0 R")).collect();
            format!("/Annots [{}]", e.join(" "))
        };
        join(&[
            &format!(
                "<< /Type /Page /Parent {} 0 R /Resources << /Font << /F1 5 0 R >>{xobj} >>",
                self.page_parent
            ),
            &annots,
            "/Contents 4 0 R",
            &self.page_extra,
            ">>",
        ])
    }

    /// Writes objects 1–5 into `b`.
    pub fn emit(&self, b: &mut PdfBuilder) {
        b.object(1, self.catalog_body())
            .object(2, self.pages_body())
            .object(3, self.page_body())
            .stream(4, "", &self.content, &self.content_filters)
            .object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    }

    pub fn builder(&self) -> PdfBuilder {
        let mut b = PdfBuilder::new(self.version);
        self.emit(&mut b);
        b
    }

    pub fn build(&self) -> Vec<u8> {
        self.builder().build()
    }
}

fn join(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Link annotation (object 6) whose `/A` points at object 10.
pub(crate) const LINK_TO_10: &str =
    "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /Border [0 0 0] /A 10 0 R >>";

/// The full fixture set, in a stable order.
pub fn all() -> Vec<Fixture> {
    let mut out = Vec::new();
    out.extend(benign::all());
    out.extend(filetype::all());
    out.extend(malformed::all());
    out.extend(dict_cases::all());
    out.extend(special::all());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_bodies() {
        let mut d = Doc::new();
        assert_eq!(d.catalog_body(), "<< /Type /Catalog /Pages 2 0 R >>");
        d.xobjects.push(("Q1", 10));
        d.annots.push(6);
        let page = d.page_body();
        assert!(page.contains("/XObject << /Q1 10 0 R >>"), "{page}");
        assert!(page.contains("/Annots [6 0 R]"), "{page}");
        assert!(d.pages_body().contains("/Kids [3 0 R] /Count 1 /MediaBox"));
    }

    #[test]
    fn good_rejects_own_rule() {
        let r =
            std::panic::catch_unwind(|| good("ACTIVE.LAUNCH", "x", vec![], &["ACTIVE.LAUNCH"], ""));
        assert!(r.is_err());
    }
}
