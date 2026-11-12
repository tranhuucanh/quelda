//! `ACTIVE.XFA_SCRIPT`: an XFA form carries a script (JavaScript or
//! FormCalc) that Acrobat runs. `ACTIVE.JAVASCRIPT` only sees JavaScript in
//! PDF dictionaries; XFA scripts live in the form's XML.

use std::collections::BTreeSet;

use crate::facts::visitor::visit_dicts;
use crate::facts::{Ctx, Location};
use crate::rules::xml_text::{Packet, Tag, ascii_views, find_ci, start_tags, xfa_packets};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct XfaScript;

static META: RuleMeta = RuleMeta {
    id: "ACTIVE.XFA_SCRIPT",
    category: Category::ActiveContent,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.3.0",
    message: "XFA form contains a script",
    description: "An XFA packet (a stream or string named by /XFA, every definition, in \
        UTF-8, UTF-16 or UTF-32) has a <script> element with code in it: JavaScript or \
        FormCalc that Acrobat and Reader run when the form opens, calculates or validates, \
        with the same reach as document JavaScript. Empty <script/> elements, which form \
        designers leave in templates, <script> settings in the config packet \
        (<runScripts>, <currentPage>, <exclude>) and elements named script in the form \
        data (<datasets>) are not reported.",
};

/// The language of the first `<script>` with code in `view`.
fn script(view: &[u8]) -> Option<&'static str> {
    let data = data_ranges(view);
    start_tags(view, "script").find_map(|Tag { start, end, empty }| {
        if empty || data.iter().any(|&(from, to)| (from..to).contains(&start)) {
            return None;
        }
        let body = &view[end..];
        let close = find_ci(body, b"script>")
            .and_then(|p| body[..p].iter().rposition(|&b| b == b'<').map(|lt| (lt, p)))
            .map_or(body.len(), |(lt, _)| lt);
        has_code(&body[..close]).then(|| {
            let tag = &view[start..end];
            if find_ci(tag, b"javascript").is_some() {
                "JavaScript"
            } else {
                "FormCalc"
            }
        })
    })
}

/// The insides of `<datasets>` elements in `view`: form data, which no
/// XFA processor runs. Only closed ones: an unclosed `<datasets>` hides
/// nothing.
fn data_ranges(view: &[u8]) -> Vec<(usize, usize)> {
    start_tags(view, "datasets")
        .filter(|t| !t.empty)
        .filter_map(|t| close_tag(&view[t.end..], b"datasets").map(|c| (t.end, t.end + c)))
        .collect()
}

/// Offset of the first `</local>` or `</prefix:local >` in `view`.
fn close_tag(view: &[u8], local: &[u8]) -> Option<usize> {
    memchr::memmem::find_iter(view, b"</").find(|&at| {
        let rest = &view[at + 2..];
        let name_end = rest
            .iter()
            .position(|&b| b.is_ascii_whitespace() || b == b'>')
            .unwrap_or(rest.len());
        let name = &rest[..name_end];
        name.rsplit(|&b| b == b':')
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case(local))
            && rest[name_end..].trim_ascii_start().first() == Some(&b'>')
    })
}

/// Children of the config packet's `<script>` settings element.
const SETTINGS: [&[u8]; 3] = [b"runScripts", b"currentPage", b"exclude"];

/// A settings child at the start of `rest` (`<runScripts>both</runScripts>`
/// or `<exclude/>`, any prefix): what follows it.
fn setting(rest: &[u8]) -> Option<&[u8]> {
    let name_end = rest
        .iter()
        .skip(1)
        .position(|&b| b.is_ascii_whitespace() || b == b'>' || b == b'/')?
        + 1;
    let name = &rest[1..name_end];
    let local = name.rsplit(|&b| b == b':').next()?;
    if !SETTINGS.iter().any(|s| s.eq_ignore_ascii_case(local)) {
        return None;
    }
    let gt = name_end + memchr::memchr(b'>', &rest[name_end..])?;
    let after = &rest[gt + 1..];
    if rest[gt - 1] == b'/' {
        return Some(after);
    }
    // Text only (no markup) up to its own end tag.
    let close = memchr::memchr(b'<', after)?;
    let end = close_tag(&after[close..], local)?;
    if end != 0 {
        return None;
    }
    let gt = memchr::memchr(b'>', &after[close..])?;
    Some(&after[close + gt + 1..])
}

/// Anything but whitespace, CDATA markers, comments and config settings.
fn has_code(body: &[u8]) -> bool {
    let mut rest = body;
    loop {
        rest = rest.trim_ascii_start();
        if rest.is_empty() {
            return false;
        }
        if let Some(r) = rest.strip_prefix(b"<![CDATA[") {
            rest = r;
        } else if let Some(r) = rest.strip_prefix(b"]]>") {
            rest = r;
        } else if let Some(r) = rest.strip_prefix(b"<!--") {
            rest = find_ci(r, b"-->").map_or(&[][..], |e| &r[e + 3..]);
        } else if let Some(r) = rest.starts_with(b"<").then(|| setting(rest)).flatten() {
            rest = r;
        } else {
            return true;
        }
    }
}

fn detail(data: &[u8], what: &str) -> Option<String> {
    ascii_views(data).iter().find_map(|(enc, view)| {
        script(view).map(|lang| format!("{lang} <script> in XFA {what} ({enc})"))
    })
}

impl Rule for XfaScript {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_document(&self, ctx: &Ctx, out: &mut Findings) {
        let mut streams = BTreeSet::new();
        visit_dicts(ctx.objects(), |dict, loc| {
            for p in xfa_packets(ctx, dict, loc) {
                match p {
                    Packet::Stream(i) => {
                        streams.insert(i);
                    }
                    Packet::String(s, loc) => {
                        if let Some(d) = detail(s, "string") {
                            out.report(&META, &loc, Some(d));
                        }
                    }
                }
            }
        });
        for i in streams {
            let Some(outcome) = ctx.decode(i) else { continue };
            let Some(data) = outcome.data() else { continue };
            if let Some(d) = detail(data, "stream") {
                out.report(&META, &Location::of(i, &ctx.objects()[i]), Some(d));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    #[test]
    fn scripts_with_code() {
        let js = br#"<event activity="initialize"><script contentType="application/x-javascript">app.alert(1)</script></event>"#;
        assert_eq!(script(js), Some("JavaScript"));
        assert_eq!(script(b"<calculate><script>Sum(a)</script></calculate>"), Some("FormCalc"));
        assert_eq!(script(b"<t:script><![CDATA[x()]]></t:script>"), Some("FormCalc"));
        // Unclosed: code up to the end.
        assert_eq!(script(b"<script>x()"), Some("FormCalc"));
        // Settings, then code.
        assert_eq!(script(b"<script><runScripts>both</runScripts>x()</script>"), Some("FormCalc"));
        assert_eq!(script(b"<script><runScripts><b/>x()</runScripts></script>"), Some("FormCalc"));
        assert_eq!(script(b"<script><other>x()</other></script>"), Some("FormCalc"));
        // Outside the form data, or in data that is never closed.
        assert_eq!(script(b"<xfa:datasets><a/></xfa:datasets ><script>x()</script>"), Some("FormCalc"));
        assert_eq!(script(b"<xfa:datasets><script>x()</script>"), Some("FormCalc"));
        for empty in [
            &b"<script/>"[..],
            b"<script contentType='application/x-javascript'/>",
            b"<script>  \n </script>",
            b"<script><![CDATA[ ]]></script>",
            b"<script><!-- nothing --></script>",
            b"<scripts>x</scripts>",
            b"<draw>&lt;script&gt;x&lt;/script&gt;</draw>",
            b"<acrobat><script><runScripts>server</runScripts></script></acrobat>",
            b"<script>\n  <currentPage>0</currentPage>\n  <exclude/>\n  <!-- x -->\n  <runScripts>both</runScripts>\n</script>",
            b"<xfa:datasets><xfa:data><form1><script>Act 1</script></form1></xfa:data></xfa:datasets>",
        ] {
            assert_eq!(script(empty), None, "{}", String::from_utf8_lossy(empty));
        }
    }

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&XfaScript])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn packets_as_streams_and_strings() {
        let tpl = b"<template><field><event><script contentType='application/x-javascript'>app.alert(1)</script></event></field></template>";
        let stream = |n: u32, data: &[u8]| {
            [
                format!("{n} 0 obj << /Length {} >> stream\n", data.len()).into_bytes(),
                data.to_vec(),
                b"\nendstream endobj\n".to_vec(),
            ]
            .concat()
        };
        let utf16: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain(tpl.iter().flat_map(|&b| [0, b]))
            .collect();
        let src = [
            b"1 0 obj << /AcroForm 2 0 R >> endobj\n2 0 obj << /XFA [(template) 3 0 R (datasets) 4 0 R] >> endobj\n".to_vec(),
            stream(3, tpl),
            stream(4, b"<xfa:datasets><a>&lt;script&gt;</a></xfa:datasets>"),
            b"5 0 obj << /XFA 6 0 R >> endobj\n".to_vec(),
            stream(6, &utf16),
            b"7 0 obj << /XFA [(template) (<script>x()</script>)] >> endobj\n".to_vec(),
            // Named twice: reported once.
            b"8 0 obj << /XFA 3 0 R >> endobj\n".to_vec(),
            // A script nothing names as XFA.
            stream(9, tpl),
        ]
        .concat();
        assert_eq!(
            hits(&src),
            vec![
                "7 0: FormCalc <script> in XFA string (UTF-8)".to_string(),
                "3 0: JavaScript <script> in XFA stream (UTF-8)".to_string(),
                "6 0: JavaScript <script> in XFA stream (UTF-16)".to_string(),
            ]
        );
    }
}
