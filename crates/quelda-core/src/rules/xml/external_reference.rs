//! `XML.EXTERNAL_REFERENCE`: embedded XML (XMP metadata, XFA) that tells
//! its parser to fetch something else: an XInclude, a stylesheet, or a web
//! service connection. Namespace URIs (`xmlns="http://…"`) are names, not
//! references, and do not count.

use crate::facts::{Ctx, Location};
use crate::parser::Dict;
use crate::rules::xml_text::{Packet, ascii_views, find_ci, start_tags, xfa_packets};
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct ExternalReference;

static META: RuleMeta = RuleMeta {
    id: "XML.EXTERNAL_REFERENCE",
    category: Category::Xml,
    severity: Severity::High,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.3.0",
    message: "Embedded XML references an external resource",
    description: "A decoded XML stream (XMP metadata, XFA packet) or an XFA packet written \
        as a string, in UTF-8, UTF-16 or UTF-32, with an XInclude element (an <include> \
        and the XInclude namespace), an <?xml-stylesheet?> instruction, or an XFA web \
        service connection (<wsdlConnection>). These make an XML parser or the form \
        engine read a file or call a URL: server-side request forgery and local file \
        disclosure, like XXE without a DOCTYPE. Namespace URIs and schema locations are \
        not reported.",
};

/// The first external reference in `view`.
fn reference(view: &[u8]) -> Option<&'static str> {
    if find_ci(view, b"<?xml-stylesheet").is_some() {
        return Some("<?xml-stylesheet?>");
    }
    if find_ci(view, b"xinclude").is_some() && start_tags(view, "include").next().is_some() {
        return Some("XInclude <include>");
    }
    if start_tags(view, "wsdlConnection").next().is_some() {
        return Some("XFA <wsdlConnection>");
    }
    None
}

fn detail(data: &[u8], what: &str) -> Option<String> {
    ascii_views(data)
        .iter()
        .find_map(|(enc, view)| reference(view).map(|r| format!("{r} in {what} ({enc})")))
}

impl Rule for ExternalReference {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        for p in xfa_packets(ctx, dict, loc) {
            if let Packet::String(s, at) = p {
                if let Some(d) = detail(s, "XFA string") {
                    out.report(&META, &at, Some(d));
                    break;
                }
            }
        }
        // A stream object's own dictionary.
        if !loc.is_object()
            || ctx
                .objects()
                .get(loc.object)
                .and_then(|e| e.object.as_stream())
                .is_none()
            || !ctx.stream_roles(loc.object).xml
        {
            return;
        }
        let Some(data) = ctx.decoded_stream(loc) else {
            return;
        };
        if let Some(d) = detail(&data, "XML stream") {
            out.report(&META, loc, Some(d));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    #[test]
    fn references() {
        assert_eq!(
            reference(b"<?xml version='1.0'?><?xml-stylesheet href='http://x/a.xsl'?><a/>"),
            Some("<?xml-stylesheet?>")
        );
        assert_eq!(
            reference(br#"<a xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></a>"#),
            Some("XInclude <include>")
        );
        assert_eq!(
            reference(b"<connectionSet><wsdlConnection dataDescription='d'><soapAddress>http://x</soapAddress></wsdlConnection></connectionSet>"),
            Some("XFA <wsdlConnection>")
        );
        for ok in [
            &br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta>"#[..],
            b"<include>no namespace</include>",
            b"<a xsi:schemaLocation='http://x a.xsd'/>",
            b"<connectionSet><xsdConnection/></connectionSet>",
            b"<p>&lt;?xml-stylesheet?&gt;</p>",
        ] {
            assert_eq!(reference(ok), None, "{}", String::from_utf8_lossy(ok));
        }
    }

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&ExternalReference])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn xml_streams_and_xfa_strings() {
        let pi = b"<?xml-stylesheet href='http://x'?><x:xmpmeta/>";
        let src = [
            b"1 0 obj << /Metadata 2 0 R >> endobj\n".to_vec(),
            format!("2 0 obj << /Length {} >> stream\n", pi.len()).into_bytes(),
            pi.to_vec(),
            b"\nendstream endobj\n".to_vec(),
            b"3 0 obj << /XFA [(template) (<?xml-stylesheet href='x'?>)] >> endobj\n".to_vec(),
            // A stream nothing names as XML.
            format!("4 0 obj << /Length {} >> stream\n", pi.len()).into_bytes(),
            pi.to_vec(),
            b"\nendstream endobj\n".to_vec(),
        ]
        .concat();
        assert_eq!(
            hits(&src),
            vec![
                "2 0: <?xml-stylesheet?> in XML stream (UTF-8)".to_string(),
                "3 0: <?xml-stylesheet?> in XFA string (UTF-8)".to_string(),
            ]
        );
    }
}
