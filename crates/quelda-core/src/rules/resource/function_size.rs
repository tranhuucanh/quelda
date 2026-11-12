//! `RESOURCE.FUNCTION_SIZE`: a sampled function declares a sample table so
//! large that a renderer allocating it runs out of memory.

use crate::facts::{Ctx, Location};
use crate::parser::{Dict, PdfObject};
use crate::rules::values::values;
use crate::rules::{Action, Category, Findings, Rule, RuleMeta, Severity, Stage};

pub struct FunctionSize;

static META: RuleMeta = RuleMeta {
    id: "RESOURCE.FUNCTION_SIZE",
    category: Category::Resource,
    severity: Severity::Medium,
    default_action: Action::Block,
    locked: false,
    stage: Stage::Stable,
    since: "0.3.0",
    message: "Sampled function declares a huge sample table",
    description: "A sampled function (/FunctionType 0, ISO 32000-2 §7.10.2, used by colour \
        spaces, shadings, transfer functions and soft masks) whose /Size, number of outputs \
        (/Range) and /BitsPerSample declare more than 64 MiB of samples. Renderers \
        allocate the table from these numbers, so a few bytes can exhaust a server's \
        memory (like an image pixel bomb). Real tables, colour lookup tables included, \
        are at most a few MiB. Every value counts (duplicate keys, every definition).",
};

/// Largest sample table reported as fine.
const MAX_SAMPLE_BYTES: f64 = (64u64 << 20) as f64;

/// Declared sample bytes of a type 0 function, if its numbers can be read
/// (f64: an overflow is +inf, still over).
fn sample_bytes(ctx: &Ctx, dict: &Dict) -> Option<f64> {
    let size = values(ctx, dict, "Size").find_map(PdfObject::as_array)?;
    let mut samples = 1.0f64;
    for s in size {
        samples *= ctx.resolve(s).find_map(PdfObject::as_number)?.max(0.0);
    }
    let outputs = values(ctx, dict, "Range")
        .find_map(PdfObject::as_array)
        .map_or(1.0, |r| (r.len() / 2).max(1) as f64);
    let bits = values(ctx, dict, "BitsPerSample")
        .find_map(PdfObject::as_number)
        .unwrap_or(8.0)
        .max(1.0);
    Some(samples * outputs * bits / 8.0)
}

impl Rule for FunctionSize {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check_dict(&self, dict: &Dict, loc: &Location, ctx: &Ctx, out: &mut Findings) {
        if !values(ctx, dict, "FunctionType").any(|t| t.as_int() == Some(0)) {
            return;
        }
        if let Some(bytes) = sample_bytes(ctx, dict).filter(|&b| b > MAX_SAMPLE_BYTES) {
            let mib = bytes / f64::from(1u32 << 20);
            let shown = if mib.is_finite() && mib < 1e12 {
                format!("{mib:.0} MiB")
            } else {
                "more than 10^12 MiB".to_string()
            };
            out.report(&META, loc, Some(format!("{shown} of samples (max 64 MiB)")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, Thresholds};
    use crate::rules::{Site, run};

    fn hits(src: &[u8]) -> Vec<String> {
        let ctx = Ctx::new(src, Limits::default(), Thresholds::default());
        run(&ctx, &[&FunctionSize])
            .iter()
            .map(|f| match &f.site {
                Site::Object(l) => format!("{}: {}", l.id, f.detail.clone().unwrap_or_default()),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn huge_tables_only() {
        let src = b"1 0 obj << /FunctionType 0 /Domain [0 1 0 1] /Range [0 1 0 1 0 1] /Size [65536 65536] /BitsPerSample 16 >> endobj\n\
            2 0 obj << /FunctionType 0 /Size [99999999999 99999999999 99999999999 99999999999] /BitsPerSample 32 >> endobj\n\
            3 0 obj << /FunctionType 0 /Range [0 1 0 1 0 1 0 1] /Size [33 33 33 33] /BitsPerSample 16 >> endobj\n\
            4 0 obj << /FunctionType 2 /Size [65536 65536] >> endobj\n\
            5 0 obj << /FunctionType 0 /Size 6 0 R /Range [0 1] /BitsPerSample 8 >> endobj\n6 0 obj [16384 16384] endobj\n\
            7 0 obj << /FunctionType 0 /Size [(a) 2] >> endobj\n";
        assert_eq!(
            hits(src),
            vec![
                "1 0: 24576 MiB of samples (max 64 MiB)".to_string(),
                "2 0: more than 10^12 MiB of samples (max 64 MiB)".to_string(),
                "5 0: 256 MiB of samples (max 64 MiB)".to_string(),
            ]
        );
    }
}
