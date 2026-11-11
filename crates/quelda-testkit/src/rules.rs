//! The rule set the fixtures target (design §5.7) and the preset table (§6.2),
//! used only to compute each fixture's expected verdict in `manifest.json`.
//! This is a spec mirror: when design §5.7/§6.2 changes, change it here too.

/// A policy preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    Strict,
    Balanced,
    Permissive,
}

impl Preset {
    pub const ALL: [Preset; 3] = [Preset::Strict, Preset::Balanced, Preset::Permissive];

    pub fn key(self) -> &'static str {
        match self {
            Preset::Strict => "strict",
            Preset::Balanced => "balanced",
            Preset::Permissive => "permissive",
        }
    }
}

/// What a resolved rule does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Block,
    Warn,
    Off,
}

impl Action {
    pub fn key(self) -> &'static str {
        match self {
            Action::Block => "block",
            Action::Warn => "warn",
            Action::Off => "off",
        }
    }
}

use Action::{Block as B, Off as O, Warn as W};

/// Category defaults per preset `[strict, balanced, permissive]` (design §6.2).
pub const CATEGORIES: &[(&str, &str, [Action; 3])] = &[
    ("filetype", "FILETYPE", [B, B, B]),
    ("postscript", "POSTSCRIPT", [B, B, B]),
    ("active_content", "ACTIVE", [B, B, W]),
    ("embedded", "EMBED", [B, B, W]),
    ("external", "EXTERNAL", [B, W, O]),
    ("forms", "FORMS", [B, W, O]),
    ("xml", "XML", [B, B, W]),
    ("structure", "STRUCT", [B, W, O]),
    ("encryption", "CRYPT", [B, B, B]),
    ("codecs", "CODEC", [B, W, O]),
    ("resource", "RESOURCE", [B, B, W]),
];

/// One rule of design §5.7.
#[derive(Clone, Copy, Debug)]
pub struct RuleSpec {
    pub id: &'static str,
    pub locked: bool,
    /// Per-rule preset override `[strict, balanced, permissive]` (design §6.2 note).
    pub presets: Option<[Action; 3]>,
}

const fn r(id: &'static str) -> RuleSpec {
    RuleSpec {
        id,
        locked: false,
        presets: None,
    }
}

const fn locked(id: &'static str) -> RuleSpec {
    RuleSpec {
        id,
        locked: true,
        presets: None,
    }
}

const fn custom(id: &'static str, presets: [Action; 3]) -> RuleSpec {
    RuleSpec {
        id,
        locked: false,
        presets: Some(presets),
    }
}

/// Rule set: 40 rules in v0.1 (design §5.7, ADR #13, #26), 45 from v0.2 (ADR #40), 48 from v0.3 (ADR #42).
pub const RULES: &[RuleSpec] = &[
    locked("FILETYPE.NOT_PDF_HEADER"),
    locked("FILETYPE.POSTSCRIPT_MAGIC"),
    locked("FILETYPE.FOREIGN_MAGIC"),
    r("FILETYPE.POLYGLOT"),
    locked("POSTSCRIPT.XOBJECT"),
    locked("POSTSCRIPT.CONTENT_OP"),
    r("POSTSCRIPT.TYPE4_FUNCTION"),
    r("ACTIVE.JAVASCRIPT"),
    locked("ACTIVE.LAUNCH"),
    r("ACTIVE.OPEN_ACTION"),
    r("ACTIVE.ADDITIONAL_ACTIONS"),
    custom("ACTIVE.OTHER_ACTIONS", [B, W, W]),
    r("EMBED.EMBEDDED_FILE"),
    r("EMBED.FILE_ATTACHMENT"),
    r("EMBED.RICH_MEDIA"),
    r("EMBED.PORTFOLIO"),
    r("EXTERNAL.URI"),
    r("EXTERNAL.REMOTE_GOTO"),
    r("EXTERNAL.SUBMIT_FORM"),
    r("EXTERNAL.IMPORT_DATA"),
    r("EXTERNAL.URL_FILESPEC"),
    r("FORMS.XFA"),
    r("FORMS.ACROFORM"),
    r("XML.DOCTYPE"),
    r("STRUCT.TRAILING_DATA"),
    r("STRUCT.MISSING_EOF"),
    r("STRUCT.XREF_MISMATCH"),
    r("STRUCT.CONFLICTING_OBJECTS"),
    custom("STRUCT.INCREMENTAL_UPDATE", [W, O, O]),
    r("STRUCT.MULTIPLE_HEADERS"),
    r("STRUCT.PAGE_TREE_CYCLE"),
    r("STRUCT.FILTER_CHAIN"),
    r("STRUCT.TRUNCATED_STREAM"),
    r("RESOURCE.IMAGE_DIMENSIONS"),
    r("RESOURCE.PAGE_SIZE"),
    r("RESOURCE.PAGE_COUNT"),
    r("CRYPT.ENCRYPTED"),
    r("CODEC.JBIG2"),
    r("CODEC.JPX"),
    custom("CODEC.TYPE1_FONT", [W, O, O]),
    // 0.2.0
    custom("EXTERNAL.STREAM_FILE", [B, B, W]),
    custom("EXTERNAL.OPI", [B, B, W]),
    custom("STRUCT.NAME_TOO_LONG", [B, B, B]),
    custom("CODEC.DECODE_PARAMS", [B, B, B]),
    r("STRUCT.PRINT_VIEW_MISMATCH"),
    // 0.3.0
    custom("CODEC.FONT_MALFORMED", [B, B, W]),
    custom("CODEC.ICC_MALFORMED", [B, B, W]),
    r("STRUCT.SIGNATURE_MODIFIED"),
];

/// Looks up a rule by ID.
pub fn rule(id: &str) -> Option<&'static RuleSpec> {
    RULES.iter().find(|r| r.id == id)
}

/// The category key of a rule (from its ID prefix).
pub fn category_of(id: &str) -> Option<&'static str> {
    let prefix = id.split('.').next()?;
    CATEGORIES.iter().find(|c| c.1 == prefix).map(|c| c.0)
}

/// Resolved action of a rule under a preset with no overrides.
///
/// # Panics
/// On an unknown rule ID (a typo in a fixture).
pub fn action(id: &str, preset: Preset) -> Action {
    let spec = rule(id).unwrap_or_else(|| panic!("unknown rule {id}"));
    if spec.locked {
        return Action::Block;
    }
    let idx = preset as usize;
    if let Some(p) = spec.presets {
        return p[idx];
    }
    let prefix = id.split('.').next().unwrap_or_default();
    CATEGORIES
        .iter()
        .find(|c| c.1 == prefix)
        .map(|c| c.2[idx])
        .unwrap_or_else(|| panic!("no category for {id}"))
}

/// Expected verdict of one fixture under one preset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    /// `PASS`, `REJECT` or `ERROR`.
    pub status: &'static str,
    pub violations: Vec<&'static str>,
    pub warnings: Vec<&'static str>,
}

/// Computes the verdict from the rules that fire and whether the engine must error.
pub fn expected(fires: &[&'static str], engine_error: bool, preset: Preset) -> Expected {
    let mut violations = Vec::new();
    let mut warnings = Vec::new();
    for &id in fires {
        match action(id, preset) {
            Action::Block => violations.push(id),
            Action::Warn => warnings.push(id),
            Action::Off => {}
        }
    }
    violations.sort_unstable();
    warnings.sort_unstable();
    let status = if engine_error {
        "ERROR"
    } else if violations.is_empty() {
        "PASS"
    } else {
        "REJECT"
    };
    Expected {
        status,
        violations,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_set_has_48_unique_well_formed_ids() {
        assert_eq!(RULES.len(), 48);
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 48, "duplicate rule ID");
        for id in ids {
            let (cat, name) = id.split_once('.').expect("CATEGORY.NAME");
            assert!(
                cat.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "{id}"
            );
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                "{id}"
            );
            assert!(category_of(id).is_some(), "{id} has no category");
        }
    }

    #[test]
    fn every_category_is_used() {
        for c in CATEGORIES {
            assert!(
                RULES.iter().any(|r| r.id.starts_with(&format!("{}.", c.1))),
                "{}",
                c.0
            );
        }
    }

    #[test]
    fn locked_rules_block_everywhere() {
        for p in Preset::ALL {
            assert_eq!(action("ACTIVE.LAUNCH", p), Action::Block);
            assert_eq!(action("FILETYPE.POSTSCRIPT_MAGIC", p), Action::Block);
        }
    }

    #[test]
    fn category_and_rule_overrides() {
        assert_eq!(action("EXTERNAL.URI", Preset::Balanced), Action::Warn);
        assert_eq!(action("EXTERNAL.URI", Preset::Permissive), Action::Off);
        assert_eq!(
            action("ACTIVE.JAVASCRIPT", Preset::Permissive),
            Action::Warn
        );
        assert_eq!(
            action("ACTIVE.OTHER_ACTIONS", Preset::Balanced),
            Action::Warn
        );
        assert_eq!(action("CODEC.TYPE1_FONT", Preset::Strict), Action::Warn);
        assert_eq!(
            action("STRUCT.INCREMENTAL_UPDATE", Preset::Balanced),
            Action::Off
        );
        assert_eq!(
            action("RESOURCE.PAGE_SIZE", Preset::Balanced),
            Action::Block
        );
    }

    #[test]
    fn expected_status() {
        let e = expected(&["EXTERNAL.URI"], false, Preset::Balanced);
        assert_eq!((e.status, e.warnings.len()), ("PASS", 1));
        let e = expected(&["EXTERNAL.URI"], false, Preset::Strict);
        assert_eq!((e.status, e.violations), ("REJECT", vec!["EXTERNAL.URI"]));
        let e = expected(&[], true, Preset::Permissive);
        assert_eq!(e.status, "ERROR");
        let e = expected(&[], false, Preset::Strict);
        assert_eq!(e.status, "PASS");
    }
}
