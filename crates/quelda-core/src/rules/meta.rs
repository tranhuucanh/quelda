//! Rule metadata (design §5.2) and the enums policy keys use (§5.6, §6).

/// Rule category: the stable key policies use (design §5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Filetype,
    Postscript,
    ActiveContent,
    Embedded,
    External,
    Forms,
    Xml,
    Structure,
    Encryption,
    Codecs,
    Resource,
}

impl Category {
    pub const ALL: [Category; 11] = [
        Category::Filetype,
        Category::Postscript,
        Category::ActiveContent,
        Category::Embedded,
        Category::External,
        Category::Forms,
        Category::Xml,
        Category::Structure,
        Category::Encryption,
        Category::Codecs,
        Category::Resource,
    ];

    /// Policy key, e.g. `active_content`.
    pub fn key(self) -> &'static str {
        match self {
            Category::Filetype => "filetype",
            Category::Postscript => "postscript",
            Category::ActiveContent => "active_content",
            Category::Embedded => "embedded",
            Category::External => "external",
            Category::Forms => "forms",
            Category::Xml => "xml",
            Category::Structure => "structure",
            Category::Encryption => "encryption",
            Category::Codecs => "codecs",
            Category::Resource => "resource",
        }
    }

    /// Rule ID prefix, e.g. `ACTIVE`.
    pub fn prefix(self) -> &'static str {
        match self {
            Category::Filetype => "FILETYPE",
            Category::Postscript => "POSTSCRIPT",
            Category::ActiveContent => "ACTIVE",
            Category::Embedded => "EMBED",
            Category::External => "EXTERNAL",
            Category::Forms => "FORMS",
            Category::Xml => "XML",
            Category::Structure => "STRUCT",
            Category::Encryption => "CRYPT",
            Category::Codecs => "CODEC",
            Category::Resource => "RESOURCE",
        }
    }

    pub fn from_key(key: &str) -> Option<Category> {
        Category::ALL.into_iter().find(|c| c.key() == key)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn key(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// What a resolved rule does (design §6). Ordered `Off < Warn < Block`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    Off,
    Warn,
    Block,
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

/// Rollout stage (design §6.4): a preview rule is at most `warn` unless the
/// policy names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    Preview,
    Stable,
}

impl Stage {
    pub fn key(self) -> &'static str {
        match self {
            Stage::Preview => "preview",
            Stage::Stable => "stable",
        }
    }
}

/// Everything about a rule except how it detects (design §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleMeta {
    /// `CATEGORY.NAME`, stable forever, never reused.
    pub id: &'static str,
    pub category: Category,
    pub severity: Severity,
    /// Action in the `balanced` preset.
    pub default_action: Action,
    /// Policy cannot lower it below `block` (except `unsafe_allow_unlock`).
    pub locked: bool,
    pub stage: Stage,
    /// Engine version that added the rule.
    pub since: &'static str,
    /// Short reason shown to users (English).
    pub message: &'static str,
    /// Longer explanation and references.
    pub description: &'static str,
}

/// What [`crate::list_rules`] returns (settings screens).
pub type RuleInfo = RuleMeta;

/// `^[A-Z0-9]+\.[A-Z0-9_]+$` (design §5.5).
pub fn is_valid_rule_id(id: &str) -> bool {
    let Some((prefix, name)) = id.split_once('.') else {
        return false;
    };
    !prefix.is_empty()
        && !name.is_empty()
        && prefix
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::codegen;

    #[test]
    fn categories_match_codegen_and_testkit() {
        let ours: Vec<_> = Category::ALL
            .iter()
            .map(|c| (c.key(), c.prefix(), format!("{c:?}")))
            .collect();
        let gen_: Vec<_> = codegen::CATEGORIES
            .iter()
            .map(|(k, p, v)| (*k, *p, v.to_string()))
            .collect();
        assert_eq!(ours, gen_);
        let spec: Vec<_> = quelda_testkit::rules::CATEGORIES
            .iter()
            .map(|c| (c.0, c.1))
            .collect();
        let ours: Vec<_> = Category::ALL
            .iter()
            .map(|c| (c.key(), c.prefix()))
            .collect();
        assert_eq!(ours, spec);
    }

    #[test]
    fn category_from_key() {
        for c in Category::ALL {
            assert_eq!(Category::from_key(c.key()), Some(c));
        }
        assert_eq!(Category::from_key("ACTIVE"), None);
        assert_eq!(Category::from_key(""), None);
    }

    #[test]
    fn keys() {
        assert_eq!(Severity::Critical.key(), "critical");
        assert_eq!(Severity::Info.key(), "info");
        assert_eq!(Action::Warn.key(), "warn");
        assert!(Action::Off < Action::Warn && Action::Warn < Action::Block);
        assert_eq!(Stage::Preview.key(), "preview");
    }

    #[test]
    fn rule_id_format_matches_codegen() {
        for id in [
            "ACTIVE.LAUNCH",
            "A1.B_2",
            "X.Y",
            "active.launch",
            "ACTIVE",
            "ACTIVE.",
            ".X",
            "A.B.C",
            "A_B.C",
            "A.b",
            "",
        ] {
            assert_eq!(is_valid_rule_id(id), codegen::is_valid_id(id), "{id}");
        }
        assert!(is_valid_rule_id("STRUCT.XREF_MISMATCH"));
        assert!(!is_valid_rule_id("STRUCT.XREF-MISMATCH"));
    }
}
