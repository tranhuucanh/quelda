//! Presets (design §6.2) as data: an action per category, plus the few rules
//! whose action differs from their category's.

use serde::{Deserialize, Serialize};

use crate::rules::{Action, Category};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Strict,
    #[default]
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

    fn column(self) -> usize {
        match self {
            Preset::Strict => 0,
            Preset::Balanced => 1,
            Preset::Permissive => 2,
        }
    }
}

use Action::{Block as B, Off as O, Warn as W};

/// `[strict, balanced, permissive]` per category (design §6.2).
const CATEGORIES: [(Category, [Action; 3]); 11] = [
    (Category::Filetype, [B, B, B]),
    (Category::Postscript, [B, B, B]),
    (Category::ActiveContent, [B, B, W]),
    (Category::Embedded, [B, B, W]),
    (Category::External, [B, W, O]),
    (Category::Forms, [B, W, O]),
    (Category::Xml, [B, B, W]),
    (Category::Structure, [B, W, O]),
    (Category::Encryption, [B, B, B]),
    (Category::Codecs, [B, W, O]),
    (Category::Resource, [B, B, W]),
];

/// Rules whose preset action differs from their category's (design §6.2).
/// The `balanced` column must equal the rule's `default_action`.
const RULES: [(&str, [Action; 3]); 7] = [
    ("ACTIVE.OTHER_ACTIONS", [B, W, W]),
    ("STRUCT.INCREMENTAL_UPDATE", [W, O, O]),
    ("CODEC.TYPE1_FONT", [W, O, O]),
    ("EXTERNAL.STREAM_FILE", [B, B, W]),
    ("EXTERNAL.OPI", [B, B, W]),
    ("STRUCT.NAME_TOO_LONG", [B, B, B]),
    ("CODEC.DECODE_PARAMS", [B, B, B]),
];

/// Preset action of a category.
pub fn category_action(preset: Preset, category: Category) -> Action {
    CATEGORIES
        .iter()
        .find(|(c, _)| *c == category)
        .map_or(Action::Block, |(_, a)| a[preset.column()])
}

/// Preset action of a rule, when it differs from its category's.
pub fn rule_override(preset: Preset, id: &str) -> Option<Action> {
    RULES
        .iter()
        .find(|(r, _)| *r == id)
        .map(|(_, a)| a[preset.column()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::meta::is_valid_rule_id;
    use quelda_testkit::rules as spec;

    #[test]
    fn every_category_has_a_row() {
        for c in Category::ALL {
            assert_eq!(
                CATEGORIES.iter().filter(|(x, _)| *x == c).count(),
                1,
                "{c:?}"
            );
        }
    }

    #[test]
    fn table_matches_design() {
        use Preset::*;
        assert_eq!(category_action(Strict, Category::External), B);
        assert_eq!(category_action(Balanced, Category::External), W);
        assert_eq!(category_action(Permissive, Category::External), O);
        assert_eq!(category_action(Permissive, Category::Encryption), B);
        assert_eq!(category_action(Permissive, Category::Resource), W);
        assert_eq!(rule_override(Strict, "CODEC.TYPE1_FONT"), Some(W));
        assert_eq!(rule_override(Balanced, "ACTIVE.OTHER_ACTIONS"), Some(W));
        assert_eq!(rule_override(Balanced, "ACTIVE.LAUNCH"), None);
    }

    /// The testkit mirror of design §6.2 computes the manifest: same table.
    #[test]
    fn matches_testkit_spec() {
        for (key, prefix, actions) in spec::CATEGORIES {
            let c = Category::from_key(key).unwrap();
            assert_eq!(c.prefix(), *prefix);
            for p in Preset::ALL {
                assert_eq!(
                    category_action(p, c).key(),
                    actions[p.column()].key(),
                    "{key} {p:?}"
                );
            }
        }
        for r in spec::RULES {
            for p in Preset::ALL {
                let want = r.presets.map(|a| a[p.column()].key());
                assert_eq!(rule_override(p, r.id).map(Action::key), want, "{}", r.id);
            }
        }
        for (id, _) in RULES {
            assert!(is_valid_rule_id(id) && spec::rule(id).is_some(), "{id}");
        }
    }

    #[test]
    fn preset_serde_and_keys() {
        for p in Preset::ALL {
            assert_eq!(serde_json::json!(p), serde_json::json!(p.key()));
        }
        assert_eq!(Preset::default(), Preset::Balanced);
        let keys: Vec<_> = Preset::ALL.iter().map(|p| p.key()).collect();
        let spec_keys: Vec<_> = spec::Preset::ALL.iter().map(|p| p.key()).collect();
        assert_eq!(keys, spec_keys);
    }
}
