//! Policy (design §6): which rules run and whether they block or warn, plus
//! engine limits and detection thresholds. Every field is optional; `{}` is
//! the `balanced` preset with default limits.
//!
//! Policy never knows how a rule detects; rules never read the policy.
//! Parsing is strict (fail-closed): unknown fields, duplicate keys, values of
//! the wrong type and unknown rule IDs are `POLICY.INVALID`, because a typo
//! that silently turns a rule off is worse than an error.

pub mod presets;
pub mod resolve;

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Deserializer, MapAccess};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::limits::{Limits, Thresholds};
use crate::rules::{Action, Category, Rule};
pub use presets::Preset;
pub use resolve::{resolve, resolve_all};

/// A policy (design §6.1). Build one with [`Policy::from_json`] or by hand.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// `None`: `balanced`.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub preset: Option<Preset>,
    /// Category overrides (beat the preset).
    #[serde(
        default,
        deserialize_with = "unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub categories: BTreeMap<Category, Action>,
    /// Rule overrides by ID (beat the category). IDs must exist.
    #[serde(
        default,
        deserialize_with = "unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub rules: BTreeMap<String, Action>,
    #[serde(
        default,
        deserialize_with = "object",
        skip_serializing_if = "PolicyLimits::is_empty"
    )]
    pub limits: PolicyLimits,
    #[serde(
        default,
        deserialize_with = "object",
        skip_serializing_if = "PolicyThresholds::is_empty"
    )]
    pub thresholds: PolicyThresholds,
    /// Stop at the first `block` finding (faster, fewer reasons).
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_on_first: Option<bool>,
    /// Lets the policy lower locked rules. Reported in the verdict.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub unsafe_allow_unlock: Option<bool>,
}

/// `limits` (design §4.5): engine guardrails. Unset fields keep the default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLimits {
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_file_bytes: Option<u64>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_objects: Option<u64>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_nesting_depth: Option<u32>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_decoded_bytes_total: Option<u64>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_decoded_bytes_per_stream: Option<u64>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_compression_ratio: Option<u32>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_revisions: Option<u32>,
}

/// `thresholds` (design §4.5): detection thresholds of some rules.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyThresholds {
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_image_pixels: Option<u64>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_page_side_pt: Option<f64>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_pages: Option<u64>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_filter_chain: Option<u32>,
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_trailing_bytes: Option<u64>,
}

/// Why a policy is invalid (`POLICY.INVALID`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Policy {
    /// Parses a policy. The top level must be a JSON object.
    pub fn from_json(json: &str) -> Result<Policy, PolicyError> {
        let mut de = serde_json::Deserializer::from_str(json);
        object(&mut de)
            .and_then(|p| de.end().map(|()| p))
            .map_err(|e| PolicyError(format!("invalid policy: {e}")))
    }

    /// Checks what JSON parsing cannot: every rule override names one of
    /// `rules`, and `max_page_side_pt` is a non-negative number.
    pub fn validate(&self, rules: &[&dyn Rule]) -> Result<(), PolicyError> {
        for id in self.rules.keys() {
            if !rules.iter().any(|r| r.meta().id == id) {
                return Err(PolicyError(format!("invalid policy: unknown rule `{id}`")));
            }
        }
        if let Some(v) = self.thresholds.max_page_side_pt {
            if !(v.is_finite() && v >= 0.0) {
                return Err(PolicyError(format!(
                    "invalid policy: thresholds.max_page_side_pt must be >= 0, got {v}"
                )));
            }
        }
        Ok(())
    }

    pub fn preset(&self) -> Preset {
        self.preset.unwrap_or_default()
    }

    pub fn stop_on_first(&self) -> bool {
        self.stop_on_first.unwrap_or(false)
    }

    pub fn unsafe_allow_unlock(&self) -> bool {
        self.unsafe_allow_unlock.unwrap_or(false)
    }

    /// Locked rules of `rules` that `rules` overrides below `block` without
    /// `unsafe_allow_unlock`: the override is ignored (they still block),
    /// which callers can tell the user.
    pub fn ignored_unlocks(&self, rules: &[&dyn Rule]) -> Vec<&'static str> {
        if self.unsafe_allow_unlock() {
            return Vec::new();
        }
        rules
            .iter()
            .map(|r| r.meta())
            .filter(|m| m.locked && self.rules.get(m.id).is_some_and(|&a| a < Action::Block))
            .map(|m| m.id)
            .collect()
    }

    /// Engine limits: defaults overridden by `limits`.
    pub fn limits(&self) -> Limits {
        let p = &self.limits;
        let d = Limits::default();
        Limits {
            max_file_bytes: p.max_file_bytes.unwrap_or(d.max_file_bytes),
            max_nesting_depth: p.max_nesting_depth.unwrap_or(d.max_nesting_depth),
            max_decoded_bytes_per_stream: p
                .max_decoded_bytes_per_stream
                .unwrap_or(d.max_decoded_bytes_per_stream),
            max_decoded_bytes_total: p
                .max_decoded_bytes_total
                .unwrap_or(d.max_decoded_bytes_total),
            max_compression_ratio: p.max_compression_ratio.unwrap_or(d.max_compression_ratio),
            max_objects: p.max_objects.unwrap_or(d.max_objects),
            max_revisions: p.max_revisions.unwrap_or(d.max_revisions),
        }
    }

    /// Detection thresholds: defaults overridden by `thresholds`.
    pub fn thresholds(&self) -> Thresholds {
        let p = &self.thresholds;
        let d = Thresholds::default();
        Thresholds {
            max_image_pixels: p.max_image_pixels.unwrap_or(d.max_image_pixels),
            max_page_side_pt: p.max_page_side_pt.unwrap_or(d.max_page_side_pt),
            max_pages: p.max_pages.unwrap_or(d.max_pages),
            max_filter_chain: p.max_filter_chain.unwrap_or(d.max_filter_chain),
            max_trailing_bytes: p.max_trailing_bytes.unwrap_or(d.max_trailing_bytes),
        }
    }

    /// `sha256:<hex>` of the canonical form: fields in a fixed order, map keys
    /// sorted, unset fields and empty maps left out. Key order and whitespace
    /// in the input do not change it; `{}` and `{"preset": "balanced"}` differ
    /// (the digest identifies what was written, not its effect).
    pub fn digest(&self) -> String {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        let hash = Sha256::digest(&canonical);
        let mut s = String::with_capacity(7 + 64);
        s.push_str("sha256:");
        for b in hash.iter() {
            s.push(char::from(HEX[usize::from(b >> 4)]));
            s.push(char::from(HEX[usize::from(b & 0xf)]));
        }
        s
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

impl PolicyLimits {
    fn is_empty(&self) -> bool {
        *self == PolicyLimits::default()
    }
}

impl PolicyThresholds {
    fn is_empty(&self) -> bool {
        *self == PolicyThresholds::default()
    }
}

/// A present field: `null` is not a value (absent fields are `None`).
fn some<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// A struct from a JSON object only (derived structs also accept an array of
/// fields in order: `[]` would be an empty policy).
fn object<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct V_<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for V_<T> {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    d.deserialize_map(V_(PhantomData))
}

/// A JSON object as a map, rejecting duplicate keys (serde_json keeps the
/// last one silently: `{"X": "block", "X": "off"}` must not mean `off`).
fn unique_map<'de, D, K, V>(d: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord + fmt::Debug,
    V: Deserialize<'de>,
{
    struct V_<K, V>(PhantomData<(K, V)>);

    impl<'de, K, V> de::Visitor<'de> for V_<K, V>
    where
        K: Deserialize<'de> + Ord + fmt::Debug,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((k, v)) = map.next_entry::<K, V>()? {
                if out.contains_key(&k) {
                    return Err(de::Error::custom(format_args!("duplicate key {k:?}")));
                }
                out.insert(k, v);
            }
            Ok(out)
        }
    }

    d.deserialize_map(V_(PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::registry;

    fn parse(json: &str) -> Result<Policy, PolicyError> {
        Policy::from_json(json)
    }

    #[test]
    fn empty_is_balanced_with_defaults() {
        let p = parse("{}").unwrap();
        assert_eq!(p, Policy::default());
        assert_eq!(p.preset(), Preset::Balanced);
        assert!(!p.stop_on_first());
        assert!(!p.unsafe_allow_unlock());
        assert_eq!(p.limits(), Limits::default());
        assert_eq!(p.thresholds(), Thresholds::default());
        assert!(p.validate(registry::all()).is_ok());
    }

    #[test]
    fn full_policy_parses() {
        let p = parse(
            r#"{
              "preset": "strict",
              "categories": { "external": "warn", "codecs": "off" },
              "rules": { "ACTIVE.LAUNCH": "off" },
              "limits": { "max_file_bytes": 1000, "max_objects": 5, "max_nesting_depth": 7,
                          "max_decoded_bytes_total": 9, "max_decoded_bytes_per_stream": 8,
                          "max_compression_ratio": 3, "max_revisions": 2 },
              "thresholds": { "max_image_pixels": 10, "max_page_side_pt": 14400.5,
                              "max_pages": 3, "max_filter_chain": 4, "max_trailing_bytes": 0 },
              "stop_on_first": true,
              "unsafe_allow_unlock": true
            }"#,
        )
        .unwrap();
        assert_eq!(p.preset(), Preset::Strict);
        assert_eq!(p.categories[&Category::External], Action::Warn);
        assert_eq!(p.categories[&Category::Codecs], Action::Off);
        assert_eq!(p.rules["ACTIVE.LAUNCH"], Action::Off);
        assert!(p.stop_on_first() && p.unsafe_allow_unlock());
        let l = p.limits();
        assert_eq!(
            (l.max_file_bytes, l.max_objects, l.max_nesting_depth),
            (1000, 5, 7)
        );
        assert_eq!(
            (
                l.max_decoded_bytes_total,
                l.max_decoded_bytes_per_stream,
                l.max_compression_ratio,
                l.max_revisions
            ),
            (9, 8, 3, 2)
        );
        let t = p.thresholds();
        assert_eq!(
            (t.max_image_pixels, t.max_pages, t.max_filter_chain),
            (10, 3, 4)
        );
        assert_eq!((t.max_page_side_pt, t.max_trailing_bytes), (14400.5, 0));
        assert!(p.validate(registry::all()).is_ok());
    }

    #[test]
    fn partial_limits_keep_other_defaults() {
        let p = parse(r#"{"limits": {"max_objects": 3}, "thresholds": {"max_pages": 1}}"#).unwrap();
        assert_eq!(
            p.limits(),
            Limits {
                max_objects: 3,
                ..Limits::default()
            }
        );
        assert_eq!(
            p.thresholds(),
            Thresholds {
                max_pages: 1,
                ..Thresholds::default()
            }
        );
    }

    #[test]
    fn invalid_policies_are_rejected() {
        for bad in [
            "",
            "null",
            "[]",
            "\"balanced\"",
            "{",
            r#"{"preset": "paranoid"}"#,
            r#"{"preset": "Strict"}"#,
            r#"{"preset": 1}"#,
            r#"{"rule": {}}"#,
            r#"{"categories": {"activecontent": "off"}}"#,
            r#"{"categories": {"external": "disable"}}"#,
            r#"{"categories": []}"#,
            r#"{"limits": []}"#,
            r#"{"limits": [1, 2]}"#,
            r#"{"thresholds": [5]}"#,
            r#"{} {}"#,
            r#"{"categories": {"external": "warn", "external": "off"}}"#,
            r#"{"rules": {"ACTIVE.LAUNCH": "off", "ACTIVE.LAUNCH": "block"}}"#,
            r#"{"rules": {"ACTIVE.LAUNCH": true}}"#,
            r#"{"limits": {"max_file_bytes": -1}}"#,
            r#"{"limits": {"max_file_bytes": 1.5}}"#,
            r#"{"limits": {"max_file_bytes": "10"}}"#,
            r#"{"limits": {"max_nesting_depth": 4294967296}}"#,
            r#"{"limits": {"max_pages": 1}}"#,
            r#"{"thresholds": {"max_pages": -3}}"#,
            r#"{"thresholds": {"max_page_side_pt": "a"}}"#,
            r#"{"stop_on_first": "yes"}"#,
            r#"{"unsafe_allow_unlock": 1}"#,
            r#"{"preset": "strict", "preset": "permissive"}"#,
        ] {
            let e = parse(bad).expect_err(bad);
            assert!(e.0.starts_with("invalid policy:"), "{bad}: {e}");
        }
    }

    #[test]
    fn validate_rejects_unknown_rules_and_bad_page_side() {
        let p = parse(r#"{"rules": {"ACTIVE.LAUNCHH": "off"}}"#).unwrap();
        let e = p.validate(registry::all()).unwrap_err();
        assert!(e.0.contains("unknown rule `ACTIVE.LAUNCHH`"), "{e}");
        let p = parse(r#"{"thresholds": {"max_page_side_pt": -1}}"#).unwrap();
        assert!(p.validate(registry::all()).is_err());
        let p = parse(r#"{"thresholds": {"max_page_side_pt": 0}}"#).unwrap();
        assert!(p.validate(registry::all()).is_ok());
        // Rule IDs are checked against the rule set given.
        let p = parse(r#"{"rules": {"ACTIVE.LAUNCH": "off"}}"#).unwrap();
        assert!(p.validate(&[]).is_err());
    }

    #[test]
    fn ignored_unlocks_name_locked_rules_lowered_by_id() {
        let all = registry::all();
        let p = parse(
            r#"{"rules": {"FILETYPE.NOT_PDF_HEADER": "off", "FILETYPE.FOREIGN_MAGIC": "block",
                "ACTIVE.JAVASCRIPT": "off"}, "categories": {"filetype": "off"}}"#,
        )
        .unwrap();
        assert_eq!(p.ignored_unlocks(all), vec!["FILETYPE.NOT_PDF_HEADER"]);
        let p =
            parse(r#"{"rules": {"FILETYPE.NOT_PDF_HEADER": "warn"}, "unsafe_allow_unlock": true}"#)
                .unwrap();
        assert!(p.ignored_unlocks(all).is_empty());
        assert!(Policy::default().ignored_unlocks(all).is_empty());
    }

    #[test]
    fn null_is_not_a_value() {
        for bad in [
            r#"{"preset": null}"#,
            r#"{"stop_on_first": null}"#,
            r#"{"unsafe_allow_unlock": null}"#,
            r#"{"categories": null}"#,
            r#"{"rules": null}"#,
            r#"{"rules": {"ACTIVE.LAUNCH": null}}"#,
            r#"{"limits": null}"#,
            r#"{"limits": {"max_objects": null}}"#,
            r#"{"thresholds": {"max_page_side_pt": null}}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn digest_ignores_key_order_and_whitespace() {
        let a = parse(
            r#"{"preset":"strict","rules":{"ACTIVE.LAUNCH":"off","FILETYPE.NOT_PDF_HEADER":"warn"},"categories":{"xml":"warn","codecs":"off"},"limits":{"max_objects":5,"max_revisions":2}}"#,
        )
        .unwrap();
        let b = parse(
            r#"{ "limits": { "max_revisions": 2, "max_objects": 5 },
                 "categories": { "codecs": "off", "xml": "warn" },
                 "rules": { "FILETYPE.NOT_PDF_HEADER": "warn", "ACTIVE.LAUNCH": "off" },
                 "preset": "strict" }"#,
        )
        .unwrap();
        assert_eq!(a.digest(), b.digest());
        let d = a.digest();
        assert!(d.starts_with("sha256:") && d.len() == 7 + 64, "{d}");
        assert!(d[7..].bytes().all(|c| HEX.contains(&c)));
        // Empty maps are the same as absent.
        let empty = parse("{}").unwrap().digest();
        assert_eq!(
            parse(r#"{"rules":{},"categories":{},"limits":{},"thresholds":{}}"#)
                .unwrap()
                .digest(),
            empty
        );
        // Any change in meaning changes it.
        for other in [
            r#"{"preset":"balanced"}"#,
            r#"{"stop_on_first":false}"#,
            r#"{"rules":{"ACTIVE.LAUNCH":"warn"}}"#,
            r#"{"limits":{"max_objects":5}}"#,
            r#"{"thresholds":{"max_page_side_pt":1}}"#,
        ] {
            assert_ne!(parse(other).unwrap().digest(), empty, "{other}");
        }
        // SHA-256 of "{}" (the canonical form of the empty policy).
        assert_eq!(
            empty,
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
}
