//! Resolution (design §6.5): the action of one rule under a policy.
//!
//! ```text
//! action = preset.rule_override(id) ?? preset.category(category)
//! action = policy.categories[category] ?? action
//! action = policy.rules[id] ?? action
//! preview rule not named in policy.rules → at most warn
//! locked rule and not unsafe_allow_unlock → block
//! ```

use super::Policy;
use super::presets::{category_action, rule_override};
use crate::rules::{Action, Rule, RuleMeta, Stage};

/// The action of `rule` under `policy`.
pub fn resolve(rule: &RuleMeta, policy: &Policy) -> Action {
    let preset = policy.preset();
    let mut action =
        rule_override(preset, rule.id).unwrap_or_else(|| category_action(preset, rule.category));
    if let Some(&a) = policy.categories.get(&rule.category) {
        action = a;
    }
    let named = policy.rules.get(rule.id);
    if let Some(&a) = named {
        action = a;
    }
    if rule.stage == Stage::Preview && named.is_none() {
        action = action.min(Action::Warn);
    }
    if rule.locked && !policy.unsafe_allow_unlock() {
        action = Action::Block;
    }
    action
}

/// Every rule of `rules` with its action, in order, `off` rules included.
pub fn resolve_all<'r>(rules: &[&'r dyn Rule], policy: &Policy) -> Vec<(&'r dyn Rule, Action)> {
    rules
        .iter()
        .map(|&r| (r, resolve(r.meta(), policy)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Preset;
    use crate::rules::{Category, Severity, registry};
    use Action::{Block as B, Off as O, Warn as W};

    const fn meta(id: &'static str, category: Category, locked: bool, stage: Stage) -> RuleMeta {
        RuleMeta {
            id,
            category,
            severity: Severity::Medium,
            default_action: B,
            locked,
            stage,
            since: "0.1.0",
            message: "test",
            description: "test",
        }
    }

    fn policy(
        preset: Option<Preset>,
        cat: Option<(Category, Action)>,
        rule: Option<(&str, Action)>,
        unlock: bool,
    ) -> Policy {
        Policy {
            preset,
            categories: cat.into_iter().collect(),
            rules: rule.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            unsafe_allow_unlock: unlock.then_some(true),
            ..Policy::default()
        }
    }

    const PRESETS: [Option<Preset>; 4] = [
        None,
        Some(Preset::Strict),
        Some(Preset::Balanced),
        Some(Preset::Permissive),
    ];
    const OVERRIDES: [Option<Action>; 4] = [None, Some(O), Some(W), Some(B)];

    /// Every preset × category override × rule override × locked × unlock ×
    /// stage, against the rules of design §6.1–6.4 written out case by case.
    #[test]
    fn every_combination() {
        // External: strict block, balanced warn, permissive off.
        let preset_action = |p: Option<Preset>| match p {
            None | Some(Preset::Balanced) => W,
            Some(Preset::Strict) => B,
            Some(Preset::Permissive) => O,
        };
        let mut n = 0;
        for locked in [false, true] {
            for stage in [Stage::Stable, Stage::Preview] {
                let m = meta("EXTERNAL.QUELDA_TEST", Category::External, locked, stage);
                for p in PRESETS {
                    for c in OVERRIDES {
                        for r in OVERRIDES {
                            for unlock in [false, true] {
                                let pol = policy(
                                    p,
                                    c.map(|a| (Category::External, a)),
                                    r.map(|a| (m.id, a)),
                                    unlock,
                                );
                                let want = if locked && !unlock {
                                    B
                                } else if let Some(a) = r {
                                    a
                                } else {
                                    let a = c.unwrap_or_else(|| preset_action(p));
                                    if stage == Stage::Preview { a.min(W) } else { a }
                                };
                                assert_eq!(
                                    resolve(&m, &pol),
                                    want,
                                    "locked={locked} {stage:?} preset={p:?} cat={c:?} rule={r:?} unlock={unlock}"
                                );
                                n += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(n, 2 * 2 * 4 * 4 * 4 * 2);
    }

    #[test]
    fn spot_checks() {
        let stable = meta(
            "EXTERNAL.QUELDA_TEST",
            Category::External,
            false,
            Stage::Stable,
        );
        let locked = meta(
            "ACTIVE.QUELDA_TEST",
            Category::ActiveContent,
            true,
            Stage::Stable,
        );
        let preview = meta(
            "ACTIVE.QUELDA_TEST",
            Category::ActiveContent,
            false,
            Stage::Preview,
        );
        // `{}` = balanced.
        assert_eq!(resolve(&stable, &Policy::default()), W);
        // Rule beats category beats preset.
        let p = policy(
            Some(Preset::Permissive),
            Some((Category::External, W)),
            Some((stable.id, B)),
            false,
        );
        assert_eq!(resolve(&stable, &p), B);
        let p = policy(
            Some(Preset::Strict),
            Some((Category::External, O)),
            None,
            false,
        );
        assert_eq!(resolve(&stable, &p), O);
        // Locked: nothing lowers it, unless unsafe_allow_unlock.
        let p = policy(
            Some(Preset::Permissive),
            Some((Category::ActiveContent, O)),
            Some((locked.id, O)),
            false,
        );
        assert_eq!(resolve(&locked, &p), B);
        let p = Policy {
            unsafe_allow_unlock: Some(true),
            ..p
        };
        assert_eq!(resolve(&locked, &p), O);
        assert_eq!(
            resolve(&locked, &policy(Some(Preset::Permissive), None, None, true)),
            W
        );
        // Preview: at most warn, even when its category says block...
        assert_eq!(resolve(&preview, &Policy::default()), W);
        let p = policy(None, Some((Category::ActiveContent, B)), None, false);
        assert_eq!(resolve(&preview, &p), W);
        // ...unless the policy names it; off stays off.
        let p = policy(None, None, Some((preview.id, B)), false);
        assert_eq!(resolve(&preview, &p), B);
        let p = policy(None, Some((Category::ActiveContent, O)), None, false);
        assert_eq!(resolve(&preview, &p), O);
    }

    #[test]
    fn preset_rule_overrides_apply_before_category_overrides() {
        let m = meta("CODEC.TYPE1_FONT", Category::Codecs, false, Stage::Stable);
        assert_eq!(
            resolve(&m, &policy(Some(Preset::Strict), None, None, false)),
            W
        );
        assert_eq!(resolve(&m, &Policy::default()), O);
        let p = policy(None, Some((Category::Codecs, B)), None, false);
        assert_eq!(resolve(&m, &p), B);
    }

    /// Registered rules: `balanced` with no overrides is the rule's
    /// `default_action`, and every preset matches the testkit spec (which
    /// computes the manifest's expected verdicts).
    #[test]
    fn registered_rules_match_default_action_and_spec() {
        for r in registry::all() {
            let m = r.meta();
            let default = match m.stage {
                Stage::Stable => m.default_action,
                Stage::Preview => m.default_action.min(W),
            };
            assert_eq!(resolve(m, &Policy::default()), default, "{}", m.id);
            for p in Preset::ALL {
                let spec_p = quelda_testkit::rules::Preset::ALL
                    .into_iter()
                    .find(|s| s.key() == p.key())
                    .unwrap();
                let want = quelda_testkit::rules::action(m.id, spec_p).key();
                let got = resolve(m, &policy(Some(p), None, None, false));
                // A preview rule is capped at warn; the spec describes stable.
                if m.stage == Stage::Stable {
                    assert_eq!(got.key(), want, "{} {p:?}", m.id);
                }
            }
        }
    }

    #[test]
    fn resolve_all_keeps_order_and_off_rules() {
        let p = policy(None, None, Some(("FILETYPE.NOT_PDF_HEADER", O)), true);
        let all = resolve_all(registry::all(), &p);
        assert_eq!(all.len(), registry::all().len());
        for ((r, a), orig) in all.iter().zip(registry::all()) {
            assert_eq!(r.meta().id, orig.meta().id);
            if r.meta().id == "FILETYPE.NOT_PDF_HEADER" {
                assert_eq!(*a, O);
            }
        }
    }
}
