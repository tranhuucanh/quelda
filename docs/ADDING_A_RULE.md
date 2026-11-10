# Adding a rule

1. Pick a stable ID `CATEGORY.NAME` (prefix = category, e.g. `ACTIVE.` for `active_content`). Never reuse or rename an ID.
2. Table-shaped match (key / name / name_in / int / all / any / content_op)? Add a `[[rule]]` to `crates/quelda-core/rules/<category>.toml`. The build validates it.
3. Otherwise add one file `crates/quelda-core/src/rules/<category>/<name>.rs` with `pub struct X;`, a `static META: RuleMeta` and `impl Rule for X`. `build.rs` registers it; no other file changes.
4. Rules only detect: read `Ctx`, call `out.report(&META, location, detail)`. No byte parsing, no policy, no `unwrap`/`panic`. Read values with `rules::values` (duplicate keys, indirect values, `/Filter` arrays) and thresholds with `ctx.thresholds()`.
5. New rules start with `stage = "preview"` (at most `warn`) unless the design says otherwise.
6. Fixtures: add `bad` (incl. evasion variants: name-encoded, in-objstm, old-revision, nested-dict, indirect-value; dict cases in `fixtures/dict_cases.rs` get them generically) and `good` (near-miss) cases to `quelda-testkit`, run `cargo run -p quelda-testkit --bin gen-fixtures`.
7. Add the rule to `quelda_testkit::rules::RULES` (spec mirror). If its preset actions differ from its category's, add it to `crates/quelda-core/src/policy/presets.rs` too. Unit-test code rules in their file.
8. `cargo test --workspace`: the fixture harness fails if `rules/<ID>/bad/` or `good/` is missing or wrong.
