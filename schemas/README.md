# schemas

JSON Schemas (draft 2020-12) for the public formats — the contract every binding shares:

- `policy.schema.json` (`urn:quelda:schema:policy:1`): the policy input (preset → category →
  rule overrides, `limits`, `thresholds`, `stop_on_first`, `unsafe_allow_unlock`).
- `verdict.schema.json` (`urn:quelda:schema:verdict:1`): the verdict output (`valid`,
  `status`, violations, warnings, errors, policy digest, stats).
- `rules.schema.json` (`urn:quelda:schema:rules:1`): the rule list (`list_rules`), one
  entry of rule metadata per rule, sorted by `id`.

The engine is stricter than the policy schema in one way: it also rejects duplicate keys
and rule IDs it does not know (`POLICY.INVALID`). Tests in `crates/quelda-core/tests/`
validate real verdicts and sample policies against these files; the npm package tests
(`packages/quelda-js/test/schema.test.ts`) validate WASM verdicts and the native + WASM
rule lists, and check the TypeScript types field by field against all three schemas.
