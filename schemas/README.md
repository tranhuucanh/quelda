# schemas

JSON Schemas (draft 2020-12) for the public formats — the contract every binding shares:

- `policy.schema.json` (`urn:quelda:schema:policy:1`): the policy input (preset → category →
  rule overrides, `limits`, `thresholds`, `stop_on_first`, `unsafe_allow_unlock`).
- `verdict.schema.json` (`urn:quelda:schema:verdict:1`): the verdict output (`valid`,
  `status`, violations, warnings, errors, policy digest, stats).

The engine is stricter than the policy schema in one way: it also rejects duplicate keys
and rule IDs it does not know (`POLICY.INVALID`). Tests in `crates/quelda-core/tests/`
validate real verdicts and sample policies against these files.
