# schemas

JSON Schemas for the public formats, added in Step 8:

- `policy.schema.json`: the policy input (preset → category → rule overrides).
- `verdict.schema.json`: the verdict output (`valid`, `status`, violations, warnings, errors).

Every binding (WASM, CLI) validates against these schemas in the conformance suite.
