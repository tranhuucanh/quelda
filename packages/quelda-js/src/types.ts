// Public types of the JSON contract (schemas/*.schema.json at the repo root).
// test/schema.test.ts checks these against the schemas field by field.

/** Preset names (`policy.schema.json` `preset`). */
export const PRESETS = ['strict', 'balanced', 'permissive'] as const;
export type Preset = (typeof PRESETS)[number];

/** Category keys (design §5.6), in engine order. */
export const CATEGORIES = [
  'filetype',
  'postscript',
  'active_content',
  'embedded',
  'external',
  'forms',
  'xml',
  'structure',
  'encryption',
  'codecs',
  'resource',
] as const;
export type Category = (typeof CATEGORIES)[number];

/** What a policy can set for a category or rule. */
export const ACTIONS = ['block', 'warn', 'off'] as const;
export type Action = (typeof ACTIONS)[number];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const STAGES = ['preview', 'stable'] as const;
export type Stage = (typeof STAGES)[number];

export const STATUSES = ['PASS', 'REJECT', 'ERROR'] as const;
export type Status = (typeof STATUSES)[number];

/** Rule ID, `CATEGORY.NAME` (e.g. `ACTIVE.LAUNCH`); stable forever. */
export type RuleId = string;

/** Engine guardrails; exceeding one makes the verdict `ERROR` (`LIMIT.*`). */
export interface PolicyLimits {
  max_file_bytes?: number;
  max_objects?: number;
  /** Clamped to 512 by the engine. */
  max_nesting_depth?: number;
  max_decoded_bytes_total?: number;
  max_decoded_bytes_per_stream?: number;
  max_compression_ratio?: number;
  max_revisions?: number;
}

/** Detection thresholds of some rules; exceeding one is a finding. */
export interface PolicyThresholds {
  max_image_pixels?: number;
  max_page_side_pt?: number;
  max_pages?: number;
  max_filter_chain?: number;
  max_trailing_bytes?: number;
}

/**
 * Scan policy (`schemas/policy.schema.json`, design §6). Every field is
 * optional; `{}` is the `balanced` preset. The engine parses it strictly:
 * unknown fields, `null`, wrong types, unknown categories and rule IDs the
 * engine does not know give an `ERROR` verdict with `POLICY.INVALID`.
 */
export interface Policy {
  preset?: Preset;
  /** Category overrides; beat the preset. */
  categories?: { [C in Category]?: Action };
  /** Rule overrides by ID; beat the category. Unknown IDs are rejected. */
  rules?: { [id: RuleId]: Action };
  limits?: PolicyLimits;
  thresholds?: PolicyThresholds;
  /** Stop at the first block finding. */
  stop_on_first?: boolean;
  /** Allow lowering locked rules (reported in the verdict). */
  unsafe_allow_unlock?: boolean;
}

/** Where a rule fired. Every field is optional. */
export interface Location {
  /** `"N G"` of the object. */
  object?: string;
  /** Byte offset in the file (object, its object stream, or the finding). */
  offset?: number;
  /** `file` or `objstm:N`. */
  source?: string;
  /** From the object to the nested dictionary, e.g. `/AA/O`. */
  path?: string;
  /** Offset of a content operator in the decoded stream. */
  op_offset?: number;
  detail?: string;
}

/** One rule that fired (all its hits merged). */
export interface Violation {
  rule_id: RuleId;
  category: Category;
  severity: Severity;
  /** `block` in `violations`, `warn` in `warnings`. */
  action: Exclude<Action, 'off'>;
  message: string;
  /** Every hit, including those beyond the kept locations. */
  count: number;
  /** At most 64. */
  locations: Location[];
}

/**
 * Why a verdict is `ERROR`. Engine codes start with `LIMIT.`, `ENGINE.` or
 * `POLICY.`; the codes this package adds itself are {@link ScannerErrorCode}.
 */
export interface EngineError {
  code: string;
  message: string;
  offset?: number;
}

export interface VerdictPolicy {
  /** `null` when the policy could not be parsed. */
  preset: Preset | null;
  /** `sha256:<hex>` of the canonical policy; `null` when it could not be parsed. */
  digest: string | null;
  unsafe_allow_unlock: boolean;
  stop_on_first: boolean;
}

export interface VerdictStats {
  bytes: number;
  objects: number;
  revisions: number;
  decoded_bytes: number;
  /**
   * Engine time in ms. The WASM engine has no clock, so this package fills it
   * in from `performance.now()` around the engine call (in the worker).
   */
  duration_ms: number;
}

/**
 * Scan result (`schemas/verdict.schema.json`, design §7).
 * `valid` is `true` exactly when `status` is `PASS`; treat anything else as
 * invalid.
 */
export interface Verdict {
  valid: boolean;
  status: Status;
  /** Rules that fired with action `block`, sorted by `rule_id`. */
  violations: Violation[];
  /** Rules that fired with action `warn`, sorted by `rule_id`. */
  warnings: Violation[];
  errors: EngineError[];
  engine_version: string;
  policy: VerdictPolicy;
  stats: VerdictStats;
}

/** One entry of `listRules()` (`schemas/rules.schema.json`). */
export interface RuleInfo {
  id: RuleId;
  category: Category;
  severity: Severity;
  /** Action in the `balanced` preset. */
  default_action: Action;
  /** Policy cannot lower it below `block` (except `unsafe_allow_unlock`). */
  locked: boolean;
  stage: Stage;
  /** Engine version that added the rule. */
  since: string;
  message: string;
  description: string;
}

/**
 * Error codes of `ERROR` verdicts made by this package (not by the engine):
 * - `LIMIT.TIMEOUT`: the scan ran longer than `timeoutMs`; the worker was killed.
 * - `ENGINE.ABORTED`: the `AbortSignal` fired or `terminate()` was called.
 * - `ENGINE.WORKER`: the worker or the WASM engine failed (crash, trap, load
 *   error, malformed reply).
 * - `ENGINE.INPUT`: the input or the scan options could not be used.
 * - `POLICY.INVALID`: the policy object could not be serialized to JSON.
 */
export const SCANNER_ERROR_CODES = [
  'LIMIT.TIMEOUT',
  'ENGINE.ABORTED',
  'ENGINE.WORKER',
  'ENGINE.INPUT',
  'POLICY.INVALID',
] as const;
export type ScannerErrorCode = (typeof SCANNER_ERROR_CODES)[number];

/** What `scan` accepts. `File` is a `Blob`. */
export type ScanInput = Blob | ArrayBuffer | ArrayBufferView;

/** A policy object, or policy JSON text passed to the engine verbatim. */
export type PolicyInput = Policy | string;
