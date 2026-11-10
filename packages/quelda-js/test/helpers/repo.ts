// Paths into the repo and the shared JSON contract (schemas/*.schema.json).

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';

export const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const ROOT = resolve(PKG, '../..');
export const TESTS = join(ROOT, 'tests');
export const DIST = join(PKG, 'dist');

export type SchemaName = 'policy' | 'verdict' | 'rules';

export function schemaJson(name: SchemaName): Record<string, any> {
  return JSON.parse(readFileSync(join(ROOT, 'schemas', `${name}.schema.json`), 'utf8'));
}

const ajv = new Ajv2020({ strict: true, strictTypes: false, allErrors: true });
const validators = new Map<SchemaName, ValidateFunction>();

/** Schema errors of `value` (empty = valid). */
export function schemaErrors(name: SchemaName, value: unknown): string[] {
  let v = validators.get(name);
  if (v === undefined) {
    v = ajv.compile(schemaJson(name));
    validators.set(name, v);
  }
  return v(value) ? [] : (v.errors ?? []).map((e) => `${e.instancePath} ${e.message ?? ''}`);
}

export interface GoldenCase {
  file: string;
  policy: string;
  verdict: string;
}

export interface Golden {
  version: string;
  list_rules: string;
  cases: GoldenCase[];
}

/** Native verdicts (`cargo run -p quelda-wasm --example wasm_golden`). */
export function golden(): Golden {
  const path = join(TESTS, 'wasm/golden.json');
  if (!existsSync(path)) {
    throw new Error(
      `${path} missing: run \`cargo run -p quelda-testkit --bin gen-fixtures\` then \`cargo run -p quelda-wasm --example wasm_golden\``,
    );
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Fixture bytes as a plain Uint8Array owning its buffer (a Node Buffer may be a pooled view). */
export function fixture(file: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(readFileSync(join(TESTS, 'fixtures', file)));
}
