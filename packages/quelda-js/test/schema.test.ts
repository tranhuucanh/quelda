// The TypeScript types (src/types.ts) against the shared JSON Schemas
// (schemas/*.schema.json), field by field: names, required vs optional,
// primitive types, enums, nested objects, arrays and maps. Uses the
// TypeScript compiler API to read the declared types.

import { join } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  CATEGORIES,
  PRESETS,
  SCANNER_ERROR_CODES,
  SEVERITIES,
  STAGES,
  STATUSES,
} from '../src/types.js';
import { golden, PKG, schemaErrors, schemaJson } from './helpers/repo.js';

type Schema = Record<string, any>;

const TYPES = join(PKG, 'src/types.ts');
const DRIFTED = join(PKG, 'test/fixtures/drifted-types.ts');
const program = ts.createProgram([TYPES, DRIFTED], { strict: true, target: ts.ScriptTarget.ES2022, noEmit: true });
const checker = program.getTypeChecker();

function declaredType(file: string, name: string): ts.Type {
  const sf = program.getSourceFile(file);
  if (sf === undefined) throw new Error(`${file} not in program`);
  const sym = checker.getSymbolAtLocation(sf);
  const exp = sym && checker.getExportsOfModule(sym).find((s) => s.name === name);
  if (exp === undefined) throw new Error(`${name} not exported from ${file}`);
  return checker.getDeclaredTypeOfSymbol(exp);
}

/** Resolves `$ref` and `allOf: [{$ref}, {narrowing}]` (narrowing parts carry no new fields). */
function resolve(root: Schema, node: Schema): Schema {
  if (typeof node.$ref === 'string') {
    const path = (node.$ref as string).replace(/^#\//, '').split('/');
    const target = path.reduce<Schema>((n, k) => n[k], root);
    return resolve(root, { ...target, ...Object.fromEntries(Object.entries(node).filter(([k]) => k !== '$ref')) });
  }
  if (Array.isArray(node.allOf) && node.type === undefined && node.properties === undefined) {
    return resolve(root, node.allOf[0]);
  }
  return node;
}

const members = (t: ts.Type): ts.Type[] => (t.isUnion() ? t.types : [t]);
const withoutUndefined = (t: ts.Type): ts.Type[] => members(t).filter((m) => !(m.flags & ts.TypeFlags.Undefined));
const show = (t: ts.Type): string => checker.typeToString(t);

/** Literal values of a union of literals (+ null), or undefined if it is not one. */
function literals(t: ts.Type): unknown[] | undefined {
  const out: unknown[] = [];
  for (const m of withoutUndefined(t)) {
    if (m.isStringLiteral() || m.isNumberLiteral()) out.push(m.value);
    else if (m.flags & ts.TypeFlags.Null) out.push(null);
    else if (m.flags & ts.TypeFlags.BooleanLiteral) out.push(show(m) === 'true');
    else return undefined;
  }
  return out;
}

/** Schema `type` of a node as a set of primitive names (oneOf / nullable folded). */
function schemaTypes(node: Schema): Set<string> | undefined {
  if (Array.isArray(node.oneOf)) {
    const s = new Set<string>();
    for (const n of node.oneOf) for (const x of schemaTypes(n) ?? []) s.add(x);
    return s;
  }
  if (node.type === undefined) return undefined;
  const ts_ = Array.isArray(node.type) ? node.type : [node.type];
  return new Set(ts_.map((x: string) => (x === 'integer' ? 'number' : x)));
}

function tsPrimitives(t: ts.Type): Set<string> | undefined {
  const s = new Set<string>();
  for (const m of withoutUndefined(t)) {
    if (m.flags & ts.TypeFlags.String) s.add('string');
    else if (m.flags & ts.TypeFlags.Number) s.add('number');
    else if (m.flags & (ts.TypeFlags.Boolean | ts.TypeFlags.BooleanLiteral)) s.add('boolean');
    else if (m.flags & ts.TypeFlags.Null) s.add('null');
    else if (checker.isArrayType(m)) s.add('array');
    else if (m.flags & ts.TypeFlags.Object) s.add('object');
    else return undefined;
  }
  return s;
}

/** Differences between a TS type and a schema node (empty = they agree). */
export function compare(root: Schema, t: ts.Type, raw: Schema, path = '$'): string[] {
  const node = resolve(root, raw);
  const errs: string[] = [];
  if (Array.isArray(node.enum)) {
    const lits = literals(t);
    const want = [...node.enum].map(String).sort();
    if (lits === undefined) return [`${path}: ${show(t)} is not a literal union; schema enum ${JSON.stringify(node.enum)}`];
    const got = lits.map(String).sort();
    if (JSON.stringify(got) !== JSON.stringify(want)) errs.push(`${path}: ${JSON.stringify(got)} ≠ enum ${JSON.stringify(want)}`);
    return errs;
  }
  if (node.const !== undefined) {
    const lits = literals(t);
    if (lits?.length !== 1 || lits[0] !== node.const) errs.push(`${path}: ${show(t)} ≠ const ${JSON.stringify(node.const)}`);
    return errs;
  }
  const want = schemaTypes(node);
  const got = tsPrimitives(t);
  if (want === undefined) return [`${path}: schema node has no type`];
  if (got === undefined || [...want].sort().join() !== [...got].sort().join()) {
    return [`${path}: ${show(t)} (${[...(got ?? ['?'])].join('|')}) ≠ schema ${[...want].join('|')}`];
  }
  const obj = withoutUndefined(t).find((m) => !(m.flags & ts.TypeFlags.Null)) ?? t;
  if (want.has('array')) {
    const el = checker.getTypeArguments(obj as ts.TypeReference)[0];
    if (el === undefined || node.items === undefined) return [`${path}: array without element type`];
    return compare(root, el, node.items, `${path}[]`);
  }
  if (want.has('object')) {
    const props = checker.getPropertiesOfType(obj);
    const propType = (p: ts.Symbol): ts.Type => checker.getTypeOfSymbol(p);
    if (node.properties !== undefined) {
      const required = new Set<string>(node.required ?? []);
      const names = new Set(props.map((p) => p.name));
      for (const k of Object.keys(node.properties)) if (!names.has(k)) errs.push(`${path}.${k}: missing in the type`);
      for (const p of props) {
        const sub = node.properties[p.name];
        if (sub === undefined) {
          errs.push(`${path}.${p.name}: not in the schema`);
          continue;
        }
        const optional = (p.flags & ts.SymbolFlags.Optional) !== 0;
        if (optional === required.has(p.name)) {
          errs.push(`${path}.${p.name}: ${optional ? 'optional' : 'required'} in the type, not in the schema`);
        }
        errs.push(...compare(root, propType(p), sub, `${path}.${p.name}`));
      }
      if (node.additionalProperties !== false) errs.push(`${path}: schema allows additional properties`);
    } else if (node.additionalProperties !== undefined && node.additionalProperties !== false) {
      // A map: either named keys (enum propertyNames) or a string index.
      const keys = node.propertyNames && resolve(root, node.propertyNames);
      if (Array.isArray(keys?.enum)) {
        const names = props.map((p) => p.name).sort();
        if (JSON.stringify(names) !== JSON.stringify([...keys.enum].sort())) {
          errs.push(`${path}: keys ${JSON.stringify(names)} ≠ propertyNames ${JSON.stringify(keys.enum)}`);
        }
        for (const p of props) {
          if (!(p.flags & ts.SymbolFlags.Optional)) errs.push(`${path}.${p.name}: map keys must be optional`);
          errs.push(...compare(root, propType(p), node.additionalProperties, `${path}.${p.name}`));
        }
      } else {
        const index = checker.getIndexInfoOfType(obj, ts.IndexKind.String);
        if (index === undefined || props.length > 0) errs.push(`${path}: expected a string index signature`);
        else errs.push(...compare(root, index.type, node.additionalProperties, `${path}[key]`));
      }
    } else {
      errs.push(`${path}: object schema without properties`);
    }
  }
  return errs;
}

describe('types match the schemas', () => {
  it.each([
    ['Policy', 'policy', (s: Schema) => s],
    ['Verdict', 'verdict', (s: Schema) => s],
    ['RuleInfo', 'rules', (s: Schema) => s.items],
  ] as const)('%s ↔ %s.schema.json', (type, schema, pick) => {
    const root = schemaJson(schema);
    expect(compare(root, declaredType(TYPES, type), pick(root))).toEqual([]);
  });

  it('the comparison catches drift', () => {
    const root = schemaJson('rules');
    const errs = compare(root, declaredType(DRIFTED, 'DriftedRuleInfo'), root.items);
    const where = (p: string): boolean => errs.some((e) => e.startsWith(p));
    expect(where('$.category:')).toBe(true);
    expect(where('$.severity:')).toBe(true);
    expect(where('$.locked: optional')).toBe(true);
    expect(where('$.since:')).toBe(true);
    expect(where('$.description: missing')).toBe(true);
    expect(where('$.extra: not in the schema')).toBe(true);
    expect(where('$.id')).toBe(false);
  });

  it('the exported constants equal the schema enums', () => {
    const policy = schemaJson('policy');
    const verdict = schemaJson('verdict');
    const rules = schemaJson('rules');
    expect([...PRESETS]).toEqual(policy.properties.preset.enum);
    expect([...CATEGORIES]).toEqual(policy.properties.categories.propertyNames.enum);
    expect([...CATEGORIES]).toEqual(verdict.$defs.violation.properties.category.enum);
    expect([...CATEGORIES]).toEqual(rules.$defs.rule.properties.category.enum);
    expect([...ACTIONS]).toEqual(policy.properties.rules.additionalProperties.enum);
    expect([...ACTIONS]).toEqual(rules.$defs.rule.properties.default_action.enum);
    expect([...SEVERITIES]).toEqual(verdict.$defs.violation.properties.severity.enum);
    expect([...STAGES]).toEqual(rules.$defs.rule.properties.stage.enum);
    expect([...STATUSES]).toEqual(verdict.properties.status.enum);
  });

  it('the package error codes fit the verdict schema', () => {
    const pattern = new RegExp(schemaJson('verdict').properties.errors.items.properties.code.pattern);
    for (const code of SCANNER_ERROR_CODES) expect(code).toMatch(pattern);
  });
});

describe('rules.schema.json', () => {
  it('accepts the native list_rules output', () => {
    const rules = JSON.parse(golden().list_rules);
    expect(rules.length).toBeGreaterThan(0);
    expect(schemaErrors('rules', rules)).toEqual([]);
    const ids = rules.map((r: { id: string }) => r.id);
    expect(ids).toEqual([...ids].sort());
  });

  it('rejects malformed rule lists', () => {
    const rule = JSON.parse(golden().list_rules)[0];
    expect(schemaErrors('rules', {})).not.toEqual([]);
    expect(schemaErrors('rules', [{ ...rule, extra: 1 }])).not.toEqual([]);
    expect(schemaErrors('rules', [{ ...rule, id: 'lower.case' }])).not.toEqual([]);
    expect(schemaErrors('rules', [{ ...rule, stage: 'beta' }])).not.toEqual([]);
    const { description: _, ...missing } = rule;
    expect(schemaErrors('rules', [missing])).not.toEqual([]);
  });
});
