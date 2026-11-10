// The built package (dist/: API + worker + .wasm) with the real engine, in a
// Node worker thread. Verdicts must equal the native Rust lib's
// (tests/wasm/golden.json), `stats.duration_ms` aside, on every fixture ×
// preset + every conformance case. Nothing here hard-codes the rule set.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createScanner, type Policy, type Scanner, type ScanInput, type Verdict } from '../dist/index.js';
import { nodeWorkers } from './helpers/node-worker.js';
import { DIST, fixture, golden, schemaErrors, TESTS, type Golden } from './helpers/repo.js';

const PRESET_POLICIES = new Set(['{}', '{"preset":"strict"}', '{"preset":"balanced"}', '{"preset":"permissive"}']);

const comparable = (v: Verdict | string): unknown => {
  const o = typeof v === 'string' ? JSON.parse(v) : structuredClone(v);
  delete o.stats.duration_ms;
  return o;
};

/** The same bytes as each input kind the API accepts. */
function asInput(bytes: Uint8Array<ArrayBuffer>, kind: number): ScanInput {
  switch (kind % 5) {
    case 0:
      return bytes.slice().buffer;
    case 1:
      return bytes;
    case 2:
      return new Blob([bytes]);
    case 3:
      return new File([bytes], 'upload.pdf', { type: 'application/pdf' });
    default: {
      const padded = new Uint8Array(bytes.length + 3);
      padded.set(bytes, 3);
      return padded.subarray(3);
    }
  }
}

let g: Golden;
let module: WebAssembly.Module;
let scanner: Scanner;
const files = new Map<string, Uint8Array<ArrayBuffer>>();
const bytesOf = (file: string): Uint8Array<ArrayBuffer> => {
  let b = files.get(file);
  if (b === undefined) {
    b = fixture(file);
    files.set(file, b);
  }
  return b;
};

beforeAll(async () => {
  g = golden();
  module = new WebAssembly.Module(readFileSync(join(DIST, 'wasm/quelda_bg.wasm')));
  scanner = await createScanner({ worker: nodeWorkers({}).make, wasm: module });
});

afterAll(() => scanner?.terminate());

describe('real engine through the package API', () => {
  it('reports the native engine version and rule list', async () => {
    expect(scanner.engineVersion).toBe(g.version);
    const rules = await scanner.listRules();
    expect(rules).toEqual(JSON.parse(g.list_rules));
    expect(rules.length).toBeGreaterThan(0);
    expect(schemaErrors('rules', rules)).toEqual([]);
  });

  it('matches the native lib on every golden case (fixtures × presets + conformance)', async () => {
    expect(g.cases.length).toBeGreaterThan(0);
    const mismatches: string[] = [];
    let i = 0;
    for (const c of g.cases) {
      const v = await scanner.scan(asInput(bytesOf(c.file), i++), c.policy);
      if (JSON.stringify(comparable(v)) !== JSON.stringify(comparable(c.verdict))) {
        mismatches.push(`${c.file} under ${c.policy}:\n  js:     ${JSON.stringify(v)}\n  native: ${c.verdict}`);
      }
      const errs = schemaErrors('verdict', v);
      if (errs.length > 0) mismatches.push(`${c.file} under ${c.policy}: schema: ${errs.join('; ')}`);
      expect(Number.isInteger(v.stats.duration_ms) && v.stats.duration_ms >= 0).toBe(true);
    }
    expect(mismatches.slice(0, 5)).toEqual([]);
  });

  it('gives the same verdicts for policy objects as for policy JSON', async () => {
    let i = 0;
    let checked = 0;
    for (const c of g.cases) {
      if (!PRESET_POLICIES.has(c.policy)) continue;
      const policy = JSON.parse(c.policy) as Policy;
      const v = await scanner.scan(asInput(bytesOf(c.file), i++), policy);
      expect(comparable(v), `${c.file} under ${c.policy}`).toEqual(comparable(c.verdict));
      checked++;
    }
    expect(checked).toBeGreaterThan(0);
  });

  it('clean file → PASS, malicious file → REJECT', async () => {
    const clean = await scanner.scan(new File([bytesOf('benign/minimal.pdf')], 'minimal.pdf'));
    expect(clean.status).toBe('PASS');
    expect(clean.valid).toBe(true);
    const bad = await scanner.scan(new File([bytesOf('rules/ACTIVE.LAUNCH/bad/in-objstm.pdf')], 'x.pdf'));
    expect(bad.status).toBe('REJECT');
    expect(bad.valid).toBe(false);
    expect(bad.violations.map((v) => v.rule_id)).toContain('ACTIVE.LAUNCH');
  });

  it('scans a pooled Node Buffer (a view into a larger buffer) by its own bytes', async () => {
    const buf = readFileSync(join(TESTS, 'fixtures/benign/minimal.pdf'));
    expect(buf.buffer.byteLength).toBeGreaterThanOrEqual(buf.length);
    const v = await scanner.scan(buf);
    expect(v.status).toBe('PASS');
    expect(v.stats.bytes).toBe(buf.length);
  });

  it('transfer: true detaches the caller buffer and still scans it', async () => {
    const buf = bytesOf('benign/minimal.pdf');
    const own = buf.slice();
    const v = await scanner.scan(own, undefined, { transfer: true });
    expect(own.byteLength).toBe(0);
    expect(v.status).toBe('PASS');
    expect(v.stats.bytes).toBe(buf.length);
  });

  it('a policy naming a rule this engine does not know → POLICY.INVALID; filtering with listRules fixes it', async () => {
    const newer: Policy = { rules: { 'ACTIVE.LAUNCH': 'block', 'ZZZ.FROM_THE_FUTURE': 'warn' } };
    const v = await scanner.scan(bytesOf('benign/minimal.pdf'), newer);
    expect(v.status).toBe('ERROR');
    expect(v.errors.map((e) => e.code)).toEqual(['POLICY.INVALID']);
    const known = new Set((await scanner.listRules()).map((r) => r.id));
    const filtered: Policy = {
      rules: Object.fromEntries(Object.entries(newer.rules ?? {}).filter(([id]) => known.has(id))),
    };
    expect((await scanner.scan(bytesOf('benign/minimal.pdf'), filtered)).status).toBe('PASS');
  });

  it('a malformed policy string → POLICY.INVALID, not an exception', async () => {
    for (const p of ['not json', '[]', 'null', '{"preset":"strict","preset":"strict"}']) {
      const v = await scanner.scan(bytesOf('benign/minimal.pdf'), p);
      expect(v.errors.map((e) => e.code)).toEqual(['POLICY.INVALID']);
      expect(schemaErrors('verdict', v)).toEqual([]);
    }
  });

  it('an empty file is not valid', async () => {
    const v = await scanner.scan(new Uint8Array(0));
    expect(v.valid).toBe(false);
  });
});

describe('real worker lifecycle', () => {
  it('loads the bundled .wasm from its default location next to the worker', async () => {
    const s = await createScanner({ worker: nodeWorkers({ fileFetch: true }).make });
    expect(s.engineVersion).toBe(g.version);
    expect((await s.scan(bytesOf('benign/minimal.pdf'))).status).toBe('PASS');
    s.terminate();
  });

  it('fails to start (rejects) when the .wasm cannot be loaded', async () => {
    // No file: fetch in Node → the default URL cannot load.
    await expect(createScanner({ worker: nodeWorkers({}).make, timeoutMs: 10_000 })).rejects.toMatchObject({
      name: 'QueldaError',
      code: 'ENGINE.WORKER',
    });
    await expect(
      createScanner({ worker: nodeWorkers({}).make, wasm: new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0])) }),
    ).rejects.toMatchObject({ code: 'ENGINE.WORKER' });
  });

  it.each(['exit', 'throw'] as const)('a worker that crashes (%s) mid-scan → ENGINE.WORKER, next scan recovers', async (sabotage) => {
    const f = nodeWorkers({ sabotage }, {});
    const s = await createScanner({ worker: f.make, wasm: module });
    const v = await s.scan(bytesOf('benign/minimal.pdf'));
    expect(v.status).toBe('ERROR');
    expect(v.errors.map((e) => e.code)).toEqual(['ENGINE.WORKER']);
    expect(schemaErrors('verdict', v)).toEqual([]);
    expect((await s.scan(bytesOf('benign/minimal.pdf'))).status).toBe('PASS');
    expect(f.made).toHaveLength(2);
    s.terminate();
  });

  it('a hung engine is killed at the timeout → LIMIT.TIMEOUT, next scan recovers', async () => {
    const f = nodeWorkers({ sabotage: 'hang' }, {});
    const s = await createScanner({ worker: f.make, wasm: module, timeoutMs: 2000 });
    const t0 = performance.now();
    const v = await s.scan(bytesOf('benign/minimal.pdf'), undefined, { timeoutMs: 300 });
    expect(performance.now() - t0).toBeLessThan(1900);
    expect(v.errors.map((e) => e.code)).toEqual(['LIMIT.TIMEOUT']);
    expect((await s.scan(bytesOf('benign/minimal.pdf'))).status).toBe('PASS');
    s.terminate();
  });

  it('terminate during a scan → ENGINE.ABORTED', async () => {
    const s = await createScanner({ worker: nodeWorkers({ sabotage: 'hang' }).make, wasm: module });
    const p = s.scan(bytesOf('benign/minimal.pdf'));
    await new Promise((r) => setTimeout(r, 50));
    s.terminate();
    expect((await p).errors.map((e) => e.code)).toEqual(['ENGINE.ABORTED']);
  });
});
