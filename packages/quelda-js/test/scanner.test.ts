// Wrapper logic with a mock worker (no engine): input normalization, policy
// serialization, verdict parsing, timeouts, cancellation, worker crashes,
// terminate. Every verdict the wrapper makes itself must fit the schema.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createScannerWith, DEFAULT_TIMEOUT_MS, QueldaError, RECYCLE_MEMORY_BYTES, type Scanner } from '../src/scanner.js';
import type { ToWorker } from '../src/protocol.js';
import type { Verdict } from '../src/types.js';
import { defaultReply, factory, MockWorker, RULES, VERSION, verdictJson, type Reply } from './helpers/mock-worker.js';
import { schemaErrors } from './helpers/repo.js';

const PDF = new TextEncoder().encode('%PDF-1.7\n%%EOF\n');

function expectError(v: Verdict, code: string): void {
  expect(v.valid).toBe(false);
  expect(v.status).toBe('ERROR');
  expect(v.errors.map((e) => e.code)).toEqual([code]);
  expect(schemaErrors('verdict', v)).toEqual([]);
}

function expectPass(v: Verdict): void {
  expect(v.status).toBe('PASS');
  expect(v.valid).toBe(true);
}

/** Answers init normally and leaves scans / rules unanswered. */
const silent: Reply = (msg, w) => {
  if (msg.type === 'init') defaultReply(msg, w);
};

/** Answers scans after `ms`. */
const slow =
  (ms: number): Reply =>
  (msg, w) => {
    if (msg.type === 'scan') w.reply({ type: 'scan', id: msg.id, verdict: verdictJson(), durationMs: 1 }, ms);
    else defaultReply(msg, w);
  };

/** Replies to a scan with `data(id)`. */
const scanReply =
  (data: (id: number) => unknown): Reply =>
  (msg, w) => {
    if (msg.type === 'scan') w.reply(data(msg.id));
    else defaultReply(msg, w);
  };

async function scanner(...replies: Reply[]): Promise<{ s: Scanner; workers: MockWorker[] }> {
  const f = factory(...replies);
  const s = await createScannerWith(f.make);
  return { s, workers: f.workers };
}

describe('createScanner', () => {
  it('loads the engine once and reports its version', async () => {
    const { s, workers } = await scanner();
    expect(s.engineVersion).toBe(VERSION);
    expect(workers).toHaveLength(1);
    expect(workers[0]!.posted.map((p) => p.msg)).toEqual([{ type: 'init', wasm: undefined }]);
    expect(Object.isFrozen(s)).toBe(true);
    expect(Object.keys(s).sort()).toEqual(['engineVersion', 'listRules', 'scan', 'terminate']);
    s.terminate();
  });

  it('passes the wasm option to the worker (URL → href, Module as is)', async () => {
    const f = factory();
    await createScannerWith(f.make, { wasm: new URL('https://cdn.example/q.wasm') });
    expect(f.workers[0]!.posted[0]!.msg).toEqual({ type: 'init', wasm: 'https://cdn.example/q.wasm' });
    const module = new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
    await createScannerWith(f.make, { wasm: module });
    const init = f.workers[1]!.posted[0]!.msg as Extract<ToWorker, { type: 'init' }>;
    expect(init.wasm).toBeInstanceOf(WebAssembly.Module);
    await createScannerWith(f.make, { wasm: '/assets/q.wasm' });
    expect(f.workers[2]!.posted[0]!.msg).toEqual({ type: 'init', wasm: '/assets/q.wasm' });
  });

  it('prefers the worker option over the default factory', async () => {
    const f = factory();
    const unused = vi.fn(() => new MockWorker());
    const s = await createScannerWith(unused, { worker: f.make });
    expect(unused).not.toHaveBeenCalled();
    expect(f.workers).toHaveLength(1);
    s.terminate();
  });

  it.each([
    [{ timeoutMs: 0 }],
    [{ timeoutMs: -5 }],
    [{ timeoutMs: Number.NaN }],
    [{ timeoutMs: '100' }],
    [{ worker: 'nope' }],
    [{ wasm: 42 }],
    ['options'],
  ])('rejects bad options %j with ENGINE.INPUT', async (opts) => {
    const f = factory();
    const err = await createScannerWith(f.make, opts as never).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(QueldaError);
    expect((err as QueldaError).code).toBe('ENGINE.INPUT');
    expect(f.workers).toHaveLength(0);
  });

  it('rejects when the engine fails to load, and cleans up the worker', async () => {
    const f = factory((msg, w) => w.reply({ type: 'init-error', message: 'engine failed to load: 404' }));
    const err = await createScannerWith(f.make).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(QueldaError);
    expect((err as QueldaError).code).toBe('ENGINE.WORKER');
    expect((err as QueldaError).message).toContain('404');
    expect(f.workers[0]!.terminated).toBe(1);
    expect(f.workers[0]!.listenerCount()).toBe(0);
  });

  it('rejects when the worker cannot be created', async () => {
    const err = await createScannerWith(() => {
      throw new Error('CSP: worker-src');
    }).catch((e: unknown) => e);
    expect((err as QueldaError).code).toBe('ENGINE.WORKER');
    expect((err as QueldaError).message).toContain('CSP');
  });

  it('rejects when the worker script fails (error event)', async () => {
    const f = factory((msg, w) => setTimeout(() => w.emit('error', { message: 'SyntaxError' })));
    const err = await createScannerWith(f.make).catch((e: unknown) => e);
    expect((err as QueldaError).code).toBe('ENGINE.WORKER');
    expect((err as QueldaError).message).toContain('SyntaxError');
    expect(f.workers[0]!.terminated).toBe(1);
  });

  it('rejects with LIMIT.TIMEOUT when the engine never gets ready', async () => {
    vi.useFakeTimers();
    try {
      const f = factory(() => undefined);
      const p = createScannerWith(f.make, { timeoutMs: 500 }).catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(500);
      const err = await p;
      expect((err as QueldaError).code).toBe('LIMIT.TIMEOUT');
      expect(f.workers[0]!.terminated).toBe(1);
      expect(f.workers[0]!.listenerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('has a 30 s default timeout', () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(30_000);
  });
});

describe('input', () => {
  let s: Scanner;
  let w: MockWorker;
  beforeEach(async () => {
    const r = await scanner();
    s = r.s;
    w = r.workers[0]!;
  });
  afterEach(() => s.terminate());

  const sent = (): Uint8Array => new Uint8Array(w.scans().at(-1)!.bytes!);

  it('copies an ArrayBuffer; the caller keeps it', async () => {
    const buf = PDF.slice().buffer;
    expectPass(await s.scan(buf));
    expect(buf.byteLength).toBe(PDF.length);
    expect(sent()).toEqual(PDF);
    // The posted buffer is always transferred (no second copy).
    const post = w.posted.at(-1)!;
    expect(post.transfer).toHaveLength(1);
    expect(post.transfer[0]).not.toBe(buf);
  });

  it('snapshots the bytes when scan is called', async () => {
    const buf = PDF.slice();
    const p = s.scan(buf);
    buf.fill(0);
    expectPass(await p);
    expect(sent()).toEqual(PDF);
  });

  it('takes only the bytes of a view', async () => {
    const big = new Uint8Array(PDF.length + 8);
    big.set(PDF, 4);
    expectPass(await s.scan(big.subarray(4, 4 + PDF.length)));
    expect(sent()).toEqual(PDF);
    expectPass(await s.scan(new DataView(big.buffer, 4, PDF.length)));
    expect(sent()).toEqual(PDF);
    const words = new Uint16Array([0x2525, 0x4450]);
    expectPass(await s.scan(words));
    expect(sent()).toEqual(new Uint8Array(words.buffer));
  });

  it('passes a Blob or File to the worker unread (the worker reads what it needs)', async () => {
    for (const input of [new Blob([PDF]), new File([PDF], 'a.pdf', { type: 'application/pdf' })]) {
      const read = vi.spyOn(input, 'arrayBuffer');
      expectPass(await s.scan(input));
      expect(read).not.toHaveBeenCalled();
      const msg = w.scans().at(-1)!;
      expect(msg.bytes).toBeUndefined();
      expect(new Uint8Array(await msg.blob!.arrayBuffer())).toEqual(PDF);
      expect(w.posted.at(-1)!.transfer).toHaveLength(0);
    }
  });

  it('copies SharedArrayBuffer data', async () => {
    const sab = new SharedArrayBuffer(PDF.length);
    new Uint8Array(sab).set(PDF);
    expectPass(await s.scan(sab as unknown as ArrayBuffer));
    expect(sent()).toEqual(PDF);
    expectPass(await s.scan(new Uint8Array(sab)));
    expect(sent()).toEqual(PDF);
  });

  it('transfer: true hands over the caller buffer at call time (detached)', async () => {
    const buf = PDF.slice().buffer;
    const p = s.scan(buf, undefined, { transfer: true });
    expect(buf.byteLength).toBe(0); // detached right away, not when the scan starts
    expectPass(await p);
    expect(sent()).toEqual(PDF);
    const whole = PDF.slice();
    expectPass(await s.scan(whole, undefined, { transfer: true }));
    expect(whole.byteLength).toBe(0);
  });

  it('transfer: true copies a view that does not span its buffer', async () => {
    const big = new Uint8Array(PDF.length + 1);
    big.set(PDF);
    const view = big.subarray(0, PDF.length);
    expectPass(await s.scan(view, undefined, { transfer: true }));
    expect(big.byteLength).toBe(PDF.length + 1);
    expect(sent()).toEqual(PDF);
  });

  it.each([
    ['a string', '%PDF-1.7'],
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['a plain object', { byteLength: 3 }],
    ['an array of numbers', [37, 80, 68, 70]],
  ])('rejects %s as ENGINE.INPUT without contacting the engine', async (_, input) => {
    expectError(await s.scan(input as never), 'ENGINE.INPUT');
    expect(w.scans()).toHaveLength(0);
  });

  it('rejects a detached buffer', async () => {
    const buf = PDF.slice().buffer;
    const view = new Uint8Array(buf);
    structuredClone(buf, { transfer: [buf] });
    expectError(await s.scan(buf), 'ENGINE.INPUT');
    expectError(await s.scan(view), 'ENGINE.INPUT');
    expect(w.scans()).toHaveLength(0);
  });

  it('gives ENGINE.INPUT when the worker cannot read the file; the worker is kept', async () => {
    const { s, workers } = await scanner((msg, w) => {
      if (msg.type === 'scan' && msg.blob !== undefined) {
        w.reply({ type: 'input-error', id: msg.id, message: 'could not read the file: file changed' });
      } else defaultReply(msg, w);
    });
    const v = await s.scan(new Blob([PDF]));
    expectError(v, 'ENGINE.INPUT');
    expect(v.errors[0]!.message).toContain('file changed');
    expect(v.stats.bytes).toBe(PDF.length);
    expectPass(await s.scan(PDF));
    expect(workers).toHaveLength(1);
    expect(workers[0]!.terminated).toBe(0);
    s.terminate();
  });

  it.each([
    [{ transfer: 'yes' }],
    [{ signal: {} }],
    [{ timeoutMs: -1 }],
    [{ timeoutMs: Number.NaN }],
    ['fast'],
  ])('rejects bad scan options %j as ENGINE.INPUT', async (opts) => {
    expectError(await s.scan(PDF, undefined, opts as never), 'ENGINE.INPUT');
    expect(w.scans()).toHaveLength(0);
  });
});

describe('policy', () => {
  let s: Scanner;
  let w: MockWorker;
  beforeEach(async () => {
    const r = await scanner();
    s = r.s;
    w = r.workers[0]!;
  });
  afterEach(() => s.terminate());

  it('sends {} by default, objects as JSON, strings verbatim', async () => {
    await s.scan(PDF);
    expect(w.scans().at(-1)!.policy).toBe('{}');
    await s.scan(PDF, { preset: 'strict', rules: { 'ACTIVE.LAUNCH': 'block' } });
    expect(w.scans().at(-1)!.policy).toBe('{"preset":"strict","rules":{"ACTIVE.LAUNCH":"block"}}');
    const raw = '{"preset":"strict","preset":"permissive"}'; // engine rejects duplicates
    await s.scan(PDF, raw);
    expect(w.scans().at(-1)!.policy).toBe(raw);
  });

  it('leaves null and other values for the engine to reject', async () => {
    await s.scan(PDF, null as never);
    expect(w.scans().at(-1)!.policy).toBe('null');
    await s.scan(PDF, 5 as never);
    expect(w.scans().at(-1)!.policy).toBe('5');
  });

  it('gives POLICY.INVALID when the policy is not serializable', async () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expectError(await s.scan(PDF, cyclic as never), 'POLICY.INVALID');
    expectError(await s.scan(PDF, { limits: { max_file_bytes: 10n } } as never), 'POLICY.INVALID');
    expectError(await s.scan(PDF, (() => 1) as never), 'POLICY.INVALID');
    expect(w.scans()).toHaveLength(0);
  });
});

describe('verdict', () => {
  it('returns the engine verdict and fills duration_ms', async () => {
    const { s } = await scanner(scanReply((id) => ({ type: 'scan', id, verdict: verdictJson('REJECT'), durationMs: 12.6 })));
    const v = await s.scan(PDF);
    expect(v.status).toBe('REJECT');
    expect(v.valid).toBe(false);
    expect(v.violations[0]!.rule_id).toBe('ACTIVE.LAUNCH');
    expect(v.stats.duration_ms).toBe(13);
    expect(schemaErrors('verdict', v)).toEqual([]);
    s.terminate();
  });

  it('keeps a non-zero duration_ms from the engine', async () => {
    const json = verdictJson('PASS', { stats: { bytes: 1, objects: 1, revisions: 1, decoded_bytes: 0, duration_ms: 7 } });
    const { s } = await scanner(scanReply((id) => ({ type: 'scan', id, verdict: json, durationMs: 99 })));
    expect((await s.scan(PDF)).stats.duration_ms).toBe(7);
    s.terminate();
  });

  it.each([
    ['NaN', Number.NaN],
    ['negative', -3],
    ['missing', undefined],
  ])('ignores a %s durationMs', async (_, durationMs) => {
    const { s } = await scanner(scanReply((id) => ({ type: 'scan', id, verdict: verdictJson(), durationMs })));
    expect((await s.scan(PDF)).stats.duration_ms).toBe(0);
    s.terminate();
  });

  it('passes engine ERROR verdicts through', async () => {
    const { s } = await scanner(scanReply((id) => ({ type: 'scan', id, verdict: verdictJson('ERROR'), durationMs: 1 })));
    expectError(await s.scan(PDF), 'LIMIT.DECODED_BYTES');
    s.terminate();
  });

  const pass = JSON.parse(verdictJson('PASS'));
  it.each([
    ['not JSON', '{"valid":'],
    ['not a string', 42],
    ['an array', '[]'],
    ['valid without PASS', JSON.stringify({ ...JSON.parse(verdictJson('REJECT')), valid: true })],
    ['PASS but not valid', JSON.stringify({ ...pass, valid: false })],
    ['an unknown status', JSON.stringify({ ...pass, status: 'OK' })],
    ['PASS with violations', JSON.stringify({ ...JSON.parse(verdictJson('REJECT')), status: 'PASS', valid: true })],
    ['PASS with errors', JSON.stringify({ ...pass, errors: [{ code: 'ENGINE.X', message: 'x' }] })],
    ['REJECT without violations', JSON.stringify({ ...pass, status: 'REJECT', valid: false })],
    ['ERROR without errors', JSON.stringify({ ...pass, status: 'ERROR', valid: false })],
    ['no stats', JSON.stringify({ ...pass, stats: undefined })],
    ['no engine_version', JSON.stringify({ ...pass, engine_version: 1 })],
    ['warnings not a list', JSON.stringify({ ...pass, warnings: {} })],
  ])('turns a verdict that is %s into ENGINE.WORKER and replaces the worker', async (_, verdict) => {
    const { s, workers } = await scanner(
      scanReply((id) => ({ type: 'scan', id, verdict, durationMs: 1 })),
      defaultReply,
    );
    expectError(await s.scan(PDF), 'ENGINE.WORKER');
    expect(workers[0]!.terminated).toBe(1);
    expectPass(await s.scan(PDF));
    expect(workers).toHaveLength(2);
    s.terminate();
  });
});

/** With fake timers the mock's ready reply needs a timer tick. */
async function started<T>(p: Promise<T>): Promise<T> {
  await vi.advanceTimersByTimeAsync(0);
  return p;
}

describe('timeout', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('kills a stuck scan: LIMIT.TIMEOUT, then a fresh worker', async () => {
    const f = factory(silent, defaultReply);
    const s = await started(createScannerWith(f.make, { timeoutMs: 1000 }));
    const p = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(999);
    let settled = false;
    void p.then(() => (settled = true));
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const v = await p;
    expectError(v, 'LIMIT.TIMEOUT');
    expect(v.stats.bytes).toBe(PDF.length);
    expect(v.engine_version).toBe(VERSION);
    expect(f.workers[0]!.terminated).toBe(1);
    expect(f.workers[0]!.listenerCount()).toBe(0);
    const next = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(10);
    expectPass(await next);
    expect(f.workers).toHaveLength(2);
    s.terminate();
  });

  it('per-scan timeoutMs overrides the scanner one', async () => {
    const s = await started(createScannerWith(factory(slow(300)).make, { timeoutMs: 1000 }));
    const p = s.scan(PDF, undefined, { timeoutMs: 200 });
    await vi.advanceTimersByTimeAsync(200);
    expectError(await p, 'LIMIT.TIMEOUT');
    s.terminate();
  });

  it('counts each scan from when it starts, not from when it was queued', async () => {
    const f = factory(slow(700));
    const s = await started(createScannerWith(f.make, { timeoutMs: 1000 }));
    const a = s.scan(PDF);
    const b = s.scan(PDF);
    const c = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(2100);
    for (const v of await Promise.all([a, b, c])) expectPass(v);
    expect(f.workers).toHaveLength(1);
    s.terminate();
  });

  it('a timeout kills only the running scan; queued scans run on a new worker', async () => {
    const f = factory(silent, defaultReply);
    const s = await started(createScannerWith(f.make, { timeoutMs: 1000 }));
    const a = s.scan(PDF);
    const b = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(1000);
    expectError(await a, 'LIMIT.TIMEOUT');
    await vi.advanceTimersByTimeAsync(10);
    expectPass(await b);
    expect(f.workers).toHaveLength(2);
    s.terminate();
  });

  it('a timeout while a replacement worker starts kills that worker too', async () => {
    const f = factory(silent, () => undefined, defaultReply);
    const s = await started(createScannerWith(f.make, { timeoutMs: 1000 }));
    const a = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(1000);
    expectError(await a, 'LIMIT.TIMEOUT');
    const b = s.scan(PDF); // worker 2 never gets ready
    await vi.advanceTimersByTimeAsync(1000);
    expectError(await b, 'LIMIT.TIMEOUT');
    expect(f.workers[1]!.terminated).toBe(1);
    const c = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(10);
    expectPass(await c);
    expect(f.workers).toHaveLength(3);
    s.terminate();
  });

  it('clamps timeouts beyond what setTimeout supports instead of firing at once', async () => {
    const s = await started(createScannerWith(factory(slow(50)).make, { timeoutMs: 1e12 }));
    const p = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(50);
    expectPass(await p);
    s.terminate();
  });

  it('Infinity disables the timeout', async () => {
    const s = await started(createScannerWith(factory(slow(10 * 60_000)).make, { timeoutMs: Infinity }));
    const p = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expectPass(await p);
    s.terminate();
  });

  it('listRules rejects with LIMIT.TIMEOUT', async () => {
    const s = await started(createScannerWith(factory(silent).make, { timeoutMs: 100 }));
    const p = s.listRules().catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(100);
    expect(((await p) as QueldaError).code).toBe('LIMIT.TIMEOUT');
    s.terminate();
  });

  it('a late reply from a killed worker is ignored', async () => {
    const f = factory(slow(2000), defaultReply);
    const s = await started(createScannerWith(f.make, { timeoutMs: 1000 }));
    const a = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(1000);
    expectError(await a, 'LIMIT.TIMEOUT');
    const b = s.scan(PDF);
    await vi.advanceTimersByTimeAsync(5000); // worker 1 "replies" at 2000 ms
    expectPass(await b);
    expect(f.workers[1]!.terminated).toBe(0);
    s.terminate();
  });
});

describe('abort', () => {
  it('an already aborted signal gives ENGINE.ABORTED without contacting the engine', async () => {
    const { s, workers } = await scanner();
    expectError(await s.scan(PDF, undefined, { signal: AbortSignal.abort() }), 'ENGINE.ABORTED');
    expect(workers[0]!.scans()).toHaveLength(0);
    await expect(s.listRules({ signal: AbortSignal.abort() })).rejects.toMatchObject({ code: 'ENGINE.ABORTED' });
    s.terminate();
  });

  it('aborting a running scan kills the worker; the next scan gets a new one', async () => {
    const { s, workers } = await scanner(silent, defaultReply);
    const ctl = new AbortController();
    const p = s.scan(PDF, undefined, { signal: ctl.signal });
    await vi.waitFor(() => expect(workers[0]!.scans()).toHaveLength(1));
    ctl.abort();
    expectError(await p, 'ENGINE.ABORTED');
    expect(workers[0]!.terminated).toBe(1);
    expectPass(await s.scan(PDF));
    expect(workers).toHaveLength(2);
    s.terminate();
  });

  it('aborting a queued scan leaves the running one and the worker alone', async () => {
    const { s, workers } = await scanner(slow(30));
    const ctl = new AbortController();
    const a = s.scan(PDF);
    const b = s.scan(PDF, undefined, { signal: ctl.signal });
    const c = s.scan(PDF);
    ctl.abort();
    expectError(await b, 'ENGINE.ABORTED');
    expectPass(await a);
    expectPass(await c);
    expect(workers[0]!.terminated).toBe(0);
    expect(workers[0]!.scans()).toHaveLength(2);
    s.terminate();
  });

  it('removes its abort listener when the scan ends', async () => {
    const { s } = await scanner();
    const ctl = new AbortController();
    const add = vi.spyOn(ctl.signal, 'addEventListener');
    const remove = vi.spyOn(ctl.signal, 'removeEventListener');
    for (let i = 0; i < 5; i++) expectPass(await s.scan(PDF, undefined, { signal: ctl.signal }));
    expect(add).toHaveBeenCalledTimes(5);
    expect(remove).toHaveBeenCalledTimes(5);
    expect(remove.mock.calls.map((c) => c[1])).toEqual(add.mock.calls.map((c) => c[1]));
    ctl.abort(); // no effect on finished scans
    s.terminate();
  });
});

describe('worker failures', () => {
  it('error event during a scan → ENGINE.WORKER, then a new worker', async () => {
    const crash: Reply = (msg, w) => {
      if (msg.type === 'scan') setTimeout(() => w.emit('error', { message: 'out of memory' }));
      else defaultReply(msg, w);
    };
    const { s, workers } = await scanner(crash, defaultReply);
    const v = await s.scan(PDF);
    expectError(v, 'ENGINE.WORKER');
    expect(v.errors[0]!.message).toContain('out of memory');
    expect(workers[0]!.terminated).toBe(1);
    expect(workers[0]!.listenerCount()).toBe(0);
    expectPass(await s.scan(PDF));
    s.terminate();
  });

  it('messageerror → ENGINE.WORKER', async () => {
    const bad: Reply = (msg, w) => {
      if (msg.type === 'scan') setTimeout(() => w.emit('messageerror', {}));
      else defaultReply(msg, w);
    };
    const { s } = await scanner(bad, defaultReply);
    expectError(await s.scan(PDF), 'ENGINE.WORKER');
    expectPass(await s.scan(PDF));
    s.terminate();
  });

  it('an engine trap (fail) → ENGINE.WORKER and the worker is never reused', async () => {
    const { s, workers } = await scanner(
      scanReply((id) => ({ type: 'fail', id, message: 'engine failed: RuntimeError: unreachable' })),
      defaultReply,
    );
    const v = await s.scan(PDF);
    expectError(v, 'ENGINE.WORKER');
    expect(v.errors[0]!.message).toContain('unreachable');
    expect(workers[0]!.terminated).toBe(1);
    expectPass(await s.scan(PDF));
    expect(workers).toHaveLength(2);
    s.terminate();
  });

  it.each([
    ['a reply for another id', (id: number) => ({ type: 'scan', id: id + 1, verdict: verdictJson(), durationMs: 1 })],
    ['a rules reply to a scan', (id: number) => ({ type: 'rules', id, rules: '[]' })],
    ['garbage', () => 'hello'],
    ['null', () => null],
    ['a second ready with a bad version', () => ({ type: 'ready', version: 1 })],
  ])('%s → ENGINE.WORKER', async (_, data) => {
    const { s, workers } = await scanner(scanReply(data), defaultReply);
    expectError(await s.scan(PDF), 'ENGINE.WORKER');
    expect(workers[0]!.terminated).toBe(1);
    expectPass(await s.scan(PDF));
    s.terminate();
  });

  it('a crash while idle is recovered on the next scan', async () => {
    const { s, workers } = await scanner();
    workers[0]!.emit('error', { message: 'boom' });
    expect(workers[0]!.terminated).toBe(1);
    expectPass(await s.scan(PDF));
    expect(workers).toHaveLength(2);
    s.terminate();
  });

  it('a replacement worker that fails to start → ENGINE.WORKER; the next scan retries', async () => {
    let n = 0;
    const flaky = (): MockWorker => {
      n++;
      if (n === 2) throw new Error('quota exceeded');
      if (n === 3) return new MockWorker((msg, w) => w.reply({ type: 'init-error', message: 'bad wasm' }));
      return new MockWorker(n === 1 ? scanReply((id) => ({ type: 'fail', id, message: 'trap' })) : defaultReply);
    };
    const s = await createScannerWith(flaky);
    expectError(await s.scan(PDF), 'ENGINE.WORKER'); // trap on worker 1
    const v2 = await s.scan(PDF); // worker 2 cannot be created
    expectError(v2, 'ENGINE.WORKER');
    expect(v2.errors[0]!.message).toContain('quota exceeded');
    const v3 = await s.scan(PDF); // worker 3 fails to load the engine
    expectError(v3, 'ENGINE.WORKER');
    expect(v3.errors[0]!.message).toContain('bad wasm');
    expectPass(await s.scan(PDF)); // worker 4 works
    s.terminate();
  });

  it('postMessage throwing → ENGINE.WORKER', async () => {
    const f = factory();
    const s = await createScannerWith(f.make);
    f.workers[0]!.postMessage = () => {
      throw new DOMException('could not clone', 'DataCloneError');
    };
    const v = await s.scan(PDF);
    expectError(v, 'ENGINE.WORKER');
    expect(v.errors[0]!.message).toContain('could not clone');
    expectPass(await s.scan(PDF));
    s.terminate();
  });
});

describe('queue', () => {
  it('runs one request at a time, in order', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const order: number[] = [];
    const reply: Reply = (msg, w) => {
      if (msg.type === 'init') return defaultReply(msg, w);
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      order.push(msg.id);
      setTimeout(() => {
        inFlight--;
        defaultReply(msg, w);
      }, 5);
    };
    const { s } = await scanner(reply);
    const results = await Promise.all([s.scan(PDF), s.listRules(), s.scan(new Blob([PDF])), s.scan(PDF.buffer)]);
    expect(maxInFlight).toBe(1);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(results).toHaveLength(4);
    s.terminate();
  });

  it('many concurrent scans all settle', async () => {
    const { s } = await scanner(slow(1));
    const vs = await Promise.all(Array.from({ length: 50 }, () => s.scan(PDF)));
    for (const v of vs) expectPass(v);
    s.terminate();
  });
});

describe('listRules', () => {
  it('returns the rules, asks the engine once, and hands out fresh copies', async () => {
    const { s, workers } = await scanner();
    const a = await s.listRules();
    expect(a).toEqual(RULES);
    a[0]!.locked = false;
    const b = await s.listRules();
    expect(b).toEqual(RULES);
    expect(workers[0]!.posted.filter((p) => p.msg.type === 'rules')).toHaveLength(1);
    s.terminate();
  });

  it.each([
    ['not JSON', 'nope'],
    ['not a list', '{}'],
    ['entries without id', '[{"name":"x"}]'],
  ])('rejects a rule list that is %s', async (_, rules) => {
    const reply: Reply = (msg, w) => {
      if (msg.type === 'rules') w.reply({ type: 'rules', id: msg.id, rules });
      else defaultReply(msg, w);
    };
    const { s, workers } = await scanner(reply, defaultReply);
    await expect(s.listRules()).rejects.toMatchObject({ name: 'QueldaError', code: 'ENGINE.WORKER' });
    expect(workers[0]!.terminated).toBe(1);
    s.terminate();
  });
});

describe('terminate', () => {
  it('ends pending work with ENGINE.ABORTED and refuses new work', async () => {
    const { s, workers } = await scanner(silent);
    const running = s.scan(PDF);
    const queued = s.scan(PDF);
    const rules = s.listRules().catch((e: unknown) => e);
    await vi.waitFor(() => expect(workers[0]!.scans()).toHaveLength(1));
    s.terminate();
    s.terminate(); // idempotent
    expectError(await running, 'ENGINE.ABORTED');
    expectError(await queued, 'ENGINE.ABORTED');
    expect(((await rules) as QueldaError).code).toBe('ENGINE.ABORTED');
    expect(workers[0]!.terminated).toBe(1);
    expect(workers[0]!.listenerCount()).toBe(0);
    expectError(await s.scan(PDF), 'ENGINE.ABORTED');
    await expect(s.listRules()).rejects.toMatchObject({ code: 'ENGINE.ABORTED' });
    expect(workers).toHaveLength(1);
  });

  it('works while a scan of a file is queued', async () => {
    const { s, workers } = await scanner();
    const p = s.scan(new Blob([PDF]));
    s.terminate();
    expectError(await p, 'ENGINE.ABORTED');
    expect(workers[0]!.scans()).toHaveLength(0);
  });
});

describe('worker recycling', () => {
  const withMemory =
    (memory: number): Reply =>
    (msg, w) => {
      if (msg.type === 'scan') w.reply({ type: 'scan', id: msg.id, verdict: verdictJson(), durationMs: 1, memory });
      else defaultReply(msg, w);
    };

  it('replaces a worker whose WASM memory grew past the threshold', async () => {
    const { s, workers } = await scanner(withMemory(RECYCLE_MEMORY_BYTES + 1), withMemory(1 << 20));
    expectPass(await s.scan(PDF));
    expect(workers[0]!.terminated).toBe(1);
    expectPass(await s.scan(PDF)); // a fresh worker
    expect(workers).toHaveLength(2);
    expect(workers[1]!.scans()).toHaveLength(1);
    expectPass(await s.scan(PDF)); // small memory: kept
    expect(workers).toHaveLength(2);
    expect(workers[1]!.terminated).toBe(0);
    s.terminate();
  });

  it('a queued request runs on the new worker', async () => {
    const { s, workers } = await scanner(withMemory(RECYCLE_MEMORY_BYTES * 2), withMemory(0));
    const [a, rules, b] = await Promise.all([s.scan(PDF), s.listRules(), s.scan(new Blob([PDF]))]);
    expectPass(a);
    expect(rules).toEqual(RULES);
    expectPass(b);
    expect(workers).toHaveLength(2);
    s.terminate();
  });
});
