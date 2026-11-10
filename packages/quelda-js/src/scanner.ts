// Main-thread side of the scanner: input normalization, one worker running one
// request at a time, timeouts / cancellation (kill the worker), and turning
// every failure into an ERROR verdict (fail-closed). No scan logic: the WASM
// engine in the worker does all of it.

import { errorMessage, type FromWorker, type WorkerEvent, type WorkerLike } from './protocol.js';
import {
  STATUSES,
  type PolicyInput,
  type RuleInfo,
  type ScanInput,
  type ScannerErrorCode,
  type Verdict,
} from './types.js';

/** Default per-request timeout (ms). */
export const DEFAULT_TIMEOUT_MS = 30_000;
/** Longest delay `setTimeout` honours (larger values fire at once). */
const MAX_TIMER_MS = 2_147_483_647;

export interface ScannerOptions {
  /**
   * Per request (scan, listRules, worker start-up) in ms; default 30 000.
   * `Infinity` disables it. On timeout the worker is killed and the scan
   * gives an `ERROR` verdict (`LIMIT.TIMEOUT`).
   */
  timeoutMs?: number;
  /**
   * Where the worker loads the engine from: a URL (resolved against the
   * page) or a compiled `WebAssembly.Module`. Default: the `.wasm` file
   * shipped next to the worker, located by your bundler.
   */
  wasm?: string | URL | WebAssembly.Module;
  /**
   * Advanced: creates the worker (e.g. under a strict CSP or when the package
   * is served from another origin). It must run this package's `worker.js`.
   */
  worker?: () => WorkerLike;
}

export interface ScanOptions {
  /** Overrides the scanner's `timeoutMs` for this scan. */
  timeoutMs?: number;
  /** Aborting gives an `ERROR` verdict (`ENGINE.ABORTED`). */
  signal?: AbortSignal;
  /**
   * `true`: hand the caller's `ArrayBuffer` (or the buffer of a `Uint8Array`
   * that spans it whole) to the worker without copying. The caller's buffer
   * is detached (length 0) afterwards. Default `false`: the bytes are copied
   * when `scan` is called and the caller's buffer is untouched.
   */
  transfer?: boolean;
}

export interface ListRulesOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface Scanner {
  /** Engine version (`engine_version` in verdicts). */
  readonly engineVersion: string;
  /**
   * Scans one file. Never rejects: anything that goes wrong (bad input,
   * timeout, abort, worker crash, `terminate()`) gives a verdict with
   * `status: "ERROR"` and `valid: false`.
   */
  scan(input: ScanInput, policy?: PolicyInput, options?: ScanOptions): Promise<Verdict>;
  /** Every rule the engine knows, sorted by ID. Rejects with a {@link QueldaError}. */
  listRules(options?: ListRulesOptions): Promise<RuleInfo[]>;
  /** Kills the worker. Pending scans give `ERROR` verdicts; later calls fail. Idempotent. */
  terminate(): void;
}

/** Rejection reason of `createScanner` and `listRules`. */
export class QueldaError extends Error {
  readonly code: ScannerErrorCode;
  constructor(code: ScannerErrorCode, message: string) {
    super(message);
    this.name = 'QueldaError';
    this.code = code;
  }
}

/** A failure outside the engine (internal; never confused with DOMException & co). */
class Failure {
  constructor(
    readonly code: ScannerErrorCode,
    readonly message: string,
  ) {}
}

type Outcome = { ok: true; verdict?: Verdict; rules?: RuleInfo[] } | { ok: false; failure: Failure };

type Phase = 'queued' | 'preparing' | 'starting' | 'running';

interface Job {
  id: number;
  kind: 'scan' | 'rules';
  phase: Phase;
  done: boolean;
  timeoutMs: number | null;
  /** Owned bytes + policy JSON (scan only); rejects with a Failure. */
  payload?: Promise<{ bytes: ArrayBuffer; policy: string }>;
  /** Input size for synthesized verdicts. */
  bytes: number;
  started: number;
  timer?: ReturnType<typeof setTimeout>;
  slot?: Slot;
  unlisten?: () => void;
  settle(outcome: Outcome): void;
}

interface Slot {
  worker: WorkerLike;
  ready: Promise<void>;
  dead: boolean;
  onReady(): void;
  onDead(reason: Error): void;
  detach(): void;
}

const now = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());

const tag = (x: unknown): string => Object.prototype.toString.call(x);

function isDetached(buf: ArrayBufferLike): boolean {
  return (buf as { detached?: boolean }).detached === true;
}

/**
 * Moves the caller's buffer into a new one without copying, so it is detached
 * right when `scan` is called (not later, when a queued scan starts).
 */
function take(buf: ArrayBuffer): ArrayBuffer {
  if (typeof structuredClone !== 'function') return buf; // detached when posted
  try {
    return structuredClone(buf, { transfer: [buf] });
  } catch (e) {
    throw failure('ENGINE.INPUT', `could not transfer the buffer: ${errorMessage(e)}`);
  }
}

function failure(code: ScannerErrorCode, message: string): Failure {
  return new Failure(code, message);
}

function isFailure(x: unknown): x is Failure {
  return x instanceof Failure;
}

/** Validated timeout: `null` = none. Throws a Failure. */
export function resolveTimeout(value: unknown, fallback: number | null): number | null {
  if (value === undefined) return fallback;
  if (value === Infinity) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw failure('ENGINE.INPUT', `timeoutMs must be a positive number or Infinity, got ${String(value)}`);
  }
  return Math.min(value, MAX_TIMER_MS);
}

/**
 * Turns the input into an `ArrayBuffer` the scanner owns (safe to transfer).
 * Copies unless `transfer` is set and the buffer can be handed over whole.
 * Throws / rejects with a Failure.
 */
export async function normalizeInput(input: unknown, transfer: boolean): Promise<ArrayBuffer> {
  const t = tag(input);
  if (t === '[object ArrayBuffer]') {
    const buf = input as ArrayBuffer;
    if (isDetached(buf)) throw failure('ENGINE.INPUT', 'the ArrayBuffer is detached');
    return transfer ? take(buf) : buf.slice(0);
  }
  if (t === '[object SharedArrayBuffer]') {
    return new Uint8Array(input as SharedArrayBuffer).slice().buffer;
  }
  if (ArrayBuffer.isView(input)) {
    const buf = input.buffer;
    if (isDetached(buf)) throw failure('ENGINE.INPUT', 'the buffer of the view is detached');
    if (
      transfer &&
      tag(buf) === '[object ArrayBuffer]' &&
      input.byteOffset === 0 &&
      input.byteLength === buf.byteLength
    ) {
      return take(buf as ArrayBuffer);
    }
    return new Uint8Array(buf, input.byteOffset, input.byteLength).slice().buffer;
  }
  const isBlob =
    (typeof Blob !== 'undefined' && input instanceof Blob) ||
    ((t === '[object Blob]' || t === '[object File]') &&
      typeof (input as { arrayBuffer?: unknown }).arrayBuffer === 'function');
  if (isBlob) {
    let buf: unknown;
    try {
      buf = await (input as Blob).arrayBuffer();
    } catch (e) {
      throw failure('ENGINE.INPUT', `could not read the file: ${errorMessage(e)}`);
    }
    if (tag(buf) !== '[object ArrayBuffer]') throw failure('ENGINE.INPUT', 'could not read the file');
    return buf as ArrayBuffer;
  }
  throw failure('ENGINE.INPUT', `unsupported input (${t}): expected File, Blob, ArrayBuffer or Uint8Array`);
}

/** Policy JSON for the engine (which validates it). Throws a Failure. */
export function policyJson(policy: unknown): string {
  if (policy === undefined) return '{}';
  if (typeof policy === 'string') return policy;
  let json: unknown;
  try {
    json = JSON.stringify(policy);
  } catch (e) {
    throw failure('POLICY.INVALID', `policy is not serializable to JSON: ${errorMessage(e)}`);
  }
  if (typeof json !== 'string') throw failure('POLICY.INVALID', 'policy is not serializable to JSON');
  return json;
}

const isObject = (x: unknown): x is Record<string, unknown> =>
  typeof x === 'object' && x !== null && !Array.isArray(x);

/**
 * Parses the engine's verdict JSON and checks its invariants (schema §7).
 * Fills `stats.duration_ms` (the WASM engine has no clock) with the
 * worker-measured engine time. Throws a Failure on anything unexpected.
 */
export function parseVerdict(text: unknown, durationMs: unknown): Verdict {
  const bad = (why: string): Failure => failure('ENGINE.WORKER', `malformed verdict from the engine: ${why}`);
  if (typeof text !== 'string') throw bad('not a string');
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw bad('not JSON');
  }
  if (!isObject(v)) throw bad('not an object');
  const { valid, status, violations, warnings, errors, stats, policy, engine_version } = v;
  if (typeof status !== 'string' || !(STATUSES as readonly string[]).includes(status)) throw bad('status');
  if (typeof valid !== 'boolean' || valid !== (status === 'PASS')) throw bad('valid does not match status');
  if (!Array.isArray(violations) || !Array.isArray(warnings) || !Array.isArray(errors)) throw bad('lists');
  if (status === 'PASS' && (violations.length > 0 || errors.length > 0)) throw bad('PASS with findings');
  if (status === 'REJECT' && (violations.length === 0 || errors.length > 0)) throw bad('REJECT');
  if (status === 'ERROR' && errors.length === 0) throw bad('ERROR without errors');
  if (!isObject(stats) || typeof stats.duration_ms !== 'number') throw bad('stats');
  if (!isObject(policy) || typeof engine_version !== 'string') throw bad('policy / engine_version');
  if (stats.duration_ms === 0 && typeof durationMs === 'number' && Number.isFinite(durationMs) && durationMs > 0) {
    stats.duration_ms = Math.round(durationMs);
  }
  return v as unknown as Verdict;
}

/** Parses the engine's rule list; throws a Failure if it is not one. */
export function parseRules(text: unknown): RuleInfo[] {
  const bad = failure('ENGINE.WORKER', 'malformed rule list from the engine');
  if (typeof text !== 'string') throw bad;
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw bad;
  }
  if (!Array.isArray(v) || !v.every((r) => isObject(r) && typeof r.id === 'string')) throw bad;
  return v as RuleInfo[];
}

/** An `ERROR` verdict for failures outside the engine. */
export function errorVerdict(f: Failure, engineVersion: string, bytes: number, durationMs: number): Verdict {
  return {
    valid: false,
    status: 'ERROR',
    violations: [],
    warnings: [],
    errors: [{ code: f.code, message: f.message }],
    engine_version: engineVersion,
    policy: { preset: null, digest: null, unsafe_allow_unlock: false, stop_on_first: false },
    stats: {
      bytes,
      objects: 0,
      revisions: 0,
      decoded_bytes: 0,
      duration_ms: Math.max(0, Math.round(durationMs)),
    },
  };
}

function isSignal(x: unknown): x is AbortSignal {
  return (
    typeof x === 'object' &&
    x !== null &&
    typeof (x as AbortSignal).aborted === 'boolean' &&
    typeof (x as AbortSignal).addEventListener === 'function' &&
    typeof (x as AbortSignal).removeEventListener === 'function'
  );
}

function resolveWasm(wasm: unknown): string | WebAssembly.Module | undefined {
  if (wasm === undefined) return undefined;
  if (typeof WebAssembly !== 'undefined' && wasm instanceof WebAssembly.Module) return wasm;
  if (wasm instanceof URL) return wasm.href;
  if (typeof wasm === 'string') {
    // Relative URLs would resolve against the worker script; use the page.
    const base = (globalThis as { location?: { href?: string } }).location?.href;
    try {
      return base === undefined ? wasm : new URL(wasm, base).href;
    } catch {
      return wasm;
    }
  }
  throw new QueldaError('ENGINE.INPUT', 'wasm must be a URL, a string or a WebAssembly.Module');
}

/** The scanner engine room. Use {@link createScannerWith}. */
class ScannerImpl implements Scanner {
  engineVersion = '';
  private slot: Slot | undefined;
  private readonly queue: Job[] = [];
  private active: Job | undefined;
  private terminated = false;
  private nextId = 1;
  private rulesJson: string | undefined;

  constructor(
    private readonly makeWorker: () => WorkerLike,
    private readonly wasm: string | WebAssembly.Module | undefined,
    readonly timeoutMs: number | null,
  ) {}

  /** Starts the first worker; rejects with a QueldaError. */
  async start(): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const slot = this.spawn();
      const timeout = new Promise<never>((_, reject) => {
        if (this.timeoutMs !== null) {
          timer = setTimeout(
            () => reject(new QueldaError('LIMIT.TIMEOUT', `the engine did not start within ${this.timeoutMs} ms`)),
            this.timeoutMs,
          );
        }
      });
      await Promise.race([slot.ready, timeout]);
    } catch (e) {
      this.terminate();
      if (e instanceof QueldaError) throw e;
      if (isFailure(e)) throw new QueldaError(e.code, e.message);
      throw new QueldaError('ENGINE.WORKER', `could not start the scanner: ${errorMessage(e)}`);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  scan(input: ScanInput, policy?: PolicyInput, options?: ScanOptions): Promise<Verdict> {
    const started = now();
    const size = (): number => {
      try {
        const x = input as { byteLength?: unknown; size?: unknown };
        const n = typeof x?.byteLength === 'number' ? x.byteLength : typeof x?.size === 'number' ? x.size : 0;
        return Number.isFinite(n) && n >= 0 ? n : 0;
      } catch {
        return 0;
      }
    };
    return new Promise<Verdict>((resolve) => {
      const fail = (f: Failure, bytes: number): void =>
        resolve(errorVerdict(f, this.engineVersion, bytes, now() - started));
      try {
        if (this.terminated) throw failure('ENGINE.ABORTED', 'the scanner was terminated');
        if (options !== undefined && !isObject(options)) throw failure('ENGINE.INPUT', 'options must be an object');
        const { timeoutMs, signal, transfer } = options ?? {};
        if (transfer !== undefined && typeof transfer !== 'boolean') {
          throw failure('ENGINE.INPUT', 'transfer must be a boolean');
        }
        if (signal !== undefined && !isSignal(signal)) throw failure('ENGINE.INPUT', 'signal must be an AbortSignal');
        const timeout = resolveTimeout(timeoutMs, this.timeoutMs);
        const json = policyJson(policy);
        if (signal?.aborted) throw failure('ENGINE.ABORTED', 'the scan was aborted');
        const bytes = size();
        // Normalize now: copies snapshot the caller's bytes at call time.
        const payload = normalizeInput(input, transfer === true).then((buf) => ({ bytes: buf, policy: json }));
        payload.catch(() => undefined);
        const job: Job = {
          id: this.nextId++,
          kind: 'scan',
          phase: 'queued',
          done: false,
          timeoutMs: timeout,
          payload,
          bytes,
          started,
          settle: (o) => {
            if (o.ok) resolve(o.verdict as Verdict);
            else fail(o.failure, job.bytes);
          },
        };
        this.enqueue(job, signal);
      } catch (e) {
        fail(isFailure(e) ? e : failure('ENGINE.INPUT', errorMessage(e)), size());
      }
    });
  }

  listRules(options?: ListRulesOptions): Promise<RuleInfo[]> {
    return new Promise<RuleInfo[]>((resolve, reject) => {
      const fail = (f: Failure): void => reject(new QueldaError(f.code, f.message));
      try {
        if (this.terminated) throw failure('ENGINE.ABORTED', 'the scanner was terminated');
        if (options !== undefined && !isObject(options)) throw failure('ENGINE.INPUT', 'options must be an object');
        const { timeoutMs, signal } = options ?? {};
        if (signal !== undefined && !isSignal(signal)) throw failure('ENGINE.INPUT', 'signal must be an AbortSignal');
        const timeout = resolveTimeout(timeoutMs, this.timeoutMs);
        if (signal?.aborted) throw failure('ENGINE.ABORTED', 'listRules was aborted');
        if (this.rulesJson !== undefined) {
          resolve(parseRules(this.rulesJson)); // fresh objects every call
          return;
        }
        const job: Job = {
          id: this.nextId++,
          kind: 'rules',
          phase: 'queued',
          done: false,
          timeoutMs: timeout,
          bytes: 0,
          started: now(),
          settle: (o) => (o.ok ? resolve(o.rules as RuleInfo[]) : fail(o.failure)),
        };
        this.enqueue(job, signal);
      } catch (e) {
        fail(isFailure(e) ? e : failure('ENGINE.INPUT', errorMessage(e)));
      }
    });
  }

  terminate(): void {
    if (this.terminated) return;
    this.terminated = true;
    this.killWorker(new Error('the scanner was terminated'));
    const pending = [...(this.active ? [this.active] : []), ...this.queue];
    this.queue.length = 0;
    for (const job of pending) this.finish(job, { ok: false, failure: failure('ENGINE.ABORTED', 'the scanner was terminated') });
  }

  // ---- queue -------------------------------------------------------------

  private enqueue(job: Job, signal: AbortSignal | undefined): void {
    if (signal !== undefined) {
      const onAbort = (): void => this.abort(job);
      signal.addEventListener('abort', onAbort, { once: true });
      job.unlisten = () => signal.removeEventListener('abort', onAbort);
    }
    this.queue.push(job);
    this.pump();
  }

  /** Settles a job once; frees its timer/listener and moves the queue on. */
  private finish(job: Job, outcome: Outcome): void {
    if (job.done) return;
    job.done = true;
    if (job.timer !== undefined) clearTimeout(job.timer);
    job.unlisten?.();
    job.unlisten = undefined;
    job.payload = undefined; // drop the bytes
    const i = this.queue.indexOf(job);
    if (i >= 0) this.queue.splice(i, 1);
    if (this.active === job) this.active = undefined;
    job.settle(outcome);
    this.pump();
  }

  private abort(job: Job): void {
    if (job.done) return;
    // Only a running request occupies the engine; WASM cannot be interrupted.
    if (job.phase === 'running') this.killWorker(new Error('request aborted'));
    this.finish(job, { ok: false, failure: failure('ENGINE.ABORTED', `the ${job.kind === 'scan' ? 'scan' : 'request'} was aborted`) });
  }

  private onTimeout(job: Job): void {
    if (job.done) return;
    // A request stuck in the engine or in worker start-up: kill that worker.
    if (job.phase === 'running' || job.phase === 'starting') this.killWorker(new Error('request timed out'));
    this.finish(job, { ok: false, failure: failure('LIMIT.TIMEOUT', `the ${job.kind === 'scan' ? 'scan' : 'request'} took longer than ${job.timeoutMs} ms`) });
  }

  private pump(): void {
    if (this.active !== undefined || this.terminated) return;
    const job = this.queue.shift();
    if (job === undefined) return;
    this.active = job;
    job.phase = 'preparing';
    if (job.timeoutMs !== null) job.timer = setTimeout(() => this.onTimeout(job), job.timeoutMs);
    void this.run(job);
  }

  private async run(job: Job): Promise<void> {
    try {
      const payload = job.payload === undefined ? undefined : await job.payload;
      if (job.done) return;
      if (payload !== undefined) job.bytes = payload.bytes.byteLength;
      job.phase = 'starting';
      const slot = this.slot ?? this.spawn();
      await slot.ready;
      if (job.done) return;
      if (slot.dead || slot !== this.slot) throw failure('ENGINE.WORKER', 'the worker stopped');
      job.phase = 'running';
      job.slot = slot;
      if (job.kind === 'scan' && payload !== undefined) {
        slot.worker.postMessage({ type: 'scan', id: job.id, bytes: payload.bytes, policy: payload.policy }, [payload.bytes]);
      } else {
        slot.worker.postMessage({ type: 'rules', id: job.id }, []);
      }
    } catch (e) {
      if (job.done) return;
      // Start-up / posting failures leave no usable worker.
      if (job.phase === 'starting' || job.phase === 'running') this.killWorker(new Error('worker failure'));
      this.finish(job, {
        ok: false,
        failure: isFailure(e) ? e : failure('ENGINE.WORKER', `the worker failed: ${errorMessage(e)}`),
      });
    }
  }

  // ---- worker ------------------------------------------------------------

  private spawn(): Slot {
    if (this.terminated) throw failure('ENGINE.ABORTED', 'the scanner was terminated');
    let resolveReady!: () => void;
    let rejectReady!: (e: Error) => void;
    const ready = new Promise<void>((res, rej) => {
      resolveReady = res;
      rejectReady = rej;
    });
    ready.catch(() => undefined); // observed by run()/start(); never unhandled

    let worker: WorkerLike;
    try {
      worker = this.makeWorker();
    } catch (e) {
      throw failure('ENGINE.WORKER', `could not create the worker: ${errorMessage(e)}`);
    }
    const onMessage = (e: WorkerEvent): void => this.onMessage(slot, e.data);
    const onError = (e: WorkerEvent): void =>
      this.onWorkerDied(slot, `the worker crashed${typeof e?.message === 'string' && e.message ? `: ${e.message}` : ''}`);
    const onMessageError = (): void => this.onWorkerDied(slot, 'the worker sent a message that could not be read');
    const slot: Slot = {
      worker,
      ready,
      dead: false,
      onReady: resolveReady,
      onDead: rejectReady,
      detach: () => {
        worker.removeEventListener('message', onMessage);
        worker.removeEventListener('error', onError);
        worker.removeEventListener('messageerror', onMessageError);
      },
    };
    worker.addEventListener('message', onMessage);
    worker.addEventListener('error', onError);
    worker.addEventListener('messageerror', onMessageError);
    this.slot = slot;
    try {
      worker.postMessage({ type: 'init', wasm: this.wasm }, []);
    } catch (e) {
      this.killWorker(new Error(`could not start the worker: ${errorMessage(e)}`));
    }
    return slot;
  }

  /** Stops the current worker (if any); it is never reused. */
  private killWorker(reason: Error): void {
    const slot = this.slot;
    if (slot === undefined) return;
    this.slot = undefined;
    slot.dead = true;
    slot.detach();
    try {
      slot.worker.terminate();
    } catch {
      // already gone
    }
    slot.onDead(reason);
  }

  private onWorkerDied(slot: Slot, message: string): void {
    if (slot !== this.slot) return;
    this.killWorker(new Error(message));
    const job = this.active;
    // A job waiting for this worker's start-up fails through `ready` in run().
    if (job !== undefined && job.phase === 'running' && job.slot === slot) {
      this.finish(job, { ok: false, failure: failure('ENGINE.WORKER', message) });
    }
  }

  private onMessage(slot: Slot, data: unknown): void {
    if (slot !== this.slot) return;
    const msg = (isObject(data) ? data : {}) as Partial<FromWorker> & Record<string, unknown>;
    if (msg.type === 'ready') {
      if (typeof msg.version !== 'string') return this.onWorkerDied(slot, 'the worker sent a malformed message');
      if (this.engineVersion === '') this.engineVersion = msg.version;
      slot.onReady();
      return;
    }
    if (msg.type === 'init-error') {
      return this.onWorkerDied(slot, typeof msg.message === 'string' ? msg.message : 'the engine failed to load');
    }
    const job = this.active;
    if (job === undefined || job.phase !== 'running' || job.slot !== slot || msg.id !== job.id) {
      return this.onWorkerDied(slot, 'the worker sent an unexpected message');
    }
    try {
      if (msg.type === 'fail') {
        // The engine threw or trapped: do not trust this instance again.
        throw failure('ENGINE.WORKER', typeof msg.message === 'string' ? msg.message : 'the engine failed');
      }
      if (job.kind === 'scan' && msg.type === 'scan') {
        this.finish(job, { ok: true, verdict: parseVerdict(msg.verdict, msg.durationMs) });
        return;
      }
      if (job.kind === 'rules' && msg.type === 'rules') {
        const rules = parseRules(msg.rules);
        this.rulesJson = msg.rules as string;
        this.finish(job, { ok: true, rules });
        return;
      }
      throw failure('ENGINE.WORKER', 'the worker sent an unexpected message');
    } catch (e) {
      this.killWorker(new Error('bad reply'));
      this.finish(job, { ok: false, failure: isFailure(e) ? e : failure('ENGINE.WORKER', errorMessage(e)) });
    }
  }
}

/**
 * Creates a scanner with an explicit worker factory and waits until its
 * engine is loaded. Rejects with a {@link QueldaError}.
 */
export async function createScannerWith(makeWorker: () => WorkerLike, options: ScannerOptions = {}): Promise<Scanner> {
  if (!isObject(options)) throw new QueldaError('ENGINE.INPUT', 'options must be an object');
  const opts: ScannerOptions = options;
  let timeout: number | null;
  try {
    timeout = resolveTimeout(opts.timeoutMs, DEFAULT_TIMEOUT_MS);
  } catch (e) {
    throw new QueldaError('ENGINE.INPUT', isFailure(e) ? e.message : errorMessage(e));
  }
  if (opts.worker !== undefined && typeof opts.worker !== 'function') {
    throw new QueldaError('ENGINE.INPUT', 'worker must be a function');
  }
  const impl = new ScannerImpl(opts.worker ?? makeWorker, resolveWasm(opts.wasm), timeout);
  await impl.start();
  // Expose only the public surface.
  return Object.freeze({
    get engineVersion() {
      return impl.engineVersion;
    },
    scan: impl.scan.bind(impl),
    listRules: impl.listRules.bind(impl),
    terminate: impl.terminate.bind(impl),
  });
}
