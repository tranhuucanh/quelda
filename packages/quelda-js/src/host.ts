// Worker side: answers the scanner's messages with the WASM engine. Kept apart
// from worker.ts (which wires it to the real engine and the worker scope) so it
// can be unit-tested with a fake engine. No scan logic: the engine does it all.

import { errorMessage, type FromWorker } from './protocol.js';

/** What `scan_source` reads the file through (see quelda-wasm). */
export interface Reader {
  size: number;
  /** Fills `into` with the bytes at `offset`, synchronously, or throws. */
  readInto(offset: number, into: Uint8Array): void;
}

/** The wasm-bindgen exports the host calls. */
export interface Engine {
  scan(bytes: Uint8Array, policyJson: string): string;
  scan_source(reader: Reader, policyJson: string): string;
  list_rules(): string;
  version(): string;
  /** Current WASM memory size in bytes. */
  memory(): number;
}

/** A synchronous reader over a Blob, if this scope can read one. */
export type BlobReader = (blob: Blob) => Reader | undefined;

/**
 * `FileReaderSync` (dedicated workers in browsers): each `readInto` reads
 * one slice of the Blob, so the file is never loaded whole. `undefined`
 * where it does not exist (Node).
 */
export const fileReaderSync: BlobReader = (blob) => {
  const FRS = (globalThis as { FileReaderSync?: new () => { readAsArrayBuffer(b: Blob): ArrayBuffer } })
    .FileReaderSync;
  if (typeof FRS !== 'function') return undefined;
  const frs = new FRS();
  return {
    size: blob.size,
    readInto(offset, into) {
      const buf = frs.readAsArrayBuffer(blob.slice(offset, offset + into.length));
      if (buf.byteLength !== into.length) throw new Error('the file changed while it was read');
      into.set(new Uint8Array(buf));
    },
  };
};

const isBlob = (x: unknown): x is Blob => typeof Blob !== 'undefined' && x instanceof Blob;

/** Loads the engine; `wasm` is the scanner's `wasm` option (or `undefined`). */
export type EngineLoader = (wasm: string | WebAssembly.Module | undefined) => Promise<Engine>;

/**
 * Returns the worker's message handler. The engine is loaded once (`init`);
 * after it throws or traps the host refuses further work (`fail`), since a
 * trapped WASM instance may be left in a broken state. The scanner then
 * replaces the worker.
 */
export function createHost(
  load: EngineLoader,
  post: (message: FromWorker) => void,
  now: () => number = () => performance.now(),
  readerFor: BlobReader = fileReaderSync,
): (data: unknown) => Promise<void> {
  let engine: Engine | undefined;
  let initStarted = false;
  let broken: string | undefined;

  const call = (id: number, run: (e: Engine) => FromWorker): void => {
    if (engine === undefined || broken !== undefined) {
      post({ type: 'fail', id, message: broken ?? 'engine not loaded' });
      return;
    }
    let reply: FromWorker;
    try {
      reply = run(engine);
    } catch (e) {
      broken = `engine failed: ${errorMessage(e)}`;
      reply = { type: 'fail', id, message: broken };
    }
    post(reply);
  };

  return async (data: unknown): Promise<void> => {
    if (typeof data !== 'object' || data === null) return;
    const msg = data as Record<string, unknown>;
    switch (msg.type) {
      case 'init': {
        if (initStarted) return;
        initStarted = true;
        const wasm = msg.wasm;
        if (wasm !== undefined && typeof wasm !== 'string' && !(wasm instanceof WebAssembly.Module)) {
          post({ type: 'init-error', message: 'invalid wasm source' });
          return;
        }
        try {
          const loaded = await load(wasm);
          const version = loaded.version();
          if (typeof version !== 'string') throw new Error('engine version is not a string');
          engine = loaded;
          post({ type: 'ready', version });
        } catch (e) {
          broken = `engine failed to load: ${errorMessage(e)}`;
          post({ type: 'init-error', message: broken });
        }
        return;
      }
      case 'scan': {
        const { id, bytes, blob, policy } = msg;
        if (typeof id !== 'number') return;
        const ok = bytes instanceof ArrayBuffer ? blob === undefined : bytes === undefined && isBlob(blob);
        if (!ok || typeof policy !== 'string') {
          post({ type: 'fail', id, message: 'malformed scan request' });
          return;
        }
        const timed = (scan: (e: Engine) => string) => (e: Engine): FromWorker => {
          const start = now();
          const verdict = scan(e);
          const durationMs = now() - start;
          return { type: 'scan', id, verdict, durationMs, memory: e.memory() };
        };
        if (bytes instanceof ArrayBuffer) {
          call(id, timed((e) => e.scan(new Uint8Array(bytes), policy)));
          return;
        }
        const file = blob as Blob;
        const reader = readerFor(file);
        if (reader !== undefined) {
          call(id, timed((e) => e.scan_source(reader, policy)));
          return;
        }
        // No synchronous reads here: the whole file, then the slice path.
        let whole: ArrayBuffer;
        try {
          whole = await file.arrayBuffer();
        } catch (e) {
          post({ type: 'input-error', id, message: `could not read the file: ${errorMessage(e)}` });
          return;
        }
        call(id, timed((e) => e.scan(new Uint8Array(whole), policy)));
        return;
      }
      case 'rules': {
        const { id } = msg;
        if (typeof id !== 'number') return;
        call(id, (e) => ({ type: 'rules', id, rules: e.list_rules() }));
        return;
      }
      default:
        return;
    }
  };
}
