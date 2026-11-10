// Worker side: answers the scanner's messages with the WASM engine. Kept apart
// from worker.ts (which wires it to the real engine and the worker scope) so it
// can be unit-tested with a fake engine. No scan logic: the engine does it all.

import { errorMessage, type FromWorker } from './protocol.js';

/** The wasm-bindgen exports the host calls. */
export interface Engine {
  scan(bytes: Uint8Array, policyJson: string): string;
  list_rules(): string;
  version(): string;
}

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
        const { id, bytes, policy } = msg;
        if (typeof id !== 'number') return;
        if (!(bytes instanceof ArrayBuffer) || typeof policy !== 'string') {
          post({ type: 'fail', id, message: 'malformed scan request' });
          return;
        }
        call(id, (e) => {
          const start = now();
          const verdict = e.scan(new Uint8Array(bytes), policy);
          const durationMs = now() - start;
          return { type: 'scan', id, verdict, durationMs };
        });
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
