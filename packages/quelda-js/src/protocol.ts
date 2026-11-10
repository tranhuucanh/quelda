// Messages between the main thread (scanner.ts) and the worker (host.ts).
// Internal: not part of the public API.

/** What the worker loads the engine from; `undefined` = the bundled `.wasm`. */
export type WasmSource = string | URL | WebAssembly.Module;

export type ToWorker =
  | { type: 'init'; wasm?: string | WebAssembly.Module }
  /** `bytes` is transferred (detached on the sending side). */
  | { type: 'scan'; id: number; bytes: ArrayBuffer; policy: string }
  | { type: 'rules'; id: number };

export type FromWorker =
  | { type: 'ready'; version: string }
  | { type: 'init-error'; message: string }
  /** `verdict` is the engine's JSON text; `durationMs` is the engine call's wall time. */
  | { type: 'scan'; id: number; verdict: string; durationMs: number }
  | { type: 'rules'; id: number; rules: string }
  /** The engine threw or trapped; the worker must not be reused. */
  | { type: 'fail'; id: number; message: string };

/** The subset of `Worker` the scanner uses (a browser `Worker` fits). */
export interface WorkerLike {
  postMessage(message: ToWorker, transfer: Transferable[]): void;
  addEventListener(type: WorkerEventType, listener: (event: WorkerEvent) => void): void;
  removeEventListener(type: WorkerEventType, listener: (event: WorkerEvent) => void): void;
  terminate(): void;
}

export type WorkerEventType = 'message' | 'error' | 'messageerror';

/** The fields of `MessageEvent` / `ErrorEvent` the scanner reads. */
export interface WorkerEvent {
  data?: unknown;
  message?: string;
}

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message || e.name;
  try {
    return String(e);
  } catch {
    return 'unknown error';
  }
}
