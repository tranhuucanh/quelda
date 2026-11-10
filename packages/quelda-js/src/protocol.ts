// Messages between the main thread (scanner.ts) and the worker (host.ts).
// Internal: not part of the public API.

/** What the worker loads the engine from; `undefined` = the bundled `.wasm`. */
export type WasmSource = string | URL | WebAssembly.Module;

export type ToWorker =
  | { type: 'init'; wasm?: string | WebAssembly.Module }
  /**
   * `bytes` is transferred (detached on the sending side). A `blob` is
   * passed as is (no copy) and read by the worker, on demand when it can
   * (`FileReaderSync`), whole otherwise.
   */
  | ({ type: 'scan'; id: number; policy: string } & (
      | { bytes: ArrayBuffer; blob?: undefined }
      | { blob: Blob; bytes?: undefined }
    ))
  | { type: 'rules'; id: number };

export type FromWorker =
  | { type: 'ready'; version: string }
  | { type: 'init-error'; message: string }
  /**
   * `verdict` is the engine's JSON text; `durationMs` is the engine call's
   * wall time; `memory` the WASM memory size after it (bytes; it never
   * shrinks, so the scanner replaces a worker that grew too much).
   */
  | { type: 'scan'; id: number; verdict: string; durationMs: number; memory?: number }
  /** The worker could not read the `blob` (whole-file fallback only). */
  | { type: 'input-error'; id: number; message: string }
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
