// quelda — PDF security scanner (WebAssembly in a Web Worker). Design §8.2.
//
//   const scanner = await createScanner();
//   const verdict = await scanner.scan(file, { preset: 'strict' });
//   if (!verdict.valid) showReasons(verdict.violations);
//   scanner.terminate();

import { crossOriginWorkerSource } from './cdn.js';
import type { WorkerLike } from './protocol.js';
import { createScannerWith, type Scanner, type ScannerOptions } from './scanner.js';

export {
  DEFAULT_TIMEOUT_MS,
  QueldaError,
  type ListRulesOptions,
  type Scanner,
  type ScannerOptions,
  type ScanOptions,
} from './scanner.js';
export type { WorkerEvent, WorkerEventType, WorkerLike } from './protocol.js';
export * from './types.js';

function defaultWorker(): WorkerLike {
  if (typeof Worker === 'undefined') {
    throw new Error('Web Workers are not available here (quelda runs in browsers; see the README for Node)');
  }
  const blob = crossOriginWorkerSource(import.meta.url, globalThis.location?.href);
  if (blob !== undefined) {
    const url = URL.createObjectURL(new Blob([blob], { type: 'text/javascript' }));
    return new Worker(url, { type: 'module', name: 'quelda' });
  }
  // Kept literal so Vite and webpack 5 bundle the worker and its .wasm.
  return new Worker(new URL('./worker.js', import.meta.url), { type: 'module', name: 'quelda' });
}

/**
 * Starts a Web Worker, loads the WASM engine once and resolves when it is
 * ready. Rejects with a {@link QueldaError} if the engine cannot start.
 */
export function createScanner(options?: ScannerOptions): Promise<Scanner> {
  return createScannerWith(defaultWorker, options);
}
