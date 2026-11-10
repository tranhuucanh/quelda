// A WorkerLike over Node's worker_threads running the built dist/worker.js,
// so the real package (worker + WASM engine) can be tested in Node.

import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import type { ToWorker, WorkerEvent, WorkerEventType, WorkerLike } from '../../src/protocol.js';
import { DIST } from './repo.js';

export interface NodeWorkerOptions {
  fileFetch?: boolean;
  sabotage?: 'exit' | 'throw' | 'hang';
}

const BOOTSTRAP = new URL('./node-worker-bootstrap.mjs', import.meta.url);

export class NodeWorker implements WorkerLike {
  readonly worker: Worker;
  private terminatedByUs = false;
  private readonly bound = new Map<(e: WorkerEvent) => void, [string, (...a: any[]) => void][]>();

  constructor(opts: NodeWorkerOptions = {}) {
    this.worker = new Worker(BOOTSTRAP, {
      workerData: { entry: pathToFileURL(join(DIST, 'worker.js')).href, ...opts },
    });
  }

  postMessage(message: ToWorker, transfer: Transferable[]): void {
    this.worker.postMessage(message, transfer as never);
  }

  addEventListener(type: WorkerEventType, listener: (e: WorkerEvent) => void): void {
    const handlers: [string, (...a: any[]) => void][] = [];
    if (type === 'message') handlers.push(['message', (data: unknown) => listener({ data })]);
    if (type === 'messageerror') handlers.push(['messageerror', () => listener({})]);
    if (type === 'error') {
      handlers.push(['error', (err: Error) => listener({ message: err.message })]);
      // A Web Worker has no 'exit'; an unexpected exit is a crash.
      handlers.push([
        'exit',
        (code: number) => {
          if (!this.terminatedByUs) listener({ message: `worker exited with code ${code}` });
        },
      ]);
    }
    for (const [ev, fn] of handlers) this.worker.on(ev, fn);
    this.bound.set(listener, [...(this.bound.get(listener) ?? []), ...handlers]);
  }

  removeEventListener(_type: WorkerEventType, listener: (e: WorkerEvent) => void): void {
    for (const [ev, fn] of this.bound.get(listener) ?? []) this.worker.off(ev, fn);
    this.bound.delete(listener);
  }

  terminate(): void {
    this.terminatedByUs = true;
    void this.worker.terminate();
  }
}

/** Worker factory; `plan[i]` configures the i-th worker (last one repeats). */
export function nodeWorkers(...plan: NodeWorkerOptions[]): { make: () => NodeWorker; made: NodeWorker[] } {
  const made: NodeWorker[] = [];
  return {
    made,
    make: () => {
      const w = new NodeWorker(plan[Math.min(made.length, plan.length - 1)] ?? {});
      made.push(w);
      return w;
    },
  };
}
