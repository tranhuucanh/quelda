// Web Worker entry: loads the WASM engine and serves scan / list_rules
// requests from the scanner (see host.ts). Started by createScanner().

import init, { list_rules, scan, scan_source, version } from './wasm/quelda.js';
import { createHost } from './host.js';
import type { FromWorker } from './protocol.js';

interface WorkerScope {
  postMessage(message: FromWorker): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
}

const scope = globalThis as unknown as WorkerScope;

const host = createHost(
  async (wasm) => {
    // No source: wasm-bindgen's glue loads `new URL('quelda_bg.wasm', import.meta.url)`,
    // which bundlers (Vite, webpack 5) emit as an asset next to this worker.
    const exports = await (wasm === undefined ? init() : init({ module_or_path: wasm }));
    return { scan, scan_source, list_rules, version, memory: () => exports.memory.buffer.byteLength };
  },
  (message) => scope.postMessage(message),
);

scope.addEventListener('message', (event) => {
  void host(event.data);
});
