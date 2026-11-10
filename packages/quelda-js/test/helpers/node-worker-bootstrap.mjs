// Runs the package's real dist/worker.js inside a Node worker_threads Worker,
// emulating the bits of a Web Worker scope it uses (self.postMessage,
// addEventListener('message')). Test-only.
//
// workerData:
//   entry       file URL of dist/worker.js
//   fileFetch   true: let fetch() read file: URLs (the default .wasm location)
//   fileRoot    with fileFetch: directory that site-absolute paths (`/assets/x.wasm`,
//               as a bundle built with base `/` asks for) resolve against
//   sabotage    'exit' | 'throw' | 'hang': misbehave on the first scan request
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parentPort, workerData } from 'node:worker_threads';

const { entry, fileFetch, fileRoot, sabotage } = workerData;

globalThis.postMessage = (message, transfer) => parentPort.postMessage(message, transfer);
globalThis.addEventListener = (type, listener) => {
  if (type !== 'message') return;
  parentPort.on('message', (data) => {
    if (sabotage !== undefined && data?.type === 'scan') {
      if (sabotage === 'exit') process.exit(3);
      if (sabotage === 'throw') setTimeout(() => {
        throw new Error('sabotaged worker');
      });
      if (sabotage === 'hang') for (;;);
      return;
    }
    listener({ data });
  });
};

if (fileFetch) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    if (url.protocol !== 'file:') return realFetch(input, init);
    let path = fileURLToPath(url);
    if (fileRoot !== undefined && !existsSync(path)) path = join(fileRoot, url.pathname);
    return new Response(await readFile(path), { headers: { 'content-type': 'application/wasm' } });
  };
}

await import(entry);
