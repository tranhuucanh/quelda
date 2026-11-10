// Real-browser check for the examples (scripts/build-examples.mjs): serves
// built pages and opens each one in headless Chrome, which runs the page's
// self-test (clean PDF → PASS, PostScript as a Blob → REJECT, through the real
// worker + .wasm) and sets <body data-selftest="ok|fail">.
//
// Chrome: $CHROME, else the usual install paths. Driven with the DevTools
// protocol (Node's built-in WebSocket); no browser automation dependency.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join, normalize, resolve, sep } from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
};

/** Static server for `root` on 127.0.0.1 (random port). `cors`: send Access-Control-Allow-Origin: * (a CDN does). */
export function serve(root, { cors = false } = {}) {
  root = resolve(root);
  const server = createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname);
    const file = normalize(join(root, path.endsWith('/') ? `${path}index.html` : path));
    const headers = cors ? { 'access-control-allow-origin': '*' } : {};
    if (file !== root && !file.startsWith(root + sep)) {
      res.writeHead(403, headers).end();
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, { ...headers, 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(body);
    } catch {
      res.writeHead(404, headers).end('not found');
    }
  });
  return new Promise((ok) =>
    server.listen(0, '127.0.0.1', () => ok({ url: `http://127.0.0.1:${server.address().port}/`, close: () => server.close() })),
  );
}

export function findChrome() {
  const candidates = [
    process.env.CHROME,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ];
  return candidates.find((c) => c && existsSync(c));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Opens each URL in a fresh tab of one headless Chrome and waits for
 * `document.body.dataset.selftest`. Returns [{ url, result, detail }].
 */
export async function checkPages(chrome, urls, timeoutMs = 30000) {
  const profile = mkdtempSync(join(tmpdir(), 'quelda-chrome-'));
  const proc = spawn(
    chrome,
    ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-gpu', ...(process.platform === 'linux' ? ['--no-sandbox'] : []), 'about:blank'],
    { stdio: 'ignore' },
  );
  try {
    let port;
    for (let i = 0; i < 100 && port === undefined; i++) {
      await sleep(100);
      const f = join(profile, 'DevToolsActivePort');
      if (existsSync(f)) port = readFileSync(f, 'utf8').split('\n')[0];
    }
    if (!port) throw new Error('Chrome did not start (no DevToolsActivePort)');
    const results = [];
    for (const url of urls) {
      const target = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURI(url)}`, { method: 'PUT' })).json();
      const ws = new WebSocket(target.webSocketDebuggerUrl);
      await new Promise((ok, ko) => {
        ws.onopen = ok;
        ws.onerror = ko;
      });
      let id = 0;
      const pending = new Map();
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data);
        pending.get(msg.id)?.(msg);
      };
      const evaluate = (expression) =>
        new Promise((ok) => {
          const n = ++id;
          pending.set(n, (msg) => ok(msg.result?.result?.value));
          ws.send(JSON.stringify({ id: n, method: 'Runtime.evaluate', params: { expression, returnByValue: true } }));
        });
      let result;
      const end = Date.now() + timeoutMs;
      while (Date.now() < end) {
        result = await evaluate('document.body && document.body.dataset.selftest');
        if (result === 'ok' || result === 'fail') break;
        await sleep(200);
      }
      const detail = await evaluate(
        "[...document.querySelectorAll('#status,#selftest')].map((e) => e.textContent).join(' | ')",
      );
      results.push({ url, result: result ?? 'timeout', detail });
      ws.close();
      await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`);
    }
    return results;
  } finally {
    proc.kill();
    await sleep(200);
    rmSync(profile, { recursive: true, force: true });
  }
}
