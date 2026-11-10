// Worker side (host.ts) with a fake engine.

import { describe, expect, it, vi } from 'vitest';
import { createHost, type Engine } from '../src/host.js';
import type { FromWorker } from '../src/protocol.js';

function setup(engine: Partial<Engine> = {}, load?: () => Promise<Engine>) {
  const posted: FromWorker[] = [];
  const full: Engine = {
    scan: vi.fn(() => '{"verdict":true}'),
    list_rules: vi.fn(() => '[]'),
    version: vi.fn(() => '1.2.3'),
    ...engine,
  };
  const loader = vi.fn(load ?? (async () => full));
  let t = 0;
  const host = createHost(loader, (m) => posted.push(m), () => (t += 5));
  return { host, posted, engine: full, loader };
}

const bytes = (): ArrayBuffer => new Uint8Array([37, 80, 68, 70]).buffer;

describe('host', () => {
  it('loads the engine on init and reports ready', async () => {
    const { host, posted, loader } = setup();
    await host({ type: 'init' });
    expect(loader).toHaveBeenCalledWith(undefined);
    expect(posted).toEqual([{ type: 'ready', version: '1.2.3' }]);
    await host({ type: 'init', wasm: 'x' }); // second init ignored
    expect(loader).toHaveBeenCalledTimes(1);
    expect(posted).toHaveLength(1);
  });

  it('passes a wasm URL or module to the loader', async () => {
    const a = setup();
    await a.host({ type: 'init', wasm: 'https://x/q.wasm' });
    expect(a.loader).toHaveBeenCalledWith('https://x/q.wasm');
    const b = setup();
    const m = new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
    await b.host({ type: 'init', wasm: m });
    expect(b.loader).toHaveBeenCalledWith(m);
  });

  it('refuses a bad wasm source', async () => {
    const { host, posted, loader } = setup();
    await host({ type: 'init', wasm: 42 });
    expect(loader).not.toHaveBeenCalled();
    expect(posted).toEqual([{ type: 'init-error', message: 'invalid wasm source' }]);
  });

  it('reports a load failure and refuses work afterwards', async () => {
    const { host, posted } = setup({}, () => Promise.reject(new Error('404')));
    await host({ type: 'init' });
    expect(posted[0]).toEqual({ type: 'init-error', message: 'engine failed to load: 404' });
    await host({ type: 'scan', id: 1, bytes: bytes(), policy: '{}' });
    expect(posted[1]).toMatchObject({ type: 'fail', id: 1 });
  });

  it('reports an engine whose version() is broken as a load failure', async () => {
    const { host, posted } = setup({ version: (() => 7) as never });
    await host({ type: 'init' });
    expect(posted[0]).toMatchObject({ type: 'init-error' });
  });

  it('scans: bytes + policy to the engine, verdict text + engine time back', async () => {
    const { host, posted, engine } = setup();
    await host({ type: 'init' });
    await host({ type: 'scan', id: 7, bytes: bytes(), policy: '{"preset":"strict"}' });
    expect(engine.scan).toHaveBeenCalledWith(new Uint8Array([37, 80, 68, 70]), '{"preset":"strict"}');
    expect(posted[1]).toEqual({ type: 'scan', id: 7, verdict: '{"verdict":true}', durationMs: 5 });
  });

  it('lists rules', async () => {
    const { host, posted } = setup();
    await host({ type: 'init' });
    await host({ type: 'rules', id: 3 });
    expect(posted[1]).toEqual({ type: 'rules', id: 3, rules: '[]' });
  });

  it('refuses work before init', async () => {
    const { host, posted, engine } = setup();
    await host({ type: 'scan', id: 1, bytes: bytes(), policy: '{}' });
    await host({ type: 'rules', id: 2 });
    expect(posted).toEqual([
      { type: 'fail', id: 1, message: 'engine not loaded' },
      { type: 'fail', id: 2, message: 'engine not loaded' },
    ]);
    expect(engine.scan).not.toHaveBeenCalled();
  });

  it('after the engine throws (trap), every later request fails', async () => {
    const { host, posted, engine } = setup({
      scan: vi.fn(() => {
        throw new WebAssembly.RuntimeError('unreachable');
      }),
    });
    await host({ type: 'init' });
    await host({ type: 'scan', id: 1, bytes: bytes(), policy: '{}' });
    expect(posted[1]).toEqual({ type: 'fail', id: 1, message: 'engine failed: unreachable' });
    await host({ type: 'rules', id: 2 });
    expect(posted[2]).toEqual({ type: 'fail', id: 2, message: 'engine failed: unreachable' });
    expect(engine.list_rules).not.toHaveBeenCalled();
  });

  it('answers a malformed scan request with fail', async () => {
    const { host, posted, engine } = setup();
    await host({ type: 'init' });
    await host({ type: 'scan', id: 1, bytes: [1, 2], policy: '{}' });
    await host({ type: 'scan', id: 2, bytes: bytes(), policy: {} });
    expect(posted.slice(1)).toEqual([
      { type: 'fail', id: 1, message: 'malformed scan request' },
      { type: 'fail', id: 2, message: 'malformed scan request' },
    ]);
    expect(engine.scan).not.toHaveBeenCalled();
  });

  it('ignores messages it cannot answer', async () => {
    const { host, posted } = setup();
    await host({ type: 'init' });
    for (const m of [null, 'scan', 42, {}, { type: 'other' }, { type: 'scan', bytes: bytes() }, { type: 'rules' }]) {
      await host(m);
    }
    expect(posted).toHaveLength(1);
  });
});
