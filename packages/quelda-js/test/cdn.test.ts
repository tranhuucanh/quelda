import { describe, expect, it } from 'vitest';
import { crossOriginWorkerSource } from '../src/cdn.js';

describe('crossOriginWorkerSource', () => {
  const cdn = 'https://cdn.jsdelivr.net/npm/quelda@1/dist/index.js';

  it('imports the worker next to the module when the page is on another origin', () => {
    expect(crossOriginWorkerSource(cdn, 'https://app.example/upload')).toBe(
      'import "https://cdn.jsdelivr.net/npm/quelda@1/dist/worker.js";\n',
    );
    // Another port is another origin.
    expect(crossOriginWorkerSource('http://127.0.0.1:9001/q/index.js', 'http://127.0.0.1:9000/')).toBe(
      'import "http://127.0.0.1:9001/q/worker.js";\n',
    );
  });

  it('uses the worker URL directly when same-origin, bundled or unknown', () => {
    expect(crossOriginWorkerSource('https://app.example/assets/index-abc.js', 'https://app.example/upload')).toBeUndefined();
    // webpack replaces import.meta.url with the source file:// URL.
    expect(crossOriginWorkerSource('file:///app/node_modules/quelda/dist/index.js', 'https://app.example/')).toBeUndefined();
    expect(crossOriginWorkerSource(cdn, undefined)).toBeUndefined();
    expect(crossOriginWorkerSource('not a url', 'https://app.example/')).toBeUndefined();
    expect(crossOriginWorkerSource('blob:https://x/1', 'https://app.example/')).toBeUndefined();
  });

  it('escapes the URL as a JS string', () => {
    const src = crossOriginWorkerSource('https://cdn.example/a"b/index.js', 'https://app.example/');
    expect(src).toBe('import "https://cdn.example/a%22b/worker.js";\n');
  });
});
