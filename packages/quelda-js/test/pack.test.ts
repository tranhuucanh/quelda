// What `npm pack` would publish: exactly the built JS, the .d.ts files and the
// .wasm (no sources, tests or scripts), and the entry points bundlers rely on.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DIST, PKG } from './helpers/repo.js';

interface PackResult {
  files: { path: string; size: number }[];
  size: number;
  unpackedSize: number;
}

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const pack = (): PackResult =>
  JSON.parse(execFileSync(npm, ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: PKG, encoding: 'utf8' }))[0];

const pkg = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8'));

describe('npm pack', () => {
  const result = pack();
  const files = result.files.map((f) => f.path).sort();

  it('contains exactly the package files', () => {
    const modules = ['host', 'index', 'protocol', 'scanner', 'types', 'worker'];
    const expected = [
      'LICENSE-APACHE',
      'LICENSE-MIT',
      'README.md',
      'package.json',
      ...modules.flatMap((m) => [`dist/${m}.js`, `dist/${m}.d.ts`]),
      'dist/wasm/quelda.js',
      'dist/wasm/quelda.d.ts',
      'dist/wasm/quelda_bg.wasm',
    ].sort();
    expect(files).toEqual(expected);
  });

  it('ships the .wasm as a separate file identical to the build', () => {
    const wasm = result.files.find((f) => f.path === 'dist/wasm/quelda_bg.wasm');
    expect(wasm?.size).toBe(readFileSync(join(DIST, 'wasm/quelda_bg.wasm')).length);
    const bytes = readFileSync(join(DIST, 'wasm/quelda_bg.wasm'));
    expect([...bytes.subarray(0, 4)]).toEqual([0, 0x61, 0x73, 0x6d]);
  });

  it('every exports / main / types target is in the package', () => {
    const targets: string[] = [pkg.main, pkg.types];
    const walk = (x: unknown): void => {
      if (typeof x === 'string') targets.push(x);
      else if (x && typeof x === 'object') Object.values(x).forEach(walk);
    };
    walk(pkg.exports);
    for (const t of targets) expect(files, t).toContain(t.replace(/^\.\//, ''));
  });

  it('is publishable, with provenance pointing at the source repo', () => {
    expect(pkg.private).toBeUndefined();
    expect(pkg.publishConfig).toEqual({ access: 'public', provenance: true });
    // npm checks provenance against this URL; it must name the GitHub repo.
    expect(pkg.repository).toEqual({
      type: 'git',
      url: 'git+https://github.com/tranhuucanh/quelda.git',
      directory: 'packages/quelda-js',
    });
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+(-rc\.\d+)?$/);
    expect(pkg.engines.node).toBe('>=20');
    expect(pkg.type).toBe('module');
    expect(pkg.license).toBe('MIT OR Apache-2.0');
  });

  it('keeps the asset references bundlers detect', () => {
    const index = readFileSync(join(DIST, 'index.js'), 'utf8');
    expect(index).toContain("new Worker(new URL('./worker.js', import.meta.url), { type: 'module'");
    const worker = readFileSync(join(DIST, 'worker.js'), 'utf8');
    expect(worker).toMatch(/from '\.\/wasm\/quelda\.js'/);
    const glue = readFileSync(join(DIST, 'wasm/quelda.js'), 'utf8');
    expect(glue).toContain("new URL('quelda_bg.wasm', import.meta.url)");
  });

  it('is small (reports the size)', () => {
    console.log(`npm pack: ${result.files.length} files, ${result.size} B packed, ${result.unpackedSize} B unpacked`);
    expect(result.size).toBeLessThan(400 * 1024);
  });
});
