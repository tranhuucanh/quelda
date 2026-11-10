// node --test scripts/docs-examples-test.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { snippet } from './docs-examples-test.mjs';

test('snippet: the fenced block after the marker', () => {
  const md = 'x\n<!-- a -->\n\n```bash\none\ntwo\n```\n<!-- b -->\n```\nthree\n```\n';
  assert.equal(snippet(md, 'a'), 'one\ntwo\n');
  assert.equal(snippet(md, 'b'), 'three\n');
  assert.throws(() => snippet(md, 'c'), /no <!-- c -->/);
});

test('docs/cli.md install snippets download the release archive for this machine', () => {
  const md = readFileSync(new URL('../docs/cli.md', import.meta.url), 'utf8');
  const url = 'https://github.com/tranhuucanh/quelda/releases/latest/download/quelda-$(uname -m)-unknown-linux-musl.tar.gz';
  for (const marker of ['install: linux', 'install: docker']) assert.ok(snippet(md, marker).includes(url), marker);
  assert.match(snippet(md, 'install: docker'), /^FROM your-app-image$/m);
});
