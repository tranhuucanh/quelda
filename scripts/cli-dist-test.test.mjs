// node --test scripts/cli-dist-test.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compare, expectedExit, normalize } from './cli-dist-test.mjs';

const verdict = (status, ms) =>
  JSON.stringify({ valid: status === 'PASS', status, violations: [], warnings: [], errors: [], stats: { bytes: 1, duration_ms: ms } });

test('exit code follows status', () => {
  assert.equal(expectedExit(verdict('PASS', 0)), 0);
  assert.equal(expectedExit(verdict('REJECT', 0)), 1);
  assert.equal(expectedExit(verdict('ERROR', 0)), 2);
});

test('duration_ms is ignored, everything else compared', () => {
  assert.equal(normalize(verdict('PASS', 5)), normalize(verdict('PASS', 900)));
  const c = { verdict: verdict('PASS', 3) };
  assert.deepEqual(compare(c, 0, `${verdict('PASS', 7)}\n`), []);
  assert.match(compare(c, 1, verdict('PASS', 7))[0], /exit 1, want 0/);
  assert.match(compare(c, 0, verdict('REJECT', 7)).join(), /verdict differs/);
  assert.match(compare(c, 0, 'oops').join(), /not JSON/);
});
