// Type-level tests: compiled by `tsc -p tsconfig.test.json` (part of
// `npm test`), never run. Against the built declarations (dist/), i.e. what
// users get. `@ts-expect-error` lines must fail to type-check.

import {
  createScanner,
  QueldaError,
  type Category,
  type Policy,
  type RuleInfo,
  type Scanner,
  type ScannerErrorCode,
  type Verdict,
  type WorkerLike,
} from '../dist/index.js';

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
const assert = <T extends true>(): T => true as T;

export async function api(file: File, buf: ArrayBuffer, bytes: Uint8Array, blob: Blob): Promise<void> {
  const scanner: Scanner = await createScanner();
  const scanner2 = await createScanner({ timeoutMs: 10_000, wasm: new URL('https://x/q.wasm') });

  // Every input kind and policy form.
  const v1: Verdict = await scanner.scan(file);
  await scanner.scan(blob, { preset: 'strict' });
  await scanner.scan(buf, '{"preset":"permissive"}');
  await scanner.scan(bytes, { rules: { 'ACTIVE.OPEN_ACTION': 'off' }, categories: { external: 'block' } });
  await scanner.scan(new DataView(buf), {}, { timeoutMs: 1000, signal: new AbortController().signal, transfer: true });

  assert<Equal<typeof v1.valid, boolean>>();
  assert<Equal<typeof v1.status, 'PASS' | 'REJECT' | 'ERROR'>>();
  assert<Equal<(typeof v1.violations)[number]['action'], 'block' | 'warn'>>();
  assert<Equal<typeof v1.policy.preset, 'strict' | 'balanced' | 'permissive' | null>>();
  assert<Equal<typeof v1.policy.digest, string | null>>();
  assert<Equal<Category, RuleInfo['category']>>();
  assert<Equal<ReturnType<Scanner['listRules']>, Promise<RuleInfo[]>>>();
  assert<Equal<QueldaError['code'], ScannerErrorCode>>();

  // A browser Worker fits the worker option.
  const w: WorkerLike = new Worker('x.js', { type: 'module' });
  await createScanner({ worker: () => w });

  // @ts-expect-error unknown preset
  await scanner.scan(file, { preset: 'strickt' });
  // @ts-expect-error unknown category
  await scanner.scan(file, { categories: { scripts: 'off' } });
  // @ts-expect-error unknown action
  await scanner.scan(file, { rules: { 'ACTIVE.LAUNCH': 'allow' } });
  // @ts-expect-error unknown policy field
  const typo: Policy = { rule: {} };
  // @ts-expect-error limits are numbers
  await scanner.scan(file, { limits: { max_file_bytes: '10MB' } });
  // @ts-expect-error not a scannable input
  await scanner.scan('file.pdf');
  // @ts-expect-error engineVersion is read-only
  scanner.engineVersion = 'x';

  void typo;
  scanner.terminate();
  scanner2.terminate();
}
