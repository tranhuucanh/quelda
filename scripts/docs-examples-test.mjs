#!/usr/bin/env node
// Runs every caller example of docs/cli.md (docs/examples/cli/*) against a
// real Linux `quelda` binary, each in its language's official container
// image, on a PASS file, a REJECT file and a missing file (ADR #34 (f)):
//
//   node scripts/docs-examples-test.mjs --bin target/aarch64-unknown-linux-musl/release/quelda --docker linux/arm64
//   … --timeout     instead: a `quelda` that hangs → every example reports TIMEOUT (~30 s each)
//
// crates/quelda-cli/tests/docs.rs checks that docs/cli.md shows these files
// verbatim. Needs fixtures (cargo run -p quelda-testkit --bin gen-fixtures).

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** [language, image, command (example at /ex)]. Images pinned by tag. */
export const EXAMPLES = [
  ['python', 'python:3.12-alpine', ['python3', '/ex/python/scan.py']],
  ['ruby', 'ruby:3.3-alpine', ['ruby', '/ex/ruby/scan.rb']],
  ['node', 'node:22-alpine', ['node', '/ex/node/scan.mjs']],
  ['go', 'golang:1.23-alpine', ['go', 'run', '/ex/go/scan.go']],
  ['php', 'php:8.3-cli-alpine', ['php', '/ex/php/scan.php']],
  ['java', 'eclipse-temurin:21-jdk-alpine', ['java', '/ex/java/QueldaScan.java']],
];

/** [fixture path or missing path, expected output line]. */
export const CASES = [
  ['/f/benign/minimal.pdf', 'valid=true status=PASS'],
  ['/f/rules/FILETYPE.POSTSCRIPT_MAGIC/bad/ps-adobe.pdf', 'valid=false status=REJECT'],
  ['/f/no-such-upload.pdf', 'valid=false status=ERROR'],
];

/** `--timeout`: a fake `quelda` that hangs; every example must give up (30 s). */
const HANG = ['/f/benign/minimal.pdf', 'valid=false status=TIMEOUT'];

function main() {
  const argv = process.argv.slice(2);
  const hang = argv.includes('--timeout');
  const get = (k) => argv[argv.indexOf(k) + 1];
  const bin = argv.includes('--bin') ? resolve(get('--bin')) : null;
  const platform = argv.includes('--docker') ? get('--docker') : null;
  if (!bin || !existsSync(bin) || !platform) throw new Error('usage: --bin <linux quelda> --docker <linux/arm64|linux/amd64>');
  if (!existsSync(join(root, 'tests/fixtures/manifest.json'))) throw new Error('run `cargo run -p quelda-testkit --bin gen-fixtures` first');
  let failed = 0;
  for (const [lang, image, cmd] of EXAMPLES) {
    // One container per language; each case is one run of the example.
    const cases = hang ? [HANG] : CASES;
    const script = cases.map(([file]) => `${cmd.map((c) => `'${c}'`).join(' ')} '${file}'`).join('\n');
    const fake = hang ? ['-v', `${join(root, 'scripts/testdata/quelda-hang.sh')}:/usr/local/bin/quelda:ro`] : ['-v', `${bin}:/usr/local/bin/quelda:ro`];
    const r = spawnSync(
      'docker',
      [
        'run', '--rm', '--platform', platform,
        ...fake,
        '-v', `${join(root, 'docs/examples/cli')}:/ex:ro`,
        '-v', `${join(root, 'tests/fixtures')}:/f:ro`,
        image, 'sh', '-c', `set -e\n${script}`,
      ],
      { encoding: 'utf8' },
    );
    const got = r.stdout.trim().split('\n');
    const want = cases.map(([, w]) => w);
    if (r.status !== 0 || JSON.stringify(got) !== JSON.stringify(want)) {
      failed++;
      console.error(`✘ ${lang} (${image}): exit ${r.status}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(want)}\n${r.stderr}`);
    } else {
      console.log(`✔ ${lang} (${image})`);
    }
  }
  if (failed) process.exit(1);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(1);
  }
}
