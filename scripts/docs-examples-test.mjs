#!/usr/bin/env node
// Runs every caller example of docs/cli.md (docs/examples/cli/*) against a
// real Linux `quelda` binary, each in its language's official container
// image, on a PASS file, a REJECT file and a missing file (ADR #34 (f)):
//
//   node scripts/docs-examples-test.mjs --bin target/aarch64-unknown-linux-musl/release/quelda --docker linux/arm64
//   … --timeout     instead: a `quelda` that hangs → every example reports TIMEOUT (~30 s each)
//
// Also runs the install snippets of docs/cli.md (`<!-- install: linux -->`,
// `<!-- install: docker -->`) as written, with the GitHub release URL pointed
// at a local server holding a release archive of --bin.
//
// crates/quelda-cli/tests/docs.rs checks that docs/cli.md shows these files
// verbatim. Needs fixtures (cargo run -p quelda-testkit --bin gen-fixtures).

import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
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

const RELEASES = 'https://github.com/tranhuucanh/quelda/releases';

/** The fenced block after `<!-- marker -->` in docs/cli.md. */
export function snippet(md, marker) {
  const at = md.indexOf(`<!-- ${marker} -->`);
  if (at < 0) throw new Error(`docs/cli.md: no <!-- ${marker} -->`);
  const start = md.indexOf('\n', md.indexOf('```', at)) + 1;
  return md.slice(start, md.indexOf('\n```', start) + 1);
}

/** Installs the way docs/cli.md says, in containers of `platform`. Returns problems. */
async function testInstall(bin, platform) {
  const md = readFileSync(join(root, 'docs/cli.md'), 'utf8');
  const arch = platform === 'linux/arm64' ? 'aarch64' : 'x86_64';
  const work = mkdtempSync(join(tmpdir(), 'quelda-install-'));
  const problems = [];
  const stage = join(work, 'stage');
  const download = join(work, 'srv/releases/latest/download');
  mkdirSync(stage);
  mkdirSync(download, { recursive: true });
  copyFileSync(bin, join(stage, 'quelda'));
  copyFileSync(join(root, 'LICENSE'), join(stage, 'LICENSE'));
  const tar = spawnSync('tar', ['-C', stage, '-czf', join(download, `quelda-${arch}-unknown-linux-musl.tar.gz`), 'quelda', 'LICENSE']);
  if (tar.status !== 0) throw new Error(`tar: ${tar.stderr}`);
  const server = createServer((req, res) => {
    const file = join(work, 'srv', decodeURIComponent(new URL(req.url, 'http://x').pathname));
    if (!file.startsWith(join(work, 'srv')) || !existsSync(file)) return res.writeHead(404).end();
    res.writeHead(200).end(readFileSync(file));
  });
  await new Promise((ok) => server.listen(0, '0.0.0.0', ok));
  const local = `http://host.docker.internal:${server.address().port}/releases`;
  const host = ['--add-host', 'host.docker.internal:host-gateway'];
  try {
    // Linux server: the one-liner, as root (no sudo in the image).
    const linux = snippet(md, 'install: linux').replaceAll(RELEASES, local).replaceAll('sudo ', '');
    const r = await runAsync(['run', '--rm', '--platform', platform, ...host, 'buildpack-deps:bookworm-curl', 'sh', '-ec', linux]);
    if (r.code !== 0 || !/^quelda \d/m.test(r.stdout)) problems.push(`install: linux: exit ${r.code}\n${r.stdout}${r.stderr}`);
    else console.log(`✔ install: linux (${platform}): ${r.stdout.trim().split('\n')[0]}`);
    // Docker: the stages, with a real base image instead of the placeholder.
    const ctx = join(work, 'docker');
    mkdirSync(ctx);
    const dockerfile = snippet(md, 'install: docker').replaceAll(RELEASES, local).replace('FROM your-app-image', 'FROM debian:12-slim');
    writeFileSync(join(ctx, 'Dockerfile'), `${dockerfile}RUN quelda --version\n`);
    const tag = `quelda-install-test:${process.pid}`;
    const b = await runAsync(['build', '-q', '--no-cache', '--platform', platform, ...host, '-t', tag, ctx]);
    if (b.code !== 0) problems.push(`install: docker: build failed\n${b.stderr}`);
    else {
      const v = await runAsync(['run', '--rm', '--platform', platform, tag, 'quelda', '--version']);
      if (v.code !== 0) problems.push(`install: docker: ${v.stderr}`);
      else console.log(`✔ install: docker (${platform}): ${v.stdout.trim().split('\n')[0]}`);
      await runAsync(['image', 'rm', '-f', tag]);
    }
  } finally {
    server.close();
    rmSync(work, { recursive: true, force: true });
  }
  return problems;
}

/** docker, without blocking the event loop (the local release server must answer). */
function runAsync(args) {
  return new Promise((ok) => {
    const child = spawn('docker', args);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => ok({ code, stdout, stderr }));
  });
}

async function main() {
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
  if (!hang) {
    const problems = await testInstall(bin, platform);
    for (const p of problems) console.error(`✘ ${p}`);
    failed += problems.length;
  }
  if (failed) process.exit(1);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(`error: ${e.message}`);
    process.exit(1);
  });
}
