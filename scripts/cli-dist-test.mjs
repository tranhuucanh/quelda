#!/usr/bin/env node
// Tests a `quelda` CLI binary exactly as users get it (ADR #34 (i)):
//
//   node scripts/cli-dist-test.mjs --bin <quelda>                        # native (macOS / Linux host)
//   node scripts/cli-dist-test.mjs --bin <quelda> --docker linux/arm64   # Linux binary in containers
//
// Each environment runs the smoke checks (version, PASS/REJECT/ERROR exit
// codes, stdin, usage error) and — where a shell exists — every case of
// tests/wasm/golden.json (fixtures × presets + conformance; native lib
// verdicts), which must match exactly (`stats.duration_ms` aside).
// Docker mode: `scratch` (smoke only: no shell) + IMAGES (override with
// --images a,b). Needs fixtures and tests/wasm/golden.json:
//   cargo run -p quelda-testkit --bin gen-fixtures
//   cargo run -p quelda-wasm --example wasm_golden

import { execFile, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir, availableParallelism } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = join(root, 'tests/fixtures');
const goldenPath = join(root, 'tests/wasm/golden.json');

// Old and new glibc distros, musl, busybox: a static binary must not care.
const IMAGES = ['alpine:3.20', 'debian:10', 'debian:12', 'ubuntu:18.04', 'ubuntu:24.04', 'busybox:1.36'];

function args() {
  const a = { bin: null, docker: null, images: IMAGES };
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const [k, v] = [argv[i], argv[i + 1]];
    if (k === '--bin') a.bin = resolve(v);
    else if (k === '--docker') a.docker = v;
    else if (k === '--images') a.images = v.split(',').filter(Boolean);
    else throw new Error(`unknown argument ${k}`);
    i++;
  }
  if (!a.bin || !existsSync(a.bin)) throw new Error('--bin <path to quelda> is required');
  return a;
}

/** `{...}` minus `stats.duration_ms`, for comparison. */
export function normalize(json) {
  const v = JSON.parse(json);
  if (v && v.stats) v.stats.duration_ms = 0;
  return JSON.stringify(v);
}

export function expectedExit(verdictJson) {
  const s = JSON.parse(verdictJson).status;
  return s === 'PASS' ? 0 : s === 'REJECT' ? 1 : 2;
}

/** Problems comparing one CLI run with its golden case. */
export function compare(c, code, stdout) {
  const p = [];
  const want = expectedExit(c.verdict);
  if (code !== want) p.push(`exit ${code}, want ${want}`);
  let got;
  try {
    got = normalize(stdout);
  } catch {
    return [...p, `stdout is not JSON: ${stdout.slice(0, 200)}`];
  }
  if (got !== normalize(c.verdict)) p.push(`verdict differs:\n    cli ${got}\n    lib ${normalize(c.verdict)}`);
  return p;
}

function loadGolden() {
  if (!existsSync(join(fixtures, 'manifest.json'))) throw new Error('run `cargo run -p quelda-testkit --bin gen-fixtures` first');
  if (!existsSync(goldenPath)) throw new Error('run `cargo run -p quelda-wasm --example wasm_golden` first');
  return JSON.parse(readFileSync(goldenPath, 'utf8'));
}

/** Smoke checks: [name, argv, stdin file | null, check(code, stdout, stderr) -> problem | null]. */
function smoke(version, f) {
  const json = (out) => {
    try {
      return JSON.parse(out);
    } catch {
      return {};
    }
  };
  return [
    ['--version', ['--version'], null, (c, o) => (c === 0 && o.startsWith(`quelda ${version}\n`) ? null : `got ${c}: ${o}`)],
    ['PASS', ['scan', f('benign/minimal.pdf')], null, (c, o) => (c === 0 && json(o).status === 'PASS' ? null : `got ${c}: ${o}`)],
    ['REJECT', ['scan', f('rules/FILETYPE.POSTSCRIPT_MAGIC/bad/ps-adobe.pdf')], null, (c, o) => (c === 1 && json(o).status === 'REJECT' ? null : `got ${c}: ${o}`)],
    ['ERROR policy', ['scan', f('benign/minimal.pdf'), '--policy-json', '{'], null, (c, o) => (c === 2 && json(o).errors?.[0]?.code === 'POLICY.INVALID' ? null : `got ${c}: ${o}`)],
    ['ERROR missing file', ['scan', '/nonexistent.pdf'], null, (c, o) => (c === 2 && json(o).errors?.[0]?.code === 'ENGINE.READ' ? null : `got ${c}: ${o}`)],
    ['stdin', ['scan', '-', '--preset', 'strict'], 'rules/FILETYPE.POSTSCRIPT_MAGIC/bad/ps-adobe.pdf', (c, o) => (c === 1 && json(o).policy?.preset === 'strict' ? null : `got ${c}: ${o}`)],
    ['usage', ['scan'], null, (c, o, e) => (c === 64 && o === '' && e.startsWith('quelda: ') ? null : `got ${c}: ${o}${e}`)],
    ['rules', ['rules'], null, (c, o) => (c === 0 && Array.isArray(json(o)) && json(o).length > 0 ? null : `got ${c}: ${o.slice(0, 200)}`)],
  ];
}

function run(cmd, argv, input) {
  const r = spawnSync(cmd, argv, { input: input ?? '', maxBuffer: 64 << 20 });
  if (r.error) throw r.error;
  return [r.status, r.stdout.toString(), r.stderr.toString()];
}

function report(env, problems) {
  if (problems.length) {
    console.error(`✘ ${env}: ${problems.length} problem(s)`);
    for (const p of problems.slice(0, 20)) console.error(`  ${p}`);
    return false;
  }
  return true;
}

/** Every golden case through `bin` on this host, a few at a time. */
async function goldenNative(bin, golden) {
  const problems = [];
  const queue = golden.cases.map((c, i) => [c, i]);
  const worker = async () => {
    for (let item = queue.shift(); item; item = queue.shift()) {
      const [c] = item;
      const [code, stdout] = await new Promise((res) => {
        execFile(bin, ['scan', join(fixtures, c.file), '--policy-json', c.policy], { maxBuffer: 64 << 20 }, (err, out) => res([err ? (err.code ?? -1) : 0, out]));
      });
      for (const p of compare(c, code, stdout)) problems.push(`${c.file} ${c.policy}: ${p}`);
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, availableParallelism()) }, worker));
  return problems;
}

function nativeMode(bin, golden) {
  const problems = [];
  for (const [name, argv, stdin, check] of smoke(golden.version, (p) => join(fixtures, p))) {
    const [c, o, e] = run(bin, argv, stdin ? readFileSync(join(fixtures, stdin)) : null);
    const p = check(c, o, e);
    if (p) problems.push(`${name}: ${p}`);
  }
  return goldenNative(bin, golden).then((g) => problems.concat(g));
}

function docker(argv, input) {
  return run('docker', argv, input);
}

/** Shell script that runs every golden case inside a container. */
function goldenScript(work, golden) {
  mkdirSync(join(work, 'p'));
  mkdirSync(join(work, 'o'));
  const q = (s) => `'${s.replaceAll("'", `'\\''`)}'`;
  const lines = ['#!/bin/sh'];
  golden.cases.forEach((c, i) => {
    writeFileSync(join(work, 'p', `${i}.json`), c.policy);
    lines.push(`/q/quelda scan ${q(`/f/${c.file}`)} --policy /w/p/${i}.json > /w/o/${i}.json; echo $? > /w/o/${i}.code`);
  });
  writeFileSync(join(work, 'run.sh'), `${lines.join('\n')}\n`);
}

function dockerMode(bin, platform, images, golden) {
  const work = mkdtempSync(join(tmpdir(), 'quelda-dist-'));
  try {
    mkdirSync(join(work, 'q'));
    copyFileSync(bin, join(work, 'q/quelda'));
    chmodSync(join(work, 'q/quelda'), 0o755);
    const user = process.getuid ? ['--user', `${process.getuid()}:${process.getgid()}`] : [];
    const mounts = ['-v', `${join(work, 'q')}:/q:ro`, '-v', `${fixtures}:/f:ro`];
    // `scratch`: nothing but the binary (and the fixtures, copied in).
    const ctx = join(work, 'scratch');
    mkdirSync(ctx);
    copyFileSync(bin, join(ctx, 'quelda'));
    writeFileSync(join(ctx, 'Dockerfile'), 'FROM scratch\nCOPY quelda /q/quelda\nENTRYPOINT ["/q/quelda"]\n');
    const tag = `quelda-dist-test-scratch:${process.pid}`;
    const [bc, , be] = docker(['build', '-q', '--platform', platform, '-t', tag, ctx]);
    if (bc !== 0) throw new Error(`docker build scratch: ${be}`);
    let ok = true;
    try {
      const envs = [['scratch', tag, true], ...images.map((i) => [i, i, false])];
      for (const [name, image, isScratch] of envs) {
        const problems = [];
        for (const [check, argv, stdin, fn] of smoke(golden.version, (p) => `/f/${p}`)) {
          const base = ['run', '--rm', '-i', '--platform', platform, ...user, '-v', `${fixtures}:/f:ro`];
          const cmd = isScratch ? [...base, image, ...argv] : [...base, '-v', `${join(work, 'q')}:/q:ro`, image, '/q/quelda', ...argv];
          const [c, o, e] = docker(cmd, stdin ? readFileSync(join(fixtures, stdin)) : null);
          const p = fn(c, o, e);
          if (p) problems.push(`${check}: ${p}`);
        }
        let full = '';
        if (!isScratch) {
          const g = join(work, `golden-${name.replace(/[^a-z0-9]/gi, '_')}`);
          mkdirSync(g);
          goldenScript(g, golden);
          const [c, , e] = docker(['run', '--rm', '--platform', platform, ...user, ...mounts, '-v', `${g}:/w`, image, 'sh', '/w/run.sh']);
          if (c !== 0) problems.push(`golden run: exit ${c} ${e}`);
          golden.cases.forEach((cs, i) => {
            const out = existsSync(join(g, 'o', `${i}.json`)) ? readFileSync(join(g, 'o', `${i}.json`), 'utf8') : '';
            const code = existsSync(join(g, 'o', `${i}.code`)) ? Number(readFileSync(join(g, 'o', `${i}.code`), 'utf8')) : -1;
            for (const p of compare(cs, code, out)) problems.push(`${cs.file} ${cs.policy}: ${p}`);
          });
          full = `, ${golden.cases.length} golden cases`;
        }
        if (report(`${platform} ${name}`, problems)) console.log(`✔ ${platform} ${name}: smoke${full}`);
        else ok = false;
      }
    } finally {
      docker(['image', 'rm', '-f', tag]);
    }
    return ok;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

async function main() {
  const a = args();
  const golden = loadGolden();
  if (a.docker) {
    if (!dockerMode(a.bin, a.docker, a.images, golden)) process.exit(1);
    return;
  }
  const problems = await nativeMode(a.bin, golden);
  if (!report(`native ${a.bin}`, problems)) process.exit(1);
  console.log(`✔ native: smoke, ${golden.cases.length} golden cases`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(`error: ${e.message}`);
    process.exit(1);
  });
}
