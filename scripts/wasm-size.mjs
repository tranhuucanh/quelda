#!/usr/bin/env node
// Measures a .wasm (raw, gzip -9, brotli q11) and checks the size budget
// (design §8.2). Exit 0 = within budget, 1 = over budget, 2 = usage error.
//
//   node scripts/wasm-size.mjs <file.wasm> [--budget budget.json]
//        [--max-raw N] [--max-gzip N] [--max-brotli N] [--json out.json] [--no-fail]
//
// budget.json: { "raw_bytes": N, "gzip_bytes": N, "brotli_bytes": N } (each
// optional). --max-* override the file. Tests: scripts/wasm-size.test.mjs.
import { readFileSync, writeFileSync } from 'node:fs';
import { argv, exit } from 'node:process';
import { pathToFileURL } from 'node:url';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';

export const KINDS = ['raw', 'gzip', 'brotli'];

/** Sizes in bytes of `buf` raw, gzip -9 and brotli (quality 11). */
export function measure(buf) {
  return {
    raw: buf.length,
    gzip: gzipSync(buf, { level: 9 }).length,
    brotli: brotliCompressSync(buf, {
      params: {
        [constants.BROTLI_PARAM_QUALITY]: 11,
        [constants.BROTLI_PARAM_SIZE_HINT]: buf.length,
      },
    }).length,
  };
}

/** Budget lines exceeded: [{ kind, size, max }]. Missing limits are not checked. */
export function overBudget(sizes, budget) {
  return KINDS.filter((k) => Number.isFinite(budget[k]) && sizes[k] > budget[k]).map((k) => ({
    kind: k,
    size: sizes[k],
    max: budget[k],
  }));
}

function parseLimit(name, value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${name} needs a non-negative integer, got '${value}'`);
  return n;
}

/** Parses argv (without node + script). Throws on bad usage. */
export function parseArgs(args) {
  const opts = { file: null, budget: {}, json: null, fail: true };
  const overrides = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const next = () => {
      if (i + 1 >= args.length) throw new Error(`${a} needs a value`);
      return args[++i];
    };
    if (a === '--budget') {
      const b = JSON.parse(readFileSync(next(), 'utf8'));
      for (const k of KINDS) {
        if (b[`${k}_bytes`] !== undefined) opts.budget[k] = parseLimit(`${k}_bytes`, b[`${k}_bytes`]);
      }
    } else if (a.startsWith('--max-') && KINDS.includes(a.slice(6))) {
      overrides[a.slice(6)] = parseLimit(a, next());
    } else if (a === '--json') {
      opts.json = next();
    } else if (a === '--no-fail') {
      opts.fail = false;
    } else if (a.startsWith('--') || opts.file !== null) {
      throw new Error(`unexpected argument '${a}'`);
    } else {
      opts.file = a;
    }
  }
  if (opts.file === null) throw new Error('missing <file.wasm>');
  Object.assign(opts.budget, overrides);
  return opts;
}

const kb = (n) => `${(n / 1024).toFixed(1)} KiB`;

/** Runs the CLI; returns the exit code. */
export function main(args, log = console.log, err = console.error) {
  let opts;
  try {
    opts = parseArgs(args);
  } catch (e) {
    err(`wasm-size: ${e.message}`);
    return 2;
  }
  let buf;
  try {
    buf = readFileSync(opts.file);
  } catch (e) {
    err(`wasm-size: cannot read ${opts.file}: ${e.message}`);
    return 2;
  }
  const sizes = measure(buf);
  for (const k of KINDS) {
    const max = opts.budget[k];
    const limit = Number.isFinite(max) ? ` (budget ${max} B = ${kb(max)})` : '';
    log(`${k.padEnd(6)} ${String(sizes[k]).padStart(9)} B  ${kb(sizes[k]).padStart(11)}${limit}`);
  }
  const over = overBudget(sizes, opts.budget);
  if (opts.json) writeFileSync(opts.json, `${JSON.stringify({ file: opts.file, sizes, budget: opts.budget, over }, null, 2)}\n`);
  for (const o of over) err(`wasm-size: ${o.kind} size ${o.size} B is over budget ${o.max} B`);
  return over.length > 0 && opts.fail ? 1 : 0;
}

if (argv[1] && import.meta.url === pathToFileURL(argv[1]).href) exit(main(argv.slice(2)));
