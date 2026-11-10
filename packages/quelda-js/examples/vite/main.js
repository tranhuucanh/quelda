// Demo page (identical in examples/vite/main.js and examples/webpack/src/main.js): scan a file you pick,
// plus a self-test on load (a clean PDF must PASS, a PostScript file must be
// REJECTed). The self-test result is also put on <body data-selftest="..."> so
// a browser test can read it.
import { createScanner } from 'quelda';

const $ = (id) => document.getElementById(id);

/** A one-page PDF with a correct xref table. */
function cleanPdf() {
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>',
    '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>',
    '<< /Length 0 >>\nstream\n\nendstream',
  ];
  let out = '%PDF-1.7\n';
  const offsets = [];
  objs.forEach((body, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) out += `${String(o).padStart(10, '0')} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return new TextEncoder().encode(out);
}

/** Inert PostScript (what an attacker would rename to .pdf). */
const postscript = () => new TextEncoder().encode('%!PS-Adobe-3.0\n% inert test file\nshowpage\n%%EOF\n');

function show(verdict) {
  $('verdict').textContent = JSON.stringify(verdict, null, 2);
  const reasons = [...verdict.violations, ...verdict.warnings].map((v) => `${v.action}: ${v.rule_id} (${v.message})`);
  reasons.push(...verdict.errors.map((e) => `error: ${e.code} (${e.message})`));
  $('summary').textContent = `${verdict.valid ? 'VALID' : 'INVALID'} — ${verdict.status}${reasons.length ? `\n${reasons.join('\n')}` : ''}`;
  $('summary').className = verdict.valid ? 'ok' : 'bad';
}

async function main() {
  const t0 = performance.now();
  let scanner;
  try {
    scanner = await createScanner();
  } catch (e) {
    $('status').textContent = `scanner failed to start: ${e.code ?? ''} ${e.message}`;
    document.body.dataset.selftest = 'fail';
    return;
  }
  const rules = await scanner.listRules();
  $('status').textContent = `engine ${scanner.engineVersion}, ${rules.length} rules, ready in ${Math.round(performance.now() - t0)} ms`;

  const clean = await scanner.scan(cleanPdf());
  const ps = await scanner.scan(new Blob([postscript()]), { preset: 'balanced' });
  const ok = clean.valid === true && ps.status === 'REJECT' && ps.violations.some((v) => v.rule_id === 'FILETYPE.POSTSCRIPT_MAGIC');
  $('selftest').textContent = `self-test: ${ok ? 'OK' : 'FAILED'} (clean PDF → ${clean.status}, PostScript → ${ps.status})`;
  $('selftest').className = ok ? 'ok' : 'bad';
  document.body.dataset.selftest = ok ? 'ok' : 'fail';

  $('file').addEventListener('change', async () => {
    const file = $('file').files?.[0];
    if (!file) return;
    $('summary').textContent = `scanning ${file.name} (${file.size} bytes)…`;
    show(await scanner.scan(file, { preset: $('preset').value }));
  });
}

void main();
