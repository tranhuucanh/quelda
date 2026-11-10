import { execFile } from 'node:child_process';

/** Scans one file with the quelda CLI. Only exit code 0 means valid. */
export function queldaScan(path, policy) {
  const args = ['scan', path, ...(policy ? ['--policy', policy] : [])];
  return new Promise((resolve) => {
    execFile('quelda', args, { timeout: 30_000, maxBuffer: 16 << 20 }, (err, stdout) => {
      let verdict;
      try {
        verdict = JSON.parse(stdout);
      } catch {
        verdict = { status: err?.killed ? 'TIMEOUT' : `EXIT ${err?.code}` };
      }
      resolve({ ...verdict, valid: err === null });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const v = await queldaScan(process.argv[2]);
  console.log(`valid=${v.valid} status=${v.status}`);
}
