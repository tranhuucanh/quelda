# quelda CLI

**English** | [日本語](cli.ja.md)

`quelda` scans a file, or whole folders of them, and prints a verdict: valid or invalid, with
the reason for each rule the file violates. It is a single static binary with no runtime dependencies, meant to be called by a
backend written in any language before a file reaches Ghostscript, ImageMagick or any other PDF
processor.

- [Install](#install)
- [Scan a file](#scan-a-file)
- [Scan a folder](#scan-a-folder) (thousands of files, nested)
- [Exit codes](#exit-codes)
- [The verdict](#the-verdict)
- [Policy](#policy) (details: [policy.md](policy.md), [rules.md](rules.md))
- [Call it from your backend](#call-it-from-your-backend)
- [Other commands](#other-commands)

## Install

One static binary, no dependencies: **Linux x64 and arm64** (any distribution, even a `scratch`
or distroless container) and **macOS on Apple Silicon**.

### Homebrew (macOS, Apple Silicon)

```bash
brew install tranhuucanh/quelda/quelda
```

### Linux server (one command)

<!-- install: linux -->
```bash
curl -fsSL "https://github.com/tranhuucanh/quelda/releases/latest/download/quelda-$(uname -m)-unknown-linux-musl.tar.gz" | sudo tar -xz -C /usr/local/bin quelda
quelda --version
```

`$(uname -m)` picks the right binary (`x86_64` or `aarch64`).

### Docker (ECS, Kubernetes, Cloud Run, …)

Add a stage to your Dockerfile and copy the binary into your image. It works for
`linux/amd64` and `linux/arm64` (AWS Graviton) builds, and with any base image (Debian, Ubuntu,
Alpine, distroless):

<!-- install: docker -->
```dockerfile
FROM alpine:3.20 AS quelda
RUN wget -qO- "https://github.com/tranhuucanh/quelda/releases/latest/download/quelda-$(uname -m)-unknown-linux-musl.tar.gz" | tar -xz -C /usr/local/bin quelda

FROM your-app-image
COPY --from=quelda /usr/local/bin/quelda /usr/local/bin/quelda
```

Then call `quelda` from your application as shown in
[Call it from your backend](#call-it-from-your-backend).

### Pin a version

`latest` is the newest release. In production, pin one: replace `releases/latest/download/`
with `releases/download/vX.Y.Z/` (see [Releases](https://github.com/tranhuucanh/quelda/releases)),
and upgrade the server and the browser package together
(see [Keep every engine on the same rule set](#keep-every-engine-on-the-same-rule-set)).

### Verify a download

Each release has `SHA256SUMS` and a signed build provenance attestation:

```bash
asset=quelda-x86_64-unknown-linux-musl.tar.gz
curl -fsSLO "https://github.com/tranhuucanh/quelda/releases/latest/download/$asset"
curl -fsSLO https://github.com/tranhuucanh/quelda/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify "$asset" --repo tranhuucanh/quelda
```

| Platform | Archive |
|---|---|
| Linux x64 | `quelda-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `quelda-aarch64-unknown-linux-musl.tar.gz` |
| macOS, Apple Silicon | `quelda-aarch64-apple-darwin.tar.gz` |

### From source

With Rust (stable, via [rustup](https://rustup.rs)), on any platform Rust supports:

```bash
cargo install --locked --git https://github.com/tranhuucanh/quelda quelda-cli
```

## Scan a file

```bash
quelda scan upload.pdf                         # default preset (balanced); JSON verdict on stdout
quelda scan upload.pdf --preset strict
quelda scan upload.pdf --policy policy.json
quelda scan upload.pdf --rule EMBED.EMBEDDED_FILE=warn --rule EXTERNAL.URI=off
quelda scan upload.pdf --policy-json '{"rules": {"EMBED.EMBEDDED_FILE": "warn"}}'
quelda scan - < upload.pdf                     # read the file from stdin
quelda scan upload.pdf --format text           # human-readable
```

| Option | Meaning |
|---|---|
| `-p`, `--preset strict\|balanced\|permissive` | Preset. Overrides the preset of `--policy` / `--policy-json`. Default: `balanced`. |
| `--rule <ID>=<action>` | Action of one rule: `off`, `warn` or `block`. Repeat it for more rules. Wins over the same rule in `--policy` / `--policy-json`. |
| `--policy <file>` | Policy JSON file. |
| `--policy-json <json>` | Policy as a JSON string. |
| `--stop-on-first` | Stop at the first blocking finding: faster on bad files, lists fewer reasons. |
| `-f`, `--format json\|text` | `json` (default) is for programs; `text` is for people. |
| `--` | End of options, for a file name that starts with `-`. |

A regular file is read on demand, so memory use does not grow with its size, and there is no
size limit by default. stdin, pipes and devices must be read into memory: they are kept up to
`limits.max_file_bytes`, or 4 GiB when the policy sets no limit. A larger input is `ERROR`
(`LIMIT.FILE_BYTES`) and is not kept, so an endless stream cannot use up the memory.

Files are identified by content, not by extension. PDF and modern Adobe Illustrator `.ai` files
(Illustrator 9 and later) are scanned. PostScript, EPS and legacy `.ai` files are **always
rejected** (`FILETYPE.POSTSCRIPT_MAGIC`, a locked rule).

## Scan a folder

Give folders, files, or both. Folders are scanned recursively; every file gets its own result,
with its full path:

```bash
quelda scan uploads/                           # one JSON line per file
quelda scan uploads/ --format text             # for people: each file, then a summary by rule
quelda scan uploads/ --format csv > report.csv # for a spreadsheet
quelda scan uploads/ upload.pdf --preset strict
quelda scan uploads/ | jq -r 'select(.verdict.valid | not) | .file'   # the invalid files
```

`--format text`:

<!-- batch-text -->
```text
REJECT  uploads/2026/11/brochure.pdf
  block  FILETYPE.NOT_PDF_HEADER  [critical]  File does not start with a PDF header
         at file, offset 0, file starts with "%!PS-Ado"
  block  FILETYPE.POSTSCRIPT_MAGIC  [critical]  File is PostScript/EPS, not PDF
         at file, offset 0, PostScript magic `%!`
  warn   STRUCT.XREF_MISMATCH  [medium]  Cross-reference data does not match the file (×2)
PASS    uploads/2026/11/invoice.pdf
REJECT  uploads/2026/12/form.pdf
  block  ACTIVE.JAVASCRIPT  [high]  Document contains JavaScript
         at object 10 0, file, offset 519
PASS    uploads/2026/12/logo.AI

4 files: 2 PASS, 2 REJECT, 0 ERROR in 0.0 s (4 jobs)
Skipped: 1 file not .pdf or .ai (--all scans them)

ACTIVE.JAVASCRIPT (block): 1 file
  uploads/2026/12/form.pdf

FILETYPE.NOT_PDF_HEADER (block): 1 file
  uploads/2026/11/brochure.pdf

FILETYPE.POSTSCRIPT_MAGIC (block): 1 file
  uploads/2026/11/brochure.pdf

STRUCT.XREF_MISMATCH (warn): 1 file
  uploads/2026/11/brochure.pdf
```

The default output is [JSON Lines](https://jsonlines.org/): one line per file
([`schemas/scan-line.schema.json`](../schemas/scan-line.schema.json)), with the path, the
SHA-256 of the file and the same [verdict](#the-verdict) as a single scan:

```jsonl
{"file":"uploads/2026/12/form.pdf","sha256":"5a4d17bf…","verdict":{"valid":false,"status":"REJECT",…}}
```

`--format csv` has one row per file: `file`, `status`, `valid`, `violations` and `warnings`
(rule IDs separated by spaces), `errors` (`CODE: message`, separated by `; `), `sha256`,
`bytes`, `duration_ms`. A cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so
a spreadsheet does not run a file name as a formula.

What is scanned:

- **Every file named on the command line**, whatever its name.
- **Inside folders, `.pdf` and `.ai` files** (any case: `.PDF`, `.Ai`), at any depth.
  `--all` scans every file instead (files are always identified by content, so a disguised
  file is still caught). The summary says how many files were left out and why.
- **Symbolic links inside folders are not followed**, nor pipes or devices (counted as
  skipped). A link named on the command line is followed.
- A file or folder that cannot be read gets its own `ERROR` result (`ENGINE.READ`): nothing
  is dropped silently.

The order is fixed: the arguments in order, and inside a folder the paths sorted by name, so
two runs give the same output. Paths are printed as you typed them (`uploads/…`,
`./uploads/…`, `/srv/uploads/…`); `--absolute` prints absolute paths.

| Option | Meaning |
|---|---|
| `-f`, `--format jsonl\|text\|csv` | Default: `jsonl`. (`json` is for one file only.) |
| `--all` | In folders, scan every file, not only `.pdf` and `.ai`. |
| `--absolute` | Print absolute paths. |
| `--no-hash` | Do not compute the SHA-256 (`"sha256": null`); about 15% faster. |
| `-j`, `--jobs <n>` | Files scanned at once. Default: one per CPU core. |

`--preset`, `--rule`, `--policy`, `--policy-json` and `--stop-on-first` apply to every file. An invalid
policy scans nothing (exit code `2`, message on stderr).

**Exit code**: `0` only when every file is `PASS`; `2` when any file is `ERROR`, or when no
file was found to scan; otherwise `1`. With `jsonl` and `csv` the summary line goes to
stderr, so stdout stays machine-readable.

**Speed**: files are scanned in parallel, one per CPU core. On an Apple M2 Pro (10 cores),
5,820 files in nested folders (8 GB) take 6 s; one file at a time (`-j 1`) takes 26 s.
**Memory**: each file being scanned needs its own memory (a few MB for most files, a few
hundred MB for the [heaviest](../README.md#-speed-and-memory)); the 5,820 files above peaked at
370 MB. Lower `-j` to cap memory on a small server.

To scan one PDF passed with a single name, nothing changes: `quelda scan upload.pdf` prints
one verdict. To get the one-line-per-file format even for a single file (for example from a
glob that may match one file), pass `--format jsonl`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | `PASS`: the file is valid under the policy. |
| `1` | `REJECT`: at least one rule blocks the file. |
| `2` | `ERROR`: the file could not be fully inspected (damaged, too large, unreadable), or the policy is invalid or unreadable. The file is invalid. |
| `64` | Usage error (unknown option, missing file name). Nothing on stdout. |
| `74` | The verdict could not be written (stdout closed). |

**Treat every exit code other than `0` as invalid**, including a crash, a signal or a timeout.
For codes 0–2 the verdict JSON is on stdout; for the others, a message is on stderr. For a
folder or several files, the code is the worst status of any file
(see [Scan a folder](#scan-a-folder)).

## The verdict

One JSON object on one line, shown formatted here ([`schemas/verdict.schema.json`](../schemas/verdict.schema.json)):

<!-- verdict: rules/ACTIVE.JAVASCRIPT/bad/plain.pdf -->
```json
{
  "valid": false,
  "status": "REJECT",
  "violations": [
    {
      "rule_id": "ACTIVE.JAVASCRIPT",
      "category": "active_content",
      "severity": "high",
      "action": "block",
      "message": "Document contains JavaScript",
      "count": 1,
      "locations": [{ "object": "10 0", "offset": 519, "source": "file" }]
    }
  ],
  "warnings": [],
  "errors": [],
  "engine_version": "…",
  "policy": {
    "preset": "balanced",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "unsafe_allow_unlock": false,
    "stop_on_first": false
  },
  "stats": { "bytes": 816, "objects": 7, "revisions": 1, "decoded_bytes": 0, "duration_ms": 0 }
}
```

- `valid` is `true` exactly when `status` is `PASS` (and the exit code is `0`).
- `violations`: rules with action `block`; `warnings`: rules with action `warn` (they do not make
  the file invalid). One entry per rule, with the total `count` and up to 64 `locations`.
- `errors`: why the engine could not inspect everything (`ENGINE.*`, `LIMIT.*`) or why the
  policy was refused (`POLICY.INVALID`). Any error makes the status `ERROR`.
- `policy.digest` identifies the policy as written; log it next to the verdict.

## Policy

A policy chooses how strict the scan is. Full guide: **[policy.md](policy.md)** (how it works,
the presets, recipes, every field and limit, engine errors). What each rule catches:
**[rules.md](rules.md)**.

The short version:

- **Every rule always runs.** A policy starts from a preset (`strict`, `balanced` — the default
  — or `permissive`) and changes the action (`block`, `warn`, `off`) of the categories and rules
  you name; everything else keeps its preset action.
- The most specific setting wins: preset → `categories` → `rules`.
- Locked rules (PostScript, Launch, files that are not PDF, …) always block.
- The policy is parsed strictly: a typo, an unknown field or a rule ID this engine does not know
  is `ERROR` (`POLICY.INVALID`, exit code 2), never silently ignored.

```json
{
  "preset": "balanced",
  "categories": { "external": "warn", "codecs": "off" },
  "rules": { "EMBED.EMBEDDED_FILE": "warn" },
  "limits": { "max_file_bytes": 52428800 }
}
```

Pass it with `--policy policy.json` or `--policy-json '…'`; `--preset` and `--stop-on-first`
override the policy's `preset` and `stop_on_first`.

To change a few rules from the command line, `--rule` is shorter than JSON (it wins over the
same rule in the policy):

```bash
quelda scan upload.pdf --preset strict --rule EXTERNAL.URI=off --rule EMBED.EMBEDDED_FILE=warn
```

Lowering a locked rule (`[locked]` in `quelda rules -f text`) has no effect: the rule still
blocks and quelda prints a warning on stderr. `quelda help policy` sums all this up.

### Keep every engine on the same rule set

A policy written for a newer quelda (naming a rule an older one does not have) makes every scan
of the older one `ERROR`. Upgrade the CLI and the npm package together, or check the policy
against `quelda rules` before you deploy it. After an upgrade, new rules apply with their
preset's action; read the [changelog](../CHANGELOG.md) (section **Rules**) first.

## Call it from your backend

1. **Pass arguments as an array**, never through a shell, and **name the file yourself** (for
   example a UUID in a private temporary directory), never with the name the user uploaded.
2. **Set a timeout** (30 s is plenty for most files; a scan of a 100 MB file takes about a
   second). A timeout means invalid.
3. **Only exit code `0` means valid.** Read the verdict JSON for the reasons.
4. Scan on the server even if the browser already scanned the file: the browser check is a
   convenience that anyone can skip.
5. Do not use another parser (qpdf, pdf.js, …) as a filter in front of Ghostscript instead: PDF
   readers disagree about damaged files, and attacks live in those disagreements.

Each example below is a complete program, tested against the real binary in each language's
official container image (`scripts/docs-examples-test.mjs`). Run it as `<program> upload.pdf`;
it prints `valid=true status=PASS` or `valid=false status=…`.

### Python

<!-- example: python/scan.py -->
```python
import json
import subprocess
import sys


def quelda_scan(path, policy=None, timeout=30):
    """Scans one file with the quelda CLI. Only exit code 0 means valid."""
    args = ["quelda", "scan", path]
    if policy:
        args += ["--policy", policy]
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"valid": False, "status": "TIMEOUT"}
    try:
        verdict = json.loads(r.stdout)
    except ValueError:
        verdict = {"status": f"EXIT {r.returncode}"}
    verdict["valid"] = r.returncode == 0
    return verdict


if __name__ == "__main__":
    v = quelda_scan(sys.argv[1])
    print(f"valid={str(v['valid']).lower()} status={v['status']}")
```

### Ruby

<!-- example: ruby/scan.rb -->
```ruby
require "json"
require "open3"

# Scans one file with the quelda CLI. Only exit code 0 means valid.
def quelda_scan(path, policy: nil, timeout: 30)
  args = ["quelda", "scan", path]
  args += ["--policy", policy] if policy
  Open3.popen3(*args) do |stdin, stdout, stderr, wait|
    stdin.close
    out = Thread.new { stdout.read }
    Thread.new { stderr.read }
    unless wait.join(timeout)
      Process.kill("KILL", wait.pid)
      return { "valid" => false, "status" => "TIMEOUT" }
    end
    code = wait.value.exitstatus
    verdict = begin
      JSON.parse(out.value)
    rescue JSON::ParserError
      { "status" => "EXIT #{code}" }
    end
    verdict.merge("valid" => code == 0)
  end
end

if __FILE__ == $PROGRAM_NAME
  v = quelda_scan(ARGV.fetch(0))
  puts "valid=#{v['valid']} status=#{v['status']}"
end
```

### Node.js

<!-- example: node/scan.mjs -->
```js
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
```

### Go

<!-- example: go/scan.go -->
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type Verdict struct {
	Valid      bool   `json:"valid"`
	Status     string `json:"status"`
	Violations []struct {
		RuleID  string `json:"rule_id"`
		Message string `json:"message"`
	} `json:"violations"`
}

// QueldaScan scans one file with the quelda CLI. Only exit code 0 means valid.
func QueldaScan(path string) Verdict {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "quelda", "scan", path).Output()
	var v Verdict
	if ctx.Err() != nil {
		v.Status = "TIMEOUT"
	} else if json.Unmarshal(out, &v) != nil {
		v.Status = fmt.Sprintf("NO VERDICT (%v)", err)
	}
	v.Valid = err == nil // a non-zero exit, a timeout or a failed start is an error
	return v
}

func main() {
	v := QueldaScan(os.Args[1])
	fmt.Printf("valid=%t status=%s\n", v.Valid, v.Status)
}
```

### PHP

<!-- example: php/scan.php -->
```php
<?php
// Scans one file with the quelda CLI. Only exit code 0 means valid.
function quelda_scan(string $path, ?string $policy = null, int $timeout = 30): array
{
    $args = ['quelda', 'scan', $path];
    if ($policy !== null) {
        array_push($args, '--policy', $policy);
    }
    // An array command runs without a shell (PHP >= 7.4).
    $proc = proc_open($args, [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    if ($proc === false) {
        return ['valid' => false, 'status' => 'NOT STARTED'];
    }
    stream_set_blocking($pipes[1], false);
    $out = '';
    $deadline = microtime(true) + $timeout;
    do {
        $out .= stream_get_contents($pipes[1]);
        $status = proc_get_status($proc);
        if ($status['running'] && microtime(true) > $deadline) {
            proc_terminate($proc, 9);
            proc_close($proc);
            return ['valid' => false, 'status' => 'TIMEOUT'];
        }
        usleep(10000);
    } while ($status['running']);
    $out .= stream_get_contents($pipes[1]);
    proc_close($proc);
    $verdict = json_decode($out, true) ?? ['status' => 'EXIT ' . $status['exitcode']];
    $verdict['valid'] = $status['exitcode'] === 0;
    return $verdict;
}

if (realpath($argv[0] ?? '') === __FILE__) {
    $v = quelda_scan($argv[1]);
    echo 'valid=' . ($v['valid'] ? 'true' : 'false') . ' status=' . $v['status'] . "\n";
}
```

### Java

<!-- example: java/QueldaScan.java -->
```java
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class QueldaScan {
    /** {@code valid}: exit code 0; {@code json}: the verdict (parse it with your JSON library). */
    record Result(boolean valid, String json) {}

    /** Scans one file with the quelda CLI. Only exit code 0 means valid. */
    static Result scan(String path) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(List.of("quelda", "scan", path))
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        CompletableFuture<String> out = CompletableFuture.supplyAsync(() -> {
            try {
                return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            return new Result(false, "{\"status\":\"TIMEOUT\"}");
        }
        return new Result(p.exitValue() == 0, out.join());
    }

    public static void main(String[] args) throws Exception {
        Result r = scan(args[0]);
        Matcher m = Pattern.compile("\"status\":\"(\\w+)\"").matcher(r.json());
        System.out.println("valid=" + r.valid() + " status=" + (m.find() ? m.group(1) : "?"));
    }
}
```

## Other commands

```bash
quelda rules                    # every rule as JSON (schemas/rules.schema.json)
quelda rules -f text            # ID, category, default action, [locked], message
quelda version                  # version, commit, build date, number of rules (also -v)
quelda version -f json
quelda --help                   # the commands, common options and examples (also -h)
quelda help scan                # every scan option
quelda help policy              # how to change rules, with examples
```

Short options: `-p` is `--preset`, `-f` is `--format`, `-j` is `--jobs`, `-h` is `--help`,
`-v` (or `-V`) is `--version`. A short option takes its value as the next argument or
attached (`-f text`, `-ftext`).
