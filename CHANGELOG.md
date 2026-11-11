# Changelog

All notable changes to quelda are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and quelda uses
[Semantic Versioning](https://semver.org/). The CLI, the npm package and the
engine share one version.

Rule IDs never change meaning or disappear. A new rule, or a rule that starts to
match more files, is listed under **Rules** because it can change verdicts.

## [0.2.0] — unreleased

### Added

- CLI: scan folders and several files at once: `quelda scan uploads/ more.pdf`.
  Folders are walked recursively (`.pdf` and `.ai` files; `--all` for every file;
  symbolic links are not followed), files are scanned in parallel (`-j`, default
  one per CPU core), and each file gets its own result with its full path and
  SHA-256, in a fixed order. Output: JSON Lines (`schemas/scan-line.schema.json`),
  `--format text` (each file, then a summary listing the files of each rule) or
  `--format csv`. The exit code is the worst status of any file. Scanning one file
  works as before.
- npm README: scanning a whole folder picked in the browser.

### Rules

Five new rules (45 in all) and one rule that now looks in more places. On the
real files we test with, no verdict changed in any preset.

- `EXTERNAL.STREAM_FILE` (new; block in strict and balanced, warn in permissive):
  images or other content read from a file outside the PDF (a stream with `/F`,
  `/FFilter` or `/FDecodeParms`, or a reference XObject).
- `EXTERNAL.OPI` (new; block, block, warn): OPI comments that make prepress
  software swap an image for a file it reads from its own disk or network.
- `STRUCT.NAME_TOO_LONG` (new; blocks in every preset): a name longer than the
  127 bytes readers are built for (long font names have overflowed renderer
  buffers).
- `CODEC.DECODE_PARAMS` (new; blocks in every preset): decoder parameters outside
  the spec (`/Predictor`, `/Colors`, `/BitsPerComponent`, `/Columns`, `/Rows`, …).
- `STRUCT.PRINT_VIEW_MISMATCH` (new; block, warn, off): content that prints but
  is hidden on screen (print-only annotations or layers).
- `POSTSCRIPT.CONTENT_OP` (locked) also checks default appearance strings
  (`/DA` of forms, fields and free-text annotations).

### Changed

- No file size limit by default: `limits.max_file_bytes` was 256 MiB and now has
  no default, so a file of any size is scanned (files are read in place, so a
  1 GB file takes under a second and a few MB of memory). Set
  `limits.max_file_bytes` in the policy to bring a limit back.
- CLI: input from stdin or a pipe is read into memory, so it stops at 4 GiB
  (`LIMIT.FILE_BYTES`, exit 2) when the policy sets no `limits.max_file_bytes`.
  Files given by path have no such cap.
- CLI `--format text`: the status is padded so that file names line up
  (`PASS    a.pdf`), and control characters in file names and messages are
  escaped (`\u{1b}`) so a file cannot drive the terminal.

## [0.1.0] — 2026-11-11

First public release.

### Added

- Scan engine (Rust): one file + a policy in, a JSON verdict out (`valid`, `status`
  `PASS` / `REJECT` / `ERROR`, the rules that fired, where, and why). Union scan
  over every object of every revision; fail-closed: anything that cannot be
  inspected makes the file invalid.
- Policy: presets `strict`, `balanced` (default), `permissive`; per-category and
  per-rule overrides; limits and thresholds. JSON Schemas in `schemas/`.
- `quelda` CLI: `scan` (file or stdin), `rules`, `version`. Exit codes 0 PASS,
  1 REJECT, 2 ERROR, 64 usage error. Static binaries for Linux x64/arm64 (musl)
  and macOS arm64, Homebrew tap (macOS).
- npm package `quelda`: WebAssembly engine in a Web Worker, TypeScript API
  (`createScanner`, `scan`, `listRules`), for browsers; works with Vite, webpack,
  esbuild, no bundler, import maps and CDNs.

### Rules

- 40 rules in 11 categories: file type (PostScript/EPS/legacy AI, polyglots),
  PostScript, active content (JavaScript, Launch, actions), embedded files,
  external references, forms, XML (XFA, DOCTYPE), structure, encryption, codecs,
  resources. List them with `quelda rules --format text`.
