# Changelog

All notable changes to quelda are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and quelda uses
[Semantic Versioning](https://semver.org/). The CLI, the npm package and the
engine share one version.

Rule IDs never change meaning or disappear. A new rule, or a rule that starts to
match more files, is listed under **Rules** because it can change verdicts.

## [0.1.0] — unreleased

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
  and macOS arm64, Homebrew tap.
- npm package `quelda`: WebAssembly engine in a Web Worker, TypeScript API
  (`createScanner`, `scan`, `listRules`), for browsers; works with Vite, webpack,
  esbuild, no bundler, import maps and CDNs.

### Rules

- 40 rules in 11 categories: file type (PostScript/EPS/legacy AI, polyglots),
  PostScript, active content (JavaScript, Launch, actions), embedded files,
  external references, forms, XML (XFA, DOCTYPE), structure, encryption, codecs,
  resources. List them with `quelda rules --format text`.
