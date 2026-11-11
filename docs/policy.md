# Policies

A policy tells quelda how strict to be: which findings make a file invalid (`block`), which
are only reported (`warn`) and which are ignored (`off`), plus the engine's size limits and a
few detection thresholds. The same policy JSON works in the CLI and in the npm package, and gives
the same verdict in both.

- [How a policy works](#how-a-policy-works)
- [Presets](#presets)
- [Write your own policy](#write-your-own-policy)
- [Recipes](#recipes)
- [Reference](#reference)
- [Engine errors](#engine-errors)

## How a policy works

**A policy adjusts a preset; it never replaces the rule set.** Every rule quelda knows (see
[rules.md](rules.md)) runs on every scan. The policy only decides what each finding does:

```text
1. preset          every rule gets the action its preset gives its category
                   (default preset: balanced)
2. categories      a category you name gets your action, for all its rules
3. rules           a rule you name gets your action (the most specific wins)
4. locked rules    always block, unless "unsafe_allow_unlock": true
```

Anything you do not name keeps its preset action. So this policy:

```json
{
  "preset": "strict",
  "categories": { "external": "warn" },
  "rules": { "EXTERNAL.URI": "off" }
}
```

means: *all 48 rules run with the `strict` actions, except that the `external` category only
warns, and `EXTERNAL.URI` (ordinary hyperlinks) is ignored*. It does **not** mean "run only the
external rules". A rule set to `off` is skipped; there is no way to add rules through a policy.

No policy at all (`{}`, or no `--policy` flag) is the `balanced` preset with the default limits.

The three actions:

| Action | Effect |
|---|---|
| `block` | A finding makes the file invalid: `status` `REJECT`, listed in `violations`, CLI exit code 1. |
| `warn` | Reported in `warnings`; the file stays valid. Use it to watch a rule before blocking it. |
| `off` | The rule does not run. |

Separately from rules, the engine stops with `ERROR` (invalid, CLI exit code 2) when it cannot
inspect the whole file: damaged structure, a limit exceeded, an unreadable input. A policy cannot
turn these off; it can only raise the [limits](#limits). See [Engine errors](#engine-errors).

## Presets

| Category | What it covers | strict | balanced | permissive |
|---|---|---|---|---|
| `filetype` | Not a PDF, PostScript/EPS, other formats disguised as PDF, polyglots | block | block | block |
| `postscript` | PostScript code inside a PDF | block | block | block |
| `encryption` | Encrypted files (their content cannot be inspected) | block | block | block |
| `active_content` | JavaScript, Launch, actions that run on open or on events | block | block | warn |
| `embedded` | Attached files, portfolios, multimedia and 3D | block | block | warn |
| `xml` | XML with DOCTYPE/ENTITY (XXE, billion laughs) | block | block | warn |
| `resource` | Pixel bombs, huge or broken pages, page-count bombs | block | block | warn |
| `external` | Links, remote documents, form submission, network file references | block | warn | off |
| `forms` | AcroForm and XFA forms | block | warn | off |
| `structure` | Damaged or ambiguous structure (xref, duplicates, trailing data, …) | block | warn | off |
| `codecs` | Risky image codecs (JBIG2, JPEG 2000), fonts and colour profiles | block | warn | off |

Nine rules differ from their category:

| Rule | strict | balanced | permissive | Why |
|---|---|---|---|---|
| `ACTIVE.OTHER_ACTIONS` | block | warn | warn | Named actions (next page, print…) are common and harmless on their own. |
| `STRUCT.INCREMENTAL_UPDATE` | warn | off | off | Edited and signed files have updates; quelda scans every revision anyway. |
| `CODEC.TYPE1_FONT` | warn | off | off | Print files use Type 1 fonts a lot. |
| `EXTERNAL.STREAM_FILE` | block | block | warn | Content read from outside the file is never what was checked; real files embed it. |
| `EXTERNAL.OPI` | block | block | warn | Same: the printed image is a file the PDF names. Old OPI workflows can use `permissive`. |
| `STRUCT.NAME_TOO_LONG` | block | block | block | Never written by real producers; aimed at renderer buffers. |
| `CODEC.DECODE_PARAMS` | block | block | block | Never written by real producers; aimed at decoder buffers. |
| `CODEC.FONT_MALFORMED` | block | block | warn | Font tools never write them; `permissive` only warns, for archives of old, damaged files. |
| `CODEC.ICC_MALFORMED` | block | block | warn | Same, for colour profiles. |

**Locked rules** block in every preset (even `permissive`, where their category would only warn):
`FILETYPE.POSTSCRIPT_MAGIC`, `FILETYPE.NOT_PDF_HEADER`, `FILETYPE.FOREIGN_MAGIC`,
`POSTSCRIPT.CONTENT_OP`, `POSTSCRIPT.XOBJECT`, `ACTIVE.LAUNCH`. These are the ways a file gets
code executed by Ghostscript, ImageMagick or a reader.

Which preset?

- **`strict`**: files from anyone go straight into Ghostscript, ImageMagick, a print RIP or a
  thumbnailer. Rejects anything unusual, including hyperlinks, forms and damaged structure, so
  expect to reject some legitimate files; relax rule by rule after looking at what you reject.
- **`balanced`** (default): blocks everything that can execute, carry a payload or exhaust a
  server, and only warns about features common in normal documents (links, forms, structure
  repairs, risky codecs).
- **`permissive`**: files from sources you mostly trust. Still blocks the file-type, PostScript,
  encryption and locked rules; everything else at most warns.

## Write your own policy

Start from a preset and change only what you need. In the CLI:

```bash
quelda scan upload.pdf --preset strict                     # a preset only
quelda scan upload.pdf --policy policy.json                # a policy file
quelda scan upload.pdf --rule EXTERNAL.URI=off              # one rule, no JSON
quelda scan upload.pdf --policy-json '{"rules": {"EXTERNAL.URI": "off"}}'
quelda scan upload.pdf --policy policy.json --preset strict --stop-on-first
```

`--preset` replaces the `preset` of the policy file; `--rule ID=action` (repeatable) sets one
entry of `rules`, winning over the file; `--stop-on-first` sets `stop_on_first`. A locked rule
lowered without `unsafe_allow_unlock` still blocks, and the CLI prints a warning on stderr.
`quelda help policy` prints a summary of this page.

In the npm package, pass the same object:

```ts
const verdict = await scanner.scan(file, {
  preset: 'balanced',
  rules: { 'EMBED.EMBEDDED_FILE': 'warn' },
});
```

To tune a policy for your users:

1. Scan a sample of real uploads with the preset you want (`--format text` is easy to read).
2. For each rule that rejects legitimate files, read what it means in [rules.md](rules.md) and
   decide: keep it (`block`), watch it (`warn`), or ignore it (`off`). Prefer changing **one
   rule** over a whole category, and a category over the preset.
3. Keep the policy file in version control. Each verdict reports `policy.digest` (a SHA-256 of
   the policy as written), so you can tell which policy produced it.

## Recipes

Accept documents with attachments (some e-books and reports), but keep reporting them:

```json
{ "rules": { "EMBED.EMBEDDED_FILE": "warn", "EMBED.FILE_ATTACHMENT": "warn" } }
```

Maximum safety in front of Ghostscript, but allow ordinary hyperlinks:

```json
{ "preset": "strict", "rules": { "EXTERNAL.URI": "warn" } }
```

Uploads up to 20 MiB only, rejected as early as possible:

```json
{ "limits": { "max_file_bytes": 20971520 }, "stop_on_first": true }
```

Large-format printing (banners up to about 25 m long):

```json
{ "thresholds": { "max_page_side_pt": 72000 } }
```

Forms are your business (fillable PDFs), but they must not submit data anywhere:

```json
{ "categories": { "forms": "off" }, "rules": { "EXTERNAL.SUBMIT_FORM": "block" } }
```

## Reference

Every field is optional ([`schemas/policy.schema.json`](../schemas/policy.schema.json)).

| Field | Type | Meaning |
|---|---|---|
| `preset` | `"strict"` \| `"balanced"` \| `"permissive"` | Starting point. Default `balanced`. |
| `categories` | object: category → action | Action for every rule of a category. |
| `rules` | object: rule ID → action | Action for one rule (wins over its category). |
| `limits` | object | Engine limits; exceeding one is an `ERROR`. |
| `thresholds` | object | Detection thresholds of some rules; exceeding one is a finding. |
| `stop_on_first` | boolean | Stop at the first `block` finding: faster on bad files, fewer reasons listed. Default `false`. |
| `unsafe_allow_unlock` | boolean | Lets `categories` / `rules` lower locked rules. Reported in the verdict. Never for untrusted files. Default `false`. |

Categories: `filetype`, `postscript`, `active_content`, `embedded`, `external`, `forms`, `xml`,
`structure`, `encryption`, `codecs`, `resource`. Actions: `block`, `warn`, `off`.

### Limits

Guardrails that keep a scan's time and memory bounded. A file over a limit is `ERROR`
(invalid): the engine refuses to judge what it could not fully inspect.

| Limit | Default | Error |
|---|---|---|
| `max_file_bytes` | `18446744073709551615` (no limit) | `LIMIT.FILE_BYTES` |
| `max_objects` | `1000000` | `LIMIT.OBJECTS` |
| `max_revisions` | `1000` | `LIMIT.REVISIONS` |
| `max_nesting_depth` | `128` (at most 512) | `LIMIT.NESTING_DEPTH` |
| `max_decoded_bytes_per_stream` | `134217728` (128 MiB) | `LIMIT.STREAM_DECODED_BYTES` |
| `max_decoded_bytes_total` | `536870912` (512 MiB) | `LIMIT.DECODED_BYTES` |
| `max_compression_ratio` | `1000` | `LIMIT.COMPRESSION_RATIO` |

Images and attachments are never decompressed (they are not needed to judge the file), so the
decode limits only count data the engine must read: page contents, object streams, XML, and
streams of unknown role. Embedded fonts and ICC colour profiles are decompressed to check their
structure, each within the same limits but not counted in the scan's total; one that hits a
limit is not judged.

### Thresholds

| Threshold | Default | Rule |
|---|---|---|
| `max_image_pixels` | `1000000000` | `RESOURCE.IMAGE_DIMENSIONS` |
| `max_page_side_pt` | `28800` (400 in, about 10 m) | `RESOURCE.PAGE_SIZE` |
| `max_pages` | `10000` | `RESOURCE.PAGE_COUNT` |
| `max_filter_chain` | `2` | `STRUCT.FILTER_CHAIN` |
| `max_trailing_bytes` | `1024` | `STRUCT.TRAILING_DATA` |

### Strict parsing

The policy itself is checked strictly. Unknown fields, duplicate keys, `null`, values of the
wrong type, unknown categories and **rule IDs this engine version does not know** make every
scan `ERROR` with `POLICY.INVALID` (CLI exit code 2). A typo that silently switched a rule off
would be worse than an error. Before deploying a policy written for a newer quelda, check it
against `quelda rules` (or `scanner.listRules()`).

## Engine errors

An error makes the verdict `ERROR` and the file invalid, whatever the policy says.

| Code | Meaning | What to do |
|---|---|---|
| `ENGINE.PARSE` | Bytes the engine must parse are not valid PDF syntax. | Damaged or crafted file: reject. |
| `ENGINE.UNDECODABLE` | A stream that must be inspected (object stream, page content, XML) uses an unknown filter or holds corrupt data. | Reject: what is hidden there cannot be checked. |
| `ENGINE.READ` | The input could not be read (missing file, I/O error, a browser `File` that changed). | Check the path or the upload. |
| `LIMIT.FILE_BYTES` | The file is larger than `limits.max_file_bytes` (no limit unless the policy sets one); nothing was parsed. | Raise the limit if such files are expected. |
| `LIMIT.OBJECTS` | More objects than `limits.max_objects`. | Raise the limit for very large documents. |
| `LIMIT.REVISIONS` | More revisions (incremental updates) than `limits.max_revisions`. | Usually crafted: reject. |
| `LIMIT.NESTING_DEPTH` | Arrays/dictionaries nested deeper than `limits.max_nesting_depth`. | Usually crafted: reject. |
| `LIMIT.STREAM_DECODED_BYTES` | One stream decompresses to more than `limits.max_decoded_bytes_per_stream`. | A compression bomb, or a huge page: raise only if expected. |
| `LIMIT.DECODED_BYTES` | All streams together decompress to more than `limits.max_decoded_bytes_total`. | As above. |
| `LIMIT.COMPRESSION_RATIO` | A stream decompresses to more than `limits.max_compression_ratio` × its size. | A compression bomb: reject. |
| `LIMIT.FILTER_CHAIN` | A stream stacks more than 16 filters (fixed). | Crafted: reject. |
| `LIMIT.PARSE_WORK` | Overlapping objects would make parsing re-read the file too many times (fixed). | Crafted: reject. |
| `POLICY.INVALID` | The policy is not valid (see [Strict parsing](#strict-parsing)), or the CLI could not read the policy file. | Fix the policy; nothing was scanned. |
