# Rules

quelda has **56 rules in 11 categories**. Each one looks for one thing that attackers use against
PDF readers and server-side PDF tools (Ghostscript, ImageMagick, print RIPs, thumbnailers), or
that makes different PDF software see different documents. On top of the rules, the engine
refuses to judge what it cannot fully inspect (see [engine errors](policy.md#engine-errors)).

The columns give each rule's action in each [preset](policy.md#presets): `block` makes the file
invalid, `warn` reports it, `off` skips it. 🔒 marks a **locked** rule: it blocks whatever the
policy says (unless `unsafe_allow_unlock`). Change any other rule with a
[policy](policy.md#write-your-own-policy). `quelda rules` (or `scanner.listRules()`) prints the
same list with a longer technical description of each rule.

Rule IDs are stable: an ID never changes meaning and is never reused.

## How every rule sees the file

The rules do not read bytes themselves. The engine parses the file once and gives every rule the
same view, so a trick that hides something from one rule hides it from none:

- **Every object of every revision.** Old revisions (incremental updates), objects that no
  cross-reference table lists, duplicates, and objects packed in compressed object streams are
  all scanned. quelda never "repairs" a file and picks one version: if any reader could see it,
  it is checked.
- **Decoded names and strings.** `/J#61vaScript`, hex strings, UTF-16 text and escapes are
  normalized before any rule looks at them.
- **Decompressed content.** Page contents, object streams and XML go through the filter chain
  (Flate, LZW, ASCII85, ASCIIHex, RunLength, predictors), with limits against compression
  bombs. Images and attachments are not needed to judge a file and are never decompressed.
  Embedded fonts (TrueType, OpenType, CFF) and ICC colour profiles are decompressed only to
  check their structure; one that does not decompress completely is not judged.
- **Nested and indirect values.** Dictionaries inside dictionaries, values stored in other
  objects, arrays of references: a rule finds `/S /JavaScript` wherever it is.
- **Fail-closed.** Anything the engine cannot parse, decode or read, or that exceeds a limit,
  makes the file invalid (`ERROR`) instead of being skipped.

## File type (`filetype`)

What the file really is. quelda identifies files by their bytes, never by their name.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `FILETYPE.FOREIGN_MAGIC` 🔒 | Another format renamed to `.pdf`: SVG/HTML/XML, ImageMagick MVG/MSL, ZIP/7z/RAR/GZIP archives, Office/RTF documents, images, Windows/Linux executables. | block | block | block |
| `FILETYPE.NOT_PDF_HEADER` 🔒 | Files that do not start with `%PDF-1.` / `%PDF-2.`. Software that looks for the header further in, or sniffs the content, may treat them as something else. | block | block | block |
| `FILETYPE.POLYGLOT` | A real PDF that is *also* a ZIP archive or an HTML/SVG page, depending on which program opens it. | block | block | block |
| `FILETYPE.POSTSCRIPT_MAGIC` 🔒 | PostScript, EPS (also binary DOS EPS) and legacy Illustrator files, even behind a byte order mark, whitespace or a printer (PJL) header. Ghostscript and ImageMagick run them as programs whatever the file is called — the most common way to attack them. | block | block | block |

## PostScript (`postscript`)

PostScript code hidden inside a PDF, which Ghostscript-based tools may execute.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `POSTSCRIPT.CONTENT_OP` 🔒 | The `PS` operator in any content stream (pages, forms, appearances, Type 3 glyphs) or form default-appearance string (`/DA`): raw PostScript handed to the interpreter. | block | block | block |
| `POSTSCRIPT.TYPE4_FUNCTION` | Type 4 (calculator) functions that use anything beyond the 42 operators allowed by the PDF spec, or that are oversized or nested too deep. Plain colour functions from Illustrator or InDesign pass. | block | block | block |
| `POSTSCRIPT.XOBJECT` 🔒 | PostScript XObjects and forms with a PostScript alternate: PostScript code that Ghostscript may execute. | block | block | block |

## Active content (`active_content`)

Code and actions that run in a PDF reader.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `ACTIVE.ADDITIONAL_ACTIONS` | Actions triggered by events (open, close, page view, focus, keystroke, mouse) without a click. | block | block | warn |
| `ACTIVE.JAVASCRIPT` | JavaScript anywhere: actions, document-level scripts, rendition scripts, as text or as a stream. The most common PDF exploit vector. | block | block | warn |
| `ACTIVE.LAUNCH` 🔒 | Launch actions, which open or run a file or program on the reader's computer. | block | block | block |
| `ACTIVE.OPEN_ACTION` | An action that runs automatically when the document opens. Opening at a page (a plain destination) is not reported. | block | block | warn |
| `ACTIVE.OTHER_ACTIONS` | Other interactive actions (named, rendition, hide, layer state, sound, movie…), used to chain or hide content. | block | warn | warn |
| `ACTIVE.XFA_SCRIPT` | Scripts (JavaScript or FormCalc) in an XFA form's XML, which Acrobat runs like document JavaScript. Empty `<script/>` elements left by form designers, the config packet's `<script>` settings (`<runScripts>`, …) and form data fields named `script` are not reported. | block | block | warn |
| `ACTIVE.DANGEROUS_URI` | Links that run a script or reach the local machine or a network share: `javascript:`, `vbscript:`, `data:`, `file:`, `smb:`, `\\server\share`, Windows paths, `ms-*:` handlers (`ms-msdt:`, Follina), `search-ms:`; also a document base URI (`/URI << /Base … >>`) of these kinds, which relative links resolve against. Can run code in web viewers or leak Windows credentials (NTLM). Ordinary links (`http`, `https`, `mailto`, `ftp`, `tel`, relative) are not reported. | block | block | warn |

## Embedded content (`embedded`)

Payloads carried inside the PDF.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `EMBED.EMBEDDED_FILE` | Embedded files of any kind (executables, scripts, other documents), however they are referenced. The `/EF` array of an Adobe usage-rights signature (a list of permission names, not a file) is not counted. | block | block | warn |
| `EMBED.FILE_ATTACHMENT` | File attachment annotations: an icon on a page that opens an attached file. | block | block | warn |
| `EMBED.PORTFOLIO` | PDF Portfolios, containers whose real content is their attached files. | block | block | warn |
| `EMBED.RICH_MEDIA` | Multimedia and 3D content (RichMedia, Movie, Sound, Screen, U3D, PRC), handled by large and rarely audited players. | block | block | warn |

## External references (`external`)

Ways a document reaches out to the network or to other files.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `EXTERNAL.IMPORT_DATA` | Forms that load their values from an external file. | block | block | warn |
| `EXTERNAL.OPI` | OPI comments on an image or form: prepress software swaps the content for a file on its own disk or network, named by the PDF. Modern tools do not write them. | block | block | warn |
| `EXTERNAL.REMOTE_GOTO` | Links that open another document, possibly over the network (UNC/SMB paths leak Windows credentials), or an attachment: `GoToR`, `GoToE`, and thread actions that name a file. Ordinary documents link to web pages, not to other files. | block | block | warn |
| `EXTERNAL.STREAM_FILE` | Images or other content read from a file outside the PDF (external streams, reference XObjects): a renderer opens a path or URL chosen by the file, and what prints is not what was checked. Real print files embed their images. | block | block | warn |
| `EXTERNAL.SUBMIT_FORM` | Forms that send their data (or the whole document) to a URL: data exfiltration and phishing. | block | block | warn |
| `EXTERNAL.URI` | Web links. Common in normal documents (so `balanced` only warns), and what phishing documents rely on. | block | warn | off |
| `EXTERNAL.URL_FILESPEC` | File references that point at a URL, so the file is fetched from the network. | block | block | warn |

## Forms (`forms`)

Interactive forms.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `FORMS.ACROFORM` | Interactive (fillable) forms. Their scripts and submit actions are reported by their own rules. | block | warn | off |
| `FORMS.XFA` | XFA forms: a separate XML layout and scripting engine inside the PDF, with a large attack surface. Deprecated in PDF 2.0; only Adobe readers still run it. | block | block | warn |

## XML (`xml`)

XML inside the PDF (metadata, XFA forms).

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `XML.DOCTYPE` | `<!DOCTYPE` or `<!ENTITY` in embedded XML (XMP metadata, XFA), in any encoding: XML external entity (XXE) and billion-laughs attacks on the XML parsers of readers and server tools. | block | block | warn |
| `XML.EXTERNAL_REFERENCE` | Embedded XML that makes its parser fetch something: XInclude, `<?xml-stylesheet?>`, XFA web service connections. Server-side request forgery and local file reads without a DOCTYPE. Namespace URIs are not references and are not reported. | block | block | warn |

## Structure (`structure`)

Damaged, ambiguous or unusual file structure: where different PDF readers start to see different documents.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `STRUCT.BROKEN_OBJECT` | An object header (`N G obj`) whose body cannot be parsed: a file cut off in the middle, or damaged on purpose. quelda cannot inspect what it holds, while a reader that repairs files may still use part of it. Text that only looks like a header (inside a string, a comment or stream data) is not counted. | block | block | warn |
| `STRUCT.CONFLICTING_OBJECTS` | The same object defined twice with different content in one revision: which one a reader uses depends on its repair logic. | block | block | warn |
| `STRUCT.FILTER_CHAIN` | Streams that stack more than `thresholds.max_filter_chain` compression/encoding filters or repeat one: used to hide content and multiply decoding work. | block | warn | off |
| `STRUCT.INCREMENTAL_UPDATE` | The file was edited after it was created (incremental updates). quelda already scans every revision; this only reports that there are several. | warn | off | off |
| `STRUCT.MISSING_EOF` | No `%%EOF` at all: a truncated or hand-crafted file that readers repair differently. | block | block | warn |
| `STRUCT.MULTIPLE_HEADERS` | More than one `%PDF-` header: concatenated files, or a file built to look different from the front and from the back. | block | block | warn |
| `STRUCT.NAME_TOO_LONG` | Names longer than 255 bytes: long font names have overflowed buffers in renderers. Producers do not write them (the longest names in real files, structure tags copied from Word style names, stay under 255). | block | block | block |
| `STRUCT.PAGE_TREE_CYCLE` | Loops or repeated nodes in the page tree, which make naive readers loop forever or render a few objects as millions of pages. | block | block | warn |
| `STRUCT.REFERENCE_CYCLE` | Chains that readers follow to their end, made to never end: bookmarks or actions linked by `/Next`, object streams linked by `/Extends`, arrays that contain themselves. Naive readers hang or run out of memory. Ordinary back references (`/Parent`, `/Prev`) are not counted. | block | block | warn |
| `STRUCT.SIGNATURE_MODIFIED` | A signed file changed after signing: bytes after the signed ranges (an update saved later, which can change what is shown while the signature still verifies), signed ranges that leave out more than the signature value, or a malformed `/ByteRange`. Only the structure is checked, not the cryptography. Filling a form or adding a second signature also adds bytes, so `balanced` only warns. | block | warn | off |
| `STRUCT.PRINT_VIEW_MISMATCH` | Content that prints but is hidden on screen (annotations flagged print-only, layers ON for print and OFF for view): what is approved on screen is not what is printed. Some real files have print-only stamps, so `balanced` only warns. | block | warn | off |
| `STRUCT.TRAILING_DATA` | More than `thresholds.max_trailing_bytes` of data after the last `%%EOF`: how polyglots and smuggled payloads are usually built. | block | warn | off |
| `STRUCT.TRUNCATED_STREAM` | Compressed data that stops early. Common from careless producers; quelda inspects exactly what a reader would show. | block | warn | off |
| `STRUCT.XREF_MISMATCH` | The cross-reference table does not match the file (wrong offsets, unlisted or hidden objects, no usable xref, broken chains). Readers then repair the file each in their own way: the classic trick to show a scanner one document and a reader another. | block | warn | off |

## Encryption (`encryption`)

Content quelda cannot see.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `CRYPT.ENCRYPTED` | Encrypted files. Their strings and streams cannot be inspected, so they cannot be shown to be safe. | block | block | block |

## Codecs (`codecs`)

Decoders and parsers with a history of exploits: images, fonts, colour profiles.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `CODEC.DECODE_PARAMS` | Decoder parameters outside the spec (predictor, colours, bits per component, columns, rows): decoders size their buffers from them, and out-of-range values have caused overflows. Real files pass. | block | block | block |
| `CODEC.FONT_MALFORMED` | Embedded TrueType, OpenType or CFF fonts whose tables or indexes point outside the font (a classic way to overflow font parsers in renderers and printers). Font tools never write them; a font that does not decode completely is not judged. | block | block | warn |
| `CODEC.ICC_MALFORMED` | Embedded ICC colour profiles with a tag table that does not fit, or with tags past the end of the profile: colour engines read tags at the offsets the profile gives. A truncated profile (some OCR tools embed one) is not judged by its tags; data without the `acsp` signature is `CODEC.ICC_UNRECOGNIZED`'s. | block | block | warn |
| `CODEC.ICC_UNRECOGNIZED` | Embedded colour profile data that does not carry the `acsp` signature every ICC profile has: quelda cannot check it, a colour engine should refuse it. A few real producers write such profiles (an empty stream, a byte-swapped header), so `balanced` only warns. | block | warn | off |
| `CODEC.JBIG2` | Images compressed with JBIG2, whose decoders were exploited in the wild (FORCEDENTRY, CVE-2009-0658). | block | warn | off |
| `CODEC.JPX` | Images compressed with JPEG 2000, whose decoders have a long history of memory-safety bugs. | block | warn | off |
| `CODEC.TYPE1_FONT` | Embedded Type 1 (PostScript) font programs. Off in `balanced` because print files use them a lot. | warn | off | off |

## Resources (`resource`)

Files built to exhaust the memory or time of a renderer.

| Rule | Catches | strict | balanced | permissive |
|---|---|---|---|---|
| `RESOURCE.IMAGE_DIMENSIONS` | Images that declare more than `thresholds.max_image_pixels` pixels, or invalid sizes: a few bytes that make a renderer allocate gigabytes (pixel bomb). | block | block | warn |
| `RESOURCE.PAGE_COUNT` | More than `thresholds.max_pages` pages, real or declared: exhausts thumbnailers and rasterizers. | block | block | warn |
| `RESOURCE.PAGE_SIZE` | Pages larger than `thresholds.max_page_side_pt` on a side, or with zero/invalid size, in any of the five page boxes. | block | block | warn |
| `RESOURCE.DRAW_RECURSION` | A form, tiling pattern, soft mask or Type 3 glyph that draws itself, directly or through others: renderers recurse until they crash or hang. Judged on what content actually draws, not on resource lists. | block | block | warn |
| `RESOURCE.FUNCTION_SIZE` | Sampled functions (colour conversion, shadings) declaring more than 64 MiB of samples: a renderer allocating the table runs out of memory. Real colour lookup tables are a few MiB at most. | block | block | warn |
