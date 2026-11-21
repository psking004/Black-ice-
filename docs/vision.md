# ICE-VISION: artifact inspection

ICE-VISION provides deterministic, bounded parsing for selected files. It extracts representations, records selected indicators and explicit gaps, and does **not** execute artifact content. It is an inspection aid—not a malware verdict, browser, office suite, OCR system, or guarantee that an artifact is safe.

The current implementation is in `src/blackice/vision.py`, with upload/storage behavior in `src/blackice/artifacts.py`. The scope is narrower than the full ICE-VISION mission described in the project prompt. In particular, support for a file extension must not be read as complete semantic or visual inspection of that format.

## What the result means

An `ArtifactInspection` records an inspection ID, artifact ID, SHA-256, filename, format label, source, caller-supplied provenance, status, coverage, extracted representations, discrepancies, indicators, classification, confidence, uncertainty, limitations, containment recommendations, policy metadata, and creation time.

Statuses are `complete`, `partial`, or `failed`. A parser exception is caught and recorded as a partial inspection; an over-limit direct inspector input is failed without parsing. Unsupported formats, empty content, parser gaps, and format-specific limitations are not silently treated as full inspection. Coverage includes received byte count, whether the parser started, named uninspected regions, extracted representation names/count, and the byte hash.

Classification labels are `suspicious`, `needs-review`, `inconclusive`, and `no-deterministic-indicator-found`. The last phrase is deliberately not a clearance: it means only that these implemented checks found no indicator in the representations they analyzed. Even a `complete` status is not proof of safety. The confidence values are fixed code-path values, not empirically calibrated probabilities. Findings are pattern/structure indicators; they are not a complete semantic analysis.

Inspection does not strip or rewrite the original. The report retains extracted text as evidence (subject to limits); recommendations say to keep the original untrusted and review gaps.

## Format coverage in this implementation

Format identification is primarily suffix-based, with limited magic-byte recognition: PDF, PNG, and JPEG signatures are recognized, and a ZIP local-file signature falls back to generic ZIP. HTML, Office, SVG, XML, JSON, and ordinary text parsing generally depends on the filename suffix. This is not a general content-sniffing or MIME-validation layer. A mislabeled DOCX/XLSX/PPTX can be treated as generic ZIP if its ZIP signature is recognized; a ZIP merely named `.docx` takes the DOCX branch. Invalid claimed formats can fail parsing.

| Input family | What is actually extracted or checked | Important limits |
|---|---|---|
| HTML (`.html`, `.htm`) | Structural text from BeautifulSoup; a deterministic text-node heuristic excluding nodes within elements marked hidden; hidden/accessibility/style indicators; HTML comments; selected `href`/`src`/`action` values; external URL/script-reference counts. It also compares normalized structural text with the heuristic text and records a discrepancy if they differ. | Always partial. This is not a browser-rendered view. CSS handling is a small inline/embedded-style heuristic, not a CSS engine. Linked stylesheets and scripts are not fetched or executed. |
| Plain text, Markdown, source/config files | UTF-8 text decoded with replacement for invalid bytes; a simple comment extraction for selected source-language suffixes. Markdown is treated as text, not rendered or parsed as a Markdown document. | Invalid UTF-8 is replaced and marked as a limitation. Comment extraction is regex/line based and can misidentify comment-like text or miss language-specific forms. |
| JSON (`.json`) | Raw decoded JSON and flattened structural values after JSON parsing. | Flattening traverses at most 20 nested levels and at most 500 dictionary entries/list items per level. Representations are clipped; JSON schema, application meaning, and encoded payloads are not comprehensively analyzed. |
| XML (`.xml`) | Safe XML parsing; joined element text and decoded source. | No application-specific interpretation beyond XML text. Malformed or unsupported constructs can result in partial inspection. |
| SVG (`.svg`) | Safe XML parsing; structural text and source; selected hidden-style text, `<script>` element text, and selected `href` values are checked for simple active-link prefixes. Script contents are text, never run. | No rendering, full CSS interpretation, external-resource retrieval, or pixel/visual analysis. Attribute/style checks are limited heuristics. |
| PDF (PDF signature or `.pdf`) | `pypdf` text extraction and metadata, up to the first 100 pages; annotation-reference count; whether the reader reports attachments. | Always partial because visual rendering and invisible-layer comparison are not performed. Annotation visual meaning and attachment contents are not inspected; no OCR is performed. |
| DOCX (`.docx`) | ZIP manifest and bounded XML text members; selected comment parts, document/footnote/endnote/header/footer parts; indicators for hidden `vanish`/`webHidden` runs and tracked insertions/deletions; embedded-object presence. | Extracted XML is not a full Word semantic model or rendered page. Embedded object bytes are not parsed. Office visual layout is not compared with XML. |
| XLSX (`.xlsx`) | ZIP manifest and bounded XML text members; hidden/very-hidden worksheet state; hidden row/column attributes; presence of external-link and embedded-object parts. | No full spreadsheet semantics, formula evaluation, rendered sheet view, or external-link retrieval. Embedded object content is not parsed. Generic XML extraction is not equivalent to understanding cells, formulas, names, charts, macros, or workbook behavior. |
| PPTX (`.pptx`) | ZIP manifest and bounded XML text members; slide XML with `show="0"` is reported as hidden; speaker-notes parts are detected; embedded-object presence is reported. | No slide rendering, layout/reading-order comparison, or complete presentation semantics. Notes are not a separately modeled full semantic representation; embedded object content is not parsed. |
| ZIP (`.zip`, or recognized ZIP signature) | Bounded member manifest and UTF-8-decoded text/XML members; unsafe paths, selected compression ratios, and nested-container names are reported. | Binary members are not interpreted; nested archives are not unpacked recursively. Generic ZIP inspection is not full repository inspection. |
| PNG/JPEG (signature or supported suffix) | Pillow decoder dimensions/format and up to 40 metadata entries, with each metadata value clipped to 500 characters. | Always partial. Image pixels are not OCR-scanned or semantically analyzed. No pixel-level adversarial-image analysis is implemented. Images over 20 million pixels are not inspected; decoder rejection can fail inspection. |
| Other files | Format `unsupported`, with no content parser. | Partial and inconclusive; the content is uninspected. |

The implemented text suffix set is `.txt`, `.md`, `.markdown`, `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.java`, `.go`, `.rs`, `.c`, `.h`, `.cpp`, `.hpp`, `.sh`, `.bash`, `.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`, `.sql`, `.css`, `.csv`, `.log`, `.properties`, and `.env.example`. A filename such as `.env.example` has a `PurePosixPath.suffix` of `.example`, so the current suffix lookup does **not** reliably recognize that compound suffix as text. `.env` is not listed as a text suffix. Binary formats such as audio and video are not implemented.

## Bounded, non-executing behavior

The inspector does not launch documents, run scripts, evaluate formulas, execute macros, render files in a browser, or contact referenced URLs. Limits in `vision.py` include:

- Default maximum input size of 10 MiB (configurable when constructing the inspector).
- At most 50,000 characters per stored representation.
- ZIP listing capped at 1,000 members; declared expanded size over 20 MiB is recorded as a limitation.
- Generic archive text budget of 2 MiB and member text limit of 512 KiB.
- Office XML part limit of 1 MiB and aggregate Office XML budget of 2 MiB.
- Members with a compression ratio greater than 100 are skipped from the relevant extraction path and reported.
- PDF text extraction limited to 100 pages.
- Image inspection limited to 20 million pixels.

These are defensive parser/extraction bounds, not proof that every byte, object, or interpretation was inspected. Archive entries beyond a member-list cap, oversized parts, high-ratio members, nested archives, unreadable members, later PDF pages, clipped representations, and unparsed binary parts can leave gaps. ZIP expanded-size accounting uses archive-declared metadata; inspection remains bounded by the other per-member and text budgets, but it is not a recursive archive sanitizer.

The inspector scans extracted representation text for a small set of instruction-like patterns (instruction override, requests to reveal prompts, credential exfiltration language, and security-control manipulation), selected base64 candidates, Unicode format-control characters, and non-ASCII uncertainty. These rules can miss rephrased, fragmented, encoded, multilingual, visually conveyed, or otherwise transformed instructions. Non-ASCII text is not semantically normalized; homoglyph-like content is explicitly an uncertainty, not a detection guarantee. No claim is made that steganography or arbitrary encoded content can be detected.

## Hidden-content and format-specific checks

HTML findings can arise from `hidden`, `aria-hidden="true"`, selected inline-style values (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, and `left:-9999`), a narrow set of embedded CSS class/ID selectors, or non-visible containers such as `head`, `script`, `style`, `template`, and `noscript`. This approximates certain source-level concealment clues; it does not determine what an actual browser displays. The parser's “visible” representation is a deterministic heuristic, not human-visible rendering evidence.

DOCX checks are limited to selected OOXML parts and markers. XLSX checks use workbook/worksheet XML attributes and ZIP member names. PPTX checks use slide XML's root `show="0"` marker and notes-part names. These checks can flag relevant structures while leaving much of each Office format's semantics, rendering, fields, relationships, embedded content, and application-specific behavior unexamined.

PDF annotation and attachment findings are existence/count signals only. Annotation appearance, hidden layers, embedded-file payloads, forms, and non-text page imagery are not inspected. If text extraction yields no page text, the report explicitly records that image/OCR content was not inspected.

## Upload, storage, hashes, and provenance

The operator upload endpoint accepts a basename (not a path), base64 content, a source string, and optional finite JSON provenance capped at 4 KiB. The service validates base64 and rejects empty or over-configured-limit input; the API also enforces a 15 MiB request-body limit. The configured artifact limit defaults to 10 MiB in the current settings. These upload rejections occur before an inspection record is produced.

For accepted operator uploads, `ArtifactService` computes SHA-256 over the exact received bytes. The same digest is used as `artifact_id` and `sha256`. The original bytes are stored content-addressably beneath the configured artifact root (`<first-two-hex>/<full-sha256>`); directories are created with restrictive permissions where supported, and new files use mode `0600`, exclusive creation, no-follow where available, and `fsync`. An existing digest path is reused rather than overwritten. This is local storage behavior, not encryption or immutable archival.

The structured inspection result—including its source, supplied provenance, extracted representations, and limitations—is saved as JSON in the local SQLite inspections table. A separate audit event records summary identifiers and counts (including artifact ID/hash, format, status, classification, indicator count, and representation count), not the full extracted document text. The API's operator inspection response returns the full report. Treat reports and storage as sensitive: extracted document content and caller-supplied provenance may themselves contain confidential data.

The provenance dictionary is caller-supplied metadata; its presence does not independently verify origin, chain of custody, trustworthiness, or transformation history. SHA-256 identifies byte equality for the received payload; it does not establish who created the file or whether the file is safe.

## Redaction and audience boundaries

Redaction is applied on the **agent-facing registered artifact-inspection tool path** in `src/blackice/tools.py`: the report is recursively walked, selected sensitive-named fields are replaced, and known regex patterns for credentials/tokens and email addresses are replaced in string fields. The `artifact.inspect` tool returns that redacted summary and includes matched redaction-rule names. The API tests include a synthetic hidden-HTML example checking that a test key and email are absent from the agent action response.

This is best-effort pattern redaction, not comprehensive secret detection. It can miss unfamiliar credentials or formats, and it does not alter the original bytes. The operator upload endpoint and persisted inspection JSON are not passed through that agent-facing redaction function; they retain report evidence as produced by the inspector. Access to operator endpoints is authenticated, but operators should still handle raw artifacts and reports accordingly. Redaction does not make an otherwise incomplete inspection safe.

## How to use the result

Use the exact hash to refer to the received bytes, review findings and evidence, and read `coverage`, `uncertainty`, `limitations`, and `regions_uninspected` together. For decisions requiring visual interpretation, office-file semantics, OCR, embedded-object analysis, or unsupported formats, use a separately isolated specialist parser or manual review. Do not turn `no-deterministic-indicator-found` into “safe,” and do not rely on an extracted representation as authorization.

Tests in `tests/test_vision.py` and the API redaction assertions in `tests/test_api.py` demonstrate selected synthetic examples, including HTML indicators, selected DOCX/XLSX structures, archive path/compression cases, unsupported input, and agent-facing redaction. These examples do not establish exhaustive format coverage, detection rates, or results beyond the assertions in those tests.
