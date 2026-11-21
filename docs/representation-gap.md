# Human–AI representation gap: what this inspector compares

## Scope

The project mission calls for comparison among human-visible rendering, structural data, parser output, OCR, metadata/embedded objects, and model-facing or transformed content. The current implementation provides only a small, deterministic subset of that goal. It does not render artifacts as a browser or Office application would, does not run OCR, and does not compare every representation available to a human or downstream agent.

The most explicit comparison is in `src/blackice/vision.py` for HTML: it compares normalized structural text with a deterministic source-tree text heuristic. That heuristic is **not** a human-visible rendering. For PDF and Office files, the implementation records specific extraction outputs and gaps but does not produce a visual representation for comparison. There is no general model-facing/transformation lineage comparison subsystem here.

A reported gap or discrepancy is evidence to review—not a safe/unsafe verdict. A missing discrepancy means only that the implemented comparison did not report one in the limited representations it processed.

## Representation map

| Format/path | Representation produced | Comparison or indicator | What remains outside that representation |
|---|---|---|---|
| HTML upload or registered inspection | `html_source`, `html_structural_text`, `html_visible_heuristic`, `html_hidden_text`, and `html_comments`, all bounded. Structural text is BeautifulSoup `get_text`; the heuristic collects text nodes not inside selected hidden-marked nodes. | Normalized structural and heuristic text are compared; a difference produces `html-representation-divergence`. Source-tree hidden indicators and selected external/scriptable references can produce findings. | No browser, layout, viewport, accessibility-tree, computed-style, linked CSS, network, JavaScript-effect, font, image, or OCR representation. The word “visible” in the key is a heuristic label only, not proof of visibility to a person. |
| PDF | Text extracted by `pypdf` for at most the first 100 pages, plus available document metadata. | Annotation references are counted; attachment presence is noted; an absence of extractable page text is called out as a gap. | No rendered page images, OCR, invisible-layer comparison, annotation appearance/meaning, attachment extraction, or recursive attachment inspection. Text order/extraction may differ from visual reading order. |
| DOCX | Bounded archive manifest/XML-member text; selected comment text, hidden-run text, and tracked-change text. | Comment parts, `vanish`/`webHidden` run markers, tracked changes, and embedded-object member presence may be flagged. | No Word renderer, pagination/layout, full semantic document model, complete field/relationship interpretation, or embedded-object parsing. XML text is not guaranteed to match what a person sees or what an application exposes. |
| XLSX | Bounded ZIP manifest and XML text members, including workbook/worksheet XML where within budget. | Hidden/very-hidden sheet state, hidden row/column attributes, external-link part presence, and embedded-object part presence may be flagged. | No rendered worksheet comparison, formula calculation, complete cell/value semantics, external-link retrieval, or full interpretation of names, charts, macros, and object relationships. XML fragments are not equivalent to workbook behavior. |
| PPTX | Bounded ZIP manifest and XML text members, including slide and notes XML within extraction budgets. | A slide root with `show="0"`, speaker-notes part names, and embedded-object part names may be reported. | No slide renderer, visual order/layout comparison, full notes/slide semantics, or embedded-object parsing. Speaker notes may be omitted by some viewers and are not a substitute for all text a viewer presents. |
| SVG | XML structural text and source; selected hidden-style element text, script-element text, and link targets. | Simple attributes/styles and scriptable URL prefixes are checked. | No SVG renderer, full CSS/cascade evaluation, external resource loading, pixel comparison, or script execution. A static source heuristic cannot determine all rendered visibility or effects. |
| PNG/JPEG | Decoder format/dimensions and selected image metadata. | Oversized dimensions and decode failures are reported as limitations/failures. | No OCR, visual interpretation, pixel-level manipulation analysis, or image-to-text comparison. There is no image rendering analysis. |
| Text, Markdown, code, JSON, XML | Decoded text, selected comment strings, JSON flattening, or XML structural text/source, according to extension and parser. | Unicode format-control characters and a small set of instruction-like patterns are checked against extracted representations. | Markdown rendering, language-aware code parsing, broad semantic analysis, OCR, and general transformation/model-input comparison are not provided. |
| ZIP and nested objects | Bounded member manifest and selected text/XML members. | Unsafe member paths, selected compression ratios, and nested-container names may be reported. | Nested archives and embedded binaries are not recursively unpacked or semantically inspected. A member listing is not a view of all nested content. |

## HTML: structural text is not rendered visibility

The HTML parser calculates two source-derived strings:

1. **Structural text**: text returned by the HTML parser across the parsed tree.
2. **Visible-text heuristic**: text nodes not under elements marked by a limited set of hidden/accessibility/style signals.

Those strings are normalized for whitespace before comparison. A difference is recorded as `html-representation-divergence`, with an explicit description that it is not browser-rendered evidence. Both strings, the hidden text, comments, and source are clipped to the representation limit.

The hidden-element heuristic looks for the `hidden` attribute, `aria-hidden="true"`, selected inline style declarations (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, `left:-9999`), limited matching of embedded CSS class/ID selectors, and non-visible source containers such as `head`, `script`, `style`, `template`, and `noscript`. Embedded CSS is scanned with a constrained regular expression. This is not full CSS parsing: selector specificity, combinators, inherited styles, media queries, external stylesheets, pseudo-elements, animations, layout, viewport changes, and browser behavior are not evaluated. A heuristic-visible string can therefore differ from what a browser or a particular person actually sees.

The parser notes selected URL references but does not contact them. External scripts are counted, not fetched or executed. Script text, comments, and source text can contain clues that are unavailable in an ordinary visual view, but the parser does not calculate the final page a browser would display.

## Office and PDF gaps

For DOCX/XLSX/PPTX, the implementation inspects the ZIP container and selected XML parts. It has targeted structural checks, but it does not reconstruct a complete application-level document or render it. Workbooks may contain formulas, relationships, external links, embedded files, or behaviors whose meaning is not established by seeing an XML fragment. Presentations may arrange, overlay, or style text in ways not represented by extracted member text. Word layout and fields can likewise differ from raw XML ordering. Office reports explicitly mark visual comparison as unperformed and have per-part, aggregate, member, and archive budgets.

For PDF, extracted text and metadata are not a rendered-page representation. Annotation references are counted without determining visual meaning. Attachment presence is reported but attachment contents are not recursively inspected. Image-based pages, scanned content, visual overlays, and invisible text-layer discrepancies are outside the implemented checks; no OCR or page rendering is performed.

## Shared bounded-analysis behavior

Text checks run over extracted representations, not a universal decoded view of the entire artifact. A small group of regular expressions looks for selected instruction-like wording, with a bounded search for base64 candidates. Unicode format-control characters can be counted in extracted text. Non-ASCII characters trigger uncertainty about semantic normalization; the system does not generally resolve homoglyphs or infer malicious intent. These checks can produce false positives and false negatives, and can miss fragmented, reworded, multilingual, image-only, or differently encoded content.

Representations are clipped to at most 50,000 characters. Other explicit bounds include 1,000 ZIP members, 20 MiB declared archive expansion, 2 MiB of generic archive text, 512 KiB per generic member, 1 MiB per Office XML part, 2 MiB aggregate Office XML, 100 PDF pages, and 20 million image pixels. Oversized, high-compression-ratio, unreadable, unsupported, clipped, or nested content can leave regions uninspected. The report should be interpreted with its status, `coverage`, `uncertainty`, `limitations`, and `regions_uninspected` fields, not from findings alone.

No stage executes document scripts, Office macros, formulas, or embedded objects. No stage fetches external CSS, scripts, or links. These safeguards do not turn an unparsed object or a parser result into proof of safety.

## Agent-facing representation and redaction

The registered `artifact.inspect` tool reads a file from the task workspace, inspects it, and recursively redacts selected known credential/email patterns and selected sensitive-named string fields from the report before returning the agent-facing summary. This is a presentation/output control, not a different extraction representation and not comprehensive redaction. Unrecognized secret formats may remain. The raw artifact is not modified.

The authenticated operator upload endpoint follows a separate path: the full inspection report is returned to the operator and saved in SQLite without the agent-facing recursive redaction step. The original upload bytes are retained in content-addressed local storage. Therefore an operator-facing report and agent-facing summary may contain different evidence text; do not assume redaction of the agent response also sanitizes stored evidence or the original file.

## Reading a reported gap responsibly

- Treat an explicit discrepancy as a reason to examine the original and the relevant representation—not as an automatic finding of maliciousness.
- Treat an empty findings list as “no deterministic indicator found in inspected representations,” never as “cleared.”
- If the question depends on actual visual appearance, use a suitable isolated renderer and compare outputs manually or with a purpose-built pipeline.
- If image text, PDF visual layers, Office semantics, annotations, attachments, macros, or nested objects matter, use an appropriate specialist parser/renderer and record its separate coverage.
- Preserve the original and its hash; do not silently sanitize suspicious evidence and then describe the result as safe.

`tests/test_vision.py` contains synthetic assertions for selected HTML, DOCX, XLSX, archive, and unsupported-format cases. The agent-facing redaction example is in `tests/test_api.py`. These are test examples, not a complete benchmark, rendering comparison, or guarantee of detection coverage.
