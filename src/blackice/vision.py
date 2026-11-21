from __future__ import annotations

import base64
import io
import json
import re
import unicodedata
import uuid
import warnings
import zipfile
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from bs4 import BeautifulSoup, Comment
from defusedxml import ElementTree as SafeET
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader

from blackice.crypto import sha256_hex
from blackice.models import ArtifactInspection, InspectionFinding

MAX_REPRESENTATION_CHARS = 50_000
MAX_ZIP_MEMBERS = 1_000
MAX_ARCHIVE_EXPANDED = 20 * 1024 * 1024
MAX_ARCHIVE_TEXT = 2 * 1024 * 1024
MAX_ARCHIVE_MEMBER_TEXT = 512 * 1024
MAX_PDF_PAGES = 100
MAX_OFFICE_PART = 1 * 1024 * 1024
MAX_OFFICE_XML_TOTAL = 2 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction-override",
        re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
    ),
    (
        "system-prompt-reference",
        re.compile(
            r"(?i)\b(?:reveal|print|show|expose)\b.{0,60}\b(?:system prompt|hidden prompt|developer message)\b"
        ),
    ),
    (
        "credential-exfiltration-language",
        re.compile(
            r"(?i)\b(?:send|upload|exfiltrate|forward)\b.{0,80}\b(?:password|credential|api[ _-]?key|token|secret)\b"
        ),
    ),
    (
        "security-control-manipulation",
        re.compile(
            r"(?i)\b(?:disable|bypass|override)\b.{0,60}\b(?:security|policy|safeguard|logging|approval)\b"
        ),
    ),
)

TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".markdown",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".sh",
    ".bash",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".sql",
    ".css",
    ".csv",
    ".log",
    ".properties",
    ".env.example",
}


def _clip(text: str, limit: int = MAX_REPRESENTATION_CHARS) -> str:
    return text[:limit]


def _text_from_xml(root: Any) -> str:
    return "\n".join(part.strip() for part in root.itertext() if part and part.strip())


def _safe_xml(data: bytes) -> Any:
    return SafeET.fromstring(data)


def _path_is_unsafe_archive(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return path.is_absolute() or any(part in {"..", "."} for part in path.parts) or "\\" in name


def _looks_nested_archive(name: str, prefix: bytes = b"") -> bool:
    return name.lower().endswith(
        (".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx")
    ) or prefix.startswith(b"PK\x03\x04")


class ArtifactInspector:
    """Deterministic inspection helpers; no document/script content is executed."""

    def __init__(self, max_bytes: int = 10_485_760) -> None:
        self.max_bytes = max_bytes

    def inspect(
        self,
        filename: str,
        data: bytes,
        source: str = "unknown",
        provenance: dict[str, Any] | None = None,
    ) -> ArtifactInspection:
        artifact_hash = sha256_hex(data)
        findings: list[InspectionFinding] = []
        limitations: list[str] = []
        uncertainty: list[str] = []
        discrepancies: list[str] = []
        representations: dict[str, str] = {}
        coverage: dict[str, Any] = {
            "bytes_received": len(data),
            "parser_started": False,
            "regions_uninspected": [],
        }
        status = "complete"
        extension = PurePosixPath(filename).suffix.lower()
        format_name = self._format_name(extension, data)

        if len(data) > self.max_bytes:
            status = "failed"
            coverage["parser_started"] = False
            limitations.append(f"artifact exceeds the {self.max_bytes}-byte inspection limit")
            coverage["regions_uninspected"].append("entire artifact")
        elif not data:
            status = "partial"
            limitations.append("empty artifact")
            coverage["regions_uninspected"].append("content")
        else:
            coverage["parser_started"] = True
            try:
                status, parsed, parser_findings, parser_limits, parser_gaps = self._parse(
                    filename, extension, data
                )
                representations.update(parsed)
                findings.extend(parser_findings)
                limitations.extend(parser_limits)
                coverage["regions_uninspected"].extend(parser_gaps)
                if {"html_structural_text", "html_visible_heuristic"}.issubset(representations):
                    structural = " ".join(representations["html_structural_text"].split())
                    visible = " ".join(representations["html_visible_heuristic"].split())
                    if structural != visible:
                        discrepancies.append(
                            "HTML structural text differs from the deterministic visible-text heuristic; this is not browser-rendered evidence"
                        )
                        findings.append(
                            InspectionFinding(
                                code="html-representation-divergence",
                                severity="medium",
                                description="HTML structural and visible-text heuristic representations differ",
                            )
                        )
            except (
                Exception
            ) as exc:  # parser failures are recorded, never converted into a safe result
                status = "partial"
                limitations.append(
                    f"parser failed safely ({type(exc).__name__}); content is not considered inspected"
                )
                coverage["regions_uninspected"].append("format-specific content")
                uncertainty.append("parser failure prevents a complete inspection conclusion")

        text_for_analysis = "\n".join(representations.values())
        unicode_findings, unicode_uncertainty = self._inspect_unicode(text_for_analysis)
        findings.extend(unicode_findings)
        uncertainty.extend(unicode_uncertainty)
        findings.extend(self._inspect_instructions(text_for_analysis))

        if status in {"partial", "failed"}:
            uncertainty.append("one or more representations or regions were not inspected")
        if any(f.severity in {"high", "critical"} for f in findings):
            classification = "suspicious"
            containment = [
                "keep the original artifact untrusted",
                "do not use its contents as authorization",
                "review evidence before any agent receives derived text",
            ]
            confidence = 0.86
        elif findings:
            classification = "needs-review"
            containment = [
                "treat extracted content as untrusted",
                "review the listed indicators and inspection gaps",
            ]
            confidence = 0.68
        elif status != "complete":
            classification = "inconclusive"
            containment = [
                "do not treat the artifact as cleared; use an isolated specialist parser or manual review"
            ]
            confidence = 0.25
        else:
            classification = "no-deterministic-indicator-found"
            containment = [
                "no deterministic indicator was found by the implemented checks; this is not proof of safety"
            ]
            confidence = 0.55

        coverage["representations_extracted"] = sorted(representations)
        coverage["representations_count"] = len(representations)
        coverage["bytes_hash"] = artifact_hash
        if status == "complete" and limitations:
            status = "partial"
        return ArtifactInspection(
            inspection_id=str(uuid.uuid4()),
            artifact_id=artifact_hash,
            sha256=artifact_hash,
            filename=filename,
            format=format_name,
            source=source,
            provenance=provenance or {},
            status=status,
            coverage=coverage,
            representations={key: _clip(value) for key, value in representations.items()},
            discrepancies=discrepancies,
            suspicious_indicators=findings,
            threat_classification=classification,
            confidence=confidence,
            uncertainty=list(dict.fromkeys(uncertainty)),
            limitations=list(dict.fromkeys(limitations)),
            recommended_containment=containment,
            policy_metadata={
                "policy_relevant": bool(findings),
                "externally_supplied_authority": False,
            },
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _format_name(extension: str, data: bytes) -> str:
        if data.startswith(b"%PDF-"):
            return "pdf"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if data.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        mapping = {
            ".html": "html",
            ".htm": "html",
            ".md": "markdown",
            ".markdown": "markdown",
            ".txt": "text",
            ".pdf": "pdf",
            ".docx": "docx",
            ".xlsx": "xlsx",
            ".pptx": "pptx",
            ".svg": "svg",
            ".png": "png",
            ".jpg": "jpeg",
            ".jpeg": "jpeg",
            ".zip": "zip",
            ".json": "json",
            ".xml": "xml",
        }
        if extension in mapping:
            return mapping[extension]
        if extension in TEXT_EXTENSIONS:
            return (
                "source-code"
                if extension not in {".txt", ".md", ".markdown", ".csv", ".log"}
                else "text"
            )
        if data.startswith(b"PK\x03\x04"):
            return "zip"
        return "unsupported"

    def _parse(
        self, filename: str, extension: str, data: bytes
    ) -> tuple[str, dict[str, str], list[InspectionFinding], list[str], list[str]]:
        fmt = self._format_name(extension, data)
        findings: list[InspectionFinding] = []
        limits: list[str] = []
        gaps: list[str] = []
        if fmt == "unsupported":
            return (
                "partial",
                {},
                findings,
                ["unsupported format; no content parser was run"],
                ["entire content"],
            )
        if fmt == "html":
            return self._parse_html(data)
        if fmt in {"text", "source-code", "markdown"}:
            text = data.decode("utf-8", errors="replace")
            if "\ufffd" in text:
                limits.append("invalid UTF-8 bytes were replaced during text decoding")
                gaps.append("original byte-level text representation")
            reps = {"source_text": _clip(text)}
            comments = self._extract_comments(text, extension)
            if comments:
                reps["comments"] = _clip("\n".join(comments))
            return ("partial" if limits else "complete"), reps, findings, limits, gaps
        if fmt == "json":
            text = data.decode("utf-8", errors="replace")
            parsed = json.loads(text)
            return (
                "complete",
                {"raw_json": _clip(text), "structural_values": _clip(self._flatten_json(parsed))},
                findings,
                limits,
                gaps,
            )
        if fmt in {"xml", "svg"}:
            root = _safe_xml(data)
            full_text = _text_from_xml(root)
            if fmt == "svg":
                hidden = []
                scripts = []
                links = []
                for element in root.iter():
                    tag = element.tag.rsplit("}", 1)[-1].lower()
                    style = (
                        element.attrib.get("style", "")
                        + " "
                        + element.attrib.get("display", "")
                        + " "
                        + element.attrib.get("visibility", "")
                    ).lower()
                    if (
                        "display:none" in style.replace(" ", "")
                        or "visibility:hidden" in style.replace(" ", "")
                        or element.attrib.get("opacity") == "0"
                    ):
                        text = _text_from_xml(element)
                        if text:
                            hidden.append(text)
                    if tag == "script":
                        scripts.append(_text_from_xml(element))
                    if tag in {"a", "image", "use"}:
                        links.extend(v for k, v in element.attrib.items() if k.endswith("href"))
                if hidden:
                    findings.append(
                        InspectionFinding(
                            code="svg-hidden-content",
                            severity="medium",
                            description="SVG elements with hidden-style attributes contain text",
                            evidence=_clip(" | ".join(hidden), 240),
                        )
                    )
                if scripts:
                    findings.append(
                        InspectionFinding(
                            code="svg-script-element",
                            severity="medium",
                            description="SVG script element found; it was inspected as text and not executed",
                        )
                    )
                if any(
                    v.strip().lower().startswith(("javascript:", "data:text/html")) for v in links
                ):
                    findings.append(
                        InspectionFinding(
                            code="svg-active-link",
                            severity="high",
                            description="SVG contains a scriptable link target",
                        )
                    )
                return (
                    "complete",
                    {
                        "xml_structural_text": _clip(full_text),
                        "svg_source": _clip(data.decode("utf-8", errors="replace")),
                    },
                    findings,
                    limits,
                    gaps,
                )
            return (
                "complete",
                {
                    "xml_structural_text": _clip(full_text),
                    "xml_source": _clip(data.decode("utf-8", errors="replace")),
                },
                findings,
                limits,
                gaps,
            )
        if fmt == "pdf":
            reader = PdfReader(io.BytesIO(data), strict=False)
            pages = reader.pages[:MAX_PDF_PAGES]
            page_text: list[str] = []
            annotation_count = 0
            for index, page in enumerate(pages):
                text = page.extract_text() or ""
                page_text.append(f"[page {index + 1}]\n{text}")
                annotation_count += len(page.get("/Annots", []))
            if len(reader.pages) > MAX_PDF_PAGES:
                limits.append(f"only the first {MAX_PDF_PAGES} pages were extracted")
                gaps.append(f"pages {MAX_PDF_PAGES + 1} onward")
            if annotation_count:
                findings.append(
                    InspectionFinding(
                        code="pdf-annotations",
                        severity="low",
                        description=f"PDF has {annotation_count} annotation reference(s); visual meaning was not rendered",
                    )
                )
            if getattr(reader, "attachments", None):
                findings.append(
                    InspectionFinding(
                        code="pdf-attachments",
                        severity="medium",
                        description="PDF reports embedded attachments; attachment content is not recursively inspected",
                    )
                )
                gaps.append("embedded PDF attachments")
            if reader.metadata:
                metadata = "\n".join(
                    f"{key}: {value}" for key, value in reader.metadata.items() if value is not None
                )
            else:
                metadata = ""
            if not any(item.strip() for item in page_text):
                limits.append(
                    "PDF text extraction found no text; image/OCR content was not inspected"
                )
                gaps.append("image-based or visually rendered PDF content")
            limits.append("PDF visual rendering and invisible-layer comparison were not performed")
            gaps.append("human-visible page rendering")
            return (
                ("partial" if limits else "complete"),
                {
                    "pdf_extracted_text": _clip("\n".join(page_text)),
                    "pdf_metadata": _clip(metadata),
                },
                findings,
                limits,
                gaps,
            )
        if fmt in {"docx", "xlsx", "pptx", "zip"}:
            return self._parse_zip_container(fmt, data)
        if fmt in {"png", "jpeg"}:
            return self._parse_image(data, fmt)
        return (
            "partial",
            {},
            findings,
            ["format was identified but has no implemented parser"],
            ["entire content"],
        )

    def _parse_html(
        self, data: bytes
    ) -> tuple[str, dict[str, str], list[InspectionFinding], list[str], list[str]]:
        text = data.decode("utf-8", errors="replace")
        soup = BeautifulSoup(text, "html.parser")
        full_text = soup.get_text("\n", strip=True)
        hidden_text: list[str] = []
        hidden_element_ids: set[int] = set()
        hidden_nodes = 0
        suspicious_links: list[str] = []
        external_scripts = 0
        external_references = 0
        hidden_css_selectors: set[str] = set()
        for style_node in soup.find_all("style"):
            css = style_node.get_text(" ", strip=True)
            for match in re.finditer(
                r"([^{}]+)\{[^{}]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^{}]*\}",
                css,
                re.I,
            ):
                hidden_css_selectors.add(match.group(1).strip())
        for element in soup.find_all(True):
            style = re.sub(r"\s+", "", element.get("style", "").lower())
            classes = element.get("class", [])
            nonvisible_container = element.name in {
                "head",
                "script",
                "style",
                "template",
                "noscript",
            }
            selector_match = any(
                selector.startswith(".")
                and selector[1:] in classes
                or selector.startswith("#")
                and selector[1:] == element.get("id")
                for selector in hidden_css_selectors
            )
            hidden = (
                element.has_attr("hidden")
                or str(element.get("aria-hidden", "")).lower() == "true"
                or "display:none" in style
                or "visibility:hidden" in style
                or "opacity:0" in style
                or "font-size:0" in style
                or "left:-9999" in style
                or selector_match
                or nonvisible_container
            )
            if hidden:
                hidden_element_ids.add(id(element))
                hidden_nodes += 1
                node_text = element.get_text(" ", strip=True)
                if node_text:
                    hidden_text.append(node_text)
            if element.name in {"a", "iframe", "form", "script"}:
                value = element.get("href") or element.get("src") or element.get("action")
                if value and str(value).strip().lower().startswith(
                    ("javascript:", "data:text/html")
                ):
                    suspicious_links.append(str(value)[:180])
                elif value and str(value).strip().lower().startswith(("http://", "https://")):
                    external_references += 1
                if element.name == "script" and element.get("src"):
                    external_scripts += 1
        comments = [
            str(node) for node in soup.find_all(string=lambda value: isinstance(value, Comment))
        ]
        visible_parts = []
        for node in soup.find_all(string=True):
            if isinstance(node, Comment):
                continue
            if any(id(parent) in hidden_element_ids for parent in node.parents):
                continue
            stripped = str(node).strip()
            if stripped:
                visible_parts.append(stripped)
        visible_text = "\n".join(visible_parts)
        if hidden_nodes:
            yield_finding = InspectionFinding(
                code="html-hidden-dom",
                severity="medium",
                description=f"{hidden_nodes} DOM element(s) have hidden/accessibility/style indicators",
                evidence=_clip(" | ".join(hidden_text), 240) or None,
            )
            findings = [yield_finding]
        else:
            findings = []
        if comments:
            findings.append(
                InspectionFinding(
                    code="html-comments",
                    severity="low",
                    description=f"{len(comments)} HTML comment(s) extracted",
                    evidence=_clip(" | ".join(comments), 240),
                )
            )
        if suspicious_links:
            findings.append(
                InspectionFinding(
                    code="scriptable-link",
                    severity="high",
                    description="HTML includes a javascript: or data:text/html navigation target",
                    evidence=_clip(" | ".join(suspicious_links), 200),
                )
            )
        if external_scripts:
            findings.append(
                InspectionFinding(
                    code="external-script-reference",
                    severity="low",
                    description=f"{external_scripts} external script reference(s); not fetched or executed",
                )
            )
        if external_references:
            findings.append(
                InspectionFinding(
                    code="html-external-reference",
                    severity="low",
                    description=f"{external_references} external URL reference(s) were noted but not contacted",
                )
            )
        limitations = [
            "linked stylesheets, browser rendering, layout, OCR, and script effects were not evaluated"
        ]
        gaps = ["rendered human-visible page", "external CSS and scripts"]
        representations = {
            "html_structural_text": _clip(full_text),
            "html_visible_heuristic": _clip(visible_text),
            "html_hidden_text": _clip("\n".join(hidden_text)),
            "html_comments": _clip("\n".join(comments)),
            "html_source": _clip(text),
        }
        return "partial", representations, findings, limitations, gaps

    def _parse_zip_container(
        self, fmt: str, data: bytes
    ) -> tuple[str, dict[str, str], list[InspectionFinding], list[str], list[str]]:
        findings: list[InspectionFinding] = []
        limits: list[str] = []
        gaps: list[str] = []
        representations: dict[str, str] = {}
        total_read = 0
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_MEMBERS:
                infos = infos[:MAX_ZIP_MEMBERS]
                limits.append(f"archive member listing was capped at {MAX_ZIP_MEMBERS} entries")
                gaps.append("remaining archive member names")
            total_uncompressed = sum(info.file_size for info in infos)
            office_xml_bytes = 0

            def read_office_xml(info: zipfile.ZipInfo) -> Any | None:
                nonlocal office_xml_bytes
                if (
                    info.file_size > MAX_OFFICE_PART
                    or office_xml_bytes + info.file_size > MAX_OFFICE_XML_TOTAL
                ):
                    limits.append(
                        "Office XML inspection reached its bounded part or aggregate budget"
                    )
                    gaps.append(f"Office XML part not inspected: {info.filename}")
                    return None
                if info.compress_size and info.file_size / max(info.compress_size, 1) > 100:
                    findings.append(
                        InspectionFinding(
                            code="archive-compression-ratio",
                            severity="medium",
                            description="Office XML part exceeds the configured compression-ratio threshold",
                            evidence=info.filename[:180],
                        )
                    )
                    gaps.append(f"high-ratio Office XML part not parsed: {info.filename}")
                    return None
                raw = archive.read(info)
                office_xml_bytes += len(raw)
                return _safe_xml(raw)

            if total_uncompressed > MAX_ARCHIVE_EXPANDED:
                limits.append("declared archive expansion exceeds the configured inspection budget")
                gaps.append("archive member contents beyond bounded manifest inspection")
            unsafe = [info.filename for info in infos if _path_is_unsafe_archive(info.filename)]
            if unsafe:
                findings.append(
                    InspectionFinding(
                        code="archive-path-traversal",
                        severity="high",
                        description=f"{len(unsafe)} archive path(s) are absolute or traverse parent directories",
                        evidence=_clip(" | ".join(unsafe), 240),
                    )
                )
            nested = [info.filename for info in infos if _looks_nested_archive(info.filename)]
            if nested:
                findings.append(
                    InspectionFinding(
                        code="nested-archive",
                        severity="medium",
                        description=f"{len(nested)} nested archive or container(s) detected; not recursively extracted",
                        evidence=_clip(" | ".join(nested[:12]), 240),
                    )
                )
                gaps.append("nested archive contents")
            if fmt == "docx":
                hidden_run_text: list[str] = []
                comment_text: list[str] = []
                tracked_change_text: list[str] = []
                for info in infos:
                    name = info.filename
                    is_comment = name.startswith("word/comments") and name.endswith(".xml")
                    is_text_part = bool(
                        re.fullmatch(
                            r"word/(document|footnotes|endnotes|header\d+|footer\d+)\.xml",
                            name,
                        )
                    )
                    if is_comment:
                        findings.append(
                            InspectionFinding(
                                code="docx-comments",
                                severity="low",
                                description="DOCX comments part found; bounded comment text is extracted",
                            )
                        )
                    if is_comment or is_text_part:
                        root = read_office_xml(info)
                        if root is not None and is_comment:
                            comment_text.append(_text_from_xml(root))
                        if root is not None and is_text_part:
                            for element in root.iter():
                                tag = element.tag.rsplit("}", 1)[-1]
                                if tag in {"del", "ins"}:
                                    change_text = _text_from_xml(element)
                                    if change_text.strip():
                                        tracked_change_text.append(f"{tag}: {change_text}")
                            for run in root.iter():
                                if run.tag.rsplit("}", 1)[-1] != "r":
                                    continue
                                run_nodes = list(run.iter())
                                hidden_markers = [
                                    node
                                    for node in run_nodes
                                    if node.tag.rsplit("}", 1)[-1] in {"vanish", "webHidden"}
                                ]
                                hidden = any(
                                    next(
                                        (
                                            value
                                            for key, value in node.attrib.items()
                                            if key.rsplit("}", 1)[-1] == "val"
                                        ),
                                        "true",
                                    ).lower()
                                    not in {"0", "false", "off"}
                                    for node in hidden_markers
                                )
                                if hidden:
                                    text_value = "".join(
                                        node.text or ""
                                        for node in run_nodes
                                        if node.tag.rsplit("}", 1)[-1] in {"t", "delText"}
                                    )
                                    if text_value.strip():
                                        hidden_run_text.append(text_value)
                    if name.startswith("word/embeddings/"):
                        findings.append(
                            InspectionFinding(
                                code="docx-embedded-object",
                                severity="medium",
                                description="DOCX embedded object found; embedded bytes were not parsed",
                            )
                        )
                        gaps.append("embedded DOCX object")
                if comment_text:
                    representations["docx_comment_text"] = _clip("\n".join(comment_text))
                if hidden_run_text:
                    findings.append(
                        InspectionFinding(
                            code="docx-hidden-runs",
                            severity="medium",
                            description=f"{len(hidden_run_text)} hidden or web-hidden text run(s) found",
                            evidence=_clip(" | ".join(hidden_run_text), 240),
                        )
                    )
                    representations["docx_hidden_run_text"] = _clip("\n".join(hidden_run_text))
                if tracked_change_text:
                    findings.append(
                        InspectionFinding(
                            code="docx-tracked-changes",
                            severity="low",
                            description=f"{len(tracked_change_text)} tracked change(s) extracted",
                        )
                    )
                    representations["docx_tracked_changes"] = _clip("\n".join(tracked_change_text))
            elif fmt == "xlsx":
                workbook_info = next((i for i in infos if i.filename == "xl/workbook.xml"), None)
                if workbook_info:
                    root = read_office_xml(workbook_info)
                    hidden_sheets = (
                        [
                            el.attrib.get("name", "unnamed")
                            for el in root.iter()
                            if el.tag.rsplit("}", 1)[-1] == "sheet"
                            and el.attrib.get("state", "visible") != "visible"
                        ]
                        if root is not None
                        else []
                    )
                    if hidden_sheets:
                        findings.append(
                            InspectionFinding(
                                code="xlsx-hidden-sheets",
                                severity="medium",
                                description=f"{len(hidden_sheets)} hidden or veryHidden worksheet(s) detected",
                                evidence=", ".join(hidden_sheets[:20]),
                            )
                        )
                hidden_rows: list[str] = []
                hidden_columns: list[str] = []
                for info in infos:
                    if not re.fullmatch(r"xl/worksheets/sheet\d+\.xml", info.filename):
                        continue
                    root = read_office_xml(info)
                    if root is None:
                        continue
                    for element in root.iter():
                        tag = element.tag.rsplit("}", 1)[-1]
                        if tag == "row" and element.attrib.get("hidden", "0").lower() in {
                            "1",
                            "true",
                        }:
                            hidden_rows.append(f"{info.filename}:{element.attrib.get('r', '?')}")
                        elif tag == "col" and element.attrib.get("hidden", "0").lower() in {
                            "1",
                            "true",
                        }:
                            hidden_columns.append(
                                f"{info.filename}:{element.attrib.get('min', '?')}-{element.attrib.get('max', '?')}"
                            )
                if hidden_rows or hidden_columns:
                    findings.append(
                        InspectionFinding(
                            code="xlsx-hidden-rows-or-columns",
                            severity="medium",
                            description=f"{len(hidden_rows)} hidden row(s) and {len(hidden_columns)} hidden column range(s) found",
                            evidence=_clip(
                                ", ".join([*hidden_rows[:10], *hidden_columns[:10]]), 240
                            ),
                        )
                    )
                if any(i.filename.startswith("xl/externalLinks/") for i in infos):
                    findings.append(
                        InspectionFinding(
                            code="xlsx-external-links",
                            severity="medium",
                            description="Spreadsheet external-link parts found; targets were not contacted",
                        )
                    )
                if any(i.filename.startswith("xl/embeddings/") for i in infos):
                    findings.append(
                        InspectionFinding(
                            code="xlsx-embedded-object",
                            severity="medium",
                            description="Spreadsheet embedded object found; content was not parsed",
                        )
                    )
                    gaps.append("embedded spreadsheet object")
            elif fmt == "pptx":
                hidden_slides = []
                note_parts = [
                    i
                    for i in infos
                    if i.filename.startswith("ppt/notesSlides/notesSlide")
                    and i.filename.endswith(".xml")
                ]
                for info in infos:
                    if (
                        re.fullmatch(r"ppt/slides/slide\d+\.xml", info.filename)
                        and info.file_size <= MAX_OFFICE_PART
                    ):
                        root = read_office_xml(info)
                        if root is not None and root.attrib.get("show") == "0":
                            hidden_slides.append(info.filename)
                if hidden_slides:
                    findings.append(
                        InspectionFinding(
                            code="pptx-hidden-slides",
                            severity="medium",
                            description=f"{len(hidden_slides)} hidden slide(s) detected",
                            evidence=", ".join(hidden_slides[:20]),
                        )
                    )
                if note_parts:
                    findings.append(
                        InspectionFinding(
                            code="pptx-speaker-notes",
                            severity="low",
                            description=f"{len(note_parts)} speaker-notes part(s) found; bounded notes text is extracted",
                        )
                    )
                    gaps.append("notes omitted by some viewers")
                if any(i.filename.startswith("ppt/embeddings/") for i in infos):
                    findings.append(
                        InspectionFinding(
                            code="pptx-embedded-object",
                            severity="medium",
                            description="Presentation embedded object found; content was not parsed",
                        )
                    )
                    gaps.append("embedded presentation object")
            manifest = []
            extracted: list[str] = []
            for info in infos:
                manifest.append(f"{info.filename}\t{info.file_size}\t{info.compress_size}")
                if info.is_dir() or _path_is_unsafe_archive(info.filename):
                    continue
                if (
                    info.file_size > MAX_ARCHIVE_MEMBER_TEXT
                    or total_read + info.file_size > MAX_ARCHIVE_TEXT
                ):
                    if info.filename.lower().endswith(
                        tuple(TEXT_EXTENSIONS)
                    ) or info.filename.endswith(".xml"):
                        gaps.append(f"oversized part not extracted: {info.filename}")
                    continue
                if info.compress_size and info.file_size / max(info.compress_size, 1) > 100:
                    findings.append(
                        InspectionFinding(
                            code="archive-compression-ratio",
                            severity="medium",
                            description="archive member exceeds the configured compression-ratio threshold",
                            evidence=info.filename[:180],
                        )
                    )
                    gaps.append(f"high-ratio member not extracted: {info.filename}")
                    continue
                is_text_part = info.filename.lower().endswith(
                    tuple(TEXT_EXTENSIONS)
                ) or info.filename.endswith(".xml")
                if fmt in {"docx", "xlsx", "pptx"}:
                    is_text_part = info.filename.endswith(".xml") and info.filename.split("/")[
                        0
                    ] in {"word", "xl", "ppt"}
                if not is_text_part:
                    continue
                try:
                    with archive.open(info) as member:
                        raw = member.read(MAX_ARCHIVE_MEMBER_TEXT + 1)
                    if len(raw) > MAX_ARCHIVE_MEMBER_TEXT:
                        gaps.append(f"member exceeded read limit: {info.filename}")
                        continue
                    total_read += len(raw)
                    text = raw.decode("utf-8", errors="replace")
                    extracted.append(f"[{info.filename}]\n{text}")
                except (RuntimeError, zipfile.BadZipFile, OSError):
                    limits.append(f"archive member failed safe extraction: {info.filename}")
                    gaps.append(f"unreadable member: {info.filename}")
            representations["archive_manifest"] = _clip("\n".join(manifest))
            representations["archive_text_members"] = _clip("\n".join(extracted))
            if fmt in {"docx", "xlsx", "pptx"}:
                limits.append(
                    f"{fmt.upper()} rendered visual layout was not compared against extracted XML text"
                )
                gaps.append("human-visible rendered Office document")
            if fmt == "zip":
                limits.append(
                    "archive contents are inspected only to a bounded depth; nested archives are not unpacked"
                )
            if total_read >= MAX_ARCHIVE_TEXT:
                limits.append("archive text extraction reached the aggregate budget")
                gaps.append("remaining archive text parts")
        return (
            ("partial" if limits or gaps else "complete"),
            representations,
            findings,
            limits,
            gaps,
        )

    def _parse_image(
        self, data: bytes, fmt: str
    ) -> tuple[str, dict[str, str], list[InspectionFinding], list[str], list[str]]:
        findings: list[InspectionFinding] = []
        limits: list[str] = []
        gaps: list[str] = []
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            try:
                image = Image.open(io.BytesIO(data))
                if image.width * image.height > MAX_IMAGE_PIXELS:
                    return (
                        "partial",
                        {},
                        findings,
                        ["image pixel count exceeds inspection limit"],
                        ["image pixels and OCR"],
                    )
                image_format = image.format or fmt
                info = {str(key): str(value)[:500] for key, value in list(image.info.items())[:40]}
                metadata = "\n".join(f"{key}: {value}" for key, value in info.items())
            except (Image.DecompressionBombError, Image.DecompressionBombWarning):
                return (
                    "failed",
                    {},
                    findings,
                    ["image decoder rejected decompression-bomb dimensions"],
                    ["image content"],
                )
            except (UnidentifiedImageError, OSError):
                return (
                    "partial",
                    {},
                    findings,
                    ["image parser could not decode the claimed image format"],
                    ["image pixels"],
                )
        limits.append(
            "OCR is not configured in this runtime; image text may be present and was not recognized"
        )
        gaps.append("OCR and pixel-level adversarial-image analysis")
        return (
            "partial",
            {
                "image_metadata": f"format={image_format}; width={image.width}; height={image.height}\n{metadata}"
            },
            findings,
            limits,
            gaps,
        )

    @staticmethod
    def _flatten_json(value: Any, depth: int = 0) -> str:
        if depth > 20:
            return "[maximum JSON traversal depth reached]"
        if isinstance(value, dict):
            return "\n".join(
                f"{key}: {ArtifactInspector._flatten_json(item, depth + 1)}"
                for key, item in list(value.items())[:500]
            )
        if isinstance(value, list):
            return "\n".join(
                ArtifactInspector._flatten_json(item, depth + 1) for item in value[:500]
            )
        return str(value)

    @staticmethod
    def _extract_comments(text: str, extension: str) -> list[str]:
        comments: list[str] = []
        if extension in {".py", ".sh", ".bash", ".yaml", ".yml", ".toml", ".ini", ".cfg"}:
            comments.extend(
                line.split("#", 1)[1].strip() for line in text.splitlines() if "#" in line
            )
        if extension in {
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".java",
            ".go",
            ".rs",
            ".c",
            ".h",
            ".cpp",
            ".hpp",
            ".css",
            ".sql",
        }:
            comments.extend(re.findall(r"//([^\n]*)|/\*([\s\S]*?)\*/", text))
            comments = [" ".join(part for part in item if part).strip() for item in comments]
        return comments[:500]

    @staticmethod
    def _inspect_unicode(text: str) -> tuple[list[InspectionFinding], list[str]]:
        controls: dict[str, int] = {}
        for character in text:
            if unicodedata.category(character) == "Cf":
                codepoint = f"U+{ord(character):04X}"
                controls[codepoint] = controls.get(codepoint, 0) + 1
        findings: list[InspectionFinding] = []
        if controls:
            sample = ", ".join(f"{code}:{count}" for code, count in sorted(controls.items())[:16])
            findings.append(
                InspectionFinding(
                    code="unicode-format-controls",
                    severity="medium",
                    description="format-control or zero-width Unicode characters were found",
                    evidence=sample,
                )
            )
        non_ascii = sum(1 for char in text if ord(char) > 127)
        uncertainty = (
            ["non-ASCII or homoglyph-like text was not semantically normalized"]
            if non_ascii
            else []
        )
        return findings, uncertainty

    @staticmethod
    def _inspect_instructions(text: str) -> list[InspectionFinding]:
        findings: list[InspectionFinding] = []
        for code, pattern in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    InspectionFinding(
                        code=code,
                        severity="high",
                        description="instruction-like text may attempt to manipulate an agent",
                        evidence=match.group(0)[:180],
                    )
                )
        encoded = re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])", text)
        for candidate in encoded[:20]:
            try:
                decoded = base64.b64decode(candidate, validate=True).decode(
                    "utf-8", errors="ignore"
                )
            except (ValueError, UnicodeDecodeError):
                continue
            if decoded and any(pattern.search(decoded) for _, pattern in INJECTION_PATTERNS):
                findings.append(
                    InspectionFinding(
                        code="encoded-instruction",
                        severity="high",
                        description="bounded base64 candidate decodes to instruction-like content",
                    )
                )
                break
        return findings
