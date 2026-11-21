from __future__ import annotations

import hashlib
from typing import Any

from blackice.flow import classify_text, redact_sensitive_text
from blackice.sandbox.workspace import WorkspaceAdapter


def _redact_inspection(value: Any) -> tuple[Any, set[str]]:
    rules: set[str] = set()

    def clean(item: Any, key: str = "") -> Any:
        if isinstance(item, str):
            if key.lower() in {
                "password",
                "secret",
                "token",
                "api_key",
                "credential",
                "private_key",
            }:
                return "[REDACTED:sensitive-field]" if item else item
            result, matched = redact_sensitive_text(item)
            rules.update(matched)
            return result
        if isinstance(item, dict):
            return {str(name): clean(child, str(name)) for name, child in item.items()}
        if isinstance(item, list):
            return [clean(child, key) for child in item]
        return item

    return clean(value), rules


class ToolExecutionError(RuntimeError):
    pass


class ToolRegistry:
    def __init__(
        self,
        workspace: WorkspaceAdapter,
        inspector: Any | None = None,
        max_action_bytes: int = 65_536,
    ) -> None:
        self.workspace = workspace
        self.inspector = inspector
        self.max_action_bytes = max_action_bytes
        self._operations: dict[str, set[str]] = {"filesystem": {"list", "read", "write", "mkdir"}}
        if inspector is not None:
            self._operations["artifact"] = {"inspect"}

    @property
    def operations(self) -> dict[str, set[str]]:
        return {key: set(value) for key, value in self._operations.items()}

    def execute(
        self,
        tool_id: str,
        operation: str,
        workspace_id: str,
        resource: str,
        parameters: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if tool_id == "filesystem":
            if operation == "list":
                return self.workspace.list(workspace_id, resource), {"status": "completed"}
            if operation == "read":
                raw = self.workspace.read(workspace_id, resource)
                if len(raw) > self.max_action_bytes:
                    raise ToolExecutionError("file exceeds the per-action read limit")
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ToolExecutionError(
                        "binary files must be handled through the artifact inspector"
                    ) from exc
                classification = classify_text(text)
                safe_text, redacted = redact_sensitive_text(text)
                result = {
                    "path": resource,
                    "content": safe_text,
                    "bytes_read": len(raw),
                    "data_classification": classification.labels[0]
                    if classification.labels
                    else "ordinary",
                    "redacted_rules": redacted,
                }
                return result, {
                    "status": "completed",
                    "bytes_read": len(raw),
                    "data_classification": classification.labels[0]
                    if classification.labels
                    else "ordinary",
                    "redaction_count": len(redacted),
                    "content_sha256": hashlib.sha256(raw).hexdigest(),
                }
            if operation == "write":
                content = parameters.get("content")
                if not isinstance(content, str):
                    raise ToolExecutionError(
                        "filesystem.write requires a UTF-8 string content field"
                    )
                raw = content.encode("utf-8")
                if len(raw) > self.max_action_bytes:
                    raise ToolExecutionError("content exceeds the per-action write limit")
                result = self.workspace.write(workspace_id, resource, raw)
                classification = classify_text(content)
                result["sha256"] = hashlib.sha256(raw).hexdigest()
                result["data_classification"] = (
                    classification.labels[0] if classification.labels else "ordinary"
                )
                return result, {
                    "status": "completed",
                    "bytes_written": len(raw),
                    "data_classification": classification.labels[0]
                    if classification.labels
                    else "ordinary",
                    "content_sha256": hashlib.sha256(raw).hexdigest(),
                }
            if operation == "mkdir":
                return self.workspace.mkdir(workspace_id, resource), {"status": "completed"}
        if tool_id == "artifact" and operation == "inspect" and self.inspector is not None:
            raw = self.workspace.read(workspace_id, resource)
            report = self.inspector.inspect(
                resource.rsplit("/", 1)[-1], raw, source="task-workspace"
            )
            summary, redaction_rules = _redact_inspection(report.model_dump(mode="json"))
            summary["agent_visible_redaction_rules"] = sorted(redaction_rules)
            return summary, {
                "status": report.status,
                "sha256": report.sha256,
                "inspection_id": report.inspection_id,
                "suspicious_indicator_count": len(report.suspicious_indicators),
                "coverage": report.coverage,
                "redaction_count": len(redaction_rules),
                "data_classification": "credential" if redaction_rules else "ordinary",
            }
        raise ToolExecutionError("tool operation is not implemented")
