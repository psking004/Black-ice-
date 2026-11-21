from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _contains_nonfinite(value: Any) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, dict):
        return any(_contains_nonfinite(child) for child in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_nonfinite(child) for child in value)
    return False


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=True)


class TaskState(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    CLOSED = "CLOSED"


class RevocationState(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class FilesystemOperation(StrEnum):
    LIST = "list"
    READ = "read"
    WRITE = "write"
    MKDIR = "mkdir"


class DecisionOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"
    RESTRICT = "RESTRICT"


class NetworkPolicy(StrictModel):
    mode: str = "deny"
    allowed_destinations: list[str] = Field(default_factory=list)

    @field_validator("mode")
    @classmethod
    def deny_only_in_initial_runtime(cls, value: str) -> str:
        if value != "deny":
            raise ValueError("this runtime has no network adapter; network mode must be 'deny'")
        return value

    @field_validator("allowed_destinations")
    @classmethod
    def no_destinations_without_adapter(cls, value: list[str]) -> list[str]:
        if value:
            raise ValueError("outbound destinations cannot be enabled without a registered adapter")
        return value


class ResourceLimits(StrictModel):
    max_action_bytes: int = Field(default=65_536, ge=1, le=1_048_576)
    max_artifact_bytes: int = Field(default=10_485_760, ge=1, le=10_485_760)
    max_actions: int = Field(default=500, ge=1, le=100_000)
    max_runtime_seconds: int = Field(default=3600, ge=1, le=86_400)


class TaskSecurityEnvelope(StrictModel):
    task_id: str = Field(min_length=8, max_length=64)
    agent_id: str = Field(min_length=1, max_length=128)
    task_owner: str = Field(min_length=1, max_length=128)
    workspace: str = Field(min_length=1, max_length=128)
    permitted_filesystem_operations: list[FilesystemOperation] = Field(default_factory=list)
    permitted_paths: list[str] = Field(default_factory=lambda: ["."])
    restricted_paths: list[str] = Field(default_factory=list)
    permitted_tools: list[str] = Field(default_factory=list)
    permitted_command_classes: list[str] = Field(default_factory=list)
    network_policy: NetworkPolicy = Field(default_factory=NetworkPolicy)
    allowed_destinations: list[str] = Field(default_factory=list)
    data_restrictions: list[str] = Field(default_factory=lambda: ["no-credential-egress"])
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    delegation_permissions: list[str] = Field(default_factory=list)
    approval_requirements: list[str] = Field(default_factory=list)
    issued_at: datetime
    expires_at: datetime
    revocation_state: RevocationState = RevocationState.ACTIVE
    policy_version: str = Field(default="v1", min_length=1, max_length=32)
    task_state: TaskState = TaskState.ACTIVE

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_utc_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_validator("permitted_paths", "restricted_paths")
    @classmethod
    def validate_relative_paths(cls, values: list[str]) -> list[str]:
        if len(values) > 128:
            raise ValueError("too many path rules")
        normalized: list[str] = []
        for value in values:
            if not value or "\x00" in value or "\\" in value:
                raise ValueError("path rules must be non-empty POSIX-relative paths")
            if value == ".":
                normalized.append(value)
                continue
            path = PurePosixPath(value)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
                raise ValueError("path rules may not be absolute or traverse directories")
            normalized.append(path.as_posix())
        return normalized

    @field_validator(
        "permitted_tools",
        "permitted_command_classes",
        "delegation_permissions",
        "approval_requirements",
        "data_restrictions",
    )
    @classmethod
    def unique_small_lists(cls, values: list[str]) -> list[str]:
        if len(values) > 128 or len(set(values)) != len(values):
            raise ValueError("list values must be unique and bounded")
        return values

    @model_validator(mode="after")
    def validate_lifetime_and_state(self) -> TaskSecurityEnvelope:
        if self.expires_at <= self.issued_at:
            raise ValueError("task expiry must be later than issue time")
        if (self.expires_at - self.issued_at).total_seconds() > self.resource_limits.max_runtime_seconds:
            raise ValueError("task expiry may not exceed the signed maximum runtime")
        if (self.revocation_state == RevocationState.REVOKED) != (
            self.task_state == TaskState.REVOKED
        ):
            raise ValueError("revocation state and task state must agree")
        if self.allowed_destinations:
            raise ValueError("this initial implementation has no outbound transfer adapter")
        return self


class TaskCreateRequest(StrictModel):
    agent_id: str = Field(min_length=1, max_length=128)
    task_owner: str = Field(default="operator", min_length=1, max_length=128)
    permitted_filesystem_operations: list[FilesystemOperation] = Field(
        default_factory=lambda: [FilesystemOperation.LIST, FilesystemOperation.READ]
    )
    permitted_paths: list[str] = Field(default_factory=lambda: ["."])
    restricted_paths: list[str] = Field(
        default_factory=lambda: [
            ".env",
            ".env.*",
            ".git",
            ".git/**",
            ".ssh",
            ".ssh/**",
            ".aws",
            ".aws/**",
            ".kube",
            ".kube/**",
            ".docker/config.json",
            ".npmrc",
            ".pypirc",
            ".netrc",
            ".config/gcloud/**",
            "secrets",
            "secrets/**",
            "id_rsa",
            "id_ed25519",
            "*.pem",
            "**/*.pem",
            "**/id_rsa",
            "**/id_ed25519",
        ]
    )
    permitted_tools: list[str] = Field(default_factory=lambda: ["filesystem"])
    permitted_command_classes: list[str] = Field(default_factory=list)
    data_restrictions: list[str] = Field(default_factory=lambda: ["no-credential-egress"])
    approval_requirements: list[str] = Field(default_factory=list)
    expires_in_seconds: int = Field(default=3600, ge=60, le=3600)
    max_actions: int = Field(default=500, ge=1, le=100_000)


class ActionRequest(StrictModel):
    task_id: str = Field(min_length=8, max_length=64)
    agent_id: str = Field(min_length=1, max_length=128)
    tool_id: str = Field(min_length=1, max_length=64)
    operation: str = Field(min_length=1, max_length=64)
    resource: str = Field(min_length=1, max_length=2048)
    parameters: dict[str, Any] = Field(default_factory=dict)
    destination: str | None = Field(default=None, max_length=2048)
    data_classification: str = Field(default="unknown", min_length=1, max_length=64)
    requested_capability: str = Field(min_length=1, max_length=128)
    provenance: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = Field(default=None, min_length=16, max_length=128)

    @model_validator(mode="after")
    def bound_serialized_request(self) -> ActionRequest:
        if _contains_nonfinite(self.parameters) or _contains_nonfinite(self.provenance):
            raise ValueError("action request must contain finite JSON values")
        try:
            serialized = json.dumps(
                self.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("action request must contain finite JSON values") from exc
        if len(serialized.encode("utf-8")) > 1_100_000:
            raise ValueError("action request is too large")
        return self


class Decision(StrictModel):
    decision_id: str
    task_id: str
    agent_id: str
    tool_id: str
    operation: str
    resource: str
    outcome: DecisionOutcome
    reason: str
    policy_version: str
    matched_rules: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    risk_indicators: list[str] = Field(default_factory=list)
    execution_result: dict[str, Any] | None = None
    created_at: datetime


class TaskIssued(StrictModel):
    envelope: TaskSecurityEnvelope
    signature: str
    agent_token: str


class InspectionFinding(StrictModel):
    code: str
    severity: str
    description: str
    evidence: str | None = None


class ArtifactInspection(StrictModel):
    inspection_id: str
    artifact_id: str
    sha256: str
    filename: str
    format: str
    source: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    status: str
    coverage: dict[str, Any] = Field(default_factory=dict)
    representations: dict[str, str] = Field(default_factory=dict)
    discrepancies: list[str] = Field(default_factory=list)
    suspicious_indicators: list[InspectionFinding] = Field(default_factory=list)
    threat_classification: str = "unknown"
    confidence: float = Field(ge=0, le=1)
    uncertainty: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_containment: list[str] = Field(default_factory=list)
    policy_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ArtifactInspectRequest(StrictModel):
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=4, max_length=14_000_000)
    source: str = Field(default="operator-upload", min_length=1, max_length=256)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("filename")
    @classmethod
    def basename_only(cls, value: str) -> str:
        if (
            "/" in value
            or "\\" in value
            or "\x00" in value
            or any(ord(character) < 32 for character in value)
            or value in {".", ".."}
        ):
            raise ValueError("filename must be a basename, not a path")
        return value

    @model_validator(mode="after")
    def bound_provenance(self) -> ArtifactInspectRequest:
        if _contains_nonfinite(self.provenance):
            raise ValueError("artifact provenance must contain finite JSON values")
        try:
            provenance = json.dumps(
                self.provenance,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("artifact provenance must be finite JSON data") from exc
        if len(provenance.encode("utf-8")) > 4096:
            raise ValueError("artifact provenance exceeds the 4 KiB limit")
        return self


_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def utc_now() -> datetime:
    return datetime.now(UTC)
