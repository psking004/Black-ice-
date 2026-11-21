from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from blackice.models import (
    ActionRequest,
    DecisionOutcome,
    FilesystemOperation,
    TaskSecurityEnvelope,
    TaskState,
)
from blackice.sandbox.workspace import WorkspaceAdapter, WorkspaceViolation

POLICY_VERSION = "v1"


@dataclass(frozen=True, slots=True)
class PolicyResult:
    outcome: DecisionOutcome
    reason: str
    matched_rules: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    risk_indicators: tuple[str, ...] = ()


class ActionChainAnalyzer:
    """Small transparent rules over recent gateway decisions; not an ML risk score."""

    def analyze(self, request: ActionRequest, previous: list[dict[str, Any]]) -> tuple[str, ...]:
        indicators: list[str] = []
        if request.tool_id in {"network", "http"} or request.operation in {
            "send",
            "upload",
            "post",
        }:
            if any(
                item.get("details", {}).get("data_classification") == "credential"
                and item.get("details", {}).get("operation") == "read"
                for item in previous
            ):
                indicators.append("read-sensitive-then-outbound-attempt")
        if request.operation in {"change_policy", "disable_security", "disable_logging"}:
            indicators.append("agent-requested-control-plane-change")
        sensitive_denials = [
            item
            for item in previous
            if item.get("outcome") in {DecisionOutcome.DENY.value, DecisionOutcome.RESTRICT.value}
            and item.get("details", {}).get("tool_id")
            in {"command", "network", "security", "policy"}
        ]
        if len(sensitive_denials) >= 2:
            indicators.append("repeated-restricted-action-attempts")
        if request.tool_id == "delegation" and request.operation == "create":
            indicators.append("delegation-requires-explicit-nonexpanding-policy")
        return tuple(indicators)


class PolicyEngine:
    def __init__(
        self, workspaces: WorkspaceAdapter, registered_operations: dict[str, set[str]]
    ) -> None:
        self.workspaces = workspaces
        self.registered_operations = registered_operations
        self.chain = ActionChainAnalyzer()

    @staticmethod
    def _path_allowed(path: str, rules: list[str]) -> bool:
        if "." in rules:
            return True
        for rule in rules:
            if fnmatch.fnmatchcase(path, rule) or (
                not any(ch in rule for ch in "*?[") and path.startswith(rule.rstrip("/") + "/")
            ):
                return True
        return False

    @staticmethod
    def _path_restricted(path: str, rules: list[str]) -> bool:
        parts = path.split("/")
        candidates = ["/".join(parts[: index + 1]) for index in range(len(parts))]
        candidates.append(path)
        for rule in rules:
            if any(fnmatch.fnmatchcase(candidate, rule) for candidate in candidates):
                return True
        return False

    def evaluate(
        self,
        request: ActionRequest,
        envelope: TaskSecurityEnvelope,
        previous: list[dict[str, Any]],
        approved: bool = False,
    ) -> PolicyResult:
        indicators = self.chain.analyze(request, previous)
        if request.task_id != envelope.task_id or request.agent_id != envelope.agent_id:
            return PolicyResult(
                DecisionOutcome.DENY,
                "request identity does not match the signed task envelope",
                ("identity.match",),
                risk_indicators=indicators,
            )
        if envelope.task_state != TaskState.ACTIVE or envelope.revocation_state.value != "ACTIVE":
            return PolicyResult(
                DecisionOutcome.DENY,
                "task is not active or has been revoked",
                ("task.active",),
                risk_indicators=indicators,
            )
        if envelope.expires_at <= datetime.now(UTC):
            return PolicyResult(
                DecisionOutcome.DENY,
                "task envelope has expired",
                ("task.not_expired",),
                risk_indicators=indicators,
            )
        if request.requested_capability != f"{request.tool_id}.{request.operation}":
            return PolicyResult(
                DecisionOutcome.DENY,
                "requested capability does not match the structured operation",
                ("capability.exact_match",),
                risk_indicators=indicators,
            )
        if request.destination is not None:
            return PolicyResult(
                DecisionOutcome.DENY,
                "outbound destinations are disabled in this runtime",
                ("network.default_deny",),
                risk_indicators=indicators,
            )
        if indicators:
            if (
                "read-sensitive-then-outbound-attempt" in indicators
                or "agent-requested-control-plane-change" in indicators
                or "delegation-requires-explicit-nonexpanding-policy" in indicators
            ):
                return PolicyResult(
                    DecisionOutcome.DENY,
                    "action sequence or target crosses a protected control boundary",
                    ("chain.protected_sequence",),
                    risk_indicators=indicators,
                )

        registered = self.registered_operations.get(request.tool_id, set())
        if request.operation not in registered:
            return PolicyResult(
                DecisionOutcome.DENY,
                "tool operation is not registered",
                ("tool.registered",),
                risk_indicators=indicators,
            )
        if request.tool_id not in envelope.permitted_tools:
            return PolicyResult(
                DecisionOutcome.DENY,
                "tool is outside the task capability envelope",
                ("tse.tool_scope",),
                risk_indicators=indicators,
            )

        if request.tool_id == "filesystem":
            try:
                path = (
                    "."
                    if request.resource == "."
                    else "/".join(self.workspaces.normalize_path(request.resource))
                )
            except WorkspaceViolation as exc:
                return PolicyResult(
                    DecisionOutcome.DENY,
                    str(exc),
                    ("filesystem.relative_path",),
                    risk_indicators=indicators,
                )
            if self._path_restricted(path, envelope.restricted_paths):
                return PolicyResult(
                    DecisionOutcome.DENY,
                    "resource matches a restricted path rule",
                    ("filesystem.restricted_path",),
                    evidence=(path,),
                    risk_indicators=indicators,
                )
            if not self._path_allowed(path, envelope.permitted_paths):
                return PolicyResult(
                    DecisionOutcome.DENY,
                    "resource is outside permitted task paths",
                    ("filesystem.path_scope",),
                    evidence=(path,),
                    risk_indicators=indicators,
                )
            try:
                FilesystemOperation(request.operation)
            except ValueError:
                return PolicyResult(
                    DecisionOutcome.DENY,
                    "filesystem operation is not permitted by the TSE",
                    ("tse.filesystem_operation",),
                    risk_indicators=indicators,
                )
            if (
                FilesystemOperation(request.operation)
                not in envelope.permitted_filesystem_operations
            ):
                return PolicyResult(
                    DecisionOutcome.DENY,
                    "filesystem operation is outside the task capability envelope",
                    ("tse.filesystem_operation",),
                    risk_indicators=indicators,
                )
        elif request.tool_id == "artifact":
            try:
                path = "/".join(self.workspaces.normalize_path(request.resource))
            except WorkspaceViolation as exc:
                return PolicyResult(
                    DecisionOutcome.DENY,
                    str(exc),
                    ("artifact.relative_path",),
                    risk_indicators=indicators,
                )
            if self._path_restricted(path, envelope.restricted_paths):
                return PolicyResult(
                    DecisionOutcome.DENY,
                    "artifact path is not eligible for inspection",
                    ("artifact.path_scope",),
                    risk_indicators=indicators,
                )
            if not self._path_allowed(path, envelope.permitted_paths):
                return PolicyResult(
                    DecisionOutcome.DENY,
                    "artifact is outside permitted task paths",
                    ("artifact.path_scope",),
                    risk_indicators=indicators,
                )
        else:
            return PolicyResult(
                DecisionOutcome.DENY,
                "tool is not supported by the default policy",
                ("policy.default_deny",),
                risk_indicators=indicators,
            )

        required = f"{request.tool_id}.{request.operation}"
        if required in envelope.approval_requirements and not approved:
            return PolicyResult(
                DecisionOutcome.REVIEW,
                "operator approval is required for this exact action",
                ("approval.required",),
                risk_indicators=indicators,
            )
        return PolicyResult(
            DecisionOutcome.ALLOW,
            "action is within the signed task scope and registered adapter policy",
            ("policy.allow_scoped_adapter",),
            evidence=(f"policy_version={envelope.policy_version}",),
            risk_indicators=indicators,
        )
