from __future__ import annotations

import hashlib
import uuid
from typing import Any

from blackice.crypto import EnvelopeSigner, canonical_json
from blackice.database import Database
from blackice.locks import TaskLockRegistry
from blackice.models import ActionRequest, Decision, DecisionOutcome, utc_now
from blackice.policy import POLICY_VERSION, PolicyEngine, PolicyResult
from blackice.tasks import TaskManager
from blackice.tools import ToolExecutionError, ToolRegistry


class GateService:
    def __init__(
        self,
        database: Database,
        signer: EnvelopeSigner,
        tasks: TaskManager,
        tools: ToolRegistry,
        policy: PolicyEngine,
        locks: TaskLockRegistry,
    ) -> None:
        self.database = database
        self.signer = signer
        self.tasks = tasks
        self.tools = tools
        self.policy = policy
        self.locks = locks

    @staticmethod
    def request_digest(request: ActionRequest) -> str:
        data = request.model_dump(mode="json", exclude={"approval_id"})
        return hashlib.sha256(canonical_json(data)).hexdigest()

    @staticmethod
    def _details(request: ActionRequest) -> dict[str, Any]:
        # Never persist arbitrary parameters, file contents, agent-supplied risk, or secrets.
        return {
            "agent_id": request.agent_id,
            "tool_id": request.tool_id,
            "operation": request.operation,
            "resource": request.resource,
            "requested_capability": request.requested_capability,
            "destination": request.destination,
        }

    def _record(
        self,
        request: ActionRequest,
        digest: str,
        result: PolicyResult,
        execution: dict[str, Any] | None = None,
        approval_consumed: bool = False,
    ) -> Decision:
        decision_id = str(uuid.uuid4())
        created_at = utc_now()
        decision = Decision(
            decision_id=decision_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_id=request.tool_id,
            operation=request.operation,
            resource=request.resource,
            outcome=result.outcome,
            reason=result.reason,
            policy_version=POLICY_VERSION,
            matched_rules=list(result.matched_rules),
            evidence=list(result.evidence),
            risk_indicators=list(result.risk_indicators),
            execution_result=execution,
            created_at=created_at,
        )
        details = {
            **self._details(request),
            "agent_claimed_data_classification": request.data_classification,
            "approval_consumed": approval_consumed,
            "data_classification": None
            if execution is None
            else execution.get("data_classification"),
            "execution_status": None if execution is None else execution.get("status"),
        }
        self.database.save_decision(
            decision_id,
            request.task_id,
            digest,
            decision.outcome.value,
            decision.reason,
            details,
            created_at.isoformat(),
            audit_payload={
                "category": "gate",
                "event": "action_decided",
                "decision_id": decision_id,
                "task_id": request.task_id,
                "agent_id": request.agent_id,
                "tool": request.tool_id,
                "operation": request.operation,
                "resource": request.resource,
                "policy_version": decision.policy_version,
                "decision": decision.outcome.value,
                "approval_consumed": approval_consumed,
                "reason": decision.reason,
                "matched_rules": decision.matched_rules,
                "risk_indicators": decision.risk_indicators,
                "enforcement_outcome": "not-executed"
                if execution is None
                else execution.get("status"),
            },
        )
        return decision

    def _deny_untrusted(
        self, request: ActionRequest, digest: str, reason: str, rule: str
    ) -> Decision:
        decision_id = str(uuid.uuid4())
        return Decision(
            decision_id=decision_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_id=request.tool_id,
            operation=request.operation,
            resource=request.resource,
            outcome=DecisionOutcome.DENY,
            reason=reason,
            policy_version=POLICY_VERSION,
            matched_rules=[rule],
            created_at=utc_now(),
        )

    def execute(self, request: ActionRequest, agent_token: str) -> dict[str, Any]:
        digest = self.request_digest(request)
        with self.locks.for_task(request.task_id):
            record = self.database.get_task(request.task_id)
            if record is None:
                decision = self._deny_untrusted(
                    request, digest, "task does not exist", "task.exists"
                )
                return {"decision": decision, "result": None}
            if not self.tasks.verify_agent_token(record, agent_token):
                decision = self._deny_untrusted(
                    request, digest, "agent task credential is invalid", "identity.agent_credential"
                )
                return {"decision": decision, "result": None}

            verified = self.tasks.get_verified_envelope(request.task_id)
            if verified is None:
                decision = self._deny_untrusted(
                    request,
                    digest,
                    "signed envelope is unavailable or failed integrity verification",
                    "tse.signature_valid",
                )
                return {"decision": decision, "result": None}
            envelope, signed_record = verified
            if not self.signer.verify(envelope.model_dump(mode="json"), signed_record["signature"]):
                decision = self._deny_untrusted(
                    request, digest, "signed envelope verification failed", "tse.signature_valid"
                )
                return {"decision": decision, "result": None}

            if not self.database.verify_audit()["valid"]:
                decision = self._deny_untrusted(
                    request, digest, "audit integrity verification failed", "audit.integrity"
                )
                return {"decision": decision, "result": None}

            if not self.database.try_claim_action(
                request.task_id, envelope.resource_limits.max_actions
            ):
                decision = Decision(
                    decision_id=str(uuid.uuid4()),
                    task_id=request.task_id,
                    agent_id=request.agent_id,
                    tool_id=request.tool_id,
                    operation=request.operation,
                    resource=request.resource,
                    outcome=DecisionOutcome.DENY,
                    reason="task action limit reached; repeated over-budget attempts are not persisted",
                    policy_version=POLICY_VERSION,
                    matched_rules=["resource.action_limit"],
                    execution_result={"status": "not-executed"},
                    created_at=utc_now(),
                )
                return {"decision": decision, "result": None}

            previous = self.database.list_decisions(task_id=request.task_id, limit=100)
            try:
                policy_result = self.policy.evaluate(request, envelope, previous)
            except Exception as exc:
                failed_policy = PolicyResult(
                    DecisionOutcome.DENY,
                    "policy evaluation failed; the requested action was not executed",
                    ("policy.evaluation_failed",),
                    evidence=[type(exc).__name__],
                )
                return {"decision": self._record(request, digest, failed_policy), "result": None}
            approval_consumed = False
            if policy_result.outcome == DecisionOutcome.REVIEW and request.approval_id:
                consumed = self.database.consume_approval(
                    request.approval_id,
                    request.task_id,
                    digest,
                    audit_payload={
                        "category": "approval",
                        "event": "approval_consumed",
                        "task_id": request.task_id,
                        "request_digest": digest,
                        "single_use": True,
                    },
                )
                if consumed:
                    approval_consumed = True
                    try:
                        policy_result = self.policy.evaluate(
                            request, envelope, previous, approved=True
                        )
                    except Exception as exc:
                        failed_policy = PolicyResult(
                            DecisionOutcome.DENY,
                            "policy re-evaluation failed; the requested action was not executed",
                            ("policy.evaluation_failed",),
                            evidence=[type(exc).__name__],
                        )
                        return {
                            "decision": self._record(request, digest, failed_policy),
                            "result": None,
                        }
                else:
                    policy_result = PolicyResult(
                        DecisionOutcome.REVIEW,
                        "approval is missing, expired, already consumed, or bound to a different action",
                        ("approval.exact_action",),
                        risk_indicators=policy_result.risk_indicators,
                    )
            if policy_result.outcome != DecisionOutcome.ALLOW:
                return {"decision": self._record(request, digest, policy_result), "result": None}

            # Write the authorization decision before the controlled side effect. A crash then leaves
            # an auditable ALLOW with pending execution rather than an invisible operation.
            decision = self._record(
                request,
                digest,
                policy_result,
                {"status": "pending"},
                approval_consumed=approval_consumed,
            )
            try:
                execution_result, summary = self.tools.execute(
                    request.tool_id,
                    request.operation,
                    envelope.workspace,
                    request.resource,
                    request.parameters,
                )
                if summary.get("redaction_count", 0) > 0:
                    restricted_reason = "action completed with sensitive values redacted from the agent-visible result"
                    final_outcome = DecisionOutcome.RESTRICT.value
                else:
                    restricted_reason = None
                    final_outcome = None
                self.database.update_decision_execution(
                    decision.decision_id,
                    summary,
                    outcome=final_outcome,
                    reason=restricted_reason,
                    audit_payload={
                        "category": "gate",
                        "event": "adapter_executed",
                        "decision_id": decision.decision_id,
                        "task_id": request.task_id,
                        "agent_id": request.agent_id,
                        "tool": request.tool_id,
                        "operation": request.operation,
                        "resource": request.resource,
                        "enforcement_outcome": summary.get("status", "unknown"),
                        "data_classification": summary.get("data_classification"),
                    },
                )
                if summary.get("redaction_count", 0) > 0:
                    decision = decision.model_copy(
                        update={
                            "outcome": DecisionOutcome.RESTRICT,
                            "reason": restricted_reason,
                            "matched_rules": [*decision.matched_rules, "dataflow.output_redaction"],
                        }
                    )
                decision = decision.model_copy(update={"execution_result": summary})
                return {"decision": decision, "result": execution_result}
            except (OSError, ToolExecutionError, PermissionError, ValueError) as exc:
                if isinstance(exc, ToolExecutionError | PermissionError | ValueError):
                    safe_reason = str(exc)[:240]
                else:
                    safe_reason = "workspace adapter failed safely"
                summary = {
                    "status": "failed",
                    "error": safe_reason,
                    "error_class": type(exc).__name__,
                }
                self.database.update_decision_execution(
                    decision.decision_id,
                    summary,
                    audit_payload={
                        "category": "gate",
                        "event": "adapter_failed",
                        "decision_id": decision.decision_id,
                        "task_id": request.task_id,
                        "agent_id": request.agent_id,
                        "tool": request.tool_id,
                        "operation": request.operation,
                        "resource": request.resource,
                        "enforcement_outcome": "failed",
                        "error_class": type(exc).__name__,
                    },
                )
                decision = decision.model_copy(update={"execution_result": summary})
                return {"decision": decision, "result": None}
