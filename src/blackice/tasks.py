from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from blackice.crypto import EnvelopeSigner
from blackice.database import Database
from blackice.locks import TaskLockRegistry
from blackice.models import (
    NetworkPolicy,
    ResourceLimits,
    RevocationState,
    TaskCreateRequest,
    TaskIssued,
    TaskSecurityEnvelope,
    TaskState,
)
from blackice.sandbox.workspace import WorkspaceAdapter


class TaskManager:
    def __init__(
        self,
        database: Database,
        signer: EnvelopeSigner,
        workspaces: WorkspaceAdapter,
        locks: TaskLockRegistry,
    ) -> None:
        self.database = database
        self.signer = signer
        self.workspaces = workspaces
        self.locks = locks

    def create(self, request: TaskCreateRequest) -> TaskIssued:
        task_id = str(uuid.uuid4())
        workspace_id = str(uuid.uuid4())
        issued = datetime.now(UTC)
        envelope = TaskSecurityEnvelope(
            task_id=task_id,
            agent_id=request.agent_id,
            task_owner=request.task_owner,
            workspace=workspace_id,
            permitted_filesystem_operations=request.permitted_filesystem_operations,
            permitted_paths=request.permitted_paths,
            restricted_paths=request.restricted_paths,
            permitted_tools=request.permitted_tools,
            permitted_command_classes=request.permitted_command_classes,
            network_policy=NetworkPolicy(),
            allowed_destinations=[],
            data_restrictions=request.data_restrictions,
            resource_limits=ResourceLimits(
                max_actions=request.max_actions,
                max_runtime_seconds=request.expires_in_seconds,
            ),
            delegation_permissions=[],
            approval_requirements=request.approval_requirements,
            issued_at=issued,
            expires_at=issued + timedelta(seconds=request.expires_in_seconds),
            revocation_state=RevocationState.ACTIVE,
            policy_version="v1",
            task_state=TaskState.ACTIVE,
        )
        self.workspaces.create_workspace(workspace_id)
        serialized = envelope.model_dump(mode="json")
        signature = self.signer.sign(serialized)
        agent_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(agent_token.encode()).hexdigest()
        self.database.save_task(
            task_id,
            serialized,
            signature,
            token_hash,
            audit_payload={
                "category": "task",
                "event": "task_issued",
                "task_id": task_id,
                "agent_id": request.agent_id,
                "owner": request.task_owner,
                "workspace": workspace_id,
                "policy_version": envelope.policy_version,
                "expires_at": envelope.expires_at.isoformat(),
            },
        )
        return TaskIssued(envelope=envelope, signature=signature, agent_token=agent_token)

    def verify_agent_token(self, record: dict[str, Any], token: str) -> bool:
        actual = hashlib.sha256(token.encode()).hexdigest()
        return secrets.compare_digest(actual, record["agent_token_hash"])

    def get_verified_envelope(
        self, task_id: str
    ) -> tuple[TaskSecurityEnvelope, dict[str, Any]] | None:
        record = self.database.get_task(task_id)
        if record is None:
            return None
        if not self.signer.verify(record["envelope"], record["signature"]):
            return None
        try:
            envelope = TaskSecurityEnvelope.model_validate(record["envelope"])
        except Exception:
            return None
        return envelope, record

    def revoke(self, task_id: str, operator: str = "operator") -> dict[str, Any]:
        with self.locks.for_task(task_id):
            verified = self.get_verified_envelope(task_id)
            if verified is None:
                raise KeyError("task not found or envelope integrity check failed")
            envelope, _ = verified
            if envelope.task_state == TaskState.REVOKED:
                return {"task_id": task_id, "state": "REVOKED", "already_revoked": True}
            updated = envelope.model_copy(
                update={
                    "revocation_state": RevocationState.REVOKED,
                    "task_state": TaskState.REVOKED,
                }
            )
            serialized = updated.model_dump(mode="json")
            signature = self.signer.sign(serialized)
            self.database.update_task(
                task_id,
                serialized,
                signature,
                audit_payload={
                    "category": "response",
                    "event": "task_revoked",
                    "task_id": task_id,
                    "agent_id": envelope.agent_id,
                    "operator": operator,
                    "evidence": "task envelope re-signed as revoked; subsequent gateway actions fail closed",
                },
            )
            return {"task_id": task_id, "state": "REVOKED", "already_revoked": False}
