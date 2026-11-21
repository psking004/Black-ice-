from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from blackice.artifacts import ArtifactService, ArtifactStore
from blackice.crypto import EnvelopeSigner
from blackice.database import Database
from blackice.gate import GateService
from blackice.lab import run_synthetic_lab
from blackice.locks import TaskLockRegistry
from blackice.models import (
    ActionRequest,
    ArtifactInspectRequest,
    DecisionOutcome,
    TaskCreateRequest,
    TaskState,
)
from blackice.policy import PolicyEngine
from blackice.sandbox.workspace import WorkspaceAdapter
from blackice.settings import Settings
from blackice.tasks import TaskManager
from blackice.tools import ToolRegistry
from blackice.vision import ArtifactInspector

MAX_REQUEST_BODY = 15 * 1024 * 1024


class _BodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Enforce request limits for both declared Content-Length and chunked bodies."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        lengths = [
            value for name, value in scope.get("headers", []) if name.lower() == b"content-length"
        ]
        if len(set(lengths)) > 1:
            response = JSONResponse(status_code=400, content={"detail": "ambiguous Content-Length"})
            await response(scope, receive, send)
            return
        if lengths:
            try:
                declared = int(lengths[0])
            except (TypeError, ValueError):
                response = JSONResponse(
                    status_code=400, content={"detail": "invalid Content-Length"}
                )
                await response(scope, receive, send)
                return
            if declared < 0:
                response = JSONResponse(
                    status_code=400, content={"detail": "invalid Content-Length"}
                )
                await response(scope, receive, send)
                return
            if declared > self.max_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "request body exceeds the configured limit"},
                )
                await response(scope, receive, send)
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _BodyTooLarge:
            if not response_started:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "request body exceeds the configured limit"},
                )
                await response(scope, receive, send)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = Database(settings.database_path)
    database.initialize()
    workspace = WorkspaceAdapter(settings.workspace_root, max_bytes=settings.max_artifact_bytes)
    inspector = ArtifactInspector(max_bytes=settings.max_artifact_bytes)
    locks = TaskLockRegistry()
    artifacts = ArtifactService(
        database,
        ArtifactStore(settings.artifact_root),
        inspector,
        max_bytes=settings.max_artifact_bytes,
    )
    signer: EnvelopeSigner | None = None
    startup_error: str | None = None
    if settings.signing_key:
        try:
            signer = EnvelopeSigner(settings.signing_key.encode("utf-8"))
        except ValueError as exc:
            startup_error = str(exc)
    else:
        startup_error = "BLACKICE_SIGNING_KEY is not configured"

    tools = ToolRegistry(workspace, inspector=inspector, max_action_bytes=settings.max_action_bytes)
    policy = PolicyEngine(workspace, tools.operations)
    tasks = TaskManager(database, signer, workspace, locks) if signer else None
    gate = GateService(database, signer, tasks, tools, policy, locks) if signer and tasks else None

    app = FastAPI(
        title="BLACK ICE Control Plane",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.tasks = tasks
    app.state.gate = gate
    app.state.artifacts = artifacts
    app.state.startup_error = startup_error
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BODY)

    def require_operator(authorization: str | None = Header(default=None)) -> str:
        if not settings.operator_auth_ready:
            raise HTTPException(status_code=503, detail="operator credential is not configured")
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            token.strip(), settings.admin_token
        ):
            raise HTTPException(status_code=401, detail="operator authentication required")
        return "operator"

    def require_runtime() -> None:
        if signer is None or tasks is None or gate is None:
            raise HTTPException(
                status_code=503,
                detail="security signing is unavailable; protected operations fail closed",
            )

    def require_agent_token(authorization: str | None) -> str:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(status_code=401, detail="task-scoped agent credential required")
        return token.strip()

    def authenticated_agent_task(
        task_id: str, authorization: str | None
    ) -> tuple[Any, dict[str, Any]]:
        require_runtime()
        token = require_agent_token(authorization)
        record = database.get_task(task_id)
        if record is None or not tasks.verify_agent_token(record, token):  # type: ignore[union-attr]
            raise HTTPException(status_code=401, detail="task-scoped agent credential is invalid")
        verified = tasks.get_verified_envelope(task_id)  # type: ignore[union-attr]
        if verified is None:
            raise HTTPException(
                status_code=503, detail="task envelope integrity verification failed"
            )
        return verified[0], record

    def audit_healthy() -> bool:
        try:
            return bool(database.verify_audit()["valid"])
        except Exception:
            return False

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        try:
            database_ok = bool(database.verify_audit()["valid"])
        except Exception:
            database_ok = False
        signed = signer is not None
        operator_configured = settings.operator_auth_ready
        return {
            "service": "BLACK ICE",
            "version": "0.1.0",
            "status": "ready" if signed and operator_configured and database_ok else "restricted",
            "security_core": "available" if signed and operator_configured else "restricted",
            "components": {
                "tse_signing": "available" if signed else "unavailable",
                "operator_auth": "configured" if operator_configured else "not-configured",
                "sqlite": "available" if database_ok else "integrity-check-failed",
                "filesystem_adapter": "workspace-scoped",
                "network_adapter": "not-registered",
                "arbitrary_shell": "not-registered",
            },
            "audit_integrity": database.verify_audit(),
            "limitations": [
                "This single-process runtime does not isolate hostile code; only gateway-registered adapters are controlled."
            ],
        }

    @app.get("/api/overview")
    def overview(_: str = Depends(require_operator)) -> dict[str, Any]:
        tasks_data = database.list_tasks(limit=200)
        decisions = database.list_decisions(limit=100)
        inspections = database.list_inspections(limit=100)
        audit_state = database.verify_audit()
        active = sum(
            1 for item in tasks_data if item["envelope"].get("task_state") == TaskState.ACTIVE.value
        )
        counts: dict[str, int] = {outcome.value: 0 for outcome in DecisionOutcome}
        for item in decisions:
            counts[item["outcome"]] = counts.get(item["outcome"], 0) + 1
        return {
            "status": "ready"
            if settings.control_plane_ready and audit_state["valid"]
            else "restricted",
            "counts": {
                "tasks_total": len(tasks_data),
                "tasks_active": active,
                "decisions_recent": len(decisions),
                "inspections_total": len(inspections),
                "audit_events": audit_state["events_total"],
                "decision_outcomes": counts,
            },
            "recent_decisions": decisions[:12],
            "recent_inspections": inspections[:5],
            "audit_integrity": audit_state,
            "security_boundary": {
                "gateway": "registered operations only",
                "filesystem": "workspace scoped, no-follow opens",
                "network": "default denied; no outbound adapter registered",
                "commands": "arbitrary shell not registered",
                "hostile_code_isolation": "not provided by this process",
            },
        }

    @app.get("/api/system")
    def system_status(_: str = Depends(require_operator)) -> dict[str, Any]:
        return {
            "control_plane": "available" if settings.control_plane_ready else "restricted",
            "database": "SQLite local mode",
            "signing_key_configured": signer is not None,
            "operator_token_configured": settings.operator_auth_ready,
            "artifact_limit_bytes": settings.max_artifact_bytes,
            "action_limit_bytes": settings.max_action_bytes,
            "policy_version": "v1",
            "audit": database.verify_audit(),
            "not_implemented": [
                "network adapter",
                "arbitrary shell",
                "multi-process locking",
                "hostile-code sandbox",
                "dynamic taint tracking",
            ],
        }

    @app.get("/api/tasks")
    def list_tasks(_: str = Depends(require_operator)) -> list[dict[str, Any]]:
        return database.list_tasks(limit=200)

    @app.post("/api/tasks")
    def create_task(body: TaskCreateRequest, _: str = Depends(require_operator)) -> dict[str, Any]:
        require_runtime()
        if not audit_healthy():
            raise HTTPException(
                status_code=503, detail="audit integrity failed; task issuance is disabled"
            )
        try:
            issued = tasks.create(body)  # type: ignore[union-attr]
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"task could not be issued: {type(exc).__name__}"
            ) from exc
        return issued.model_dump(mode="json")

    @app.get("/api/tasks/{task_id}")
    def get_task(task_id: str, _: str = Depends(require_operator)) -> dict[str, Any]:
        record = database.get_task(task_id)
        if record is None:
            raise HTTPException(status_code=404, detail="task not found")
        return {
            "envelope": record["envelope"],
            "signature": record["signature"],
            "action_count": record["action_count"],
        }

    @app.get("/api/agent/tasks/{task_id}/envelope")
    def agent_get_envelope(
        task_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        envelope, record = authenticated_agent_task(task_id, authorization)
        if envelope.task_state != TaskState.ACTIVE or envelope.expires_at <= datetime.now(UTC):
            raise HTTPException(status_code=410, detail="task is revoked, inactive, or expired")
        return {
            "envelope": envelope.model_dump(mode="json"),
            "signature": record["signature"],
        }

    @app.get("/api/agent/tasks/{task_id}/status")
    def agent_task_status(
        task_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        envelope, record = authenticated_agent_task(task_id, authorization)
        return {
            "task_id": task_id,
            "agent_id": envelope.agent_id,
            "task_state": envelope.task_state.value,
            "expires_at": envelope.expires_at.isoformat(),
            "action_count": record["action_count"],
            "max_actions": envelope.resource_limits.max_actions,
            "audit_integrity": database.verify_audit(),
        }

    @app.get("/api/agent/tasks/{task_id}/decisions")
    def agent_task_decisions(
        task_id: str, limit: int = 50, authorization: str | None = Header(default=None)
    ) -> list[dict[str, Any]]:
        authenticated_agent_task(task_id, authorization)
        return database.list_decisions(task_id=task_id, limit=max(1, min(limit, 100)))

    @app.post("/api/agent/tasks/{task_id}/actions")
    def agent_action(
        task_id: str, body: ActionRequest, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        require_runtime()
        if body.task_id != task_id:
            raise HTTPException(
                status_code=400, detail="path task ID does not match the action request"
            )
        # Authenticate before invoking the gate: malformed/anonymous requests must not be able
        # to amplify durable audit writes. The gate rechecks the token under its task lock.
        authenticated_agent_task(task_id, authorization)
        token = require_agent_token(authorization)
        result = gate.execute(body, token)  # type: ignore[union-attr]
        return {"decision": result["decision"].model_dump(mode="json"), "result": result["result"]}

    @app.post("/api/tasks/{task_id}/revoke")
    def revoke_task(task_id: str, operator: str = Depends(require_operator)) -> dict[str, Any]:
        require_runtime()
        try:
            return tasks.revoke(task_id, operator)  # type: ignore[union-attr]
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/decisions")
    def list_decisions(
        task_id: str | None = None, limit: int = 100, _: str = Depends(require_operator)
    ) -> list[dict[str, Any]]:
        return database.list_decisions(task_id=task_id, limit=max(1, min(limit, 200)))

    @app.get("/api/decisions/{decision_id}")
    def get_decision(decision_id: str, _: str = Depends(require_operator)) -> dict[str, Any]:
        result = database.get_decision(decision_id)
        if result is None:
            raise HTTPException(status_code=404, detail="decision not found")
        return result

    @app.post("/api/decisions/{decision_id}/approve")
    def approve_decision(
        decision_id: str, operator: str = Depends(require_operator)
    ) -> dict[str, Any]:
        if not audit_healthy():
            raise HTTPException(
                status_code=503, detail="audit integrity failed; approvals are disabled"
            )
        item = database.get_decision(decision_id)
        if item is None:
            raise HTTPException(status_code=404, detail="decision not found")
        if item["outcome"] != DecisionOutcome.REVIEW.value:
            raise HTTPException(
                status_code=409, detail="only a REVIEW decision can receive approval"
            )
        record = database.get_task(item["task_id"])
        if record is None:
            raise HTTPException(status_code=404, detail="task not found")
        envelope = record["envelope"]
        if envelope.get("task_state") != TaskState.ACTIVE.value or datetime.fromisoformat(
            envelope["expires_at"]
        ) <= datetime.now(UTC):
            raise HTTPException(status_code=409, detail="task is inactive or expired")
        approval_token = secrets.token_urlsafe(32)
        approval_hash = hashlib.sha256(approval_token.encode()).hexdigest()
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        database.create_approval(
            approval_hash,
            decision_id,
            item["task_id"],
            item["request_digest"],
            expires_at.isoformat(),
            operator,
            audit_payload={
                "category": "approval",
                "event": "action_approved",
                "decision_id": decision_id,
                "task_id": item["task_id"],
                "operator": operator,
                "expires_at": expires_at.isoformat(),
                "approval_scope": "one action digest; one use",
            },
        )
        return {
            "approval_id": approval_token,
            "expires_at": expires_at.isoformat(),
            "single_use": True,
        }

    @app.get("/api/audit/events")
    def audit_events(limit: int = 100, _: str = Depends(require_operator)) -> list[dict[str, Any]]:
        return database.list_audit(max(1, min(limit, 200)))

    @app.get("/api/audit/verify")
    def verify_audit(_: str = Depends(require_operator)) -> dict[str, Any]:
        return database.verify_audit()

    @app.post("/api/artifacts/inspect")
    def inspect_artifact(
        body: ArtifactInspectRequest, _: str = Depends(require_operator)
    ) -> dict[str, Any]:
        if not audit_healthy():
            raise HTTPException(
                status_code=503,
                detail="audit integrity failed; inspection record cannot be trusted",
            )
        try:
            return artifacts.inspect_upload(body).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/artifacts/inspections")
    def list_inspections(_: str = Depends(require_operator)) -> list[dict[str, Any]]:
        return database.list_inspections(limit=200)

    @app.get("/api/artifacts/inspections/{inspection_id}")
    def get_inspection(inspection_id: str, _: str = Depends(require_operator)) -> dict[str, Any]:
        inspection = database.get_inspection(inspection_id)
        if inspection is None:
            raise HTTPException(status_code=404, detail="inspection not found")
        return inspection

    @app.get("/api/policy")
    def policy_view(_: str = Depends(require_operator)) -> dict[str, Any]:
        return {
            "version": "v1",
            "mode": "deterministic default-deny",
            "decision_outcomes": [outcome.value for outcome in DecisionOutcome],
            "rules": [
                {
                    "id": "tse.signature_valid",
                    "effect": "deny",
                    "description": "Unverifiable envelopes are not executable.",
                },
                {
                    "id": "task.active",
                    "effect": "deny",
                    "description": "Expired, closed, or revoked tasks cannot act.",
                },
                {
                    "id": "tse.tool_scope",
                    "effect": "deny",
                    "description": "Tools must be explicitly present in the signed envelope and registry.",
                },
                {
                    "id": "filesystem.path_scope",
                    "effect": "deny",
                    "description": "Paths are relative to a task workspace and checked against permit/deny rules.",
                },
                {
                    "id": "network.default_deny",
                    "effect": "deny",
                    "description": "No outbound network adapter is registered.",
                },
                {
                    "id": "command.default_deny",
                    "effect": "deny",
                    "description": "No arbitrary command adapter is registered.",
                },
                {
                    "id": "approval.required",
                    "effect": "review",
                    "description": "A signed task may require a one-use approval bound to the exact request digest.",
                },
                {
                    "id": "dataflow.output_redaction",
                    "effect": "restrict",
                    "description": "Known credential patterns are redacted from text read results.",
                },
            ],
            "mutable_from_agent": False,
        }

    @app.get("/api/flow/summary")
    def flow_summary(_: str = Depends(require_operator)) -> dict[str, Any]:
        decisions = database.list_decisions(limit=200)
        flows = [
            {
                "decision_id": row["decision_id"],
                "task_id": row["task_id"],
                "tool_id": row["details"].get("tool_id"),
                "operation": row["details"].get("operation"),
                "resource": row["details"].get("resource"),
                "data_classification": row["details"].get("data_classification"),
                "execution_status": row["details"].get("execution_status"),
                "outcome": row["outcome"],
                "created_at": row["created_at"],
            }
            for row in decisions
        ]
        return {
            "observed_operations": flows,
            "coverage": "only gateway-mediated actions and deterministic content matches are represented",
            "limitations": [
                "no dynamic taint tracking",
                "no content lineage beyond action summaries",
                "no outbound network adapter",
            ],
        }

    @app.get("/api/graph")
    def action_graph(_: str = Depends(require_operator)) -> dict[str, Any]:
        events = list(reversed(database.list_audit(limit=200)))
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, str]] = []
        for event in events:
            payload = event["payload"]
            task_id = payload.get("task_id")
            if task_id:
                nodes[f"task:{task_id}"] = {
                    "id": f"task:{task_id}",
                    "kind": "task",
                    "label": task_id[:8],
                }
            decision_id = payload.get("decision_id")
            if decision_id:
                node_id = f"decision:{decision_id}"
                nodes[node_id] = {
                    "id": node_id,
                    "kind": "decision",
                    "label": f"{payload.get('decision', payload.get('event', 'event'))} {payload.get('operation', '')}".strip(),
                    "outcome": payload.get("decision"),
                }
                if task_id:
                    edges.append(
                        {"source": f"task:{task_id}", "target": node_id, "label": "action"}
                    )
            artifact_id = payload.get("artifact_id")
            if artifact_id:
                artifact_node = f"artifact:{artifact_id}"
                nodes[artifact_node] = {
                    "id": artifact_node,
                    "kind": "artifact",
                    "label": artifact_id[:12],
                }
                if decision_id:
                    edges.append(
                        {
                            "source": f"decision:{decision_id}",
                            "target": artifact_node,
                            "label": "inspected",
                        }
                    )
        unique_edges = {f"{e['source']}|{e['target']}|{e['label']}": e for e in edges}
        return {
            "nodes": list(nodes.values()),
            "edges": list(unique_edges.values()),
            "source": "SQLite audit events",
            "truncated": len(events) >= 200,
        }

    @app.get("/api/incidents")
    def incidents(_: str = Depends(require_operator)) -> list[dict[str, Any]]:
        events = database.list_audit(limit=200)
        result: list[dict[str, Any]] = []
        for event in events:
            payload = event["payload"]
            decision = payload.get("decision")
            if (
                decision in {DecisionOutcome.DENY.value, DecisionOutcome.REVIEW.value}
                or payload.get("event") == "task_revoked"
            ):
                result.append(
                    {"event_id": event["event_id"], "sequence": event["sequence"], **payload}
                )
        return result

    @app.post("/api/lab/run")
    def run_lab(_: str = Depends(require_operator)) -> dict[str, Any]:
        require_runtime()
        if not audit_healthy():
            raise HTTPException(
                status_code=503,
                detail="audit integrity failed; synthetic lab execution is disabled",
            )
        try:
            return run_synthetic_lab(tasks, gate, workspace, database, artifacts)  # type: ignore[arg-type]
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail=f"synthetic lab failed safely: {type(exc).__name__}"
            ) from exc

    @app.get("/api/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if dist.exists():
        assets = dist / "assets"
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/manus-routes.json")
        def routes_manifest() -> FileResponse:
            manifest = dist / "manus-routes.json"
            if not manifest.exists():
                raise HTTPException(status_code=404, detail="route manifest is unavailable")
            return FileResponse(manifest, media_type="application/json")

        @app.get("/{path:path}")
        def spa_fallback(path: str) -> FileResponse:
            if path.startswith("api/") or path in {"api", "healthz"}:
                raise HTTPException(status_code=404, detail="not found")
            index = dist / "index.html"
            if not index.exists():
                raise HTTPException(status_code=503, detail="console build is unavailable")
            return FileResponse(index)

    return app


app = create_app()
