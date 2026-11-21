from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

from blackice.client_utils import validate_api_base_url
from blackice.models import TaskCreateRequest


class OperatorAPI:
    """Admin-authenticated HTTP client for the explicitly separate operator MCP process."""

    def __init__(
        self,
        api_base_url: str,
        admin_token: str,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not admin_token or len(admin_token) < 32:
            raise ValueError("operator credential must contain at least 32 characters")
        self.base_url = validate_api_base_url(api_base_url).rstrip("/")
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
            timeout=20,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str | int] | None = None,
    ) -> Any:
        response = self.client.request(method, path, json=payload, params=params)
        response.raise_for_status()
        if not response.content:
            return {"status": "ok"}
        return response.json()

    def close(self) -> None:
        self.client.close()


def build_server(api: OperatorAPI) -> FastMCP:
    """Build limited operator tools; never register them in the task-scoped agent server."""
    server = FastMCP(
        "BLACK ICE operator control plane",
        instructions=(
            "Operator-only controls authenticated with BLACKICE_ADMIN_TOKEN. Run this server in a "
            "separate operator process and never attach it to a protected-agent runtime. Its "
            "task-creation response contains a one-time agent token; transfer that token only to "
            "the intended task agent through a protected channel. No shell, generic filesystem, "
            "or unrestricted network tools are exposed."
        ),
    )

    @server.tool()
    def operator_list_tasks() -> list[dict[str, Any]]:
        """List the bounded recent task registry for the authenticated operator."""
        return api.request("GET", "/api/tasks")

    @server.tool()
    def operator_create_task(
        agent_id: str,
        task_owner: str = "operator",
        permitted_filesystem_operations: list[str] | None = None,
        permitted_tools: list[str] | None = None,
        permitted_paths: list[str] | None = None,
        restricted_paths: list[str] | None = None,
        approval_requirements: list[str] | None = None,
        expires_in_seconds: int = 3600,
        max_actions: int = 500,
    ) -> dict[str, Any]:
        """Issue a signed, time-limited task envelope; the one-time task credential is operator-visible."""
        fields: dict[str, Any] = {
            "agent_id": agent_id,
            "task_owner": task_owner,
            "expires_in_seconds": expires_in_seconds,
            "max_actions": max_actions,
        }
        optional_lists = {
            "permitted_filesystem_operations": permitted_filesystem_operations,
            "permitted_tools": permitted_tools,
            "permitted_paths": permitted_paths,
            "restricted_paths": restricted_paths,
            "approval_requirements": approval_requirements,
        }
        fields.update({name: value for name, value in optional_lists.items() if value is not None})
        body = TaskCreateRequest.model_validate(fields).model_dump(mode="json")
        return api.request("POST", "/api/tasks", body)

    @server.tool()
    def operator_inspect_task(task_id: str) -> dict[str, Any]:
        """Read one task's signed envelope and bounded action count."""
        return api.request("GET", f"/api/tasks/{quote(task_id, safe='')}")

    @server.tool()
    def operator_revoke_task(task_id: str) -> dict[str, Any]:
        """Revoke a task at the control plane; subsequent gateway operations fail closed."""
        return api.request("POST", f"/api/tasks/{quote(task_id, safe='')}/revoke", {})

    @server.tool()
    def operator_list_decisions(task_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Read recent gateway decisions, optionally limited to one task."""
        params: dict[str, str | int] = {"limit": max(1, min(limit, 200))}
        if task_id:
            params["task_id"] = task_id
        return api.request("GET", "/api/decisions", params=params)

    @server.tool()
    def operator_approve_decision(decision_id: str) -> dict[str, Any]:
        """Approve one REVIEW decision; returned approval is single-use and bound to the exact request."""
        return api.request(
            "POST", f"/api/decisions/{quote(decision_id, safe='')}/approve", {}
        )

    @server.tool()
    def operator_audit_events(limit: int = 100) -> list[dict[str, Any]]:
        """Read a bounded slice of the tamper-evident, non-immutable audit ledger."""
        return api.request(
            "GET", "/api/audit/events", params={"limit": max(1, min(limit, 200))}
        )

    @server.tool()
    def operator_verify_audit() -> dict[str, Any]:
        """Verify the local SQLite audit hash chain; this does not make storage immutable."""
        return api.request("GET", "/api/audit/verify")

    @server.tool()
    def operator_run_synthetic_lab() -> dict[str, Any]:
        """Run labeled synthetic gateway and artifact-inspection scenarios in the local process."""
        return api.request("POST", "/api/lab/run", {})

    return server


def main() -> None:
    admin_token = os.environ.get("BLACKICE_ADMIN_TOKEN", "")
    api_base_url = os.environ.get("BLACKICE_API_URL", "http://127.0.0.1:8000")
    if not admin_token:
        raise SystemExit(
            "Set BLACKICE_ADMIN_TOKEN only in the separate operator process environment."
        )
    try:
        api = OperatorAPI(api_base_url, admin_token)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    try:
        api.request("GET", "/api/overview")
    except Exception as exc:
        api.close()
        raise SystemExit(
            f"BLACK ICE operator endpoint is unavailable: {type(exc).__name__}"
        ) from exc
    try:
        build_server(api).run(transport="stdio")
    finally:
        api.close()


if __name__ == "__main__":
    main()
