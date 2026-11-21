from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from blackice.client_utils import validate_api_base_url


class BlackIceClientError(RuntimeError):
    pass


class BlackIceAgentClient:
    """Thin task-bound SDK; no direct filesystem, shell, or generic network tool is exposed."""

    def __init__(
        self,
        base_url: str,
        task_id: str,
        agent_token: str,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = validate_api_base_url(base_url)
        self.task_id = task_id
        self._agent_token = agent_token
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> BlackIceAgentClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        try:
            response = self._client.request(
                method,
                path,
                json=payload,
                headers={"Authorization": f"Bearer {self._agent_token}"},
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:2048]
            raise BlackIceClientError(
                f"BLACK ICE returned HTTP {exc.response.status_code}: {detail}"
            ) from exc
        except httpx.RequestError as exc:
            raise BlackIceClientError(
                "BLACK ICE endpoint is unavailable; do not bypass the gateway"
            ) from exc

    def get_envelope(self) -> dict[str, Any]:
        task_id = quote(self.task_id, safe="")
        return self._request("GET", f"/api/agent/tasks/{task_id}/envelope")

    def get_status(self) -> dict[str, Any]:
        task_id = quote(self.task_id, safe="")
        return self._request("GET", f"/api/agent/tasks/{task_id}/status")

    def get_decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        task_id = quote(self.task_id, safe="")
        bounded = max(1, min(limit, 100))
        return self._request("GET", f"/api/agent/tasks/{task_id}/decisions?limit={bounded}")

    def invoke(
        self,
        tool_id: str,
        operation: str,
        resource: str,
        parameters: dict[str, Any] | None = None,
        destination: str | None = None,
        approval_id: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        envelope = self.get_envelope()["envelope"]
        payload: dict[str, Any] = {
            "task_id": self.task_id,
            "agent_id": envelope["agent_id"],
            "tool_id": tool_id,
            "operation": operation,
            "resource": resource,
            "parameters": parameters or {},
            "requested_capability": f"{tool_id}.{operation}",
            "provenance": provenance or {},
        }
        if destination is not None:
            payload["destination"] = destination
        if approval_id is not None:
            payload["approval_id"] = approval_id
        task_id = quote(self.task_id, safe="")
        return self._request("POST", f"/api/agent/tasks/{task_id}/actions", payload)

    def list_files(self, path: str = ".") -> dict[str, Any]:
        return self.invoke("filesystem", "list", path)

    def read_text(self, path: str) -> dict[str, Any]:
        return self.invoke("filesystem", "read", path)

    def write_text(self, path: str, content: str, approval_id: str | None = None) -> dict[str, Any]:
        return self.invoke(
            "filesystem", "write", path, {"content": content}, approval_id=approval_id
        )

    def inspect_artifact(self, path: str) -> dict[str, Any]:
        return self.invoke("artifact", "inspect", path)
