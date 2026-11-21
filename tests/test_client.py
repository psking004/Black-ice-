from __future__ import annotations

import json
import stat

import httpx
import pytest

from blackice.cli import _initialize_secrets
from blackice.client_utils import ApiBaseUrlError, validate_api_base_url
from blackice.sdk import BlackIceAgentClient


def test_api_urls_require_https_remotely_and_reject_embedded_credentials():
    assert validate_api_base_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    assert (
        validate_api_base_url("https://console.example.invalid/")
        == "https://console.example.invalid"
    )
    for value in (
        "http://example.invalid",
        "https://user:password@example.invalid",
        "https://example.invalid/api?secret=x",
        "file:///tmp/socket",
    ):
        with pytest.raises(ApiBaseUrlError):
            validate_api_base_url(value)


def test_agent_sdk_retrieves_signed_envelope_and_uses_only_gateway_actions():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.headers["authorization"] == "Bearer task-token-test"
        if request.url.path.endswith("/envelope"):
            return httpx.Response(
                200,
                json={
                    "envelope": {"task_id": "task-12345678", "agent_id": "agent-a"},
                    "signature": "signed",
                },
            )
        return httpx.Response(200, json={"decision": {"outcome": "ALLOW"}, "result": {"ok": True}})

    client = BlackIceAgentClient(
        "http://127.0.0.1:8000",
        "task-12345678",
        "task-token-test",
        transport=httpx.MockTransport(handler),
    )
    try:
        result = client.read_text("notes.txt")
    finally:
        client.close()
    assert result["decision"]["outcome"] == "ALLOW"
    assert len(seen) == 2
    assert seen[0].url.path == "/api/agent/tasks/task-12345678/envelope"
    assert seen[1].url.path == "/api/agent/tasks/task-12345678/actions"
    payload = json.loads(seen[1].content)
    assert payload["agent_id"] == "agent-a"
    assert payload["operation"] == "read"
    assert "shell" not in payload and "command" not in payload


def test_private_operator_init_is_0600_and_does_not_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _initialize_secrets() == 0
    env_path = tmp_path / ".env"
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    contents = env_path.read_text(encoding="utf-8")
    assert "BLACKICE_ADMIN_TOKEN=" in contents
    assert "BLACKICE_SIGNING_KEY=" in contents
    first = contents
    assert _initialize_secrets() == 2
    assert env_path.read_text(encoding="utf-8") == first
