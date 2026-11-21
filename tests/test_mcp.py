from __future__ import annotations

import asyncio

import httpx

from blackice.mcp_server import build_server
from blackice.operator_mcp_server import OperatorAPI
from blackice.operator_mcp_server import build_server as build_operator_server
from blackice.sdk import BlackIceAgentClient


def test_optional_mcp_server_builds_only_around_task_scoped_sdk():
    client = BlackIceAgentClient(
        "https://console.example.invalid",
        "task-12345678",
        "one-task-token",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
    )
    try:
        server = build_server(client)
        assert server is not None
        assert callable(server.run)
    finally:
        client.close()


def test_operator_mcp_is_a_distinct_admin_authenticated_surface():
    agent_client = BlackIceAgentClient(
        "https://console.example.invalid",
        "task-12345678",
        "one-task-token",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
    )
    seen_authorization: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers.get("authorization", ""))
        return httpx.Response(200, json={"service": "BLACK ICE"})

    operator_api = OperatorAPI(
        "https://console.example.invalid",
        "operator-test-token-that-is-at-least-32-characters-long",
        transport=httpx.MockTransport(handler),
    )
    try:
        agent_names = {tool.name for tool in asyncio.run(build_server(agent_client).list_tools())}
        operator_names = {
            tool.name for tool in asyncio.run(build_operator_server(operator_api).list_tools())
        }
        assert "filesystem_read" in agent_names
        assert "operator_create_task" not in agent_names
        assert "operator_create_task" in operator_names
        assert "operator_revoke_task" in operator_names
        assert "operator_verify_audit" in operator_names
        assert not any("shell" in name or "network" in name for name in operator_names)

        result = operator_api.request("GET", "/api/overview")
        assert result == {"service": "BLACK ICE"}
        assert seen_authorization == [
            "Bearer operator-test-token-that-is-at-least-32-characters-long"
        ]
    finally:
        agent_client.close()
        operator_api.close()


def test_operator_mcp_rejects_short_admin_tokens_and_insecure_remote_http():
    try:
        OperatorAPI("https://console.example.invalid", "too-short")
    except ValueError as exc:
        assert "at least 32" in str(exc)
    else:
        raise AssertionError("short operator credentials must be rejected")

    try:
        OperatorAPI("http://remote.example.invalid", "operator-token-" + "x" * 40)
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("remote plain HTTP must be rejected")
