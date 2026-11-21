# MCP servers

The optional `mcp` package extra installs two distinct stdio MCP entry points. Keep the task-agent server and operator server in separate processes and security contexts. In particular, **do not connect `blackice-operator-mcp` to a protected-agent runtime**.

## Task-scoped agent server: `blackice-mcp`

Install with `uv sync --locked --extra dev --extra mcp`. Configure only the intended task ID and its one-time agent token as task credentials; `BLACKICE_API_URL` optionally selects the gateway origin and defaults to `http://127.0.0.1:8000`:

```bash
BLACKICE_AGENT_TASK_ID='TASK_ID' \
BLACKICE_AGENT_TOKEN='ONE_TIME_TASK_TOKEN' \
BLACKICE_API_URL='http://127.0.0.1:8000' \
uv run blackice-mcp
```

The server uses stdio transport and wraps `BlackIceAgentClient`. Its authorization is the task-scoped bearer token for the configured task; it does not use or need `BLACKICE_ADMIN_TOKEN`. It verifies endpoint availability at startup. Remote API origins must use HTTPS; plain HTTP is loopback-only. The HTTP client does not follow redirects or use environment proxy settings.

Registered agent tools are exactly:

| MCP tool | Scope |
|---|---|
| `get_task_security_envelope` | Read this task's signed, time-limited capability envelope. |
| `get_task_status` | Read this task's status, remaining action budget and audit-integrity state. |
| `get_task_decisions(limit=50)` | Read decisions for this task only; the service enforces a 1–100 limit. |
| `filesystem_list(path=".")` | List a relative path in this task workspace through the gateway. |
| `filesystem_read(path)` | Read bounded UTF-8 workspace text; detected credentials/PII are redacted. |
| `filesystem_write(path, content, approval_id=None)` | Write bounded UTF-8 text only when task permissions and policy permit it, including any required approval. |
| `inspect_workspace_artifact(path)` | Inspect a workspace artifact without executing it; extracted output is redacted. |

Every filesystem/artifact operation still passes through the gateway's policy and task permissions. The MCP surface contains no operator task-management tools, shell, package installation, generic network tool, or general Git workflow. It does not isolate arbitrary code run elsewhere in the agent process.

## Separate operator server: `blackice-operator-mcp`

Run this only as a separate operator process with the private operator credential available in its environment:

```bash
BLACKICE_ADMIN_TOKEN='PRIVATE_OPERATOR_TOKEN' \
BLACKICE_API_URL='http://127.0.0.1:8000' \
uv run blackice-operator-mcp
```

`BLACKICE_ADMIN_TOKEN` must be at least 32 characters/bytes as checked by the server; use the generated value from the private `.env`. It authenticates operator API calls and is not an agent token. The process uses stdio transport, checks the operator overview at startup, and has no generic filesystem, shell or unrestricted network tool.

The operator tools are:

- `operator_list_tasks()` — bounded recent task registry.
- `operator_create_task(agent_id, task_owner="operator", permitted_filesystem_operations=None, permitted_tools=None, permitted_paths=None, restricted_paths=None, approval_requirements=None, expires_in_seconds=3600, max_actions=500)` — issue a signed task envelope and return its **one-time agent token** in the result. Transfer that token only to the intended task agent through a protected channel.
- `operator_inspect_task(task_id)` and `operator_revoke_task(task_id)` — inspect or revoke one task.
- `operator_list_decisions(task_id=None, limit=100)` — list decisions, optionally filtered by task; limit is clamped to 1–200.
- `operator_approve_decision(decision_id)` — approve one eligible `REVIEW` decision. The returned approval is single-use, short-lived and bound to the exact action request digest.
- `operator_audit_events(limit=100)` and `operator_verify_audit()` — query a bounded audit slice or verify the local SQLite hash chain. Verification does not make the store immutable.
- `operator_run_synthetic_lab()` — run synthetic local gateway/artifact scenarios; results are not real-world validation.

Operator capabilities must remain available only to trusted operator workflows. Do not provide this MCP server, its `BLACKICE_ADMIN_TOKEN`, or its tools to a protected agent. Creating a task through the operator server is privileged; the agent token returned once is the only task credential to transfer to that task's agent.

## Shared transport and product limits

The MCP processes speak to the BLACK ICE HTTP API; their stdio transport is the MCP client connection, not an alternative execution route. Remote API URLs require HTTPS, while unencrypted HTTP is permitted only for loopback. `blackice-mcp` cannot list/create/revoke other tasks, approve decisions, or read global audit state. Conversely, the operator server does not turn task-agent calls into arbitrary host execution. Neither server adds shell access, package installation, outbound network, OS sandboxing, or general Git operations.
