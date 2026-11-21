# Python agent SDK

The implemented SDK is `blackice.sdk.BlackIceAgentClient`, a thin HTTP client bound to one operator-issued task. It exposes gateway-mediated task and action operations only; it does not expose a local filesystem, shell, generic network client, package installer, or process sandbox.

## Create and close a client

```python
from blackice.sdk import BlackIceAgentClient

with BlackIceAgentClient(
    base_url="http://127.0.0.1:8000",
    task_id="TASK_ID_FROM_OPERATOR",
    agent_token="ONE_TIME_TASK_TOKEN",
) as client:
    status = client.get_status()
    listing = client.list_files(".")
```

Constructor parameters are `base_url`, `task_id`, `agent_token`, optional `timeout` (default 10 seconds), and an optional HTTPX transport for testing/integration. The token is held privately by the client and sent as a bearer credential. Use the context manager or call `close()` explicitly.

The API base URL must be an origin only: no path, query, fragment, username or password. HTTPS is required for remote hosts. Plain HTTP is accepted only for `localhost`, `127.0.0.1`, and `::1`. Requests do not follow redirects and `trust_env=False` means HTTPX environment proxy settings are not used. `BlackIceClientError` wraps HTTP status and transport errors; transport failure reports that the gateway is unavailable and should not be bypassed.

## Methods

| Method | Gateway behavior |
|---|---|
| `get_envelope()` | Fetch the signed envelope for this task. |
| `get_status()` | Fetch task status, expiry, action count/budget, and audit-integrity state. |
| `get_decisions(limit=50)` | Fetch this task's decisions; the client clamps `limit` to 1–100. |
| `invoke(tool_id, operation, resource, parameters=None, destination=None, approval_id=None, provenance=None)` | Submit one structured action to the task's gateway endpoint. The client fetches the envelope to set the agent identity. Only registered operations permitted by the signed task and policy can execute. |
| `list_files(path=".")` | Convenience invocation of `filesystem.list`. |
| `read_text(path)` | Convenience invocation of `filesystem.read`. Results are bounded UTF-8 text and may be redacted. |
| `write_text(path, content, approval_id=None)` | Convenience invocation of `filesystem.write`; the task and policy must allow it, and any required one-use approval must be valid. |
| `inspect_artifact(path)` | Convenience invocation of `artifact.inspect`; the task must permit the artifact tool. It inspects without executing. |

There is no dedicated SDK convenience method for `filesystem.mkdir`, although `invoke("filesystem", "mkdir", ...)` can submit it if the task and policy permit it. Passing a `destination` argument does not enable network access: there is no outbound network adapter. Supplying an unregistered operation through `invoke` cannot add it to the gateway registry.

## Boundaries

The SDK is task-scoped, not an unrestricted agent SDK. Every action remains subject to task identity, token, envelope signature, expiry/revocation, action budget, path scope, approval requirements, deterministic policy and registered adapter checks. Task bearer credentials do not authenticate to operator routes. A caller that runs arbitrary code outside the SDK can bypass this path; the SDK is not an OS security sandbox and does not provide general Git workflows, dependency installation, shell execution or outbound networking.
