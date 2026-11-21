# Gateway tool integration

BLACK ICE exposes operations through a task-specific, signed capability envelope and a default-deny gateway. An agent integration must submit structured actions to the API through an authorized client such as the [Python SDK](sdk.md) or [agent MCP server](mcp.md). It does not receive direct host execution capabilities.

## Registered operations

The current `ToolRegistry` registers:

| Tool ID | Operation | Behavior and bounds |
|---|---|---|
| `filesystem` | `list` | List a relative path inside the task's workspace. |
| `filesystem` | `read` | Read UTF-8 text within the per-action byte limit (default 65,536 bytes). Binary content must use artifact inspection instead. Known credential patterns and email addresses are redacted from text results. |
| `filesystem` | `write` | Write UTF-8 text within the per-action byte limit (default 65,536 bytes), if the signed task permits `write` and policy allows it. A required operator approval is one-use and bound to the exact action request. |
| `filesystem` | `mkdir` | Create a directory within the task workspace if permitted by the task and policy. The convenience SDK methods do not include `mkdir`; it can be requested through the generic gateway invocation only. |
| `artifact` | `inspect` | Inspect a workspace file through the bounded artifact inspector without executing it. The task must permit the `artifact` tool. Results are reports with coverage, uncertainty and limitations, not a safety guarantee; output is redacted before it is returned to the agent. |

Task issuance defaults to filesystem `list` and `read` only and permits the `filesystem` tool. Other operations/tools must be explicitly permitted in the task envelope; fixed policy and registry checks still apply. The operator CLI can opt into writes and artifact inspection. The operator MCP supports the broader task-envelope fields. Task defaults also restrict sensitive path patterns such as `.env`, `.git`, SSH/cloud credential paths and private-key files. Paths are workspace-relative; absolute paths and traversal are denied by the adapter.

The task envelope and policy bound action count and runtime. Defaults include 500 actions and a one-hour maximum runtime; task issuance accepts expiry from 60 through 3,600 seconds, and the runtime enforces signed limits. These limits do not make the API a general process sandbox.

## Gateway actions and decisions

The task-authenticated action endpoint is `POST /api/agent/tasks/{task_id}/actions`. Each request must identify the task, agent, tool, operation and resource, and carry the task bearer token. The gateway verifies task identity, token, envelope signature, active/expiry/revocation state, audit integrity, permissions and the registered operation before dispatch. Decisions include `ALLOW`, `DENY`, `REVIEW` or `RESTRICT`; an HTTP success response does not necessarily mean an action ran. A denied, review-required, or restricted action can have no execution result or a limited/redacted result.

Operator endpoints are separate: they issue, inspect and revoke tasks, review decisions, approve eligible `REVIEW` decisions, inspect artifacts, view/verify audit events and run synthetic ICE-LAB scenarios. They require operator authentication and must not be exposed to an agent as a task capability. An approval token is short-lived, one-use, and bound to the exact request digest; it does not expand task permissions.

## Artifact inspection

Artifact inspection is analysis only. The operator upload endpoint accepts base64 content with a configured artifact size limit of 10 MiB, stores content by hash and records a report/audit event. The CLI's local-file `inspect` command also enforces a 10 MiB file limit. Workspace artifact inspection uses the same inspector. Supported representations and inspection coverage depend on format; partial or unsupported content remains a limitation rather than an implicit clearance. Inspection never executes a file.

## Not implemented

There is no registered shell/command tool, package-install tool, outbound-network tool, general Git workflow, or OS-level sandbox. Supplying a destination in an action request does not add a network adapter. There is no protection for an agent or process that bypasses the gateway, and the workspace adapter is not a hostile-code isolation boundary. See the repository's threat model for the broader security limits.
