# Troubleshooting

This guide follows the current Python API and CLI. It does not assume a shell runner, network adapter, automated recovery tool, or approval command that is not present.

## Start and configure the service

From the repository root, the README-supported setup is:

```bash
uv sync --extra dev
python -m blackice.cli init
set -a
source .env
set +a
uv run uvicorn blackice.api.app:app --host 127.0.0.1 --port 8000
```

If you already have a private environment file, do not overwrite it. `blackice init` refuses to replace an existing `.env`. Load the existing file as shown before running the API or authenticated CLI commands. The configured `BLACKICE_ADMIN_TOKEN` and `BLACKICE_SIGNING_KEY` must each be at least 32 UTF-8 bytes for operator authentication and protected runtime readiness. The API defaults to local state under `./var`; available path variables are `BLACKICE_STATE_DIR`, `BLACKICE_DATABASE_PATH`, `BLACKICE_WORKSPACE_ROOT`, and `BLACKICE_ARTIFACT_ROOT`. `BLACKICE_API_URL` changes the CLI target and defaults to `http://127.0.0.1:8000`.

The service can also be started with `uv run blackice serve`; it binds to loopback by default. The CLI accepts ports 1024–65535. A non-loopback bind requires `--allow-remote`; that flag does not add TLS or network protection. Provide appropriate external transport and network controls before remote access.

## Common symptoms

| Symptom | Likely cause and actual behavior | What to check |
|---|---|---|
| `BLACK ICE API is unavailable; do not bypass the gateway` | CLI cannot reach the configured API; it does not fall back to direct access. | Confirm the API process is running, host/port match `BLACKICE_API_URL`, and the URL is valid. `blackice health` is unauthenticated. |
| `BLACKICE_ADMIN_TOKEN is not configured; source the private .env file first` | Authenticated CLI command was run without the variable. | In that shell, run `set -a; source .env; set +a`; verify privately without printing secrets. |
| HTTP 503: `operator credential is not configured` | Operator token is missing or shorter than 32 bytes. | Correct private environment configuration and restart/reload the service. `operator_auth_ready` requires at least 32 UTF-8 bytes. |
| HTTP 503: `security signing is unavailable; protected operations fail closed` | Signing key is absent/invalid, or protected runtime components are unavailable. | Confirm `BLACKICE_SIGNING_KEY` is configured and at least 32 UTF-8 bytes. Check `blackice health` and operator `GET /api/system`. Do not bypass the API. |
| HTTP 401: `operator authentication required` | Missing/wrong operator bearer token, including use of a task token on an operator endpoint. | Use the operator token for operator routes. Agent task tokens are separate and task-scoped. |
| HTTP 401: invalid task-scoped agent credential | Missing/wrong task token, or token used with another task. | Use the one-time token issued for that exact task. The database stores its SHA-256 hash, not the original token; if lost, create a new task. |
| HTTP 404 on task or decision | Identifier does not exist, or task envelope failed verification on revocation. | Check the exact task/decision ID. Revocation returns 404 if the task is absent or its envelope cannot be verified. |
| `DENY` with `tool.registered` / “tool operation is not registered” | Requested tool or operation is absent from the runtime registry. | Current tools are `filesystem` (`list`, `read`, `write`, `mkdir`) and, when available, `artifact.inspect`. There is no command/shell or network adapter. |
| `DENY` with `filesystem.path_scope`, `filesystem.restricted_path`, or `filesystem.relative_path` | Path is outside permitted rules, matches a restricted rule, or is absolute/traversal/otherwise invalid. | Use a relative POSIX path inside that task's workspace. Restricted paths override allowed paths. Do not try to access host files. |
| `DENY` on write | Task defaults to `list`/`read`; write must be explicitly permitted. | Create a task with `--allow-write`. If approval is required, also use `--require-write-approval`. |
| `REVIEW` on an otherwise allowed operation | The signed task lists the exact `tool.operation` in approval requirements, or the approval is absent, expired, replayed, or does not match the request. | Only an operator can approve a recorded `REVIEW` decision. Use `POST /api/decisions/{decision_id}/approve`; the CLI currently has no approval subcommand. Include the returned `approval_id` with the same exact action request. The token expires after five minutes and is single-use. |
| HTTP 409 from approval endpoint | Decision is not `REVIEW`, or its task is inactive/expired. | Inspect the decision and task state. Approval does not broaden task scope or enable shell/network. |
| `RESTRICT` after a read/inspection | The adapter ran, but selected sensitive patterns were found and the agent-visible output was redacted. | `RESTRICT` is not a pre-execution denial. This is regex-based redaction, not complete secret/PII detection. |
| Binary file read fails with `binary files must be handled through the artifact inspector` | Filesystem text-read path requires UTF-8 text. | If permitted, request `artifact.inspect` for a workspace file or use `blackice inspect <local-file>` as operator. Inspection is bounded and may be partial/inconclusive. |
| File/action exceeds configured limit | Workspace reads use the workspace file bound and text actions also have a per-action bound; writes are bounded too. Default `max_artifact_bytes` is 10 MiB and `max_action_bytes` is 65,536 bytes. API bodies are capped at 15 MiB; CLI artifact inspection is capped at 10 MiB. | Check `/api/system` for the configured artifact/action limits. Send smaller inputs; do not increase limits by assuming the TSE fields dynamically override service configuration. |
| HTTP 413 for artifact upload | Request exceeds the 15 MiB request-body limit. | Reduce the upload. The CLI inspection limit is 10 MiB, and the artifact model also bounds encoded input. |
| Audit verification reports `valid: false` | An event payload, ordering, previous-hash link, or event hash did not verify. | Preserve the DB and any WAL state, save the verification response, and investigate using a protected copy. Do not edit/re-hash the original as a “repair.” Task issuance, approvals, inspection, and lab are disabled on detected audit failure; gateway actions do not invoke an adapter. Task revocation is still exposed, but does not repair the chain. |
| Lab returns HTTP 503 due to audit integrity | The lab refuses to run when audit verification is invalid. | Preserve and investigate the audit state first; there is no built-in audit repair workflow. |
| Lab report has failed scenarios or unexpected outcomes | The report compares actual outcomes with listed synthetic expectations; this is not proof of a general attack rate. | Inspect each scenario, decision ID, expected/actual result, status and limitations. Lab data/workspace/audit records are retained; it is not an isolated code-execution environment. |
| Several workers or duplicate service instances disagree | Per-task locks are process-local. | Run one worker for supported coordination. SQLite transactions protect selected claims, not cross-process task locks. Multi-process locking is not implemented. |

## Current command reference

Use `blackice --help` and `blackice task --help` for the CLI parser. Current documented commands include:

```bash
blackice health
blackice task create --agent example-agent
blackice task create --agent example-agent --allow-write --require-write-approval
blackice task inspect TASK_ID
blackice task revoke TASK_ID
blackice inspect ./sample.html
blackice decisions --task TASK_ID
blackice audit --verify
blackice audit --limit 100
blackice export ./audit-export.json
blackice lab
blackice lab --export ./lab-report.json
```

`--require-write-approval` requires `--allow-write`; task expiry is 60–3600 seconds, default 3600. The task-create CLI does not expose every API field such as custom paths or `max_actions`. The API supports operator approval, but the CLI does not currently offer an approval command. Audit and lab exports must target new files; existing files are preserved. Audit export is limited to the latest 200 events available through the API.

## Relevant API routes

All `/api/*` routes below except `/api/health` and `/api/healthz` require an operator bearer credential unless specifically noted as an agent route.

- Public status: `GET /api/health`, `GET /api/healthz`.
- Operator status/config view: `GET /api/system`, `GET /api/overview`, `GET /api/policy`.
- Tasks: `POST /api/tasks`, `GET /api/tasks`, `GET /api/tasks/{task_id}`, `POST /api/tasks/{task_id}/revoke`.
- Approval: `POST /api/decisions/{decision_id}/approve` (no request body required); only a `REVIEW` decision for an active, unexpired task qualifies.
- Decisions/audit: `GET /api/decisions`, `GET /api/decisions/{decision_id}`, `GET /api/audit/events`, `GET /api/audit/verify`, `GET /api/incidents`.
- Artifacts/lab: `POST /api/artifacts/inspect`, `GET /api/artifacts/inspections`, `POST /api/lab/run`.
- Agent routes use the task bearer token: `GET /api/agent/tasks/{task_id}/envelope`, `/status`, `/decisions`, and `POST /api/agent/tasks/{task_id}/actions`.

Most list routes clamp their result limits; audit events and tasks are bounded. `/api/incidents` is not a full incident manager: it scans only a recent bounded audit window and filters selected deny/review/revocation events.

## Test commands

To run the repository checks without assuming their outcome:

```bash
uv run pytest
uv run ruff check src tests
```

Relevant test files are `tests/test_api.py`, `tests/test_workspace.py`, `tests/test_models_crypto.py`, and `tests/test_mcp.py`. A test result applies only to the run actually performed; these synthetic tests are not a penetration test or proof of containment.
