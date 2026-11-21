# Incident response and recovery

## Scope

BLACK ICE currently provides operator views, local audit-integrity verification, and task-scoped revocation. It does **not** implement a full incident manager, incident lifecycle, severity/triage workflow, automated containment orchestration, process termination, or an independent kill switch. The `/api/incidents` endpoint is a small projection of recent audit events, not a complete incident record or alerting system.

This guide describes a cautious operator procedure using the existing controls. It is not a claim that BLACK ICE can contain an agent or host compromise. If an agent has shell, network, or other execution paths outside the gateway, use the controls in that execution environment; BLACK ICE cannot see or stop bypass activity.

## Operator procedure

1. **Check service and audit state.** Query the public health endpoint or use `blackice health`. For operator-authenticated detail, use `GET /api/system`, `GET /api/overview`, and `GET /api/audit/verify`. A healthy audit response reports `valid: true`; verification also returns event counts, the first invalid sequence (if any), and the currently verified head hash. Health can report a restricted service when signing/operator configuration is unavailable or audit verification fails.
2. **Review available evidence.** Use `GET /api/decisions?task_id=<id>` and `GET /api/audit/events?limit=<n>` (the API clamps event listings to 200) or the corresponding CLI commands `blackice decisions --task <id>` and `blackice audit --verify`. `GET /api/incidents` returns at most the latest 200 audit events filtered to `DENY`, `REVIEW`, and `task_revoked`; it does not include every failed execution, alert, or event type. Event/decision data is deliberately selective and does not preserve arbitrary action parameters or file contents.
3. **Revoke a task when appropriate.** The operator-only `POST /api/tasks/{task_id}/revoke` endpoint (or `blackice task revoke <task-id>`) re-signs the task envelope with `revocation_state` and `task_state` set to `REVOKED`, and appends a `task_revoked` audit event. Subsequent actions routed through ICE-GATE are denied. The call is idempotent for an already-revoked task. Revocation does not terminate a running process, invalidate unrelated credentials, or stop direct/bypass actions. It is not a global stop operation.
4. **Preserve evidence before maintenance.** The `blackice export <new-path>` command writes a new private JSON file containing the latest audit events available through the endpoint (up to 200), refusing to overwrite an existing destination. This is a limited event export, not a database backup or independent immutable copy. For broader preservation, use an operator-controlled, access-restricted backup procedure appropriate for SQLite; preserve the database and any associated WAL state consistently, and retain the original files. Avoid modifying the only copy while investigating.
5. **Verify after a response action.** Re-run `blackice audit --verify` and inspect the task with `blackice task inspect <task-id>` or `GET /api/tasks/{task_id}`. Confirm the envelope state is revoked and record the verification response alongside preserved evidence. An audit chain can verify as valid without proving that all events are present or that the host was not compromised.

Example sequence (with a running local service and a private `.env` loaded):

```bash
blackice health
blackice audit --verify
blackice decisions --task TASK_ID
blackice export ./incident-audit.json
blackice task revoke TASK_ID
blackice task inspect TASK_ID
blackice audit --verify
```

The CLI's `export` destination must be a new file. It creates the file with mode `0600`; choose a protected directory and handle the export as sensitive evidence.

## Revocation and recovery semantics

Revocation blocks **future gateway-mediated** operations because policy checks the newly signed envelope. It does not roll back an operation already completed, terminate work already running elsewhere, or prevent use of alternate tools. There is no task-unrevoke endpoint. Issue a new task with an appropriately narrow scope after review rather than attempting to edit a TSE or database record manually.

Audit verification recomputes the sequential SHA-256 links over locally stored event content and ordering. It detects edits that leave the chain unrecomputed, and the gate refuses adapter execution when verification is invalid. Task issuance, approvals, artifact inspection, and synthetic-lab invocation also check audit health and are disabled when invalid. This is tamper evidence, not immutable logging: a privileged host/database writer can alter the database and recompute the chain, and there is no external witness or remote audit sink.

There is no application repair/rebuild command for an invalid audit chain. Preserve the database and verification output, investigate the cause, and restore only through a separately controlled backup/recovery process. Do not silently delete, truncate, or recompute events and then describe the result as verified historical evidence. The task-revocation route itself does not require a healthy audit check; if called while the chain is already invalid, it may update the task and append an event, but that does **not** repair the earlier integrity failure. Continue to treat the audit as invalid until an independently justified recovery has been performed and verified.

Operator approval is a narrow action control, not incident containment. A `REVIEW` decision may be approved only for an active, unexpired task; the generated token is bound to the request digest, expires after five minutes, is stored hashed, and is consumed transactionally once. No separate approval cancellation workflow is implemented. Revoking the task prevents subsequent task actions but does not undo prior effects.

## Limits of the current incident view

- `/api/incidents` scans only a bounded recent audit window and applies a simple event filter; it has no severity, owner, status, notes, evidence attachments, acknowledgement, or response timeline.
- `/api/graph` is a bounded projection from audit events, not complete lineage or incident reconstruction.
- Audit records are local and tamper-evident only against edits that do not rebuild the chain. There is no remote immutable copy, external alerting, or independent monitor.
- Locks are process-local; concurrent service processes are not a supported coordinated response configuration.
- The synthetic lab is not incident simulation. It writes retained synthetic data and measures only its listed cases; it does not validate real-world response effectiveness.

## Relevant endpoints and commands

Operator endpoints require `Authorization: Bearer $BLACKICE_ADMIN_TOKEN`:

| Purpose | Endpoint / command |
|---|---|
| Service health | `GET /api/health` / `blackice health` |
| Operator status | `GET /api/system`, `GET /api/overview` |
| Recent decisions | `GET /api/decisions` / `blackice decisions` |
| Filtered recent incident events | `GET /api/incidents` |
| Recent audit events | `GET /api/audit/events` / `blackice audit` |
| Verify audit chain | `GET /api/audit/verify` / `blackice audit --verify` |
| Inspect/revoke task | `GET /api/tasks/{task_id}`, `POST /api/tasks/{task_id}/revoke` / `blackice task inspect|revoke` |
| Limited event export | `blackice export <new-private-file>` |
