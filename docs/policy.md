# ICE-POLICY: decision logic and failure behavior

## Policy model

The current policy engine is a small deterministic Python evaluator (`src/blackice/policy.py`), version `v1`. It is not OPA, Rego, a remote policy service, a user-configurable policy language, or a policy studio. The operator API exposes a read-only summary of rules. Agent requests cannot edit the evaluator or the signed task envelope.

The evaluator receives a structured action request, a verified task envelope, a bounded list of prior gateway decisions, and (only when re-evaluating a matching approval) an `approved` flag. It combines a registered-operation allowlist with default-deny checks and the task’s explicit scope. It does not trust an agent-supplied risk score; there is no risk-score field used to grant authorization.

## Decision outcomes

| Outcome | Meaning in current implementation |
|---|---|
| `ALLOW` | Request satisfied identity, task, capability, registration, applicable scope and approval checks; ICE-GATE attempts the registered adapter. This is authorization to attempt that adapter, not proof the operation completed. |
| `DENY` | A prerequisite or policy rule failed. ICE-GATE does not call the adapter. For untrusted credentials, unknown tasks, invalid TSE signatures, or audit failure, the gateway records a denial audit event without storing a normal task decision row. |
| `REVIEW` | This exact operation is listed in `approval_requirements` and no valid matching approval was consumed. No adapter call occurs. An operator can approve the recorded review decision. |
| `RESTRICT` | In the current flow, an allowed read/inspection returned content for which the deterministic redactor found sensitive patterns. The operation may have executed, but the agent-visible result has been redacted and the decision is marked restricted. This is not equivalent to a pre-execution denial. |

A successful policy `ALLOW` is recorded before the adapter side effect with a pending execution status. The subsequent adapter result/failure is then recorded. This prevents a crash after authorization from making an attempted side effect invisible, although it can leave a pending status if the process stops before the second write.

## Evaluation and precedence

The implementation checks conditions in this order; the first failed authorization condition returns a denial/review as applicable:

1. **Request identity:** `task_id` and `agent_id` must match the envelope.
2. **Task state:** task must be active and not revoked; its expiry time must be in the future.
3. **Capability consistency:** `requested_capability` must exactly equal `<tool_id>.<operation>`.
4. **Destination:** any non-null destination is denied in this runtime. No network adapter or allowed-destination configuration exists.
5. **Selected action-chain rules:** selected protected sequences/actions are denied (details below).
6. **Operation registration:** tool and operation must appear in the actual `ToolRegistry` operation map.
7. **Tool scope:** tool ID must be in `permitted_tools` for the TSE.
8. **Filesystem/artifact scope:** path must normalize to a relative path, must not match restricted patterns, and must match the permitted path rules. Filesystem operations must also be listed in `permitted_filesystem_operations`. Unsupported tool types are denied.
9. **Approval:** if exact `<tool_id>.<operation>` appears in `approval_requirements`, the default result is `REVIEW`; a previously issued, valid approval may permit re-evaluation and allow execution.
10. **Adapter execution:** only after policy `ALLOW` does ICE-GATE call the registered tool adapter.

The envelope’s path rules use POSIX relative paths and glob matching (`fnmatch`). A literal permitted directory also permits its descendants. The `.` permitted-path rule allows any normalized relative path, but matching restricted paths take precedence. The adapter performs its own path validation and no-follow file operations as a second boundary.

## Current fixed rules

| Rule / behavior | Effect | Notes |
|---|---|---|
| Valid task credential, signed TSE and matching identity | Deny if not satisfied | Checked by gate before policy evaluation. Envelope signature uses configured HMAC key. |
| Active, unexpired, unrevoked task | Deny if not satisfied | Timestamp checked on each action. Revoked envelope is re-signed by operator endpoint. |
| Registered tool and operation | Deny if absent | Current tools: `filesystem` (`list`, `read`, `write`, `mkdir`) and, when inspector is configured, `artifact` (`inspect`). No `command`/shell or network tool. |
| TSE capability and path scope | Deny if out of scope | Restricted paths override permitted paths. Filesystem operation is also checked against TSE list. Artifact inspection path is checked against permitted/restricted paths; it uses a workspace file. |
| Network/destination | Deny | `NetworkPolicy` validation accepts only `mode="deny"`, empty destinations; any request with a destination is denied. |
| Sensitive-read then outbound attempt | Deny sequence | Analyzer checks recent decision details for a prior credential-classified `read`; however, the destination rule already denies every destination. The sequence signal is a supplementary explanation, not the egress boundary. |
| Agent-requested control-plane change | Deny | Exact operation set includes `change_policy`, `disable_security`, `disable_logging`; no such adapters are registered either. |
| Delegation create | Deny sequence | Indicator says delegation requires explicit non-expanding policy and evaluator denies it. There is no implemented delegation adapter/protocol. |
| Repeated sensitive restricted attempts | Indicator only | Two or more prior DENY/RESTRICT decisions for selected tool IDs add an indicator; this indicator alone does not currently force a denial of an otherwise permitted action. |
| Approval requirement | Review, then possible allow | Approval only applies to exact `tool.operation` named in signed TSE and only after all other checks pass. |
| Known credential/PII in read or inspection output | Restrict result after adapter call | Regex-based classifier/redactor covers selected credentials/tokens/private-key patterns and email addresses. Output content is replaced, and result is marked `RESTRICT`; this is not general DLP. |
| Audit-chain verification | Deny before adapter if invalid | Gate checks audit verification before action-budget claim/policy/adapter execution. Task issue, approvals, artifact upload and lab API also check audit health where implemented. |
| Action budget | Deny if exhausted | SQLite transaction atomically claims an action count before policy evaluation. Requests that reach this point can consume a count even when later denied or reviewed. |

`GET /api/policy` returns a static operator-visible description, including `mutable_from_agent: false`. This endpoint is documentation/observability, not the source of a separately loaded or configurable rule bundle.

## Operator approval protocol

When a request requires approval, ICE-GATE records `REVIEW` without executing it. An operator-only approval endpoint accepts only a recorded `REVIEW` decision for a still-active, unexpired task and issues a random token valid for five minutes. The database stores a hash of that token and binds it to the decision, task, and action request digest. The digest is computed over the structured request excluding the `approval_id` field. On later action submission, consumption is transactional and one-use; missing, expired, already-consumed, wrong-task, or wrong-digest token remains `REVIEW`. A valid approval is consumed before policy re-evaluation and adapter call.

Approval authorizes only the matching operation digest; it cannot authorize a different path/content/operation, bypass unregistered-tool denial, expand the TSE, or enable network/shell actions. The API test suite covers required review, operator approval, successful one-use execution, replay rejection, and audit recording.

## Failure behavior and fail-closed limits

- **Missing signing key / invalid signing-key length:** application starts restricted; protected operations require runtime and return unavailable rather than execute without verified TSEs.
- **Invalid/missing agent token or unknown task:** deny; no adapter side effect.
- **Envelope missing or signature/validation failure:** deny; no adapter side effect.
- **Audit integrity failure:** deny gateway action before adapter; task issuance, approvals, artifact inspection, and lab invocation are also disabled by health checks. Integrity verification is local hash-chain verification, not protection from a privileged editor who rebuilds the chain.
- **Expired or revoked task:** deny future gateway actions. No process termination or bypass revocation is available.
- **Out-of-scope path, traversal, restricted path, unregistered tool/operation:** deny. Workspace adapter rejects absolute/traversal paths, symlink traversal, non-regular files, and configured size-limit excesses.
- **Missing/invalid approval:** remain `REVIEW`; no adapter call.
- **Adapter/parser failure:** ordinary filesystem adapter exceptions caught by the gate are recorded as failed execution and no result is returned. Artifact parser failures normally produce a `partial`/inconclusive report with limitations rather than a safe clearance. This is not a separate process-isolation boundary, and not every possible exception or resource-exhaustion condition is proven safe.
- **Unavailable API from SDK/CLI:** client reports failure and instructs not to bypass BLACK ICE; the client itself does not fall back to direct tool access. Other orchestration systems must enforce the same no-bypass rule independently.
- **Multi-worker deployment:** task locks are process-local, so the supported state coordination assumes one worker. Cross-process locking is not implemented; do not treat it as safe for horizontally scaled workers.

## Incomplete or non-enforced policy attributes

Although the TSE schema carries them, current policy does not implement command-class authorization, per-task execution timeout enforcement, broad data-classification policies, destination allowlists, or delegation issuance. `data_classification` supplied by the agent is logged as an agent claim, not an authorization fact. Read results are classified by fixed deterministic regexes, which can miss secrets and can match benign text. No dynamic taint tracking propagates sensitivity across arbitrary transformations. No general policy authoring/testing/version activation workflow exists.

## Validation evidence

`tests/test_api.py` exercises representative scoped allow/deny, path traversal, default restricted credential paths, secret/email redaction, approval, audit tampering, missing/weak operator credentials, and request-size limits. `tests/test_workspace.py` tests no-follow path behavior, bounded atomic writes, and absent shell/network adapters. `tests/test_models_crypto.py` covers stable/tamper-sensitive HMAC and request/provenance bounds. `tests/test_vision.py` covers selected parser scenarios. The current run on 2026-11-21 was `.venv/bin/pytest -q`: **24 passed, 1 warning**. This small synthetic suite does not measure policy false-positive/negative rates, establish comprehensive failure handling, or validate real-world containment.
