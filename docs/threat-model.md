# BLACK ICE threat model

## Purpose and security claim

BLACK ICE is a local, single-process control plane for a limited set of agent actions. Its defensible claim is narrow: **when an action is submitted through the configured API/gateway, the current registered filesystem and artifact adapters are subject to task-scoped checks and fixed default-deny rules.** It does not claim to contain arbitrary code, prevent every prompt injection, inspect every representation, track every flow of data, or stop paths that bypass ICE-GATE.

The system is early-stage software. The threat model is a design and implementation statement, not a security audit or certification. Test statuses below refer to tests in this repository; passing synthetic tests are not proof of field effectiveness.

## Assets

- Integrity and scope of each task envelope, its authorization decisions, and approval state.
- Agent task token, operator bearer token, and envelope-signing key.
- Files and contents in per-task workspaces, including synthetic or user-provided secrets.
- Artifact originals, extracted representations, inspection findings, and provenance supplied by callers.
- Action decisions, policy explanations, approvals, revocation events, and audit-chain state.
- Availability and correct behavior of the service, workspace adapter, parsers, SQLite database, and operator interface.

## Principals and trust boundaries

| Boundary | Trust assumption / control | Residual risk |
|---|---|---|
| Agent → API/gateway | Agent input is untrusted; action identity is checked against a signed envelope and task-token hash. | Agent can use any alternate path available in its runtime; BLACK ICE cannot see actions it does not receive. Task-token theft permits attempts within that task’s scope. |
| Artifact, repository, website, or tool output → inspection/agent | Inputs are untrusted; bounded parser output and suspicious findings are not authorization. | Heuristic inspection can miss instruction-like, encoded, rendered, multimodal, or transformed content. Derived text may not capture original meaning. |
| API → tool registry | Policy must allow exact structured operation and registry must contain it; unregistered command/network tools are denied. | This protects only registered gateway operations; it does not mediate direct OS, browser, API, or agent-framework capabilities. |
| Workspace adapter → host files | Adapter accepts relative paths under a generated workspace and uses no-follow opens; read/write size limits apply. | Same service process and host administrator can access configured roots. No process/container boundary protects the host from arbitrary code because arbitrary code is not run by this adapter. |
| Operator → management endpoints | Separate bearer token is required for task creation, approvals, revocation, audit and artifact management. | No multi-user identity system, role model, MFA, token rotation protocol, or remote transport encryption is supplied by this code. A leaked operator token is powerful. |
| Service → signing key and database | HMAC signature protects envelope integrity against parties lacking the key; SQLite stores agent-token hashes and transactionally tracks approvals/action counts. | Service process, host root, database writer, or signing-key holder can alter state. HMAC key is shared application configuration, not HSM-managed. |
| Audit database → verifier | Sequential SHA-256 hash links detect changes to existing event content/ordering when not recomputed. | A privileged writer can alter events and recompute subsequent hashes. No independent external anchor makes the audit immutable. |
| Operator approval → protected action | A five-minute, one-use approval binds to task ID and a digest of the request (excluding approval token itself). | Approval is only as trustworthy as operator-token security and the exact data presented to the operator. Approval does not make an otherwise unsupported operation executable. |
| Process concurrency → state | Per-task in-process locks and SQLite transactional claims provide local serialization. | Process-local locks do not coordinate multiple workers or hosts; multi-process-safe deployment is not implemented. |

## Adversary capabilities considered

The intended adversary may control or manipulate an agent; supply malicious task inputs, repository files, HTML, text, source, image, PDF, archive, office document, or tool output; attempt to expand task scope; submit malformed or oversized requests; request path traversal or restricted paths; replay or misuse an approval; request unregistered commands or outbound transfers; attempt policy/control-plane changes; and exploit incomplete parsers or detector gaps.

The implementation assumes the host, Python runtime, installed dependencies, service process, operator credentials, signing key, and local database file are not already fully compromised. Compromise of those components is outside the protection boundary and can defeat or disable the service.

## Security objectives and current treatment

- **Authority separation:** external content and agent-provided claims do not modify the TSE or policy. Policy evaluates the authenticated request and signed envelope; it does not use an agent risk score. Implemented for gateway decisions, tested for selected cases.
- **Task scope:** identity, active/revocation/expiry, registered capability, paths, filesystem operations, approval requirements, and action budget are checked by the gateway/policy. Tested for representative path/operation cases; not every model field is enforced.
- **Restricted resources:** default task creation includes sensitive path patterns (e.g., `.env`, credential directories, key filenames); traversal, absolute paths, and symlink escapes are blocked by the workspace adapter. Tested for representative cases. This does not protect secrets outside adapter access or guarantee every filename convention is covered.
- **No arbitrary execution/network in initial runtime:** no shell/command or network adapter is registered, and destinations are denied. Tested that registry lacks shell/network and an unregistered command fails. This is not a host firewall or protection against bypass.
- **Data exposure:** known credential-like patterns and email addresses are detected/redacted from text reads and inspection output. Tested with synthetic strings. This is narrow pattern matching; it is not general PII/secret detection or complete data-flow control.
- **Artifact inspection:** parser caps, unsupported/partial status, Unicode format-control checks, deterministic instruction-pattern checks, and several hidden-content indicators make gaps visible. Selected HTML, DOCX, XLSX, archive, unsupported-format cases are tested. Coverage is format-specific and incomplete; see [architecture](architecture.md).
- **Fail closed:** missing signing configuration prevents protected runtime operations; invalid credentials, envelope signatures, expired/revoked tasks, tampered audit, missing registration, out-of-scope paths and invalid approvals do not run an adapter. API and gate tests cover selected failure paths. Parser failures return partial/inconclusive results rather than a safe verdict. There is no general service-failure harness proving all possible database/OS/parser exceptions are safely handled.
- **Revocation:** operator re-signs a task envelope with revoked state; subsequent gateway actions are denied. The synthetic lab includes a revocation scenario. Revocation does not terminate a process or affect direct/bypass actions.
- **Observability:** decisions and audit events record selected identities, operation, resource, rules, reason, outcome and execution summary. Arbitrary request parameters, action content, and claimed risk are intentionally not copied to decision detail/audit. Logs are hash-linked but locally mutable; audit verification is tested against a modified payload.

## Threat scenarios and disposition

| Scenario | Existing control | Status / residual |
|---|---|---|
| Hidden prompt injection tries to override authority | Artifact parser heuristics can flag some hidden/instruction patterns; artifact contents never enter policy as authorization | Partial detection only; tests cover a synthetic hidden HTML phrase. Do not treat absence of a finding as safety. |
| Agent asks to change policy, disable controls, or access command/network tool | Protected control-plane operation heuristic and absent tool registrations; default deny | Fixed operation names and registry; not protection if the agent has an independent shell/network path. |
| Agent reads a secret-looking file then tries to send it | Restricted-path defaults, regex redaction, limited sequence indicator, and all destination requests denied | Egress is structurally unavailable through current adapter; content detection and history-based sequence analysis are incomplete. |
| Traversal or symlink read escapes task workspace | Relative path normalization, directory-fd traversal, `O_NOFOLLOW`, regular-file check | Representative traversal/symlink tests pass. No claim against kernel/filesystem vulnerabilities or compromised service process. |
| Malformed or oversized artifact exhausts resources | Request/artifact limits, bounded representation/XML/archive/image budgets, unsupported/partial result | Not isolated parser execution; DoS resilience beyond configured bounds is unverified. Parser dependencies remain in-process. |
| Replay or cross-task approval | Random approval token, hash stored, task and request-digest binding, expiry, one-time transactional consumption | API test covers one-use and mismatched/replay behavior. Operator account compromise remains in scope. |
| Audit record alteration | Hash-link verification blocks task issuance and action side effects after detected tampering | Local privileged actor can rewrite and recompute the chain. Not immutable logging. |
| Policy-service or signing failure | Missing/invalid signing service yields restricted readiness; gate verifies envelope and audit before adapter | No separate policy service exists; failure modes of all storage/runtime faults have not been exhaustively tested. |
| Multi-step action abuse | Small transparent analyzer tracks some prior gateway decisions | Only a few exact patterns and up to 100 recent decisions are used; no general action graph/behavior model. |
| Delegation authority expansion | Empty delegation permissions and no delegation adapter | No delegation system exists; this is absence of capability, not complete delegation policy enforcement. |
| Agent disables enforcement or response control | Agent token cannot reach operator management endpoints; agent actions do not expose security-control operations | Same-process service can be stopped by host/admin; no independent kill switch or protected-process supervision. |
| Malicious package, build script, shell payload | No command execution or dependency-install adapter | Such code is not sandboxed or validated here. Do not use BLACK ICE as a shell/code runner. |

## Security invariants and evidence status

The authoritative project prompt lists fourteen invariants. This table records the closest current implementation and its evidence; “partial” is not a claim that the invariant is fully achieved.

| Invariant | Current status | Evidence |
|---|---|---|
| 1. External content cannot grant authority | **Implemented at the gateway boundary; not generally proven** | Artifact data has no policy-authoring route; policy reads TSE/action fields. `tests/test_vision.py` detects a synthetic hidden injection; `tests/test_api.py` checks extraction/redaction. |
| 2. Agent instructions cannot directly override policy | **Implemented for exposed operations** | No agent policy mutation route/tool; policy view is operator-only and static. No test that exhaustively explores all API/control paths. |
| 3. Task scope is independently enforced | **Implemented for registered adapters, partial overall** | Signed TSE, identity/scope checks and workspace adapter; API tests cover read/write/path denials. Bypass paths are out of boundary. |
| 4. Restricted actions need more than agent claims | **Implemented for current registry** | Tool registry/policy requires registration and TSE scope. No arbitrary shell/network adapter exists. |
| 5. Credentials are not automatically inherited from host | **Not established for a hostile execution runtime** | No arbitrary execution runtime exists. Agent token is task-specific, stored hashed. No host credential inheritance path to test. |
| 6. Delegation cannot silently expand authority | **Partial / no delegation implementation** | TSE defaults delegation permissions empty; delegation adapter absent. No delegation protocol. |
| 7. Outbound transfers are controlled | **Restricted by absence** | Destination request is denied and no network adapter is registered. Not an OS/network egress control. |
| 8. Inspection limitations are recorded | **Implemented for inspector result** | `ArtifactInspection` contains status, coverage, discrepancies, uncertainty and limitations; parsers mark unsupported/incomplete inputs. |
| 9. Decisions independently observable | **Implemented for gateway events, local store only** | SQLite decision/audit APIs and tests for tamper detection; not independent remote monitoring. |
| 10. Agent cannot silently disable enforcement | **Partial within exposed API** | Agent routes expose task-scoped reads/actions only. No separate hardened service/process or bypass protection. |
| 11. Security-critical actions auditable | **Implemented with local tamper evidence** | Task issue, decisions, approvals, adapter outcomes and revocation append events; local DB can be rewritten. |
| 12. Policy changes require independently authorized operations | **No policy authoring exists** | Fixed policy `v1`, operator-only read view; no policy-change API or authoring workflow. |
| 13. Revocation independent of agent cooperation | **Implemented for later gateway actions** | Operator revoke updates and re-signs envelope; tests/lab exercise subsequent denial. Does not stop already-running or bypass activity. |
| 14. Enforcement unavailability is not unrestricted execution | **Implemented in supported client paths, partial overall** | Missing signing key/service returns restricted/failure; SDK error says do not bypass; no fallback adapter. Not proof about external agent orchestration. |

## Explicit non-claims

BLACK ICE does **not** currently provide arbitrary code/shell/network isolation, a container/VM sandbox, host-wide credential isolation, a real response kill switch, immutable audit, complete taint tracking, configurable policy authoring, comprehensive ICE-CHAIN analysis, full MCP operator coverage, guaranteed prompt-injection detection, complete OCR/rendering comparison, or comprehensive adversarial validation. No external security audit or certification is claimed.

## Validation evidence

On 2026-11-21, `.venv/bin/pytest -q` completed with **24 passed, 1 deprecation warning**. This is a point-in-time repository test run. The suite uses synthetic fixtures and representative unit/API cases. It does not establish real-world attack prevention, false-positive/negative rates, cross-process correctness, full service-failure resilience, or safe handling of every parser input.
