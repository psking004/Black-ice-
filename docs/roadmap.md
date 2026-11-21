# Roadmap

This roadmap records future work, not delivered functionality. The existing gateway, filesystem adapter, revocation endpoint, local audit verifier, approval path, and synthetic lab are documented elsewhere as implemented at their current limited scope. Listing an improvement here does not imply it exists or is complete. Priorities follow the project's stated security objectives: establish a real execution boundary before enabling code execution, then make response/recovery and evidence reliable, then expand enforcement, integration, validation, and operations.

## 1. Define a real controlled-execution boundary before running untrusted code

**Planned; not implemented.** Design and validate an execution architecture that isolates hostile repository/package code from the BLACK ICE control plane and host. Establish threat assumptions and containment criteria before exposing any code-execution adapter. The design must address filesystem and credential separation, network/egress restrictions, CPU/memory/process/disk/time limits, process supervision/termination, safe artifact exchange, evidence preservation, cleanup, and escape/failure testing. Do not treat the current `WorkspaceAdapter`, a denied command request, or an unreviewed container configuration as this boundary. Until a separately validated design exists, keep arbitrary command/build/test/install execution unavailable.

## 2. Build response and recovery workflows beyond task revocation

**Planned; not implemented.** Extend today's per-task revocation into authorized, auditable incident response with incident identity, severity/evidence/confidence, status/owner, response history, and recovery verification. Investigate proportionate containment controls only where the execution architecture can support them. Add process termination/isolation and an independently accessible kill switch only after safe process ownership, authorization, audit, and recovery semantics are designed. Preserve evidence and avoid destructive cleanup. No current feature terminates an agent or process, and `/api/incidents` is only a bounded audit-event projection.

## 3. Strengthen audit durability and recovery

**Planned; not implemented.** Add an independently protected/external audit witness or sink and a documented backup/restore/recovery procedure. Define what to do after failed chain verification, how to preserve database/WAL evidence, and how restored state is authenticated without concealing a prior integrity failure. Add operational health checks and failure tests. The current SQLite SHA-256 chain is local and tamper-evident, not immutable; no automatic repair or external witness exists.

## 4. Complete approval lifecycle and operator workflow

**Planned; not implemented.** Provide an operator-facing approval/review workflow with a clear exact-action preview, audit verification, rejection/expiry/cancellation handling, and safer token delivery. Keep approvals task- and request-digest-bound, time-limited, one-use, and unable to expand task scope. Add CLI/MCP support only with explicit operator authorization and tests. Today, the API can issue a five-minute single-use approval for an eligible recorded `REVIEW`; the CLI has no approval command, and there is no separate cancellation workflow.

## 5. Replace process-local coordination before scaling

**Planned; not implemented.** Introduce tested shared locking/coordination and deployment-safe database transaction patterns for multiple workers/processes. Verify revocation races, task budget claims, approval consumption, and side-effect ordering across workers. Until this is designed and validated, keep the supported service coordination model to one worker. SQLite transactions cover selected operations but do not replace cross-process locks.

## 6. Improve data-flow evidence and sequence analysis

**Planned; not implemented.** Expand ICE-FLOW/TRACE/CHAIN into explicit, queryable provenance and transformation evidence with clearly defined coverage. Evaluate more useful deterministic sequence rules and document their false-positive/false-negative limits. Design dynamic taint tracking only where actual runtime instrumentation can support it. Do not label the current regex classifier, recent-decision summaries, or `/api/graph` projection as complete lineage. Dynamic taint tracking and generalized data-flow enforcement are absent.

## 7. Expand lab coverage and validation evidence

**Planned; not implemented.** Extend the synthetic lab with bounded, reproducible scenarios for service/parser/resource failures, audit failures, action sequences, authorization boundaries, revocation races, and legitimate task completion. Keep hostile repository scripts inert unless and until the execution boundary in item 1 exists and has been approved and validated. Separate prevention from detection, report scenario-level evidence and limitations, avoid fabricating rates, and establish false-positive/false-denial measurements only from a suitable corpus. Today's lab runs a small set of synthetic gateway and inspection cases, retains synthetic workspaces/audit events, and explicitly does not provide real-world validation.

## 8. Continue inspection and integration work with explicit gaps

**Planned; not implemented.** Expand supported formats and representation comparisons only with bounded parsers and tests; improve handling of hidden/embedded content, OCR/rendered representations, Unicode/encoding anomalies, archive hazards, and parser failures. Improve SDK/MCP/operator workflow coverage, installation/configuration checks, and security observability. Record unsupported or partial formats as such rather than presenting inspection as a safety verdict. None of this work should imply complete prompt-injection detection, full document rendering comparison, universal secret discovery, or protection of paths outside the gateway.

## 9. Validate each security claim and maintain operational documentation

**Planned; not implemented.** For each future change, connect an explicit claim to source, a targeted test, failure behavior, and stated limitation. Add cross-process, recovery, host-boundary, and failure-injection tests where the design supports them; perform appropriately authorized security review before representing a new boundary as effective. Maintain status and roadmap documents based on observed implementation and actual runs. No certification or comprehensive security audit is implied by the current repository tests.
