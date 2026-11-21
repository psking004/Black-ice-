# BLACK ICE — Implementation Plan

## Mission and boundaries

BLACK ICE is a local-first control plane that mediates structured AI-agent tool requests. A request to act is not permission to act. Authority comes from a signed, time-limited Task Security Envelope (TSE), independently evaluated policy, current revocation state, and a registered adapter. External artifacts and tool responses are data, never policy authority. This implementation will be explicit about which boundary is enforced and which protections are only modeled or planned.

Initial deployment is a single-process FastAPI service with SQLite, a React/TypeScript security console, a CLI/SDK, and reproducible synthetic tests. The project will not provision a managed database, run hostile repository code on the host, expose arbitrary shell execution, or claim protection of tools that bypass the gateway. High-risk actions stay denied unless a real, separately authorized adapter exists. Missing keys, stale/revoked envelopes, policy errors, or uncertain resource scope fail closed for protected operations.

## Architecture

- **ICE-GATE:** sole dispatch path for protected tool operations; validates identity, task, expiry, revocation, capability, resource scope, data/destination restrictions, approvals, and sequence rules before calling an adapter.
- **ICE-POLICY:** deterministic default-deny evaluator with explanations and versioned policy decisions.
- **TSE:** Pydantic task model with canonical serialization and HMAC integrity check; scoped, expiring, revocable and non-expanding delegation metadata. Signing key is externally supplied; no hardcoded production key.
- **ICE-SANDBOX:** safe workspace-scoped filesystem operations and bounded resource limits. No arbitrary shell, package installation, network client, Docker socket, or host-secret inheritance in the initial build. This is a restricted adapter, not hostile-code isolation.
- **ICE-VISION:** bounded, non-executing parsers for supported formats; hashes original bytes; records representations, hidden-content indicators, discrepancies, coverage, uncertainty and limitations. Unsupported or incomplete extraction remains visibly incomplete.
- **ICE-TRACE / ICE-FLOW / ICE-CHAIN:** provenance records and deterministic sequence/data-classification rules for available operations. No claim of perfect taint tracking.
- **ICE-AUDIT:** SQLite-backed append-only-by-interface hash chain with verification. This detects modifications to linked rows but is not immutable storage against a privileged host/database operator.
- **ICE-RESPONSE:** independently callable task revocation/containment APIs, audit evidence retention, and safe recovery metadata; no destructive cleanup.
- **ICE-LAB:** synthetic attack and legitimate-task scenarios that report measured outcomes from the actual tested gateway.
- **API/UI/CLI/SDK:** FastAPI endpoints, React/TypeScript console backed only by the API, validated command-line workflows, and a minimal Python SDK.

### Main project structure

```text
blackice/
  api/                 FastAPI application, authentication, request/response schemas
  core/                TSE, policy, gate, tools, audit, provenance, chain, flow, response
  vision/              bounded format handlers and inspection models
  sandbox/             workspace-scoped file adapter and execution limits
  cli/                 operator CLI
  sdk/                 custom-agent client
  storage/              SQLite repositories and schema initialization
frontend/               React + TypeScript console, API client, real status/action views
public/                 route manifest and brand mark
policies/               versioned default policy
scenarios/              synthetic ICE-LAB fixtures
 tests/                  unit, API, integration and adversarial tests
 docs/                   threat model, architecture, TSE, integration and limitation guides
```

## Implementation sequence

1. Establish threat model, invariants, data model, project configuration, status documents and CI.
2. Implement canonical signed TSEs, identity and revocation storage, versioned default-deny policy, action gateway and a minimal allowlisted workspace adapter.
3. Implement structured audit hashing, provenance, deterministic action-chain rules, incident/revocation paths, and safe data classification.
4. Implement bounded non-executing artifact inspection for supported formats, preserving original artifacts and structured extraction gaps.
5. Add CLI, Python SDK, API integration tests and synthetic ICE-LAB cases; measure only actual suite results.
6. Build the React/TypeScript console against API endpoints, clearly distinguishing read-only, configured, demo, and unavailable states.
7. Add installation/deployment docs, open-source readiness files, run tests/security tooling, review diffs/secrets, and checkpoint safe milestones.

Any unimplemented architecture area will be labeled partial/planned rather than represented as complete.

## Development and runtime

The managed project is `/home/ubuntu/black-ice`. Use a Python 3.12 FastAPI API on port 8000 and a Vite React client on port 3000 in development; route `/api` through Vite to the API. Configure the managed preview for the actual frontend port and an API endpoint only if required by the selected runtime. For a future container, one FastAPI process may serve the built static app and API on the platform-provided port; do not publish until that contract and security review are complete. Local persistence is SQLite, with configurable location and file permissions. Secrets are supplied at runtime, never committed.

## Security console design

- **Design movement:** Swiss International Style meets a quiet incident-response control room.
- **Core principles:** authoritative state over decoration; evidence adjacent to decisions; default-deny affordances; dense but legible operator workflows.
- **Color philosophy:** near-black/navy surfaces express containment; muted slate keeps long audit tables readable; restrained ice-blue (#7DDCF4) is the brand signal; amber and red are reserved for review and denial/incident states.
- **Layout paradigm:** left navigation rail, persistent compact health strip, and a wide asymmetric workbench with the action stream and evidence taking priority over decorative cards.
- **Signature elements:** a fine ice-edge divider; provenance/action-chain graph with thin labeled edges; small square state markers whose shape and label as well as color communicate state.
- **Interaction philosophy:** actions show policy reason, scope and evidence; dangerous controls require an explicit operator intent; no fake terminal output or unlabeled simulation.
- **Animation:** brief state transitions only; no ambient motion, flashing, or motion that obscures event updates; honor reduced-motion preference.
- **Typography:** system sans for interface hierarchy with a monospace face for hashes, IDs and event metadata; use local/system fallbacks rather than a remote-font dependency.
- **Brand essence:** “Independent controls for agent actions”; precise, restrained, accountable.
- **Brand voice:** concise and evidence-led. Examples: “Request denied: path is outside this task workspace.” “Inspection incomplete: PDF visual rendering was not evaluated.”
- **Wordmark/mark:** BLACK ICE wordmark paired with a minimal angular ice-cut glyph, implemented as a local SVG.
- **Signature color:** ice-blue `#7DDCF4`, used sparingly for provenance and active navigation rather than generic success.

## Engineering and validation commitments

- Use typed Pydantic models, repository/service separation, safe path utilities and dependency-injected repositories for tests.
- Every protected side effect passes through ICE-GATE. The gateway does not trust agent-supplied risk scores or authorization assertions.
- Tests cover both denied restricted actions and functioning permitted workspace operations, plus revocation, expiry, policy/key/inspection failures, hidden instructions, path traversal, audit tampering, and legitimate flows.
- Run actual test/build/security-check commands and record outputs; do not fabricate metrics. State sandbox and parser limitations prominently.
- Before each GitHub checkpoint, inspect changed files, `.gitignore`, environment files, fixtures, generated files and secret-scanning results. No force-push, release, or public publication without the appropriate user-controlled confirmation.
