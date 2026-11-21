# BLACK ICE

**Independent Security Control Plane for Autonomous AI Systems**

BLACK ICE treats an agent's request to perform an action as a request for authorization—not permission. A task-scoped, signed envelope, deterministic policy evaluation, revocation state and registered tool adapter must all permit a protected operation before it reaches a workspace resource.

> **Security status:** This repository is an early-stage engineering project, not a security certification or a guarantee against prompt injection. The implemented execution boundary covers only actions routed through the BLACK ICE API. The initial runtime does not execute arbitrary shell commands, install dependencies, or provide outbound network access. Its workspace adapter is not a hostile-code sandbox.

## Current implementation

The Python core includes HMAC-signed and expiring Task Security Envelopes (TSEs), one-time task-scoped agent bearer credentials, independent task revocation, default-deny policy checks, scoped filesystem adapters using no-follow directory operations, action approvals bound to one request digest, deterministic sequence indicators, credential-pattern redaction on text reads, bounded multi-format artifact inspection and a SQLite audit hash chain. A React/TypeScript console uses the API rather than fabricated telemetry. CLI, Python SDK and synthetic ICE-LAB scenarios are included.

Every limit is finite and format-specific. Inspection reports retain a content-addressed copy of the original upload and a structured report; unsupported or incompletely inspected representations stay marked partial. The SQLite audit chain is tamper-evident against ordinary row edits but is not immutable against a privileged host operator. OCR, PDF visual rendering, complete Office document rendering comparison, perfect Unicode/homoglyph interpretation, steganography detection, dynamic taint tracking, multi-process locking and hostile-code isolation are not claimed.

## Requirements

- Python `>=3.11` and `uv` (CI currently runs Python 3.12)
- Node.js 22 and pnpm 11.25.0 for the React console

## Local setup

```bash
uv sync --locked --extra dev --extra mcp
pnpm install --frozen-lockfile
uv run blackice init
```

The `init` command creates a local `.env` with generated operator and signing credentials and mode `0600`; it refuses to overwrite an existing file. `.env` is ignored by Git. In a shell, load it before starting the API:

```bash
set -a
source .env
set +a
uv run blackice serve
```

In a second shell, start the console:

```bash
pnpm dev
```

The Vite server binds port 3000 and proxies `/api` to the Python service at `127.0.0.1:8000`. The console never stores the operator token in browser local storage; it is held only in the current page session. For a managed HTTPS preview, keep the required port declaration and relative browser URLs.

## Main workflows

```bash
uv run blackice health
uv run blackice task create --agent example-agent
uv run blackice task create --agent example-agent --allow-write --require-write-approval
uv run blackice task inspect <task-id>
uv run blackice task revoke <task-id>
uv run blackice inspect ./sample.html
uv run blackice decisions
uv run blackice audit --verify
uv run blackice lab
```

Task creation returns a scoped `agent_token` once. Deliver it securely to the specified agent; never put it in frontend source, source control, or logs. The Python SDK is `blackice.sdk.BlackIceAgentClient`. It offers only the gateway-mediated API.

## Tests and checks

```bash
uv run pytest
uv run ruff check src tests
pnpm typecheck
pnpm test
pnpm build
```

ICE-LAB was also run through the operator-authenticated API on 2026-11-21: 9/9 synthetic scenarios passed; all 5 listed DENY cases were denied (reported prevention rate 1.0); HTML hidden-instruction indicator was found; inspection reported 5 representations as partial; mean scenario latency was 5.309 ms in this single local run. This small fixture is not a real-world attack rate, false-positive estimate, or performance benchmark. The lab writes synthetic workspaces/audit events only to its state directory.

## Documentation

See the [installation guide](docs/installation.md), [tool integration](docs/tool-integration.md), [CLI](docs/cli.md), [Python SDK](docs/sdk.md), and [MCP](docs/mcp.md) guides. Security details: [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [TSE specification](docs/tse.md), [policy](docs/policy.md), [artifact inspection](docs/vision.md), [representation gaps](docs/representation-gap.md), [sandbox boundary](docs/sandbox.md), [incident response](docs/incident-response.md), [troubleshooting](docs/troubleshooting.md), [roadmap](docs/roadmap.md), and [security status](SECURITY_STATUS.md). See [SECURITY.md](SECURITY.md) to report a vulnerability and [CONTRIBUTING.md](CONTRIBUTING.md) to propose changes. Progress files: [TODO.md](TODO.md), [PROJECT_STATUS.md](PROJECT_STATUS.md), [NEXT_STEPS.md](NEXT_STEPS.md), and [IMPLEMENTATION_LOG.md](IMPLEMENTATION_LOG.md).

## License

MIT. See [`LICENSE`](LICENSE).
