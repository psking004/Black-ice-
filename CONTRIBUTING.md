# Contributing

Contributions are welcome. Before opening a pull request, read [`SECURITY.md`](SECURITY.md), [`docs/threat-model.md`](docs/threat-model.md), and [`SECURITY_STATUS.md`](SECURITY_STATUS.md). BLACK ICE is early-stage; preserve the distinction between a detector finding, an enforcement decision, and a claim about host isolation.

## Development setup

Requirements: Python 3.11 or newer (CI currently uses Python 3.12), `uv`, Node.js 22, and pnpm 11.25.0.

```bash
uv sync --locked --extra dev --extra mcp
pnpm install --frozen-lockfile
```

Run before submitting:

```bash
uv run ruff check src tests
uv run pytest -q
pnpm typecheck
pnpm test
pnpm build
```

For security-relevant changes, include a focused adversarial regression test that exercises the real API/gateway/adapter path. Prefer synthetic data and deterministic assertions. Do not execute untrusted repository code as a test fixture.

## Change expectations

- Preserve default-deny behavior and fail-closed handling. Do not accept artifact text, agent statements, or agent-supplied scores as policy authority.
- Do not add shell, network, package-installation, or execution features without a separate security design, explicit boundaries, and tests.
- Keep parsing bounded and non-executing; report uninspected regions rather than clearing them.
- Never commit `.env`, credentials, real customer data, private logs, or generated local state. Use synthetic values and review the complete diff.
- Update documentation, tests, and the continuation/status files when project state changes.
- Do not state that a property is “secure,” “isolated,” “immutable,” or “complete” unless the implementation and test evidence support that precise claim.

## Pull requests

Keep changes scoped and explain the behavior, threat model, test evidence, and limitations. CI must pass. A passing CI run is not a security certification. Maintainers may request changes or close work that expands the trusted computing base without adequate enforcement or validation.
