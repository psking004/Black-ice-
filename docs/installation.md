# Installation and local setup

BLACK ICE is a Python package with a local FastAPI control plane, a CLI, a task-bound Python SDK, and optional MCP entry points. This guide covers the implemented Python runtime; it does not set up or promise an isolated agent execution environment.

## Requirements

- Python satisfying the package metadata requirement `>=3.11`.
- [`uv`](https://docs.astral.sh/uv/) to install from the checked-in `uv.lock` and run project commands. The lockfile declares `requires-python = ">=3.11"`; the metadata and lockfile are not evidence that every eligible Python version or platform has been tested. No broader tested-version claim is made here.

The project declares FastAPI, HTTPX, Uvicorn, Pydantic, Beautiful Soup, defusedxml, pypdf, and Pillow as runtime dependencies. The `dev` extra adds pytest and Ruff; the `mcp` extra adds the MCP SDK. The lockfile pins the resolved dependency graph. Install the project and both extras in locked mode:

```bash
uv sync --locked --extra dev --extra mcp
```

This makes the `blackice`, `blackice-mcp`, and `blackice-operator-mcp` commands available through `uv run`. If you change dependency declarations, update the lockfile separately rather than bypassing `--locked` during a reproducible setup.

## Initialize operator and signing credentials

From the repository root, run:

```bash
uv run blackice init
```

This creates `.env` in the current directory with generated `BLACKICE_ADMIN_TOKEN` and `BLACKICE_SIGNING_KEY` values. The file is created exclusively with mode `0600`; initialization refuses to overwrite an existing `.env`. Keep it private and out of source control. `.env` is Git-ignored in this repository.

Load it into the shell used to run the control plane and operator CLI:

```bash
set -a
source .env
set +a
```

For operator endpoints, the configured operator token must be at least 32 bytes; protected task signing also requires a signing key of at least 32 bytes. Missing or invalid security configuration leaves protected functionality restricted/fail-closed. The environment example documents the optional state and API URL settings.

## Start the control plane

Run the API in one terminal:

```bash
uv run blackice serve
```

It listens on `127.0.0.1:8000` by default. `BLACKICE_STATE_DIR` defaults to `./var`; the SQLite database, task workspaces, and artifact storage default below that state directory. The service is single-process and local-state based. `blackice serve` accepts `--host` and `--port`; non-loopback binding requires `--allow-remote`. That flag only permits the bind: TLS termination and network controls must be supplied externally. See [CLI](cli.md) for details.

In another terminal, load the same private `.env` before invoking authenticated operator CLI commands. `blackice health` reads the public health endpoint and does not require the operator token; task, audit, decision, artifact and lab operations use operator-authenticated API routes.

## Verify and run tests

```bash
uv run blackice health
uv run pytest
uv run ruff check src tests
```

The test suite exercises the current gateway, CLI helpers, SDK, MCP registrations and workspace adapter. It does not establish a security certification, hostile-code isolation, or compatibility across every Python version permitted by the package metadata.

## Runtime boundary

The current adapter registry supports scoped workspace filesystem operations and artifact inspection. It does **not** provide arbitrary shell execution, package installation for a task, outbound network access, an operating-system sandbox, or a general Git workflow. A task workspace is an application-level file boundary, not isolation for hostile code. Only actions routed through the BLACK ICE gateway are governed by these controls; do not infer protection for bypass paths.

Continue with [tool integration](tool-integration.md), [CLI reference](cli.md), [Python SDK](sdk.md), and [MCP](mcp.md).
