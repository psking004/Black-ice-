# CLI reference

Install the package with the locked extras described in [installation](installation.md). Use `uv run blackice ...` from the project environment. The CLI communicates with the API; it does not directly execute agent actions on the host.

The API origin comes from `BLACKICE_API_URL` and defaults to `http://127.0.0.1:8000`. Plain HTTP is permitted only for `localhost`, `127.0.0.1`, or `::1`; a remote origin must use HTTPS. Operator requests require `BLACKICE_ADMIN_TOKEN` except the public health check. HTTP requests do not follow redirects and do not use environment-configured proxies.

## Initialize and serve

```bash
uv run blackice init
uv run blackice serve
uv run blackice serve --host 127.0.0.1 --port 8000
```

`init` creates a new private `.env` containing operator and signing credentials in the current directory. It uses exclusive creation, mode `0600`, and refuses to replace an existing file (exit status 2 on refusal). Load the file into the shell before starting the API or running authenticated commands:

```bash
set -a
source .env
set +a
```

`serve` defaults to host `127.0.0.1` and port `8000`. Port must be from 1024 through 65535. Binding to `localhost`, `127.0.0.1`, or `::1` is permitted by default; every other host requires the explicit `--allow-remote` flag:

```bash
uv run blackice serve --host 0.0.0.0 --port 8000 --allow-remote
```

`--allow-remote` is not TLS, authentication infrastructure, firewalling, or a network-security configuration. Supply TLS termination and suitable network controls externally before using a remote bind.

## Health and task administration

```bash
uv run blackice health
uv run blackice task create --agent example-agent
uv run blackice task create --agent example-agent --owner team-a --expires 1800
uv run blackice task create --agent example-agent --allow-write --require-write-approval
uv run blackice task create --agent example-agent --artifact-inspection
uv run blackice task inspect TASK_ID
uv run blackice task revoke TASK_ID
```

`health` reads the public `/api/health` endpoint without operator authentication. Task creation requires the operator token, returns a signed envelope and issues an `agent_token` once; transfer it only to the intended agent through a protected channel. Defaults are owner `operator`, expiry 3,600 seconds, filesystem operations `list` and `read`, and permitted tool `filesystem`. `--allow-write` adds filesystem write permission. `--require-write-approval` adds an approval requirement and is valid only with `--allow-write`. `--artifact-inspection` permits the `artifact` tool. CLI-created tasks otherwise use the server's envelope defaults, including the action limit.

`task inspect` returns operator-visible task envelope/signature and action count. `task revoke` revokes the task so later gateway operations are denied. Task-management requests are authenticated with `BLACKICE_ADMIN_TOKEN`, never an agent task token.

## Inspect a local artifact

```bash
uv run blackice inspect ./sample.html
uv run blackice inspect ./sample.pdf --source incident-upload
```

This explicitly uploads one local regular file for inspection using the authenticated operator API; it does not execute the file. The CLI rejects non-regular files and files larger than 10 MiB. `--source` defaults to `local-cli`. Inspection yields bounded findings and representation coverage, not a guarantee that the artifact is safe.

## Decisions, audit, export and lab

```bash
uv run blackice decisions
uv run blackice decisions --task TASK_ID --limit 50
uv run blackice audit
uv run blackice audit --verify
uv run blackice audit --limit 100
uv run blackice export ./audit-export.json
uv run blackice lab
uv run blackice lab --export ./ice-lab-report.json
```

- `decisions` lists recent operator-visible decisions, optionally filtered by task. The default limit is 100 and is clamped to 1–200.
- `audit` lists recent audit events (default limit 100, clamped to 1–200); `--verify` verifies the SQLite audit hash chain instead of listing events.
- `export PATH` writes up to 200 recent audit events to a **new** private file with mode `0600`. Existing destinations are preserved; the command fails rather than overwriting them.
- `lab` asks the service to run labeled synthetic ICE-LAB scenarios. Optional `--export PATH` writes its report to a new private mode-`0600` file, also without overwriting an existing path. Lab results describe synthetic cases, not real-world attack rates.

All output is JSON except for status/error messages. Authenticated API failures are surfaced as command errors; an unavailable gateway is not a reason to bypass it. The CLI has no command, package-install, outbound-network, OS-sandbox, or general Git-management command.
