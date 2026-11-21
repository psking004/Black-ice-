# Sandbox and execution boundary

## What exists today

BLACK ICE does **not** currently provide a hostile-code execution sandbox. The implemented boundary is an application-level `WorkspaceAdapter` (`src/blackice/sandbox/workspace.py`): a filesystem adapter that exposes `list`, `read`, `write`, and `mkdir` operations beneath a generated per-task workspace. ICE-GATE applies the task envelope and fixed policy before invoking registered adapters. The adapter constrains only those calls that go through the BLACK ICE gateway; it is not an OS reference monitor or process/container boundary.

The current registry contains the filesystem operations and, when the artifact inspector is configured, `artifact.inspect`. There is no shell/command or network adapter. Repository files, package scripts, workflow files, and command strings presented as requests remain inert data: BLACK ICE does not execute them, install dependencies, or build/test a repository. An absent adapter means the action is denied; it does not mean hostile code has been safely sandboxed.

## Filesystem adapter controls

The adapter creates a workspace root and per-task directories with restrictive `0700` permissions where the host filesystem permits. It accepts non-empty POSIX-relative paths, rejects absolute paths, traversal, NUL bytes, and backslashes, opens directories/files without following symlinks, and permits regular files for reads. Writes are bounded, staged through a unique temporary file, and atomically replaced. Listings are capped at 500 entries and identify unsupported filesystem object types rather than treating them as regular files.

At task creation, the default restricted-path rules include common credential locations and names such as `.env`, `.git`, `.ssh`, `.aws`, `.kube`, selected config files, `secrets/`, private-key filenames, and PEM files. Restricted rules take precedence over permitted paths. These are useful path rules, not a complete secret inventory; operators may supply different request rules, and BLACK ICE cannot protect files outside the adapter's scope.

The service-level `BLACKICE_MAX_*` settings do not exist. Actual configuration names are `BLACKICE_WORKSPACE_ROOT`, `BLACKICE_ARTIFACT_ROOT`, `BLACKICE_DATABASE_PATH`, `BLACKICE_STATE_DIR`, `BLACKICE_ADMIN_TOKEN`, and `BLACKICE_SIGNING_KEY`. By default, the workspace root is `./var/workspaces`. `Settings.from_env()` sets the adapter's file limit from `max_artifact_bytes` (10 MiB by default). The tool registry applies a separate per-action limit, `max_action_bytes` (65,536 bytes by default), to text reads and writes. Binary files are not returned as ordinary text; use the artifact-inspection path where the task permits it. API requests are separately capped at 15 MiB.

## What this does not isolate or enforce

The adapter is not a hostile-code execution sandbox, and BLACK ICE does not provide:

- Shell, command, package installation, repository build, or test execution.
- Network namespace, firewall, egress filtering, or any other OS-level network isolation. The application has no outbound network adapter and denies gateway destination requests; it does not control a separate process's networking.
- CPU, memory, process-count, disk, or wall-clock resource isolation for arbitrary code. File/request limits are application-level bounds, not OS resource controls.
- Process supervision, process termination, agent termination, or protection against an execution path that bypasses the API/gateway.
- Isolation from the BLACK ICE service process, host administrator, or users able to access the configured state/workspace roots.
- Multi-process/distributed locking. Per-task locks are in-process; supported coordination assumes one application worker. SQLite transactions cover specific local claims, such as action-budget and approval consumption, but are not distributed locks.
- Dynamic taint tracking or complete data lineage. Current classification/redaction is pattern-based and represents only selected gateway observations.

Do not use BLACK ICE as a shell runner, package/build runner, or containment boundary for untrusted repositories. Do not infer safety from a command being denied by the registry, a file being readable through the workspace adapter, or an artifact inspection producing no finding. Any future code-execution mode requires a separately designed and validated isolation boundary; it is not available in this version.

## Synthetic lab boundary

`blackice lab` / `POST /api/lab/run` exercises selected synthetic actions through the local TSE, ICE-GATE, policy, adapters, and inspector. It stages a synthetic repository including an inert `postinstall` script and workflow content, then submits denied command requests. It never runs those files or commands. The lab creates and retains a labeled synthetic workspace and audit evidence in the configured state. Its small scenario report is not a hostile-code sandbox test, general detection rate, or real-world validation.

## Evidence and relevant tests

Relevant implementation: `src/blackice/sandbox/workspace.py`, `src/blackice/tools.py`, `src/blackice/policy.py`, and `src/blackice/api/app.py`. Relevant tests include `tests/test_workspace.py` (workspace permissions, traversal/symlink denial, bounded atomic writes, and absent shell/network adapters) and `tests/test_api.py` (gateway-scoped file access and inert hostile-repository lab fixture). These tests cover selected cases only; they do not establish OS isolation, hostile-code containment, resource isolation, or safe multi-process deployment.
