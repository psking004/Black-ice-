from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from blackice.client_utils import validate_api_base_url


def _api_url() -> str:
    return validate_api_base_url(os.environ.get("BLACKICE_API_URL", "http://127.0.0.1:8000"))


def _api_request(
    method: str, path: str, payload: dict[str, Any] | None = None, auth: bool = True
) -> Any:
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if auth:
        token = os.environ.get("BLACKICE_ADMIN_TOKEN")
        if not token:
            raise RuntimeError(
                "BLACKICE_ADMIN_TOKEN is not configured; source the private .env file first"
            )
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = httpx.request(
            method,
            _api_url() + path,
            content=body,
            headers=headers,
            timeout=20,
            follow_redirects=False,
            trust_env=False,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        details = exc.response.text[:2048]
        raise RuntimeError(
            f"BLACK ICE returned HTTP {exc.response.status_code}: {details}"
        ) from exc
    except httpx.RequestError as exc:
        raise RuntimeError("BLACK ICE API is unavailable; do not bypass the gateway") from exc


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _initialize_secrets() -> int:
    target = Path(".env")
    if target.exists():
        print(
            "Refusing to overwrite existing .env; preserve the current credentials.",
            file=sys.stderr,
        )
        return 2
    admin = secrets.token_urlsafe(48)
    signing = secrets.token_urlsafe(48)
    content = f"BLACKICE_ADMIN_TOKEN={admin}\nBLACKICE_SIGNING_KEY={signing}\n".encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    print("Created a private .env file with unique operator and signing credentials (mode 0600).")
    print("Keep .env out of Git. Load it with: set -a; source .env; set +a")
    print(
        "The agent token is issued once by `blackice task create`; never put it in frontend code."
    )
    return 0


def _write_private_export(destination: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="blackice", description="BLACK ICE operator and agent security tools"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "init",
        help="create private local operator/signing keys in .env without overwriting existing keys",
    )
    sub.add_parser("health", help="read public service health")
    serve = sub.add_parser("serve", help="start the local control plane (loopback by default)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow a non-loopback bind; provide TLS termination and network controls externally",
    )
    task_parser = sub.add_parser("task", help="manage protected tasks")
    task_sub = task_parser.add_subparsers(dest="task_command", required=True)
    create = task_sub.add_parser("create")
    create.add_argument("--agent", required=True)
    create.add_argument("--owner", default="operator")
    create.add_argument("--allow-write", action="store_true")
    create.add_argument("--require-write-approval", action="store_true")
    create.add_argument("--artifact-inspection", action="store_true")
    create.add_argument("--expires", type=int, default=3600)
    inspect_task = task_sub.add_parser("inspect")
    inspect_task.add_argument("task_id")
    revoke = task_sub.add_parser("revoke")
    revoke.add_argument("task_id")
    file_parser = sub.add_parser(
        "inspect", help="inspect an artifact without executing its contents"
    )
    file_parser.add_argument("path")
    file_parser.add_argument("--source", default="local-cli")
    decision_parser = sub.add_parser("decisions")
    decision_parser.add_argument("--task", dest="task_id")
    decision_parser.add_argument("--limit", type=int, default=100)
    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("--verify", action="store_true")
    audit_parser.add_argument("--limit", type=int, default=100)
    export_parser = sub.add_parser("export")
    export_parser.add_argument(
        "path", help="new private JSON export destination; existing files are preserved"
    )
    lab_parser = sub.add_parser("lab", help="run the synthetic ICE-LAB scenarios")
    lab_parser.add_argument(
        "--export", dest="export_path", help="also save the report to a new private JSON file"
    )

    args = parser.parse_args()
    try:
        if args.command == "init":
            raise SystemExit(_initialize_secrets())
        if args.command == "serve":
            if not 1024 <= args.port <= 65535:
                parser.error("--port must be between 1024 and 65535")
            if args.host not in {"127.0.0.1", "::1", "localhost"} and not args.allow_remote:
                parser.error("non-loopback binds require the explicit --allow-remote flag")
            import uvicorn

            uvicorn.run(
                "blackice.api.app:app",
                host=args.host,
                port=args.port,
                workers=1,
                reload=False,
                proxy_headers=False,
            )
        elif args.command == "health":
            _print(_api_request("GET", "/api/health", auth=False))
        elif args.command == "task" and args.task_command == "create":
            if args.require_write_approval and not args.allow_write:
                parser.error("--require-write-approval requires --allow-write")
            operations = ["list", "read"] + (["write"] if args.allow_write else [])
            body: dict[str, Any] = {
                "agent_id": args.agent,
                "task_owner": args.owner,
                "permitted_filesystem_operations": operations,
                "permitted_tools": ["filesystem"]
                + (["artifact"] if args.artifact_inspection else []),
                "expires_in_seconds": args.expires,
            }
            if args.require_write_approval:
                body["approval_requirements"] = ["filesystem.write"]
            _print(_api_request("POST", "/api/tasks", body))
        elif args.command == "task" and args.task_command == "inspect":
            _print(_api_request("GET", f"/api/tasks/{quote(args.task_id, safe='')}"))
        elif args.command == "task" and args.task_command == "revoke":
            _print(_api_request("POST", f"/api/tasks/{quote(args.task_id, safe='')}/revoke", {}))
        elif args.command == "inspect":
            path = Path(args.path)
            if not path.is_file():
                raise RuntimeError("artifact path is not a regular local file")
            raw = path.read_bytes()
            if len(raw) > 10_485_760:
                raise RuntimeError("artifact exceeds the 10 MiB CLI inspection limit")
            request = {
                "filename": path.name,
                "source": args.source,
                "content_base64": base64.b64encode(raw).decode("ascii"),
                "provenance": {"origin": "explicit-local-operator-upload"},
            }
            _print(_api_request("POST", "/api/artifacts/inspect", request))
        elif args.command == "decisions":
            path = f"/api/decisions?limit={max(1, min(args.limit, 200))}"
            if args.task_id:
                path += f"&task_id={quote(args.task_id, safe='')}"
            _print(_api_request("GET", path))
        elif args.command == "audit" and args.verify:
            _print(_api_request("GET", "/api/audit/verify"))
        elif args.command == "audit":
            _print(_api_request("GET", f"/api/audit/events?limit={max(1, min(args.limit, 200))}"))
        elif args.command == "export":
            data = _api_request("GET", "/api/audit/events?limit=200")
            path = Path(args.path)
            _write_private_export(
                path, (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode()
            )
            print(f"Exported {len(data)} audit events to new private file {path}")
        elif args.command == "lab":
            report = _api_request("POST", "/api/lab/run", {})
            _print(report)
            if args.export_path:
                path = Path(args.export_path)
                _write_private_export(
                    path, (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode()
                )
                print(f"Exported synthetic ICE-LAB report to new private file {path}")
    except SystemExit:
        raise
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
