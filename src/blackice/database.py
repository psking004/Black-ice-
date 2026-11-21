from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from blackice.crypto import canonical_json


class Database:
    """Small local repository; protected operations use transactions and bound parameters."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        connection = sqlite3.connect(self.path, timeout=5, isolation_level="DEFERRED")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connection() as con:
            con.execute("PRAGMA journal_mode = WAL")
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    envelope_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    agent_token_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    action_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS decisions_task_created ON decisions(task_id, created_at);
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    decision_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    consumed_at TEXT,
                    FOREIGN KEY(decision_id) REFERENCES decisions(decision_id),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE TABLE IF NOT EXISTS inspections (
                    inspection_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                """
            )
        try:
            os.chmod(self.path, 0o600)
        except FileNotFoundError:
            pass

    def _append_audit_transaction(
        self, con: sqlite3.Connection, payload: dict[str, Any]
    ) -> dict[str, Any]:
        event_id = str(uuid.uuid4())
        occurred_at = datetime.now(UTC).isoformat()
        payload_json = canonical_json(payload).decode("utf-8")
        previous = con.execute(
            "SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_hash = previous["event_hash"] if previous else "0" * 64
        hashed = canonical_json(
            {
                "sequence": sequence,
                "event_id": event_id,
                "occurred_at": occurred_at,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        )
        event_hash = hashlib.sha256(hashed).hexdigest()
        con.execute(
            "INSERT INTO audit_events(sequence,event_id,occurred_at,payload_json,previous_hash,event_hash) "
            "VALUES(?,?,?,?,?,?)",
            (sequence, event_id, occurred_at, payload_json, previous_hash, event_hash),
        )
        return {
            "sequence": sequence,
            "event_id": event_id,
            "occurred_at": occurred_at,
            "payload": payload,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
        }

    def save_task(
        self,
        task_id: str,
        envelope: dict[str, Any],
        signature: str,
        token_hash: str,
        audit_payload: dict[str, Any] | None = None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection() as con:
            con.execute(
                "INSERT INTO tasks(task_id,envelope_json,signature,agent_token_hash,created_at) VALUES(?,?,?,?,?)",
                (task_id, canonical_json(envelope).decode(), signature, token_hash, now),
            )
            if audit_payload is not None:
                self._append_audit_transaction(con, audit_payload)

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            return None
        return {
            "task_id": row["task_id"],
            "envelope": json.loads(row["envelope_json"]),
            "signature": row["signature"],
            "agent_token_hash": row["agent_token_hash"],
            "created_at": row["created_at"],
            "action_count": row["action_count"],
        }

    def update_task(
        self,
        task_id: str,
        envelope: dict[str, Any],
        signature: str,
        audit_payload: dict[str, Any] | None = None,
    ) -> None:
        with self.connection() as con:
            cursor = con.execute(
                "UPDATE tasks SET envelope_json=?,signature=? WHERE task_id=?",
                (canonical_json(envelope).decode(), signature, task_id),
            )
            if cursor.rowcount != 1:
                raise KeyError("task does not exist")
            if audit_payload is not None:
                self._append_audit_transaction(con, audit_payload)

    def try_claim_action(self, task_id: str, max_actions: int) -> bool:
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT action_count FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if row is None or row["action_count"] >= max_actions:
                return False
            con.execute("UPDATE tasks SET action_count=action_count+1 WHERE task_id=?", (task_id,))
            return True

    def list_tasks(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as con:
            rows = con.execute(
                "SELECT task_id,envelope_json,signature,created_at,action_count FROM tasks ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "task_id": row["task_id"],
                "envelope": json.loads(row["envelope_json"]),
                "signature": row["signature"],
                "created_at": row["created_at"],
                "action_count": row["action_count"],
            }
            for row in rows
        ]

    def save_decision(
        self,
        decision_id: str,
        task_id: str,
        request_digest: str,
        outcome: str,
        reason: str,
        details: dict[str, Any],
        created_at: str,
        audit_payload: dict[str, Any] | None = None,
    ) -> None:
        with self.connection() as con:
            con.execute(
                "INSERT INTO decisions VALUES(?,?,?,?,?,?,?)",
                (
                    decision_id,
                    task_id,
                    request_digest,
                    outcome,
                    reason,
                    canonical_json(details).decode(),
                    created_at,
                ),
            )
            if audit_payload is not None:
                self._append_audit_transaction(con, audit_payload)

    def update_decision_execution(
        self,
        decision_id: str,
        execution: dict[str, Any],
        outcome: str | None = None,
        reason: str | None = None,
        audit_payload: dict[str, Any] | None = None,
    ) -> None:
        with self.connection() as con:
            row = con.execute(
                "SELECT details_json FROM decisions WHERE decision_id=?", (decision_id,)
            ).fetchone()
            if row is None:
                raise KeyError("decision not found")
            details = json.loads(row["details_json"])
            details["execution_status"] = execution.get("status")
            if execution.get("data_classification") is not None:
                details["data_classification"] = execution["data_classification"]
            con.execute(
                "UPDATE decisions SET details_json=?,outcome=COALESCE(?,outcome),reason=COALESCE(?,reason) "
                "WHERE decision_id=?",
                (canonical_json(details).decode(), outcome, reason, decision_id),
            )
            if audit_payload is not None:
                self._append_audit_transaction(con, audit_payload)

    def update_decision_outcome(self, decision_id: str, outcome: str, reason: str) -> None:
        with self.connection() as con:
            cursor = con.execute(
                "UPDATE decisions SET outcome=?,reason=? WHERE decision_id=?",
                (outcome, reason, decision_id),
            )
            if cursor.rowcount != 1:
                raise KeyError("decision not found")

    def get_decision(self, decision_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute(
                "SELECT * FROM decisions WHERE decision_id=?", (decision_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "decision_id": row["decision_id"],
            "task_id": row["task_id"],
            "request_digest": row["request_digest"],
            "outcome": row["outcome"],
            "reason": row["reason"],
            "details": json.loads(row["details_json"]),
            "created_at": row["created_at"],
        }

    def list_decisions(self, task_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as con:
            if task_id is None:
                rows = con.execute(
                    "SELECT * FROM decisions ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM decisions WHERE task_id=? ORDER BY created_at DESC LIMIT ?",
                    (task_id, limit),
                ).fetchall()
        return [
            {
                "decision_id": row["decision_id"],
                "task_id": row["task_id"],
                "request_digest": row["request_digest"],
                "outcome": row["outcome"],
                "reason": row["reason"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def create_approval(
        self,
        approval_id: str,
        decision_id: str,
        task_id: str,
        request_digest: str,
        expires_at: str,
        approved_by: str,
        audit_payload: dict[str, Any] | None = None,
    ) -> None:
        with self.connection() as con:
            con.execute(
                "INSERT INTO approvals(approval_id,decision_id,task_id,request_digest,expires_at,approved_by) "
                "VALUES(?,?,?,?,?,?)",
                (approval_id, decision_id, task_id, request_digest, expires_at, approved_by),
            )
            if audit_payload is not None:
                self._append_audit_transaction(con, audit_payload)

    def consume_approval(
        self,
        approval_id: str,
        task_id: str,
        request_digest: str,
        audit_payload: dict[str, Any] | None = None,
    ) -> bool:
        now = datetime.now(UTC).isoformat()
        approval_hash = hashlib.sha256(approval_id.encode("utf-8")).hexdigest()
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT * FROM approvals WHERE approval_id=? AND task_id=? AND request_digest=?",
                (approval_hash, task_id, request_digest),
            ).fetchone()
            if row is None or row["consumed_at"] is not None or row["expires_at"] <= now:
                return False
            cursor = con.execute(
                "UPDATE approvals SET consumed_at=? WHERE approval_id=? AND consumed_at IS NULL",
                (now, approval_hash),
            )
            if cursor.rowcount != 1:
                return False
            if audit_payload is not None:
                self._append_audit_transaction(con, audit_payload)
            return True

    def save_inspection(
        self,
        inspection_id: str,
        artifact_id: str,
        sha256: str,
        result: dict[str, Any],
        created_at: str,
        audit_payload: dict[str, Any] | None = None,
    ) -> None:
        with self.connection() as con:
            con.execute(
                "INSERT INTO inspections VALUES(?,?,?,?,?)",
                (inspection_id, artifact_id, sha256, canonical_json(result).decode(), created_at),
            )
            if audit_payload is not None:
                self._append_audit_transaction(con, audit_payload)

    def list_inspections(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as con:
            rows = con.execute(
                "SELECT result_json FROM inspections ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["result_json"]) for row in rows]

    def get_inspection(self, inspection_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute(
                "SELECT result_json FROM inspections WHERE inspection_id=?", (inspection_id,)
            ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def append_audit(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            return self._append_audit_transaction(con, payload)

    def verify_audit(self) -> dict[str, Any]:
        with self.connection() as con:
            rows = con.execute("SELECT * FROM audit_events ORDER BY sequence ASC").fetchall()
        previous_hash = "0" * 64
        verified = 0
        first_invalid: int | None = None
        for row in rows:
            payload = json.loads(row["payload_json"])
            expected = hashlib.sha256(
                canonical_json(
                    {
                        "sequence": row["sequence"],
                        "event_id": row["event_id"],
                        "occurred_at": row["occurred_at"],
                        "payload": payload,
                        "previous_hash": previous_hash,
                    }
                )
            ).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                first_invalid = row["sequence"]
                break
            verified += 1
            previous_hash = row["event_hash"]
        return {
            "valid": first_invalid is None,
            "events_total": len(rows),
            "events_verified": verified,
            "first_invalid_sequence": first_invalid,
            "head_hash": previous_hash,
            "tamper_evident_not_immutable": True,
        }

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as con:
            rows = con.execute(
                "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "sequence": row["sequence"],
                "event_id": row["event_id"],
                "occurred_at": row["occurred_at"],
                "payload": json.loads(row["payload_json"]),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def decision_count(self, task_id: str) -> int:
        with self.connection() as con:
            row = con.execute(
                "SELECT count(*) AS total FROM decisions WHERE task_id=?", (task_id,)
            ).fetchone()
        return int(row["total"])
