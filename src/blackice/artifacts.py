from __future__ import annotations

import base64
import binascii
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from blackice.database import Database
from blackice.models import ArtifactInspection, ArtifactInspectRequest
from blackice.vision import ArtifactInspector


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def put(self, data: bytes, sha256: str) -> str:
        folder = self.root / sha256[:2]
        folder.mkdir(mode=0o700, exist_ok=True)
        target = folder / sha256
        if target.exists():
            return sha256
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags, 0o600)
        except FileExistsError:
            return sha256
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        return sha256


class ArtifactService:
    def __init__(
        self, database: Database, store: ArtifactStore, inspector: ArtifactInspector, max_bytes: int
    ) -> None:
        self.database = database
        self.store = store
        self.inspector = inspector
        self.max_bytes = max_bytes

    def inspect_upload(self, request: ArtifactInspectRequest) -> ArtifactInspection:
        try:
            raw = base64.b64decode(request.content_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("content_base64 is not valid base64") from exc
        if len(raw) > self.max_bytes:
            raise ValueError("artifact exceeds the configured byte limit")
        if not raw:
            raise ValueError("artifact is empty")
        preliminary_hash = hashlib.sha256(raw).hexdigest()
        artifact_id = self.store.put(raw, preliminary_hash)
        inspection = self.inspector.inspect(
            request.filename,
            raw,
            source=request.source,
            provenance=request.provenance,
        )
        serialized: dict[str, Any] = inspection.model_dump(mode="json")
        self.database.save_inspection(
            inspection.inspection_id,
            artifact_id,
            inspection.sha256,
            serialized,
            datetime.now(UTC).isoformat(),
            audit_payload={
                "category": "vision",
                "event": "artifact_inspected",
                "inspection_id": inspection.inspection_id,
                "artifact_id": artifact_id,
                "sha256": inspection.sha256,
                "format": inspection.format,
                "status": inspection.status,
                "threat_classification": inspection.threat_classification,
                "indicator_count": len(inspection.suspicious_indicators),
                "representation_count": inspection.coverage.get("representations_count", 0),
            },
        )
        return inspection
