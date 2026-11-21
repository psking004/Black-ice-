from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    state_dir: Path
    database_path: Path
    workspace_root: Path
    artifact_root: Path
    admin_token: str | None
    signing_key: str | None
    max_artifact_bytes: int = 10_485_760
    max_action_bytes: int = 65_536

    @classmethod
    def from_env(cls) -> Settings:
        state = Path(os.environ.get("BLACKICE_STATE_DIR", "./var")).expanduser().resolve()
        db = Path(
            os.environ.get("BLACKICE_DATABASE_PATH", str(state / "blackice.sqlite3"))
        ).expanduser()
        workspaces = Path(
            os.environ.get("BLACKICE_WORKSPACE_ROOT", str(state / "workspaces"))
        ).expanduser()
        artifacts = Path(
            os.environ.get("BLACKICE_ARTIFACT_ROOT", str(state / "artifacts"))
        ).expanduser()
        return cls(
            state_dir=state,
            database_path=db.resolve(),
            workspace_root=workspaces.resolve(),
            artifact_root=artifacts.resolve(),
            admin_token=os.environ.get("BLACKICE_ADMIN_TOKEN") or None,
            signing_key=os.environ.get("BLACKICE_SIGNING_KEY") or None,
        )

    @property
    def operator_auth_ready(self) -> bool:
        return bool(self.admin_token and len(self.admin_token.encode("utf-8")) >= 32)

    @property
    def control_plane_ready(self) -> bool:
        return bool(
            self.operator_auth_ready
            and self.signing_key
            and len(self.signing_key.encode("utf-8")) >= 32
        )
