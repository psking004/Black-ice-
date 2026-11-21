from __future__ import annotations

import errno
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


class WorkspaceViolation(PermissionError):
    pass


class WorkspaceAdapter:
    """Only workspace-relative regular files are exposed; this is not a hostile-code sandbox."""

    def __init__(self, workspace_root: Path, max_bytes: int = 65_536) -> None:
        self.root = workspace_root.resolve()
        self.max_bytes = max_bytes
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError as exc:
            raise WorkspaceViolation("workspace root permissions could not be restricted") from exc

    @staticmethod
    def validate_workspace_id(workspace_id: str) -> str:
        if not re.fullmatch(r"[a-f0-9-]{8,64}", workspace_id):
            raise WorkspaceViolation("invalid workspace identifier")
        return workspace_id

    def create_workspace(self, workspace_id: str) -> Path:
        workspace_id = self.validate_workspace_id(workspace_id)
        path = self.root / workspace_id
        path.mkdir(mode=0o700, exist_ok=False)
        return path

    def _open_workspace(self, workspace_id: str) -> int:
        workspace_id = self.validate_workspace_id(workspace_id)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            return os.open(self.root / workspace_id, flags)
        except OSError as exc:
            raise WorkspaceViolation("workspace is unavailable") from exc

    @staticmethod
    def normalize_path(relative_path: str) -> tuple[str, ...]:
        if not relative_path or "\x00" in relative_path or "\\" in relative_path:
            raise WorkspaceViolation("resource must be a non-empty POSIX-relative path")
        path = PurePosixPath(relative_path)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in relative_path.split("/")):
            raise WorkspaceViolation("absolute paths and traversal are denied")
        return path.parts

    def _parent_fd(self, workspace_id: str, parts: tuple[str, ...]) -> tuple[int, str]:
        if not parts:
            raise WorkspaceViolation("workspace root is not a file resource")
        current_fd = self._open_workspace(workspace_id)
        try:
            for part in parts[:-1]:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current_fd,
                )
                os.close(current_fd)
                current_fd = next_fd
            return current_fd, parts[-1]
        except Exception:
            os.close(current_fd)
            raise

    def list(self, workspace_id: str, relative_path: str = ".") -> dict[str, Any]:
        if relative_path == ".":
            fd = self._open_workspace(workspace_id)
        else:
            parts = self.normalize_path(relative_path)
            if parts[-1] == ".":
                parts = parts[:-1]
            if not parts:
                fd = self._open_workspace(workspace_id)
            else:
                parent_fd, name = self._parent_fd(workspace_id, parts)
                try:
                    fd = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent_fd,
                    )
                finally:
                    os.close(parent_fd)
        try:
            entries: list[dict[str, str]] = []
            for name in sorted(os.listdir(fd))[:500]:
                if name in {".", ".."}:
                    continue
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    kind = (
                        "directory"
                        if stat.S_ISDIR(info.st_mode)
                        else "file"
                        if stat.S_ISREG(info.st_mode)
                        else "unsupported"
                    )
                except OSError:
                    kind = "unavailable"
                entries.append({"name": name, "type": kind})
            return {
                "path": relative_path,
                "entries": entries,
                "truncated": len(os.listdir(fd)) > 500,
            }
        finally:
            os.close(fd)

    def read(self, workspace_id: str, relative_path: str) -> bytes:
        parts = self.normalize_path(relative_path)
        parent_fd, name = self._parent_fd(workspace_id, parts)
        try:
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise WorkspaceViolation("only regular files may be read")
                if info.st_size > self.max_bytes:
                    raise WorkspaceViolation("file exceeds the configured read limit")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(fd, min(16_384, self.max_bytes + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise WorkspaceViolation("file exceeds the configured read limit")
                return b"".join(chunks)
            finally:
                os.close(fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise WorkspaceViolation("symlink traversal is denied") from exc
            raise
        finally:
            os.close(parent_fd)

    def write(self, workspace_id: str, relative_path: str, content: bytes) -> dict[str, Any]:
        if len(content) > self.max_bytes:
            raise WorkspaceViolation("content exceeds the configured write limit")
        parts = self.normalize_path(relative_path)
        parent_fd, name = self._parent_fd(workspace_id, parts)
        temp_name = f".blackice-tmp-{os.urandom(12).hex()}"
        try:
            fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            try:
                view = memoryview(content)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
            return {"path": relative_path, "bytes_written": len(content)}
        except OSError as exc:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise WorkspaceViolation("symlink traversal is denied") from exc
            raise
        finally:
            os.close(parent_fd)

    def mkdir(self, workspace_id: str, relative_path: str) -> dict[str, str]:
        parts = self.normalize_path(relative_path)
        parent_fd, name = self._parent_fd(workspace_id, parts)
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            return {"path": relative_path, "created": "true"}
        finally:
            os.close(parent_fd)
