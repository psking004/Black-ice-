from __future__ import annotations

import stat

import pytest

from blackice.sandbox.workspace import WorkspaceAdapter, WorkspaceViolation
from blackice.tools import ToolExecutionError, ToolRegistry


def test_workspace_files_are_private_and_symlink_traversal_is_denied(tmp_path):
    root = tmp_path / "workspace-root"
    adapter = WorkspaceAdapter(root, max_bytes=1024)
    workspace_id = "12345678-1234-1234-1234-123456789abc"
    workspace = adapter.create_workspace(workspace_id)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o700

    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (workspace / "escape.txt").symlink_to(outside)
    with pytest.raises(WorkspaceViolation):
        adapter.read(workspace_id, "escape.txt")
    with pytest.raises(WorkspaceViolation):
        adapter.read(workspace_id, "../outside.txt")
    with pytest.raises(WorkspaceViolation):
        adapter.read(workspace_id, "/etc/passwd")


def test_workspace_write_is_atomic_bounded_and_non_following(tmp_path):
    adapter = WorkspaceAdapter(tmp_path / "ws", max_bytes=8)
    workspace_id = "12345678-1234-1234-1234-123456789abc"
    workspace = adapter.create_workspace(workspace_id)
    result = adapter.write(workspace_id, "file.txt", b"initial")
    assert result["bytes_written"] == 7
    adapter.write(workspace_id, "file.txt", b"replace")
    assert adapter.read(workspace_id, "file.txt") == b"replace"
    with pytest.raises(WorkspaceViolation):
        adapter.write(workspace_id, "file.txt", b"too-long-content")
    assert not list(workspace.glob(".blackice-tmp-*"))


def test_registry_has_no_shell_or_network_adapter(tmp_path):
    workspace = WorkspaceAdapter(tmp_path / "ws")
    registry = ToolRegistry(workspace)
    assert set(registry.operations) == {"filesystem"}
    assert "command" not in registry.operations
    assert "network" not in registry.operations
    with pytest.raises(ToolExecutionError):
        registry.execute("command", "execute", "workspace", "id", {})
