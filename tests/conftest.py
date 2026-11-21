from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from blackice.api.app import create_app
from blackice.settings import Settings


@pytest.fixture
def settings(tmp_path):
    state = tmp_path / "state"
    return Settings(
        state_dir=state,
        database_path=state / "blackice.sqlite3",
        workspace_root=state / "workspaces",
        artifact_root=state / "artifacts",
        admin_token="operator-test-token-" + "a" * 40,
        signing_key="test-signing-key-" + "b" * 40,
    )


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_headers(settings):
    return {"Authorization": f"Bearer {settings.admin_token}"}
