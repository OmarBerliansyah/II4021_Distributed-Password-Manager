import json

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from client import crypto_utils, local_store, shamir
from client.api_client import ApiClient
from client.main import ClientError, RuntimeBackend, VaultWorkflow
from client.vault import add_entry, list_entries
from server.app import app


class ASGITestSession:
    def __init__(self, client):
        self.client = client

    def request(self, method, url, timeout, **kwargs):
        return self.client.request(method, url, **kwargs)


@pytest.fixture()
def real_workflow(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path / "client"))
    app.state.db_path = tmp_path / "server.db"

    with TestClient(app) as test_client:
        api = ApiClient(
            base_url="http://testserver",
            session=ASGITestSession(test_client),
        )
        yield VaultWorkflow(RuntimeBackend(), api), api


def test_real_normal_and_backup_workflow(real_workflow):
    workflow, api = real_workflow
    recovery_share = workflow.initialize("fulan", "master-password")
    initial_remote = api.fetch_vault("fulan")

    session = workflow.open_normal("fulan", "master-password")
    add_entry(
        session.vault,
        "GitHub",
        "fulan@example.com",
        "generated-secret",
        "Main account",
        entry_id="entry-1",
    )
    workflow.persist(session)

    updated_remote = api.fetch_vault("fulan")
    assert updated_remote["vault_nonce"] != initial_remote["vault_nonce"]
    assert "GitHub" not in json.dumps(updated_remote)
    assert "generated-secret" not in json.dumps(updated_remote)

    reopened = workflow.open_normal("fulan", "master-password")
    assert list_entries(reopened.vault)[0]["nama_layanan"] == "GitHub"

    backup = workflow.open_backup("fulan", "master-password", recovery_share)
    assert list_entries(backup.vault) == list_entries(reopened.vault)
    with pytest.raises(ClientError, match="read-only"):
        workflow.persist(backup)


def test_real_workflow_rejects_wrong_password_and_recovery_share(real_workflow):
    workflow, _ = real_workflow
    recovery_share = workflow.initialize("fulan", "master-password")
    other_recovery = workflow.initialize("omar", "other-password")

    with pytest.raises(InvalidTag):
        workflow.open_normal("fulan", "wrong-password")

    with pytest.raises((InvalidTag, crypto_utils.CryptoError, shamir.ShamirError)):
        workflow.open_backup("fulan", "master-password", other_recovery)

    assert recovery_share != other_recovery


def test_duplicate_init_preserves_existing_local_state(real_workflow):
    workflow, api = real_workflow
    workflow.initialize("fulan", "master-password")
    config_path = local_store.client_config_path("fulan")
    original_config = config_path.read_bytes()
    original_remote = api.fetch_vault("fulan")

    with pytest.raises(ClientError, match="already exists"):
        workflow.initialize("fulan", "different-password")

    assert config_path.read_bytes() == original_config
    assert api.fetch_vault("fulan") == original_remote
    workflow.open_normal("fulan", "master-password")
