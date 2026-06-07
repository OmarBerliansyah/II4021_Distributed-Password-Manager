import pytest
from fastapi.testclient import TestClient

from client.api_client import ApiClient
from client.main import ClientError, VaultWorkflow
from client.vault import add_entry, list_entries
from server.app import app


class ASGITestSession:
    def __init__(self, client):
        self.client = client

    def request(self, method, url, timeout, **kwargs):
        return self.client.request(method, url, **kwargs)


class InMemoryCryptoStorageBackend:
    """ini test doang bos"""

    def __init__(self):
        self.key = b"k" * 16
        self.passwords = {}
        self.local_shares = {}
        self.backups = {}
        self.nonce_number = 0
        self.fail_backup = False

    def generate_master_key(self):
        return self.key

    def split_master_key(self, master_key):
        assert master_key == self.key
        return ("local-share", "server-share", "recovery-share")

    def reconstruct_master_key(self, first_share, second_share):
        if first_share != "local-share":
            raise ValueError("Invalid local share")
        if second_share not in ("server-share", "recovery-share"):
            raise ValueError("Invalid second share")
        return self.key

    def encrypt_vault(self, master_key, plaintext):
        assert master_key == self.key
        self.nonce_number += 1
        nonce = self.nonce_number.to_bytes(12, "big")
        return plaintext[::-1], nonce

    def decrypt_vault(self, master_key, ciphertext, nonce):
        assert master_key == self.key
        assert len(nonce) == 12
        return ciphertext[::-1]

    def save_local_state(
        self,
        user_id,
        master_password,
        local_share,
        backup_ciphertext,
        backup_nonce,
    ):
        self.passwords[user_id] = master_password
        self.local_shares[user_id] = local_share
        self.backups[user_id] = (backup_ciphertext, backup_nonce)

    def load_local_share(self, user_id, master_password):
        if self.passwords[user_id] != master_password:
            raise ValueError("Wrong password")
        return self.local_shares[user_id]

    def save_backup(self, user_id, ciphertext, nonce):
        if self.fail_backup:
            raise OSError("disk full")
        self.backups[user_id] = (ciphertext, nonce)

    def load_backup(self, user_id):
        return self.backups[user_id]


class FailingLocalStateBackend(InMemoryCryptoStorageBackend):
    def save_local_state(
        self,
        user_id,
        master_password,
        local_share,
        backup_ciphertext,
        backup_nonce,
    ):
        raise OSError("disk unavailable")


@pytest.fixture()
def setup_workflow(tmp_path):
    app.state.db_path = tmp_path / "workflow.db"
    backend = InMemoryCryptoStorageBackend()
    with TestClient(app) as test_client:
        api = ApiClient(
            base_url="http://testserver",
            session=ASGITestSession(test_client),
        )
        workflow = VaultWorkflow(backend, api)
        yield workflow, backend, api


def test_initialize_does_not_create_server_vault_when_local_save_fails(tmp_path):
    app.state.db_path = tmp_path / "failed-init.db"
    backend = FailingLocalStateBackend()
    with TestClient(app) as test_client:
        api = ApiClient(
            base_url="http://testserver",
            session=ASGITestSession(test_client),
        )
        workflow = VaultWorkflow(backend, api)

        with pytest.raises(ClientError, match="Local state could not be saved"):
            workflow.initialize("fulan", "master-password")

        response = test_client.get("/vault/fulan")
        assert response.status_code == 404


def test_initialize_and_open_normal_vault(setup_workflow):
    workflow, backend, api = setup_workflow

    recovery_share = workflow.initialize("fulan", "master-password")
    session = workflow.open_normal("fulan", "master-password")

    assert recovery_share == "recovery-share"
    assert session.mode == "normal"
    assert list_entries(session.vault) == []
    assert api.fetch_vault("fulan")["server_share"] == "server-share"
    assert "fulan" in backend.backups


def test_mutation_uses_fresh_nonce_and_updates_server_and_backup(setup_workflow):
    workflow, backend, api = setup_workflow
    workflow.initialize("fulan", "master-password")
    session = workflow.open_normal("fulan", "master-password")
    old_nonce = session.source_nonce

    add_entry(
        session.vault,
        "GitHub",
        "fulan@example.com",
        "secret",
        entry_id="entry-1",
    )
    workflow.persist(session)

    assert session.source_nonce != old_nonce
    assert api.fetch_vault("fulan")["vault_nonce"] == session.source_nonce
    reopened = workflow.open_normal("fulan", "master-password")
    assert list_entries(reopened.vault)[0]["nama_layanan"] == "GitHub"
    assert backend.backups["fulan"][1] != (1).to_bytes(12, "big")


def test_backup_mode_uses_local_data_and_is_read_only(setup_workflow):
    workflow, _, _ = setup_workflow
    workflow.initialize("fulan", "master-password")

    session = workflow.open_backup(
        "fulan",
        "master-password",
        "recovery-share",
    )

    assert session.mode == "backup"
    assert list_entries(session.vault) == []
    with pytest.raises(ClientError, match="read-only"):
        workflow.persist(session)


def test_failed_local_backup_rolls_server_back(setup_workflow):
    workflow, backend, api = setup_workflow
    workflow.initialize("fulan", "master-password")
    session = workflow.open_normal("fulan", "master-password")
    original_ciphertext = session.source_ciphertext
    original_nonce = session.source_nonce
    add_entry(session.vault, "GitHub", "fulan", "secret")
    backend.fail_backup = True

    with pytest.raises(ClientError, match="rolled back"):
        workflow.persist(session)

    remote = api.fetch_vault("fulan")
    assert remote["vault_ciphertext"] == original_ciphertext
    assert remote["vault_nonce"] == original_nonce
