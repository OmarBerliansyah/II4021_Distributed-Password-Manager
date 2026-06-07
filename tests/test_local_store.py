import json

import pytest
from cryptography.exceptions import InvalidTag

from client import crypto_utils, local_store, shamir
from client.main import RuntimeBackend


def test_runtime_backend_keeps_local_share_encrypted(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path))
    backend = RuntimeBackend()
    master_key = backend.generate_master_key()
    local_share, _, _ = backend.split_master_key(master_key)
    ciphertext, nonce = backend.encrypt_vault(master_key, b'{"entries":[]}')

    backend.save_local_state(
        "omar",
        "master password yang benar",
        local_share,
        ciphertext,
        nonce,
    )

    path = local_store.client_config_path("omar")
    saved_text = path.read_text(encoding="utf-8")
    saved_json = json.loads(saved_text)

    assert local_share not in saved_text
    assert saved_json["kdf"] == "pbkdf2-hmac-sha256"
    assert saved_json["kdf_iterations"] == crypto_utils.KDF_ITERATIONS
    assert saved_json["kdf_key_length"] == crypto_utils.MASTER_KEY_SIZE
    assert backend.load_local_share("omar", "master password yang benar") == local_share


def test_wrong_master_password_cannot_open_local_share(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path))
    backend = RuntimeBackend()
    master_key = backend.generate_master_key()
    local_share, _, _ = backend.split_master_key(master_key)
    ciphertext, nonce = backend.encrypt_vault(master_key, b'{"entries":[]}')
    backend.save_local_state("ferro", "password-benar", local_share, ciphertext, nonce)

    with pytest.raises(InvalidTag):
        backend.load_local_share("ferro", "password-salah")


def test_backup_vault_is_saved_and_loaded_as_bytes(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path))
    backend = RuntimeBackend()
    master_key = backend.generate_master_key()
    local_share, _, _ = backend.split_master_key(master_key)
    initial_ciphertext, initial_nonce = backend.encrypt_vault(master_key, b"initial")
    updated_ciphertext, updated_nonce = backend.encrypt_vault(master_key, b"updated")

    backend.save_local_state("atharizza", "master", local_share, initial_ciphertext, initial_nonce)
    backend.save_backup("atharizza", updated_ciphertext, updated_nonce)

    loaded_ciphertext, loaded_nonce = backend.load_backup("atharizza")

    assert loaded_ciphertext == updated_ciphertext
    assert loaded_nonce == updated_nonce
    assert backend.decrypt_vault(master_key, loaded_ciphertext, loaded_nonce) == b"updated"


def test_runtime_backend_opens_vault_with_normal_and_recovery_pairs(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path))
    backend = RuntimeBackend()
    master_key = backend.generate_master_key()
    local_share, server_share, recovery_share = backend.split_master_key(master_key)

    normal_key = backend.reconstruct_master_key(local_share, server_share)
    recovery_key = backend.reconstruct_master_key(local_share, recovery_share)

    assert normal_key == master_key
    assert recovery_key == master_key


def test_wrong_recovery_share_leads_to_failed_decryption(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path))
    backend = RuntimeBackend()
    master_key = backend.generate_master_key()
    other_key = backend.generate_master_key()
    local_share, _, _ = backend.split_master_key(master_key)
    _, _, wrong_recovery_share = backend.split_master_key(other_key)
    ciphertext, nonce = backend.encrypt_vault(master_key, b'{"entries":[{"nama_layanan":"Email"}]}')

    try:
        rebuilt = backend.reconstruct_master_key(local_share, wrong_recovery_share)
    except shamir.ShamirError:
        return

    with pytest.raises((InvalidTag, crypto_utils.CryptoError)):
        backend.decrypt_vault(rebuilt, ciphertext, nonce)


def test_local_store_rejects_missing_config(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path))

    with pytest.raises(local_store.LocalStoreError):
        local_store.load_client_config("belum-ada")
    with pytest.raises(local_store.LocalStoreError):
        local_store.load_backup_vault("belum-ada")


def test_config_file_name_does_not_expose_user_id(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path))
    path = local_store.client_config_path("omar@example.com")

    assert path.parent == tmp_path
    assert "omar" not in path.name
    assert "example" not in path.name


def test_saved_share_can_be_deserialized_after_loading(monkeypatch, tmp_path):
    monkeypatch.setenv(local_store.CLIENT_DIR_ENV, str(tmp_path))
    backend = RuntimeBackend()
    master_key = backend.generate_master_key()
    local_share, server_share, _ = backend.split_master_key(master_key)
    ciphertext, nonce = backend.encrypt_vault(master_key, b"backup")
    backend.save_local_state("mahasiswa", "master", local_share, ciphertext, nonce)

    loaded_share = backend.load_local_share("mahasiswa", "master")

    assert shamir.deserialize_share(loaded_share)
    assert backend.reconstruct_master_key(loaded_share, server_share) == master_key
