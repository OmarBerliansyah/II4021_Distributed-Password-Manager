import pytest
from typer.testing import CliRunner

import client.main as main_module
from client.main import VaultSession
from client.visual_crypto import VisualCryptoError
from client.vault import create_empty_vault


runner = CliRunner()


class InteractiveWorkflow:
    def __init__(self):
        self.session = VaultSession(
            user_id="fulan",
            master_key=b"k" * 16,
            vault=create_empty_vault(),
            mode="normal",
        )
        self.initialized = []
        self.persist_count = 0

    def initialize(self, user_id, master_password):
        self.initialized.append((user_id, master_password))
        return '{"prime":"mersenne-521","x":3,"y":"AA"}'

    def open_normal(self, user_id, master_password):
        assert user_id == "fulan"
        assert master_password == "master-password"
        return self.session

    def open_backup(self, user_id, master_password, recovery_share):
        return VaultSession(
            user_id=user_id,
            master_key=b"k" * 16,
            vault=self.session.vault,
            mode="backup",
        )

    def persist(self, session):
        assert session is self.session
        self.persist_count += 1


def test_default_launch_opens_interactive_menu():
    result = runner.invoke(main_module.app, input="0\n")

    assert result.exit_code == 0
    assert "Distributed Password Manager" in result.output
    assert "Initialize new vault" in result.output
    assert "Goodbye" in result.output


def test_interactive_initialization_returns_to_main_menu(monkeypatch):
    workflow = InteractiveWorkflow()
    monkeypatch.setattr(main_module, "_workflow", lambda: workflow)

    result = runner.invoke(
        main_module.app,
        input=(
            "1\n"
            "fulan\n"
            "master-password\n"
            "master-password\n"
            "n\n"
            "0\n"
        ),
    )

    assert result.exit_code == 0
    assert workflow.initialized == [("fulan", "master-password")]
    assert "Save this recovery share now" in result.output
    assert "Goodbye" in result.output


def test_interactive_login_add_list_and_logout(monkeypatch):
    workflow = InteractiveWorkflow()
    monkeypatch.setattr(main_module, "_workflow", lambda: workflow)

    result = runner.invoke(
        main_module.app,
        input=(
            "2\n"
            "fulan\n"
            "master-password\n"
            "2\n"
            "GitHub\n"
            "fulan@example.com\n"
            "Main account\n"
            "n\n"
            "account-password\n"
            "1\n"
            "y\n"
            "0\n"
            "0\n"
        ),
    )

    assert result.exit_code == 0
    assert workflow.persist_count == 1
    assert workflow.session.vault["entries"][0]["nama_layanan"] == "GitHub"
    assert workflow.session.vault["entries"][0]["password"] == "account-password"
    assert "Vault opened for fulan" in result.output
    assert "GitHub" in result.output
    assert "Logged out" in result.output


def test_visual_output_directory_is_created_inside_repository(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    output = main_module._visual_output_directory("vae backup")

    assert output == tmp_path / "visual-crypto" / "vae backup"
    assert output.is_dir()


def test_visual_output_directory_rejects_path_traversal(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(VisualCryptoError):
        main_module._visual_output_directory("../outside")
