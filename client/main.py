from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Protocol

import typer
from rich.console import Console
from rich.table import Table

from client import crypto_utils, local_store, shamir
from client.api_client import ApiClient, ApiClientError
from client.password_generator import PasswordGeneratorError, generate_secure_password
from client.vault import (
    EntryNotFoundError,
    Vault,
    VaultError,
    add_entry,
    create_empty_vault,
    delete_entry,
    deserialize_vault,
    edit_entry,
    list_entries,
    serialize_vault,
)


app = typer.Typer(no_args_is_help=True, help="Distributed password manager client.")
console = Console()


class ClientError(RuntimeError):
    pass


class IntegrationUnavailableError(ClientError):
    pass


class Backend(Protocol):
    def generate_master_key(self) -> bytes: ...

    def split_master_key(self, master_key: bytes) -> tuple[str, str, str]: ...

    def reconstruct_master_key(self, first_share: str, second_share: str) -> bytes: ...

    def encrypt_vault(self, master_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]: ...

    def decrypt_vault(
        self,
        master_key: bytes,
        ciphertext: bytes,
        nonce: bytes,
    ) -> bytes: ...

    def save_local_state(
        self,
        user_id: str,
        master_password: str,
        local_share: str,
        backup_ciphertext: bytes,
        backup_nonce: bytes,
    ) -> None: ...

    def load_local_share(self, user_id: str, master_password: str) -> str: ...

    def save_backup(self, user_id: str, ciphertext: bytes, nonce: bytes) -> None: ...

    def load_backup(self, user_id: str) -> tuple[bytes, bytes]: ...


class VaultApi(Protocol):
    def init_vault(
        self,
        user_id: str,
        server_share: str,
        vault_ciphertext: str,
        vault_nonce: str,
    ) -> dict[str, Any]: ...

    def fetch_vault(self, user_id: str) -> dict[str, Any]: ...

    def update_vault(
        self,
        user_id: str,
        vault_ciphertext: str,
        vault_nonce: str,
    ) -> dict[str, Any]: ...


@dataclass
class VaultSession:
    user_id: str
    master_key: bytes
    vault: Vault
    mode: str
    source_ciphertext: str | None = None
    source_nonce: str | None = None

    @property
    def read_only(self) -> bool:
        return self.mode == "backup"


class VaultWorkflow:
    def __init__(self, backend: Backend, api: VaultApi) -> None:
        self.backend = backend
        self.api = api

    def initialize(self, user_id: str, master_password: str) -> str:
        user_id = _required(user_id, "User ID")
        master_password = _required(master_password, "Master password")
        master_key = self.backend.generate_master_key()
        local_share, server_share, recovery_share = self.backend.split_master_key(master_key)
        ciphertext, nonce = self.backend.encrypt_vault(
            master_key,
            serialize_vault(create_empty_vault()),
        )
        encoded_ciphertext = _encode_bytes(ciphertext)
        encoded_nonce = _encode_bytes(nonce)

        try:
            self.backend.save_local_state(
                user_id,
                master_password,
                local_share,
                ciphertext,
                nonce,
            )
        except Exception as exc:
            raise ClientError("Local state could not be saved.") from exc
        self.api.init_vault(
            user_id,
            server_share,
            encoded_ciphertext,
            encoded_nonce,
        )
        return recovery_share

    def open_normal(self, user_id: str, master_password: str) -> VaultSession:
        local_share = self.backend.load_local_share(user_id, master_password)
        remote = self.api.fetch_vault(user_id)
        master_key = self.backend.reconstruct_master_key(
            local_share,
            remote["server_share"],
        )
        plaintext = self.backend.decrypt_vault(
            master_key,
            _decode_bytes(remote["vault_ciphertext"]),
            _decode_bytes(remote["vault_nonce"]),
        )
        return VaultSession(
            user_id=user_id,
            master_key=master_key,
            vault=deserialize_vault(plaintext),
            mode="normal",
            source_ciphertext=remote["vault_ciphertext"],
            source_nonce=remote["vault_nonce"],
        )

    def open_backup(
        self,
        user_id: str,
        master_password: str,
        recovery_share: str,
    ) -> VaultSession:
        local_share = self.backend.load_local_share(user_id, master_password)
        master_key = self.backend.reconstruct_master_key(
            local_share,
            _required(recovery_share, "Recovery share"),
        )
        ciphertext, nonce = self.backend.load_backup(user_id)
        plaintext = self.backend.decrypt_vault(master_key, ciphertext, nonce)
        return VaultSession(
            user_id=user_id,
            master_key=master_key,
            vault=deserialize_vault(plaintext),
            mode="backup",
        )

    def persist(self, session: VaultSession) -> None:
        if session.read_only:
            raise ClientError("Backup mode is read-only.")

        ciphertext, nonce = self.backend.encrypt_vault(
            session.master_key,
            serialize_vault(session.vault),
        )
        encoded_ciphertext = _encode_bytes(ciphertext)
        encoded_nonce = _encode_bytes(nonce)
        self.api.update_vault(
            session.user_id,
            encoded_ciphertext,
            encoded_nonce,
        )
        try:
            self.backend.save_backup(session.user_id, ciphertext, nonce)
        except Exception as exc:
            rollback_failed = False
            if session.source_ciphertext and session.source_nonce:
                try:
                    self.api.update_vault(
                        session.user_id,
                        session.source_ciphertext,
                        session.source_nonce,
                    )
                except Exception:
                    rollback_failed = True
            detail = (
                " Local backup failed and server rollback also failed."
                if rollback_failed
                else " Server update was rolled back."
            )
            raise ClientError(f"Could not save local backup.{detail}") from exc

        session.source_ciphertext = encoded_ciphertext
        session.source_nonce = encoded_nonce


class RuntimeBackend:
    def generate_master_key(self) -> bytes:
        return _call(crypto_utils, "generate_master_key")

    def split_master_key(self, master_key: bytes) -> tuple[str, str, str]:
        shares = _call(shamir, "split_secret", master_key)
        if len(shares) != 3:
            raise ClientError("Shamir split must return exactly three shares.")
        serialized = tuple(_call(shamir, "serialize_share", share) for share in shares)
        return serialized  # type: ignore[return-value]

    def reconstruct_master_key(self, first_share: str, second_share: str) -> bytes:
        shares = [
            _call(shamir, "deserialize_share", first_share),
            _call(shamir, "deserialize_share", second_share),
        ]
        return _call(shamir, "reconstruct_secret", shares)

    def encrypt_vault(self, master_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        result = _call(crypto_utils, "aes_gcm_encrypt", master_key, plaintext)
        if not isinstance(result, tuple) or len(result) != 2:
            raise ClientError("aes_gcm_encrypt must return (ciphertext, nonce).")
        return result

    def decrypt_vault(
        self,
        master_key: bytes,
        ciphertext: bytes,
        nonce: bytes,
    ) -> bytes:
        return _call(
            crypto_utils,
            "aes_gcm_decrypt",
            master_key,
            ciphertext,
            nonce,
        )

    def save_local_state(
        self,
        user_id: str,
        master_password: str,
        local_share: str,
        backup_ciphertext: bytes,
        backup_nonce: bytes,
    ) -> None:
        salt = secrets.token_bytes(16)
        derived_key = _call(crypto_utils, "derive_key", master_password, salt)
        encrypted_share, share_nonce = self.encrypt_vault(
            derived_key,
            local_share.encode("utf-8"),
        )
        _call(
            local_store,
            "save_client_config",
            user_id,
            {
                "salt": _encode_bytes(salt),
                "kdf": "pbkdf2-hmac-sha256",
                "kdf_iterations": crypto_utils.KDF_ITERATIONS,
                "kdf_key_length": crypto_utils.MASTER_KEY_SIZE,
                "encrypted_local_share": _encode_bytes(encrypted_share),
                "local_share_nonce": _encode_bytes(share_nonce),
                "backup_ciphertext": _encode_bytes(backup_ciphertext),
                "backup_nonce": _encode_bytes(backup_nonce),
            },
        )

    def load_local_share(self, user_id: str, master_password: str) -> str:
        config = _call(local_store, "load_client_config", user_id)
        derived_key = _call(
            crypto_utils,
            "derive_key",
            master_password,
            _decode_bytes(config["salt"]),
            iterations=int(config.get("kdf_iterations", crypto_utils.KDF_ITERATIONS)),
        )
        plaintext = self.decrypt_vault(
            derived_key,
            _decode_bytes(config["encrypted_local_share"]),
            _decode_bytes(config["local_share_nonce"]),
        )
        return plaintext.decode("utf-8")

    def save_backup(self, user_id: str, ciphertext: bytes, nonce: bytes) -> None:
        _call(local_store, "save_backup_vault", user_id, ciphertext, nonce)

    def load_backup(self, user_id: str) -> tuple[bytes, bytes]:
        result = _call(local_store, "load_backup_vault", user_id)
        if not isinstance(result, tuple) or len(result) != 2:
            raise ClientError("load_backup_vault must return (ciphertext, nonce).")
        return result


def _workflow() -> VaultWorkflow:
    return VaultWorkflow(RuntimeBackend(), ApiClient())


@app.command("init")
def init_command(
    user_id: str = typer.Option(..., prompt=True),
) -> None:
    master_password = typer.prompt(
        "Master password",
        hide_input=True,
        confirmation_prompt=True,
    )
    _run_command(
        lambda: _show_recovery_share(
            _workflow().initialize(user_id, master_password)
        )
    )


@app.command()
def login(user_id: str = typer.Option(..., prompt=True)) -> None:
    master_password = typer.prompt("Master password", hide_input=True)
    _run_command(
        lambda: _show_vault(
            _workflow().open_normal(user_id, master_password),
            show_passwords=False,
        )
    )


@app.command("list")
def list_command(
    user_id: str = typer.Option(..., prompt=True),
    show_passwords: bool = typer.Option(False, "--show-passwords"),
) -> None:
    master_password = typer.prompt("Master password", hide_input=True)
    _run_command(
        lambda: _show_vault(
            _workflow().open_normal(user_id, master_password),
            show_passwords=show_passwords,
        )
    )


@app.command()
def add(
    user_id: str = typer.Option(..., prompt=True),
    nama_layanan: str = typer.Option(..., prompt="Service name"),
    username: str = typer.Option(..., prompt=True),
    catatan: str = typer.Option("", prompt="Note"),
    generated: bool = typer.Option(False, "--generate"),
    length: int = typer.Option(20, min=1),
) -> None:
    master_password = typer.prompt("Master password", hide_input=True)

    def action() -> None:
        password = (
            generate_secure_password(length)
            if generated
            else typer.prompt("Password", hide_input=True)
        )
        workflow = _workflow()
        session = workflow.open_normal(user_id, master_password)
        entry = add_entry(
            session.vault,
            nama_layanan,
            username,
            password,
            catatan,
        )
        workflow.persist(session)
        console.print(f"Entry added: {entry['id']}")
        if generated:
            console.print(f"Generated password: {password}")

    _run_command(action)


@app.command()
def edit(
    user_id: str = typer.Option(..., prompt=True),
    entry_id: str = typer.Option(..., prompt=True),
    nama_layanan: str | None = typer.Option(None),
    username: str | None = typer.Option(None),
    catatan: str | None = typer.Option(None),
    change_password: bool = typer.Option(False, "--change-password"),
) -> None:
    master_password = typer.prompt("Master password", hide_input=True)

    def action() -> None:
        new_password = (
            typer.prompt("New password", hide_input=True, confirmation_prompt=True)
            if change_password
            else None
        )
        workflow = _workflow()
        session = workflow.open_normal(user_id, master_password)
        edit_entry(
            session.vault,
            entry_id,
            nama_layanan=nama_layanan,
            username=username,
            password=new_password,
            catatan=catatan,
        )
        workflow.persist(session)
        console.print(f"Entry updated: {entry_id}")

    _run_command(action)


@app.command()
def delete(
    user_id: str = typer.Option(..., prompt=True),
    entry_id: str = typer.Option(..., prompt=True),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    master_password = typer.prompt("Master password", hide_input=True)

    def action() -> None:
        if not yes and not typer.confirm(f"Delete entry {entry_id}?"):
            raise typer.Abort()
        workflow = _workflow()
        session = workflow.open_normal(user_id, master_password)
        delete_entry(session.vault, entry_id)
        workflow.persist(session)
        console.print(f"Entry deleted: {entry_id}")

    _run_command(action)


@app.command("generate-password")
def generate_password(
    length: int = typer.Option(20, min=1, prompt=True),
    uppercase: bool = typer.Option(True, "--uppercase/--no-uppercase"),
    lowercase: bool = typer.Option(True, "--lowercase/--no-lowercase"),
    digits: bool = typer.Option(True, "--digits/--no-digits"),
    symbols: bool = typer.Option(True, "--symbols/--no-symbols"),
) -> None:
    _run_command(
        lambda: console.print(
            generate_secure_password(
                length,
                uppercase=uppercase,
                lowercase=lowercase,
                digits=digits,
                symbols=symbols,
            )
        )
    )


@app.command()
def backup(
    user_id: str = typer.Option(..., prompt=True),
    show_passwords: bool = typer.Option(False, "--show-passwords"),
) -> None:
    master_password = typer.prompt("Master password", hide_input=True)
    recovery_share = typer.prompt("Recovery share", hide_input=True)
    _run_command(
        lambda: _show_vault(
            _workflow().open_backup(
                user_id,
                master_password,
                recovery_share,
            ),
            show_passwords=show_passwords,
        )
    )


def _show_recovery_share(recovery_share: str) -> None:
    console.print("[bold yellow]Save this recovery share now.[/bold yellow]")
    console.print("It will not be shown again.")
    console.print(recovery_share)


def _show_vault(session: VaultSession, *, show_passwords: bool) -> None:
    entries = list_entries(session.vault)
    table = Table(title=f"Vault ({session.mode} mode)")
    table.add_column("ID")
    table.add_column("Service")
    table.add_column("Username")
    table.add_column("Password")
    table.add_column("Note")
    for entry in entries:
        table.add_row(
            entry["id"],
            entry["nama_layanan"],
            entry["username"],
            entry["password"] if show_passwords else "********",
            entry["catatan"],
        )
    console.print(table)


def _run_command(action: Callable[[], None]) -> None:
    try:
        action()
    except typer.Abort:
        raise
    except (
        ApiClientError,
        ClientError,
        EntryNotFoundError,
        IntegrationUnavailableError,
        PasswordGeneratorError,
        VaultError,
        KeyError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        console.print("[red]Error:[/red] Vault access or authentication failed.")
        raise typer.Exit(code=1) from exc


def _call(module: Any, name: str, *args: Any, **kwargs: Any) -> Any:
    function = getattr(module, name, None)
    if not callable(function):
        raise IntegrationUnavailableError(
            f"Missing teammate integration function: {module.__name__}.{name}()."
        )
    return function(*args, **kwargs)


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ClientError(f"{label} must not be empty.")
    return value


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_bytes(value: str) -> bytes:
    if not isinstance(value, str):
        raise ClientError("Expected base64url text.")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise ClientError("Invalid base64url data.") from exc


if __name__ == "__main__":
    app()
