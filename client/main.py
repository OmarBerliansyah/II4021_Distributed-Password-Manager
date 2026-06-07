from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

import typer
from click import Choice
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from client import crypto_utils, local_store, shamir
from client.api_client import ApiClient, ApiClientError
from client.password_generator import PasswordGeneratorError, generate_secure_password
from client.visual_crypto import (
    VisualCryptoError,
    combine_visual_shares,
    create_visual_recovery_shares,
    decode_qr,
)
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


app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=False,
    help="Distributed password manager client.",
)
console = Console()
VISUAL_OUTPUT_ROOT = "visual-crypto"


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
        self._ensure_vault_does_not_exist(user_id)
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

    def _ensure_vault_does_not_exist(self, user_id: str) -> None:
        try:
            self.api.fetch_vault(user_id)
        except ApiClientError as exc:
            if str(exc) == "Vault not found.":
                return
            raise
        raise ClientError("Vault already exists for this user.")

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


@app.callback()
def main_menu(ctx: typer.Context) -> None:
    """Open the interactive application when no subcommand is provided."""
    if ctx.invoked_subcommand is None:
        run_interactive()


def run_interactive() -> None:
    while True:
        _show_main_menu()
        choice = typer.prompt(
            "Choose an option",
            type=Choice(["0", "1", "2", "3", "4", "5"]),
        )
        if choice == "0":
            console.print("[cyan]Goodbye.[/cyan]")
            return
        if choice == "1":
            _interactive_initialize()
        elif choice == "2":
            _interactive_login()
        elif choice == "3":
            _interactive_backup()
        elif choice == "4":
            _interactive_generate_password()
        else:
            _interactive_visual_crypto()


def _show_main_menu() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]Distributed Password Manager[/bold cyan]\n"
            "Client-side encryption with Shamir Secret Sharing",
            border_style="cyan",
        )
    )
    console.print("[bold]1.[/bold] Initialize new vault")
    console.print("[bold]2.[/bold] Login to vault")
    console.print("[bold]3.[/bold] Open backup mode")
    console.print("[bold]4.[/bold] Generate secure password")
    console.print("[bold]5.[/bold] Visual recovery tools")
    console.print("[bold]0.[/bold] Exit")


def _interactive_initialize() -> None:
    user_id = typer.prompt("User ID")
    master_password = typer.prompt(
        "Master password",
        hide_input=True,
        confirmation_prompt=True,
    )

    def action() -> None:
        recovery_share = _workflow().initialize(user_id, master_password)
        _show_recovery_share(recovery_share)
        if typer.confirm("Create visual recovery shares now?", default=False):
            output_dir = _visual_output_directory(
                typer.prompt("Save name", default=user_id)
            )
            files = create_visual_recovery_shares(recovery_share, output_dir)
            _show_visual_files(files)

    _run_interactive_action(action)


def _interactive_login() -> None:
    user_id = typer.prompt("User ID")
    master_password = typer.prompt("Master password", hide_input=True)
    session: VaultSession | None = None

    def action() -> None:
        nonlocal session
        session = _workflow().open_normal(user_id, master_password)

    if _run_interactive_action(action) and session is not None:
        console.print(f"[green]Vault opened for {session.user_id}.[/green]")
        _interactive_vault_session(session)


def _interactive_vault_session(session: VaultSession) -> None:
    workflow = _workflow()
    while True:
        console.print()
        console.print(f"[bold cyan]Vault: {session.user_id}[/bold cyan]")
        console.print("[bold]1.[/bold] List entries")
        console.print("[bold]2.[/bold] Add entry")
        console.print("[bold]3.[/bold] Edit entry")
        console.print("[bold]4.[/bold] Delete entry")
        console.print("[bold]0.[/bold] Logout")
        choice = typer.prompt(
            "Choose an option",
            type=Choice(["0", "1", "2", "3", "4"]),
        )
        if choice == "0":
            console.print("[cyan]Logged out.[/cyan]")
            return
        if choice == "1":
            _show_vault(
                session,
                show_passwords=typer.confirm("Show passwords?", default=False),
            )
        elif choice == "2":
            _interactive_add_entry(workflow, session)
        elif choice == "3":
            _interactive_edit_entry(workflow, session)
        else:
            _interactive_delete_entry(workflow, session)


def _interactive_add_entry(
    workflow: VaultWorkflow,
    session: VaultSession,
) -> None:
    nama_layanan = typer.prompt("Service name")
    username = typer.prompt("Username or email")
    catatan = typer.prompt("Note", default="")
    use_generated = typer.confirm("Generate password automatically?", default=False)
    if use_generated:
        password = _interactive_password_value()
        console.print(f"Generated password: [bold]{password}[/bold]")
    else:
        password = typer.prompt("Password", hide_input=True)

    def action() -> None:
        entry = add_entry(
            session.vault,
            nama_layanan,
            username,
            password,
            catatan,
        )
        workflow.persist(session)
        console.print(f"[green]Entry added: {entry['id']}[/green]")

    _run_interactive_action(action)


def _interactive_edit_entry(
    workflow: VaultWorkflow,
    session: VaultSession,
) -> None:
    _show_vault(session, show_passwords=False)
    entry_id = typer.prompt("Entry ID")
    console.print("[bold]1.[/bold] Service name")
    console.print("[bold]2.[/bold] Username or email")
    console.print("[bold]3.[/bold] Password")
    console.print("[bold]4.[/bold] Note")
    choice = typer.prompt(
        "Field to edit",
        type=Choice(["1", "2", "3", "4"]),
    )
    updates: dict[str, str] = {}
    if choice == "1":
        updates["nama_layanan"] = typer.prompt("New service name")
    elif choice == "2":
        updates["username"] = typer.prompt("New username or email")
    elif choice == "3":
        if typer.confirm("Generate password automatically?", default=False):
            updates["password"] = _interactive_password_value()
            console.print(f"Generated password: [bold]{updates['password']}[/bold]")
        else:
            updates["password"] = typer.prompt(
                "New password",
                hide_input=True,
                confirmation_prompt=True,
            )
    else:
        updates["catatan"] = typer.prompt("New note", default="")

    def action() -> None:
        edit_entry(session.vault, entry_id, **updates)
        workflow.persist(session)
        console.print(f"[green]Entry updated: {entry_id}[/green]")

    _run_interactive_action(action)


def _interactive_delete_entry(
    workflow: VaultWorkflow,
    session: VaultSession,
) -> None:
    _show_vault(session, show_passwords=False)
    entry_id = typer.prompt("Entry ID")
    if not typer.confirm(f"Delete entry {entry_id}?", default=False):
        console.print("[yellow]Deletion cancelled.[/yellow]")
        return

    def action() -> None:
        delete_entry(session.vault, entry_id)
        workflow.persist(session)
        console.print(f"[green]Entry deleted: {entry_id}[/green]")

    _run_interactive_action(action)


def _interactive_backup() -> None:
    user_id = typer.prompt("User ID")
    master_password = typer.prompt("Master password", hide_input=True)
    recovery_share = typer.prompt("Recovery share", hide_input=True)

    def action() -> None:
        session = _workflow().open_backup(
            user_id,
            master_password,
            recovery_share,
        )
        _show_vault(
            session,
            show_passwords=typer.confirm("Show passwords?", default=False),
        )
        console.print("[yellow]Backup mode is read-only.[/yellow]")

    _run_interactive_action(action)


def _interactive_generate_password() -> None:
    password = _interactive_password_value()
    console.print(f"Generated password: [bold green]{password}[/bold green]")


def _interactive_password_value() -> str:
    length = typer.prompt("Password length", default=20, type=int)
    uppercase = typer.confirm("Include uppercase letters?", default=True)
    lowercase = typer.confirm("Include lowercase letters?", default=True)
    digits = typer.confirm("Include numbers?", default=True)
    symbols = typer.confirm("Include symbols?", default=True)
    return generate_secure_password(
        length,
        uppercase=uppercase,
        lowercase=lowercase,
        digits=digits,
        symbols=symbols,
    )


def _interactive_visual_crypto() -> None:
    while True:
        console.print()
        console.print("[bold cyan]Visual Recovery Tools[/bold cyan]")
        console.print("[bold]1.[/bold] Create QR and two visual shares")
        console.print("[bold]2.[/bold] Combine two visual shares")
        console.print("[bold]0.[/bold] Back")
        choice = typer.prompt(
            "Choose an option",
            type=Choice(["0", "1", "2"]),
        )
        if choice == "0":
            return
        if choice == "1":
            recovery_share = typer.prompt("Recovery share", hide_input=True)
            output_dir = _visual_output_directory(
                typer.prompt("Save name", default="recovery")
            )

            def split_action() -> None:
                shamir.deserialize_share(recovery_share)
                files = create_visual_recovery_shares(recovery_share, output_dir)
                _show_visual_files(files)

            _run_interactive_action(split_action)
        else:
            share_1 = Path(typer.prompt("Visual share 1 path"))
            share_2 = Path(typer.prompt("Visual share 2 path"))
            output_dir = _visual_output_directory(
                typer.prompt("Save name", default="combined")
            )
            output = output_dir / "combined_qr.png"

            def combine_action() -> None:
                combined = combine_visual_shares(share_1, share_2, output)
                recovered_share = decode_qr(combined)
                shamir.deserialize_share(recovered_share)
                console.print(f"Combined QR: {combined}")
                console.print("[green]Recovered share is valid.[/green]")
                console.print(recovered_share)

            _run_interactive_action(combine_action)


def _show_visual_files(files: Any) -> None:
    console.print(f"Original QR: {files.original_qr}")
    console.print(f"Visual share 1: {files.share_1}")
    console.print(f"Visual share 2: {files.share_2}")
    console.print(f"Combined QR: {files.combined_qr}")
    console.print("[green]Combined QR decoded successfully.[/green]")


def _visual_output_directory(save_name: str) -> Path:
    normalized = save_name.strip()
    if not normalized:
        raise VisualCryptoError("Save name must not be empty.")
    if normalized in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9._ -]+", normalized):
        raise VisualCryptoError(
            "Save name may only contain letters, numbers, spaces, '.', '-' and '_'."
        )

    output_dir = Path.cwd() / VISUAL_OUTPUT_ROOT / normalized
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _run_interactive_action(action: Callable[[], None]) -> bool:
    try:
        action()
        return True
    except (
        ApiClientError,
        ClientError,
        EntryNotFoundError,
        IntegrationUnavailableError,
        PasswordGeneratorError,
        VisualCryptoError,
        VaultError,
        KeyError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        console.print(f"[red]Error:[/red] {exc}")
    except Exception:
        console.print("[red]Error:[/red] Vault access or authentication failed.")
    return False


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


@app.command("visual-split")
def visual_split(
    output_dir: Path = typer.Option(
        Path("visual-crypto"),
        "--output-dir",
        file_okay=False,
        dir_okay=True,
    ),
) -> None:
    recovery_share = typer.prompt("Recovery share", hide_input=True)

    def action() -> None:
        shamir.deserialize_share(recovery_share)
        files = create_visual_recovery_shares(recovery_share, output_dir)
        console.print(f"Original QR: {files.original_qr}")
        console.print(f"Visual share 1: {files.share_1}")
        console.print(f"Visual share 2: {files.share_2}")
        console.print(f"Combined QR: {files.combined_qr}")
        console.print("[green]Combined QR decoded successfully.[/green]")

    _run_command(action)


@app.command("visual-combine")
def visual_combine(
    share_1: Path = typer.Option(..., "--share-1", exists=True, dir_okay=False),
    share_2: Path = typer.Option(..., "--share-2", exists=True, dir_okay=False),
    output: Path = typer.Option(Path("combined_qr.png"), "--output", dir_okay=False),
) -> None:
    def action() -> None:
        combined = combine_visual_shares(share_1, share_2, output)
        recovered_share = decode_qr(combined)
        shamir.deserialize_share(recovered_share)
        console.print(f"Combined QR: {combined}")
        console.print("[green]Recovered share is valid.[/green]")
        console.print(recovered_share)

    _run_command(action)


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
        VisualCryptoError,
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
