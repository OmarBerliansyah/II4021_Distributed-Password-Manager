from __future__ import annotations

import base64
import binascii
import os
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA_PATH = Path(__file__).with_name("schema.sql")
DEFAULT_DB_PATH = Path(__file__).with_name("vaults.db")


class DuplicateVaultError(Exception):
    pass


class InvalidCiphertextError(ValueError):
    pass


def get_db_path() -> Path:
    return Path(os.getenv("DPM_DB_PATH", DEFAULT_DB_PATH))


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path is not None else get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: str | Path | None = None) -> None:
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with connect(db_path) as connection:
        connection.executescript(schema)


def _decode_ciphertext(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            f"{value}{padding}".encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise InvalidCiphertextError("vault_ciphertext must be base64url encoded.") from exc


def _encode_ciphertext(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _row_to_vault(row: sqlite3.Row) -> dict[str, Any]:
    vault = dict(row)
    vault["vault_ciphertext"] = _encode_ciphertext(vault["vault_ciphertext"])
    return vault


def create_vault(
    *,
    user_id: str,
    server_share: str,
    vault_ciphertext: str,
    vault_nonce: str,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    try:
        with connect(db_path) as connection:
            connection.execute(
                """
                INSERT INTO vaults (
                    user_id,
                    server_share,
                    vault_ciphertext,
                    vault_nonce
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    user_id,
                    server_share,
                    _decode_ciphertext(vault_ciphertext),
                    vault_nonce,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise DuplicateVaultError(user_id) from exc

    vault = get_vault(user_id, db_path=db_path)
    if vault is None:
        raise RuntimeError("Vault creation succeeded but record could not be read.")
    return vault


def get_vault(user_id: str, db_path: str | Path | None = None) -> dict[str, Any] | None:
    with connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT
                user_id,
                server_share,
                vault_ciphertext,
                vault_nonce,
                created_at,
                updated_at
            FROM vaults
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

    return _row_to_vault(row) if row is not None else None


def update_vault(
    *,
    user_id: str,
    vault_ciphertext: str,
    vault_nonce: str,
    db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    with connect(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE vaults
            SET
                vault_ciphertext = ?,
                vault_nonce = ?,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE user_id = ?
            """,
            (_decode_ciphertext(vault_ciphertext), vault_nonce, user_id),
        )

    if cursor.rowcount == 0:
        return None
    return get_vault(user_id, db_path=db_path)
