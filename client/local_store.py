from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any


CLIENT_DIR_ENV = "DPM_CLIENT_DIR"
DEFAULT_CLIENT_DIR = Path(".vault_client")


class LocalStoreError(RuntimeError):
    pass


def save_client_config(user_id: str, config: dict[str, Any]) -> None:

    if not isinstance(config, dict):
        raise LocalStoreError("Client config must be a dictionary.")

    current = _read_state(user_id)
    current.update(config)
    _write_state(user_id, current)


def load_client_config(user_id: str) -> dict[str, Any]:
    state = _read_state(user_id)
    required = {
        "salt",
        "encrypted_local_share",
        "local_share_nonce",
        "backup_ciphertext",
        "backup_nonce",
    }
    missing = sorted(required - set(state))

    if missing:
        raise LocalStoreError(f"Client config is missing: {', '.join(missing)}")
    
    return state


def save_backup_vault(user_id: str, ciphertext: bytes, nonce: bytes) -> None:
    state = _read_state(user_id)

    state["backup_ciphertext"] = _encode_bytes(ciphertext)
    state["backup_nonce"] = _encode_bytes(nonce)

    _write_state(user_id, state)


def load_backup_vault(user_id: str) -> tuple[bytes, bytes]:
    state = _read_state(user_id)

    try:
        return _decode_bytes(state["backup_ciphertext"]), _decode_bytes(state["backup_nonce"])
    except KeyError as exc:
        raise LocalStoreError("Backup vault is not available.") from exc


def client_config_path(user_id: str) -> Path:
    root = Path(os.getenv(CLIENT_DIR_ENV, DEFAULT_CLIENT_DIR))
    digest = hashlib.sha256(_clean_user_id(user_id).encode("utf-8")).hexdigest()

    return root / f"{digest}.json"


def _read_state(user_id: str) -> dict[str, Any]:
    path = client_config_path(user_id)

    if not path.exists():
        return {}
    
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalStoreError("Local client config could not be read.") from exc
    
    if not isinstance(data, dict):
        raise LocalStoreError("Local client config is invalid.")
    
    return data


def _write_state(user_id: str, state: dict[str, Any]) -> None:
    path = client_config_path(user_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with path.open("w", encoding="utf-8") as file:
            json.dump(state, file, ensure_ascii=False, indent=2, sort_keys=True)
            file.write("\n")
    except OSError as exc:
        raise LocalStoreError("Local client config could not be saved.") from exc


def _clean_user_id(user_id: str) -> str:

    if not isinstance(user_id, str) or not user_id.strip():
        raise LocalStoreError("User ID must not be empty.")
    
    return user_id.strip()


def _encode_bytes(value: bytes) -> str:

    if not isinstance(value, bytes):
        raise LocalStoreError("Expected bytes.")
    
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_bytes(value: str) -> bytes:

    if not isinstance(value, str):
        raise LocalStoreError("Expected base64url text.")
    
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise LocalStoreError("Invalid base64url data in local storage.") from exc
