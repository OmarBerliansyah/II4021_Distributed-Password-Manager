from __future__ import annotations

import json
from copy import deepcopy
from typing import Any
from uuid import uuid4


Vault = dict[str, list[dict[str, str]]]
Entry = dict[str, str]

REQUIRED_ENTRY_FIELDS = ("nama_layanan", "username", "password")
OPTIONAL_ENTRY_FIELDS = ("catatan",)
ENTRY_FIELDS = ("id", *REQUIRED_ENTRY_FIELDS, *OPTIONAL_ENTRY_FIELDS)


class VaultError(ValueError):
    pass


class EntryNotFoundError(VaultError):
    pass


def create_empty_vault() -> Vault:
    return {"entries": []}


def list_entries(vault: Vault) -> list[Entry]:
    _validate_vault(vault)
    return deepcopy(vault["entries"])


def add_entry(
    vault: Vault,
    nama_layanan: str,
    username: str,
    password: str,
    catatan: str = "",
    *,
    entry_id: str | None = None,
) -> Entry:
    _validate_vault(vault)
    entry = _build_entry(
        entry_id=entry_id or str(uuid4()),
        nama_layanan=nama_layanan,
        username=username,
        password=password,
        catatan=catatan,
    )
    if any(existing["id"] == entry["id"] for existing in vault["entries"]):
        raise VaultError(f"Entry ID already exists: {entry['id']}")

    vault["entries"].append(entry)
    return deepcopy(entry)


def edit_entry(
    vault: Vault,
    entry_id: str,
    *,
    nama_layanan: str | None = None,
    username: str | None = None,
    password: str | None = None,
    catatan: str | None = None,
) -> Entry:
    _validate_vault(vault)
    entry = _find_entry(vault, entry_id)
    updates = {
        "nama_layanan": nama_layanan,
        "username": username,
        "password": password,
        "catatan": catatan,
    }
    if all(value is None for value in updates.values()):
        raise VaultError("At least one field must be changed.")

    candidate = {**entry}
    for field, value in updates.items():
        if value is not None:
            candidate[field] = _validate_field(field, value)

    entry.update(candidate)
    return deepcopy(entry)


def delete_entry(vault: Vault, entry_id: str) -> Entry:
    _validate_vault(vault)
    for index, entry in enumerate(vault["entries"]):
        if entry["id"] == entry_id:
            return deepcopy(vault["entries"].pop(index))
    raise EntryNotFoundError(f"Entry not found: {entry_id}")


def serialize_vault(vault: Vault) -> bytes:
    _validate_vault(vault)
    return json.dumps(
        vault,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def deserialize_vault(data: bytes | str) -> Vault:
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        parsed = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise VaultError("Vault data is not valid UTF-8 JSON.") from exc

    _validate_vault(parsed)
    return deepcopy(parsed)


def _build_entry(
    *,
    entry_id: str,
    nama_layanan: str,
    username: str,
    password: str,
    catatan: str,
) -> Entry:
    return {
        "id": _validate_field("id", entry_id),
        "nama_layanan": _validate_field("nama_layanan", nama_layanan),
        "username": _validate_field("username", username),
        "password": _validate_field("password", password),
        "catatan": _validate_field("catatan", catatan),
    }


def _find_entry(vault: Vault, entry_id: str) -> Entry:
    for entry in vault["entries"]:
        if entry["id"] == entry_id:
            return entry
    raise EntryNotFoundError(f"Entry not found: {entry_id}")


def _validate_field(field: str, value: Any) -> str:
    if not isinstance(value, str):
        raise VaultError(f"{field} must be a string.")
    if field in ("id", *REQUIRED_ENTRY_FIELDS) and not value.strip():
        raise VaultError(f"{field} must not be empty.")
    return value


def _validate_vault(vault: Any) -> None:
    if not isinstance(vault, dict) or set(vault) != {"entries"}:
        raise VaultError("Vault must contain exactly one 'entries' list.")
    if not isinstance(vault["entries"], list):
        raise VaultError("Vault entries must be a list.")

    seen_ids: set[str] = set()
    for raw_entry in vault["entries"]:
        if not isinstance(raw_entry, dict) or set(raw_entry) != set(ENTRY_FIELDS):
            raise VaultError("Each vault entry has an invalid structure.")
        for field in ENTRY_FIELDS:
            _validate_field(field, raw_entry[field])
        if raw_entry["id"] in seen_ids:
            raise VaultError(f"Duplicate entry ID: {raw_entry['id']}")
        seen_ids.add(raw_entry["id"])
