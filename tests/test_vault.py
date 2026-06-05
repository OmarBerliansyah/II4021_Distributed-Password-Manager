import json

import pytest

from client.vault import (
    EntryNotFoundError,
    VaultError,
    add_entry,
    create_empty_vault,
    delete_entry,
    deserialize_vault,
    edit_entry,
    list_entries,
    serialize_vault,
)


def test_create_add_list_edit_and_delete_entry():
    vault = create_empty_vault()

    created = add_entry(
        vault,
        "GitHub",
        "fulan@example.com",
        "secret",
        "Main account",
        entry_id="entry-1",
    )

    assert created == {
        "id": "entry-1",
        "nama_layanan": "GitHub",
        "username": "fulan@example.com",
        "password": "secret",
        "catatan": "Main account",
    }
    assert list_entries(vault) == [created]

    updated = edit_entry(
        vault,
        "entry-1",
        password="new-secret",
        catatan="Updated",
    )
    assert updated["password"] == "new-secret"
    assert updated["catatan"] == "Updated"

    deleted = delete_entry(vault, "entry-1")
    assert deleted == updated
    assert list_entries(vault) == []


def test_list_entries_returns_copy():
    vault = create_empty_vault()
    add_entry(vault, "GitHub", "fulan", "secret", entry_id="entry-1")

    listed = list_entries(vault)
    listed[0]["password"] = "changed-outside"

    assert vault["entries"][0]["password"] == "secret"


def test_serialize_deserialize_round_trip_with_unicode():
    vault = create_empty_vault()
    add_entry(
        vault,
        "Portal Kampus",
        "fulan",
        "rahasia",
        "Catatan aman",
        entry_id="entry-1",
    )

    encoded = serialize_vault(vault)

    assert isinstance(encoded, bytes)
    assert deserialize_vault(encoded) == vault


@pytest.mark.parametrize("field", ["nama_layanan", "username", "password"])
def test_add_rejects_empty_required_fields(field):
    values = {
        "nama_layanan": "GitHub",
        "username": "fulan",
        "password": "secret",
    }
    values[field] = " "

    with pytest.raises(VaultError, match="must not be empty"):
        add_entry(create_empty_vault(), **values)


def test_edit_requires_change_and_existing_entry():
    vault = create_empty_vault()
    add_entry(vault, "GitHub", "fulan", "secret", entry_id="entry-1")

    with pytest.raises(VaultError, match="At least one field"):
        edit_entry(vault, "entry-1")
    with pytest.raises(EntryNotFoundError):
        edit_entry(vault, "missing", password="new")


def test_delete_missing_entry_fails():
    with pytest.raises(EntryNotFoundError):
        delete_entry(create_empty_vault(), "missing")


def test_deserialize_rejects_invalid_or_extra_structure():
    with pytest.raises(VaultError):
        deserialize_vault(b"not-json")

    invalid = json.dumps({"entries": [], "master_key": "must-not-exist"})
    with pytest.raises(VaultError):
        deserialize_vault(invalid)


def test_duplicate_entry_ids_are_rejected():
    vault = create_empty_vault()
    add_entry(vault, "GitHub", "fulan", "secret", entry_id="same-id")

    with pytest.raises(VaultError, match="already exists"):
        add_entry(vault, "Email", "fulan", "secret", entry_id="same-id")
