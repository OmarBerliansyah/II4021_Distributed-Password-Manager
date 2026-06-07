import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from client.api_client import ApiClient, ApiClientError
from server import db
from server.app import app


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "vaults.db"


@pytest.fixture()
def client(db_path):
    app.state.db_path = db_path
    with TestClient(app) as test_client:
        yield test_client


def sample_payload(user_id="fulan"):
    return {
        "user_id": user_id,
        "server_share": '{"x":2,"y":"c2VydmVyLXNoYXJl","prime":"fixed-field-id"}',
        "vault_ciphertext": "ZW5jcnlwdGVkLXZhdWx0LWJ5dGVz",
        "vault_nonce": "cmFuZG9tLW5vbmNl",
    }


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_init_fetch_and_duplicate_vault(client):
    payload = sample_payload()

    created = client.post("/vault/init", json=payload)
    duplicate = client.post("/vault/init", json=payload)
    fetched = client.get(f"/vault/{payload['user_id']}")

    assert created.status_code == 201
    assert duplicate.status_code == 409
    assert fetched.status_code == 200
    assert fetched.json()["user_id"] == payload["user_id"]
    assert fetched.json()["server_share"] == payload["server_share"]
    assert fetched.json()["vault_ciphertext"] == payload["vault_ciphertext"]
    assert fetched.json()["vault_nonce"] == payload["vault_nonce"]


def test_update_vault_changes_ciphertext_nonce_and_timestamp(client):
    payload = sample_payload()
    created = client.post("/vault/init", json=payload).json()
    time.sleep(0.01)

    response = client.put(
        f"/vault/{payload['user_id']}",
        json={
            "vault_ciphertext": "bmV3LWVuY3J5cHRlZC12YXVsdA",
            "vault_nonce": "bmV3LW5vbmNl",
        },
    )

    assert response.status_code == 200
    updated = response.json()
    assert updated["vault_ciphertext"] == "bmV3LWVuY3J5cHRlZC12YXVsdA"
    assert updated["vault_nonce"] == "bmV3LW5vbmNl"
    assert updated["created_at"] == created["created_at"]
    assert updated["updated_at"] != created["updated_at"]


def test_missing_user_fetch_and_update_return_404(client):
    fetch_response = client.get("/vault/missing-user")
    update_response = client.put(
        "/vault/missing-user",
        json={
            "vault_ciphertext": "bmV3LWVuY3J5cHRlZC12YXVsdA",
            "vault_nonce": "bmV3LW5vbmNl",
        },
    )

    assert fetch_response.status_code == 404
    assert update_response.status_code == 404


def test_init_rejects_forbidden_zero_knowledge_fields(client):
    payload = sample_payload()
    payload["master_key"] = "server-must-not-receive-this"

    response = client.post("/vault/init", json=payload)

    assert response.status_code == 422


def test_init_rejects_invalid_ciphertext(client):
    payload = sample_payload()
    payload["vault_ciphertext"] = "not valid base64url!!!"

    response = client.post("/vault/init", json=payload)

    assert response.status_code == 422


def test_sqlite_storage_is_zero_knowledge(db_path):
    plaintext_values = [
        "GitHub",
        "user@example.com",
        "plain-password",
        "catatan rahasia",
    ]
    db.init_db(db_path)
    db.create_vault(
        user_id="zk-user",
        server_share='{"x":2,"y":"b3BhcXVlLXNlcnZlci1zaGFyZQ","prime":"fixed-field-id"}',
        vault_ciphertext="b3BhcXVlLWNpcGhlcnRleHQ",
        vault_nonce="b3BhcXVlLW5vbmNl",
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        columns = [
            row[1]
            for row in connection.execute("PRAGMA table_info(vaults)").fetchall()
        ]
        stored_values = connection.execute(
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
            ("zk-user",),
        ).fetchone()
        storage_type = connection.execute(
            "SELECT typeof(vault_ciphertext) FROM vaults WHERE user_id = ?",
            ("zk-user",),
        ).fetchone()[0]

    assert columns == [
        "user_id",
        "server_share",
        "vault_ciphertext",
        "vault_nonce",
        "created_at",
        "updated_at",
    ]
    assert storage_type == "blob"
    joined_row = " ".join(str(value) for value in stored_values)
    for plaintext in plaintext_values:
        assert plaintext not in joined_row


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.content = b"" if body is None else b"{}"
        self.text = str(body)

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(response=self)


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, timeout, **kwargs):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "timeout": timeout,
                "kwargs": kwargs,
            }
        )
        return self.response


def test_api_client_sends_expected_vault_requests():
    session = FakeSession(FakeResponse(body={"ok": True}))
    api_client = ApiClient(base_url="http://127.0.0.1:8010/", session=session)

    assert api_client.health() == {"ok": True}
    assert api_client.init_vault(
        "fulan",
        "server-share",
        "ciphertext",
        "nonce",
    ) == {"ok": True}
    assert api_client.fetch_vault("fulan") == {"ok": True}
    assert api_client.update_vault("fulan", "new-ciphertext", "new-nonce") == {"ok": True}

    assert session.calls == [
        {
            "method": "GET",
            "url": "http://127.0.0.1:8010/health",
            "timeout": 10.0,
            "kwargs": {},
        },
        {
            "method": "POST",
            "url": "http://127.0.0.1:8010/vault/init",
            "timeout": 10.0,
            "kwargs": {
                "json": {
                    "user_id": "fulan",
                    "server_share": "server-share",
                    "vault_ciphertext": "ciphertext",
                    "vault_nonce": "nonce",
                }
            },
        },
        {
            "method": "GET",
            "url": "http://127.0.0.1:8010/vault/fulan",
            "timeout": 10.0,
            "kwargs": {},
        },
        {
            "method": "PUT",
            "url": "http://127.0.0.1:8010/vault/fulan",
            "timeout": 10.0,
            "kwargs": {
                "json": {
                    "vault_ciphertext": "new-ciphertext",
                    "vault_nonce": "new-nonce",
                }
            },
        },
    ]


def test_api_client_raises_clear_error_for_failed_response():
    session = FakeSession(FakeResponse(status_code=404, body={"detail": "Vault not found."}))
    api_client = ApiClient(base_url="http://127.0.0.1:8010", session=session)

    with pytest.raises(ApiClientError, match="Vault not found."):
        api_client.fetch_vault("missing-user")
