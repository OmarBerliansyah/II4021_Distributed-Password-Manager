from __future__ import annotations

import os
from typing import Any

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:8010"


class ApiClientError(Exception):
    pass


class ApiClient:
    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 10.0,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = (base_url or os.getenv("DPM_SERVER_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def init_vault(
        self,
        user_id: str,
        server_share: str,
        vault_ciphertext: str,
        vault_nonce: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/vault/init",
            json={
                "user_id": user_id,
                "server_share": server_share,
                "vault_ciphertext": vault_ciphertext,
                "vault_nonce": vault_nonce,
            },
        )

    def fetch_vault(self, user_id: str) -> dict[str, Any]:
        return self._request("GET", f"/vault/{user_id}")

    def update_vault(
        self,
        user_id: str,
        vault_ciphertext: str,
        vault_nonce: str,
    ) -> dict[str, Any]:
        return self._request(
            "PUT",
            f"/vault/{user_id}",
            json={
                "vault_ciphertext": vault_ciphertext,
                "vault_nonce": vault_nonce,
            },
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                timeout=self.timeout,
                **kwargs,
            )
            response.raise_for_status()
        except requests.HTTPError as exc:
            detail = _extract_error_detail(exc.response)
            raise ApiClientError(detail) from exc
        except requests.RequestException as exc:
            raise ApiClientError(str(exc)) from exc

        if not response.content:
            return {}
        return response.json()


def _extract_error_detail(response: requests.Response | None) -> str:
    if response is None:
        return "API request failed."

    try:
        body = response.json()
    except ValueError:
        body = response.text

    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    if body:
        return str(body)
    return f"API request failed with status {response.status_code}."


_default_client = ApiClient()


def health() -> dict[str, Any]:
    return _default_client.health()


def init_vault(
    user_id: str,
    server_share: str,
    vault_ciphertext: str,
    vault_nonce: str,
) -> dict[str, Any]:
    return _default_client.init_vault(
        user_id,
        server_share,
        vault_ciphertext,
        vault_nonce,
    )


def fetch_vault(user_id: str) -> dict[str, Any]:
    return _default_client.fetch_vault(user_id)


def update_vault(user_id: str, vault_ciphertext: str, vault_nonce: str) -> dict[str, Any]:
    return _default_client.update_vault(user_id, vault_ciphertext, vault_nonce)
