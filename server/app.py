from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from server import db


class VaultInitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1)
    server_share: str = Field(min_length=1)
    vault_ciphertext: str = Field(min_length=1)
    vault_nonce: str = Field(min_length=1)


class VaultUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vault_ciphertext: str = Field(min_length=1)
    vault_nonce: str = Field(min_length=1)


class VaultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    server_share: str
    vault_ciphertext: str
    vault_nonce: str
    created_at: str
    updated_at: str


def _db_path(request: Request) -> Path:
    return getattr(request.app.state, "db_path", db.get_db_path())


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db(getattr(app.state, "db_path", db.get_db_path()))
    yield


app = FastAPI(
    title="Distributed Password Manager API",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/vault/init",
    response_model=VaultResponse,
    status_code=status.HTTP_201_CREATED,
)
def init_vault(payload: VaultInitRequest, request: Request) -> dict[str, Any]:
    try:
        return db.create_vault(
            user_id=payload.user_id,
            server_share=payload.server_share,
            vault_ciphertext=payload.vault_ciphertext,
            vault_nonce=payload.vault_nonce,
            db_path=_db_path(request),
        )
    except db.DuplicateVaultError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vault already exists for this user.",
        ) from exc
    except db.InvalidCiphertextError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@app.get("/vault/{user_id}", response_model=VaultResponse)
def fetch_vault(user_id: str, request: Request) -> dict[str, Any]:
    vault = db.get_vault(user_id, db_path=_db_path(request))
    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vault not found.",
        )
    return vault


@app.put("/vault/{user_id}", response_model=VaultResponse)
def update_vault(
    user_id: str,
    payload: VaultUpdateRequest,
    request: Request,
) -> dict[str, Any]:
    try:
        vault = db.update_vault(
            user_id=user_id,
            vault_ciphertext=payload.vault_ciphertext,
            vault_nonce=payload.vault_nonce,
            db_path=_db_path(request),
        )
    except db.InvalidCiphertextError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vault not found.",
        )
    return vault
