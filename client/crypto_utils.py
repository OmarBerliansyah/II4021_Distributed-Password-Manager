from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MASTER_KEY_SIZE = 16
NONCE_SIZE = 12
SALT_SIZE = 16
KDF_ITERATIONS = 390_000


class CryptoError(ValueError):
    pass


def generate_master_key() -> bytes:
    return secrets.token_bytes(MASTER_KEY_SIZE)


def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_SIZE)


def derive_key(master_password: str, salt: bytes, *, iterations: int = KDF_ITERATIONS) -> bytes:
    if not isinstance(master_password, str) or not master_password:
        raise CryptoError("Master password must not be empty.")
    
    if not isinstance(salt, bytes) or len(salt) < SALT_SIZE:
        raise CryptoError("Salt must be at least 16 bytes.")
    
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations <= 0:
        raise CryptoError("KDF iterations must be a positive integer.")

    password_bytes = master_password.encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=MASTER_KEY_SIZE, salt=salt, iterations=iterations)

    return kdf.derive(password_bytes)


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    _check_key(key)

    if not isinstance(plaintext, bytes):
        raise CryptoError("Plaintext must be bytes.")

    nonce = generate_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    return ciphertext, nonce


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    _check_key(key)

    if not isinstance(ciphertext, bytes):
        raise CryptoError("Ciphertext must be bytes.")
    
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
        raise CryptoError("AES-GCM nonce must be 12 bytes.")

    return AESGCM(key).decrypt(nonce, ciphertext, None)


def _check_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != MASTER_KEY_SIZE:
        raise CryptoError("AES-128 key must be 16 bytes.")
