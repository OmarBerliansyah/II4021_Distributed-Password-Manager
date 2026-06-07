import pytest
from cryptography.exceptions import InvalidTag

from client import crypto_utils


def test_master_key_has_aes_128_size_and_is_random():
    first = crypto_utils.generate_master_key()
    second = crypto_utils.generate_master_key()

    assert len(first) == 16
    assert len(second) == 16
    assert first != second


def test_aes_gcm_round_trip_for_vault_payload():
    key = crypto_utils.generate_master_key()
    plaintext = (
        b'{"entries":[{"nama_layanan":"Portal Kampus",'
        b'"username":"fulan@std.stei.itb.ac.id",'
        b'"password":"rahasia-kuat","catatan":"akun akademik"}]}'
    )

    ciphertext, nonce = crypto_utils.aes_gcm_encrypt(key, plaintext)
    opened = crypto_utils.aes_gcm_decrypt(key, ciphertext, nonce)

    assert opened == plaintext
    assert ciphertext != plaintext
    assert len(nonce) == 12


def test_aes_gcm_uses_fresh_nonce_for_each_encryption():
    key = crypto_utils.generate_master_key()
    plaintext = b'{"entries":[]}'

    first_ciphertext, first_nonce = crypto_utils.aes_gcm_encrypt(key, plaintext)
    second_ciphertext, second_nonce = crypto_utils.aes_gcm_encrypt(key, plaintext)

    assert first_nonce != second_nonce
    assert first_ciphertext != second_ciphertext


def test_aes_gcm_rejects_tampered_ciphertext_and_wrong_key():
    key = crypto_utils.generate_master_key()
    wrong_key = crypto_utils.generate_master_key()
    ciphertext, nonce = crypto_utils.aes_gcm_encrypt(key, b"email password")
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1

    with pytest.raises(InvalidTag):
        crypto_utils.aes_gcm_decrypt(key, bytes(tampered), nonce)
    with pytest.raises(InvalidTag):
        crypto_utils.aes_gcm_decrypt(wrong_key, ciphertext, nonce)


def test_pbkdf2_is_stable_for_same_input_and_changes_with_salt():
    salt = b"s" * 16
    other_salt = b"t" * 16

    first = crypto_utils.derive_key("master password fulan", salt, iterations=10_000)
    second = crypto_utils.derive_key("master password fulan", salt, iterations=10_000)
    third = crypto_utils.derive_key("master password fulan", other_salt, iterations=10_000)

    assert len(first) == 16
    assert first == second
    assert first != third


@pytest.mark.parametrize(
    "key, plaintext, nonce",
    [
        (b"k" * 15, b"data", b"n" * 12),
        (b"k" * 17, b"data", b"n" * 12),
        (b"k" * 16, "not-bytes", b"n" * 12),
        (b"k" * 16, b"data", b"n" * 11),
    ],
)
def test_crypto_rejects_invalid_shapes(key, plaintext, nonce):
    if isinstance(plaintext, bytes) and len(key) == 16:
        with pytest.raises(crypto_utils.CryptoError):
            crypto_utils.aes_gcm_decrypt(key, plaintext, nonce)
    else:
        with pytest.raises(crypto_utils.CryptoError):
            crypto_utils.aes_gcm_encrypt(key, plaintext)


def test_kdf_rejects_weak_parameters():
    with pytest.raises(crypto_utils.CryptoError):
        crypto_utils.derive_key("", b"s" * 16)
    with pytest.raises(crypto_utils.CryptoError):
        crypto_utils.derive_key("password", b"short")
    with pytest.raises(crypto_utils.CryptoError):
        crypto_utils.derive_key("password", b"s" * 16, iterations=0)
