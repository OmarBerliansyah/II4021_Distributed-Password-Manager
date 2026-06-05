import string

import pytest

from client.password_generator import (
    DEFAULT_SYMBOLS,
    PasswordGeneratorError,
    generate_secure_password,
)


def test_generated_password_has_requested_length_and_all_categories():
    password = generate_secure_password(32)

    assert len(password) == 32
    assert any(character in string.ascii_uppercase for character in password)
    assert any(character in string.ascii_lowercase for character in password)
    assert any(character in string.digits for character in password)
    assert any(character in DEFAULT_SYMBOLS for character in password)


def test_generated_password_uses_only_enabled_categories():
    password = generate_secure_password(
        24,
        uppercase=False,
        lowercase=True,
        digits=True,
        symbols=False,
    )

    assert set(password) <= set(string.ascii_lowercase + string.digits)
    assert any(character in string.ascii_lowercase for character in password)
    assert any(character in string.digits for character in password)


def test_generator_rejects_no_categories():
    with pytest.raises(PasswordGeneratorError, match="at least one"):
        generate_secure_password(
            20,
            uppercase=False,
            lowercase=False,
            digits=False,
            symbols=False,
        )


def test_generator_rejects_length_too_short_for_categories():
    with pytest.raises(PasswordGeneratorError, match="at least 4"):
        generate_secure_password(3)


@pytest.mark.parametrize("length", [True, 12.5, "20"])
def test_generator_rejects_non_integer_length(length):
    with pytest.raises(PasswordGeneratorError, match="integer"):
        generate_secure_password(length)
