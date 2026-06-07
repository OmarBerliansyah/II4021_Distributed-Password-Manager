from __future__ import annotations

import secrets
import string


DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?"


class PasswordGeneratorError(ValueError):
    pass


def generate_secure_password(
    length: int,
    *,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    if isinstance(length, bool) or not isinstance(length, int):
        raise PasswordGeneratorError("Password length must be an integer.")

    character_sets = [
        charset
        for enabled, charset in (
            (uppercase, string.ascii_uppercase),
            (lowercase, string.ascii_lowercase),
            (digits, string.digits),
            (symbols, DEFAULT_SYMBOLS),
        )
        if enabled
    ]
    if not character_sets:
        raise PasswordGeneratorError("Select at least one character category.")
    if length < len(character_sets):
        raise PasswordGeneratorError(
            f"Password length must be at least {len(character_sets)}"
        )

    password = [secrets.choice(charset) for charset in character_sets]
    alphabet = "".join(character_sets)
    password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)
