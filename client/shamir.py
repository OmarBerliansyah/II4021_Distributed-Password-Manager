from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any


PRIME = 2**521 - 1
FIELD_ID = "mersenne-521"
SHARE_COUNT = 3
THRESHOLD = 2


class ShamirError(ValueError):
    pass


@dataclass(frozen=True)
class Share:
    x: int
    y: int


def split_secret(secret_bytes: bytes) -> list[Share]:

    if not isinstance(secret_bytes, bytes) or not secret_bytes:
        raise ShamirError("Secret must be non-empty bytes.")

    secret = _pack_secret(secret_bytes)

    if secret >= PRIME:
        raise ShamirError("Secret is too large for the selected field.")

    slope = secrets.randbelow(PRIME - 1) + 1

    return [
        Share(x=x, y=(secret + slope * x) % PRIME)
        for x in range(1, SHARE_COUNT + 1)
    ]


def reconstruct_secret(shares: list[Share] | tuple[Share, ...]) -> bytes:

    if len(shares) < THRESHOLD:
        raise ShamirError("At least two shares are required.")

    unique: dict[int, Share] = {}

    for share in shares:
        _check_share(share)
        if share.x in unique:
            raise ShamirError("Share coordinates must be unique.")
        unique[share.x] = share

    secret = 0
    points = list(unique.values())

    for i, share_i in enumerate(points):
        numerator = 1
        denominator = 1
        for j, share_j in enumerate(points):
            if i == j:
                continue
            numerator = (numerator * -share_j.x) % PRIME
            denominator = (denominator * (share_i.x - share_j.x)) % PRIME
        basis = numerator * pow(denominator, -1, PRIME)
        secret = (secret + share_i.y * basis) % PRIME

    return _unpack_secret(secret)


def serialize_share(share: Share) -> str:
    _check_share(share)

    return json.dumps(
        {
            "x": share.x,
            "y": _int_to_base64(share.y),
            "prime": FIELD_ID,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def deserialize_share(text: str) -> Share:
    try:
        raw = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ShamirError("Share must be valid JSON.") from exc

    if not isinstance(raw, dict) or set(raw) != {"x", "y", "prime"}:
        raise ShamirError("Share has an invalid structure.")
    
    if raw["prime"] != FIELD_ID:
        raise ShamirError("Share uses an unsupported field.")
    
    if not isinstance(raw["x"], int):
        raise ShamirError("Share coordinate must be an integer.")

    share = Share(x=raw["x"], y=_base64_to_int(raw["y"]))
    _check_share(share)

    return share


def _pack_secret(secret_bytes: bytes) -> int:
    return int.from_bytes(b"\x01" + secret_bytes, "big")


def _unpack_secret(secret: int) -> bytes:
    data = secret.to_bytes(max(1, (secret.bit_length() + 7) // 8), "big")

    if len(data) < 2 or data[0] != 1:
        raise ShamirError("Shares do not reconstruct a valid secret.")
    
    return data[1:]


def _check_share(share: Any) -> None:
    if not isinstance(share, Share):
        raise ShamirError("Invalid share object.")
    
    if not 1 <= share.x <= SHARE_COUNT:
        raise ShamirError("Share coordinate is out of range.")
    
    if not 0 <= share.y < PRIME:
        raise ShamirError("Share value is out of range.")


def _int_to_base64(value: int) -> str:
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64_to_int(value: str) -> int:
    if not isinstance(value, str) or not value:
        raise ShamirError("Share value must be base64url text.")
    
    try:
        data = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise ShamirError("Share value is not valid base64url.") from exc
    
    return int.from_bytes(data, "big")
