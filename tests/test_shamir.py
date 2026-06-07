import base64
import json

import pytest

from client import shamir


def test_split_returns_three_text_serializable_shares():
    secret = b"\x00" + b"kunci-vault-128"

    shares = shamir.split_secret(secret)
    serialized = [shamir.serialize_share(share) for share in shares]

    assert len(shares) == 3
    assert [share.x for share in shares] == [1, 2, 3]
    for text in serialized:
        raw = json.loads(text)
        assert set(raw) == {"x", "y", "prime"}
        assert raw["prime"] == shamir.FIELD_ID
        assert isinstance(raw["x"], int)
        assert isinstance(raw["y"], str)


@pytest.mark.parametrize("indexes", [(0, 1), (0, 2), (1, 2), (0, 1, 2)])
def test_reconstruct_secret_from_any_valid_pair(indexes):
    secret = b"\x00\x01master-key-for-aes"
    shares = shamir.split_secret(secret)

    selected = [shares[index] for index in indexes]

    assert shamir.reconstruct_secret(selected) == secret


def test_serialized_shares_round_trip_and_reconstruct():
    secret = b"recovery-ready-key"
    shares = shamir.split_secret(secret)
    text_shares = [shamir.serialize_share(share) for share in shares]
    loaded = [shamir.deserialize_share(text) for text in text_shares]

    assert shamir.reconstruct_secret([loaded[0], loaded[2]]) == secret


def test_one_share_is_not_enough():
    share = shamir.split_secret(b"email-vault-key")[0]

    with pytest.raises(shamir.ShamirError, match="At least two"):
        shamir.reconstruct_secret([share])


def test_duplicate_coordinate_is_rejected():
    share = shamir.split_secret(b"portal-kampus-key")[0]

    with pytest.raises(shamir.ShamirError, match="unique"):
        shamir.reconstruct_secret([share, share])


def test_tampered_share_does_not_recover_the_secret():
    secret = b"github-vault-key"
    shares = shamir.split_secret(secret)
    raw = json.loads(shamir.serialize_share(shares[1]))
    raw["y"] = base64.urlsafe_b64encode((0).to_bytes(1, "big")).decode("ascii").rstrip("=")
    tampered = shamir.deserialize_share(json.dumps(raw))

    try:
        recovered = shamir.reconstruct_secret([shares[0], tampered])
    except shamir.ShamirError:
        return

    assert recovered != secret


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        "{}",
        '{"x":1,"y":"AA","prime":"wrong-field"}',
        '{"x":4,"y":"AA","prime":"mersenne-521"}',
        '{"x":1,"y":"not valid !!!","prime":"mersenne-521"}',
    ],
)
def test_deserialize_rejects_invalid_share_text(payload):
    with pytest.raises(shamir.ShamirError):
        shamir.deserialize_share(payload)
