from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from client import shamir
from client.visual_crypto import (
    VisualCryptoError,
    combine_visual_shares,
    create_visual_recovery_shares,
    decode_qr,
    generate_recovery_qr,
    split_qr_image,
)


@pytest.fixture()
def recovery_share():
    shares = shamir.split_secret(b"v" * 16)
    return shamir.serialize_share(shares[2])


def test_visual_recovery_round_trip(recovery_share, tmp_path):
    files = create_visual_recovery_shares(recovery_share, tmp_path)

    assert decode_qr(files.original_qr) == recovery_share
    assert decode_qr(files.combined_qr) == recovery_share
    assert shamir.deserialize_share(decode_qr(files.combined_qr))
    for path in (
        files.original_qr,
        files.share_1,
        files.share_2,
        files.combined_qr,
    ):
        assert path.exists()
        assert path.suffix == ".png"


def test_visual_shares_are_binary_noise_with_pixel_expansion(
    recovery_share,
    tmp_path,
):
    original = generate_recovery_qr(recovery_share, tmp_path / "original.png")
    share_1, share_2 = split_qr_image(
        original,
        tmp_path / "share_1.png",
        tmp_path / "share_2.png",
    )

    original_pixels = np.asarray(Image.open(original).convert("L"))
    first_pixels = np.asarray(Image.open(share_1).convert("L"))
    second_pixels = np.asarray(Image.open(share_2).convert("L"))

    assert first_pixels.shape == (
        original_pixels.shape[0] * 2,
        original_pixels.shape[1] * 2,
    )
    assert second_pixels.shape == first_pixels.shape
    assert set(np.unique(first_pixels)) == {0, 255}
    assert set(np.unique(second_pixels)) == {0, 255}
    assert not np.array_equal(first_pixels, second_pixels)

    with pytest.raises(VisualCryptoError, match="readable QR"):
        decode_qr(share_1)
    with pytest.raises(VisualCryptoError, match="readable QR"):
        decode_qr(share_2)


def test_combine_rejects_different_share_dimensions(recovery_share, tmp_path):
    original = generate_recovery_qr(recovery_share, tmp_path / "original.png")
    share_1, share_2 = split_qr_image(
        original,
        tmp_path / "share_1.png",
        tmp_path / "share_2.png",
    )
    second = Image.open(share_2)
    second.crop((0, 0, second.width - 2, second.height)).save(share_2)

    with pytest.raises(VisualCryptoError, match="identical dimensions"):
        combine_visual_shares(share_1, share_2, tmp_path / "combined.png")


def test_combine_rejects_tampered_visual_share(recovery_share, tmp_path):
    original = generate_recovery_qr(recovery_share, tmp_path / "original.png")
    share_1, share_2 = split_qr_image(
        original,
        tmp_path / "share_1.png",
        tmp_path / "share_2.png",
    )
    pixels = np.asarray(Image.open(share_1).convert("L")).copy()
    black_row, black_column = np.argwhere(pixels == 0)[0]
    pixels[black_row, black_column] = 255
    Image.fromarray(pixels).save(share_1)

    with pytest.raises(VisualCryptoError, match="damaged or incompatible"):
        combine_visual_shares(share_1, share_2, tmp_path / "combined.png")


@pytest.mark.parametrize(
    "recovery_share, output_name",
    [
        ("", "qr.png"),
        ("valid text", "qr.jpg"),
    ],
)
def test_qr_generation_rejects_invalid_input(recovery_share, output_name, tmp_path):
    with pytest.raises(VisualCryptoError):
        generate_recovery_qr(recovery_share, Path(tmp_path) / output_name)
