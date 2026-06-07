from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np
import qrcode
from PIL import Image


PIXEL_EXPANSION = 2
BLACK = np.uint8(0)
WHITE = np.uint8(255)

_PATTERNS = (
    np.array([[BLACK, BLACK], [WHITE, WHITE]], dtype=np.uint8),
    np.array([[WHITE, WHITE], [BLACK, BLACK]], dtype=np.uint8),
    np.array([[BLACK, WHITE], [BLACK, WHITE]], dtype=np.uint8),
    np.array([[WHITE, BLACK], [WHITE, BLACK]], dtype=np.uint8),
    np.array([[BLACK, WHITE], [WHITE, BLACK]], dtype=np.uint8),
    np.array([[WHITE, BLACK], [BLACK, WHITE]], dtype=np.uint8),
)


class VisualCryptoError(ValueError):
    pass


@dataclass(frozen=True)
class VisualRecoveryFiles:
    original_qr: Path
    share_1: Path
    share_2: Path
    combined_qr: Path


def generate_recovery_qr(
    recovery_share: str,
    output_path: str | Path,
    *,
    box_size: int = 10,
    border: int = 4,
) -> Path:
    recovery_share = _validate_recovery_text(recovery_share)
    if box_size < 1 or border < 4:
        raise VisualCryptoError("QR box size must be positive and border must be at least 4.")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(recovery_share)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white").convert("L")

    path = _png_path(output_path)
    _save_image(image, path)
    return path


def split_qr_image(
    qr_path: str | Path,
    share_1_path: str | Path,
    share_2_path: str | Path,
) -> tuple[Path, Path]:
    source = _load_binary_image(qr_path)
    height, width = source.shape
    share_1 = np.full(
        (height * PIXEL_EXPANSION, width * PIXEL_EXPANSION),
        WHITE,
        dtype=np.uint8,
    )
    share_2 = np.full_like(share_1, WHITE)

    for row in range(height):
        for column in range(width):
            pattern = _PATTERNS[secrets.randbelow(len(_PATTERNS))]
            second_pattern = pattern if source[row, column] == WHITE else _invert(pattern)
            row_start = row * PIXEL_EXPANSION
            column_start = column * PIXEL_EXPANSION
            share_1[
                row_start : row_start + PIXEL_EXPANSION,
                column_start : column_start + PIXEL_EXPANSION,
            ] = pattern
            share_2[
                row_start : row_start + PIXEL_EXPANSION,
                column_start : column_start + PIXEL_EXPANSION,
            ] = second_pattern

    first_path = _png_path(share_1_path)
    second_path = _png_path(share_2_path)
    _save_array(share_1, first_path)
    _save_array(share_2, second_path)
    return first_path, second_path


def combine_visual_shares(
    share_1_path: str | Path,
    share_2_path: str | Path,
    output_path: str | Path,
) -> Path:
    share_1 = _load_binary_image(share_1_path)
    share_2 = _load_binary_image(share_2_path)
    if share_1.shape != share_2.shape:
        raise VisualCryptoError("Visual shares must have identical dimensions.")

    height, width = share_1.shape
    if height % PIXEL_EXPANSION or width % PIXEL_EXPANSION:
        raise VisualCryptoError("Visual share dimensions are invalid.")

    _validate_share_blocks(share_1)
    _validate_share_blocks(share_2)
    overlay = np.minimum(share_1, share_2)
    blocks = overlay.reshape(
        height // PIXEL_EXPANSION,
        PIXEL_EXPANSION,
        width // PIXEL_EXPANSION,
        PIXEL_EXPANSION,
    )
    black_counts = np.sum(blocks == BLACK, axis=(1, 3))
    if not np.all(np.isin(black_counts, (2, 4))):
        raise VisualCryptoError("Visual shares are damaged or incompatible.")

    reconstructed = np.where(black_counts == 4, BLACK, WHITE).astype(np.uint8)
    path = _png_path(output_path)
    _save_array(reconstructed, path)
    return path


def decode_qr(image_path: str | Path) -> str:
    path = Path(image_path)
    image = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
    if image is None:
        raise VisualCryptoError(f"Could not read QR image: {path}")

    decoded, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if not decoded:
        raise VisualCryptoError("Image does not contain a readable QR code.")
    return decoded


def create_visual_recovery_shares(
    recovery_share: str,
    output_dir: str | Path,
) -> VisualRecoveryFiles:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    files = VisualRecoveryFiles(
        original_qr=directory / "recovery_qr.png",
        share_1=directory / "visual_share_1.png",
        share_2=directory / "visual_share_2.png",
        combined_qr=directory / "combined_qr.png",
    )

    generate_recovery_qr(recovery_share, files.original_qr)
    split_qr_image(files.original_qr, files.share_1, files.share_2)
    combine_visual_shares(files.share_1, files.share_2, files.combined_qr)
    if decode_qr(files.combined_qr) != recovery_share:
        raise VisualCryptoError("Combined QR does not match the recovery share.")
    return files


def _validate_recovery_text(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VisualCryptoError("Recovery share must not be empty.")
    return value.strip()


def _load_binary_image(path: str | Path) -> np.ndarray:
    image_path = Path(path)
    try:
        image = Image.open(image_path).convert("L")
    except (OSError, ValueError) as exc:
        raise VisualCryptoError(f"Could not read image: {image_path}") from exc

    pixels = np.asarray(image, dtype=np.uint8)
    return np.where(pixels < 128, BLACK, WHITE).astype(np.uint8)


def _invert(pattern: np.ndarray) -> np.ndarray:
    return np.where(pattern == BLACK, WHITE, BLACK).astype(np.uint8)


def _validate_share_blocks(share: np.ndarray) -> None:
    height, width = share.shape
    blocks = share.reshape(
        height // PIXEL_EXPANSION,
        PIXEL_EXPANSION,
        width // PIXEL_EXPANSION,
        PIXEL_EXPANSION,
    )
    black_counts = np.sum(blocks == BLACK, axis=(1, 3))
    if not np.all(black_counts == 2):
        raise VisualCryptoError("Visual shares are damaged or incompatible.")


def _png_path(path: str | Path) -> Path:
    result = Path(path)
    if result.suffix.lower() != ".png":
        raise VisualCryptoError("Visual cryptography images must use PNG format.")
    return result


def _save_image(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG")


def _save_array(pixels: np.ndarray, path: Path) -> None:
    _save_image(Image.fromarray(pixels, mode="L"), path)
