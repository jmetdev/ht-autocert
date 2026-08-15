from __future__ import annotations

import pytest

from app.vault import SecretBox, VaultError, aad_private_key


def test_roundtrip(box):
    blob = box.seal(b"super secret key material", "certificate:vg01:AA:private_key")
    assert box.open(blob, "certificate:vg01:AA:private_key") == b"super secret key material"


def test_ciphertext_is_not_plaintext(box):
    blob = box.seal(b"needle", "x")
    assert b"needle" not in blob


def test_wrong_aad_is_rejected(box):
    """A blob lifted from one device's row must not open under another's."""
    blob = box.seal(b"vg01 key", aad_private_key("vg01.example.com", "AA"))
    with pytest.raises(VaultError):
        box.open(blob, aad_private_key("vg02.example.com", "AA"))


def test_wrong_master_key_is_rejected(box):
    other = SecretBox.from_b64(SecretBox.generate_master_key())
    blob = box.seal(b"secret", "aad")
    with pytest.raises(VaultError):
        other.open(blob, "aad")


def test_tampering_is_detected(box):
    blob = bytearray(box.seal(b"secret", "aad"))
    blob[-1] ^= 0xFF
    with pytest.raises(VaultError):
        box.open(bytes(blob), "aad")


def test_rewrap_rotates_the_master_key(box):
    new_box = SecretBox.from_b64(SecretBox.generate_master_key())
    blob = box.seal(b"escrowed key", "aad")

    rewrapped = box.rewrap(blob, "aad", new_box)

    assert new_box.open(rewrapped, "aad") == b"escrowed key"
    with pytest.raises(VaultError):
        box.open(rewrapped, "aad")


def test_nonces_are_unique(box):
    blobs = {box.seal(b"same plaintext", "aad") for _ in range(20)}
    assert len(blobs) == 20


def test_rejects_bad_key_length():
    with pytest.raises(VaultError):
        SecretBox(b"tooshort")


def test_rejects_non_sealed_blob(box):
    with pytest.raises(VaultError, match="bad magic"):
        box.open(b"not a sealed secret at all", "aad")
