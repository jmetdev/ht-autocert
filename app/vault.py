"""Envelope encryption for escrowed key material.

Because gateway private keys are escrowed rather than device-generated, this
application is a key custodian. Every sensitive value is sealed with a
per-record data key (DEK), which is itself wrapped by the master key (KEK).
Two properties matter operationally:

* **Rotation.** Rotating the KEK only requires re-wrapping DEKs
  (:func:`SecretBox.rewrap`), not re-encrypting every ciphertext.
* **Binding.** Each ciphertext is bound to an AAD string describing what it is
  (e.g. ``certificate:vg01.example.com:0A1B:private_key``). A blob lifted from
  one row will not decrypt in another, so key material cannot be silently
  swapped between devices or tenants.
"""

from __future__ import annotations

import base64
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"HTAC1"
NONCE_LEN = 12
DEK_LEN = 32
WRAPPED_DEK_LEN = DEK_LEN + 16  # AES-GCM tag


class VaultError(RuntimeError):
    pass


class SecretBox:
    """Seals and opens secrets under a master key."""

    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise VaultError(
                f"master key must be 32 bytes, got {len(master_key)}"
            )
        self._kek = AESGCM(master_key)

    @classmethod
    def from_b64(cls, master_key_b64: str) -> "SecretBox":
        try:
            raw = base64.b64decode(master_key_b64, validate=True)
        except Exception as exc:  # noqa: BLE001 - surface as a config error
            raise VaultError(f"master key is not valid base64: {exc}") from exc
        return cls(raw)

    @staticmethod
    def generate_master_key() -> str:
        return base64.b64encode(os.urandom(32)).decode()

    def seal(self, plaintext: bytes, aad: str) -> bytes:
        aad_b = aad.encode()
        dek = os.urandom(DEK_LEN)
        dek_nonce = os.urandom(NONCE_LEN)
        wrapped = self._kek.encrypt(dek_nonce, dek, aad_b)

        data_nonce = os.urandom(NONCE_LEN)
        ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext, aad_b)

        return b"".join(
            [
                MAGIC,
                struct.pack("!H", len(wrapped)),
                dek_nonce,
                wrapped,
                data_nonce,
                ciphertext,
            ]
        )

    def open(self, blob: bytes, aad: str) -> bytes:
        dek, data_nonce, ciphertext = self._unpack(blob, aad.encode())
        try:
            return AESGCM(dek).decrypt(data_nonce, ciphertext, aad.encode())
        except InvalidTag as exc:
            raise VaultError(
                f"ciphertext failed authentication for aad={aad!r}; it was "
                "sealed under a different key or a different record"
            ) from exc

    def rewrap(self, blob: bytes, aad: str, new_box: "SecretBox") -> bytes:
        """Re-wrap the DEK under a new master key, leaving data ciphertext as-is."""
        dek, data_nonce, ciphertext = self._unpack(blob, aad.encode())
        dek_nonce = os.urandom(NONCE_LEN)
        wrapped = new_box._kek.encrypt(dek_nonce, dek, aad.encode())
        return b"".join(
            [
                MAGIC,
                struct.pack("!H", len(wrapped)),
                dek_nonce,
                wrapped,
                data_nonce,
                ciphertext,
            ]
        )

    def _unpack(self, blob: bytes, aad_b: bytes) -> tuple[bytes, bytes, bytes]:
        if not blob.startswith(MAGIC):
            raise VaultError("not a sealed secret (bad magic)")
        pos = len(MAGIC)
        (wrapped_len,) = struct.unpack("!H", blob[pos : pos + 2])
        pos += 2
        dek_nonce = blob[pos : pos + NONCE_LEN]
        pos += NONCE_LEN
        wrapped = blob[pos : pos + wrapped_len]
        pos += wrapped_len
        data_nonce = blob[pos : pos + NONCE_LEN]
        pos += NONCE_LEN
        ciphertext = blob[pos:]
        if not ciphertext:
            raise VaultError("sealed secret is truncated")
        try:
            dek = self._kek.decrypt(dek_nonce, wrapped, aad_b)
        except InvalidTag as exc:
            raise VaultError(
                f"could not unwrap data key for aad={aad_b.decode()!r}; wrong "
                "master key, or the record was tampered with"
            ) from exc
        return dek, data_nonce, ciphertext


# --- AAD builders -----------------------------------------------------------
# Natural keys, so the AAD is known at seal time (before a DB primary key exists).


def aad_account_key(ca_profile_name: str) -> str:
    return f"ca_profile:{ca_profile_name}:account_key"


def aad_eab(ca_profile_name: str, field: str) -> str:
    return f"ca_profile:{ca_profile_name}:{field}"


def aad_webex_token(email: str, field: str) -> str:
    return f"webex_token:{email.lower()}:{field}"


def aad_private_key(fqdn: str, serial: str) -> str:
    return f"certificate:{fqdn}:{serial}:private_key"


def aad_pkcs12(fqdn: str, serial: str) -> str:
    return f"certificate:{fqdn}:{serial}:pkcs12"


def aad_pkcs12_password(fqdn: str, serial: str) -> str:
    return f"certificate:{fqdn}:{serial}:pkcs12_password"
