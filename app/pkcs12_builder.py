"""PKCS12 packaging for IOS-XE import.

Two profiles, because this is the single most common silent failure when
pushing certificates to Cisco gateways:

``modern``
    OpenSSL 3 defaults -- AES-256-CBC / PBKDF2 / SHA-256 MAC. What the Ansible
    role produced (it called ``openssl pkcs12 -export`` with no cipher flags).

``legacy``
    PBE-SHA1-3DES with a SHA-1 MAC, equivalent to
    ``-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -descert``.
    Older IOS-XE trains cannot parse the modern profile: the device creates the
    trustpoint, imports the key, then deletes everything and logs
    ``%PKI-3-PKCS12_IMPORT_FAILURE ... Reason: Unknown reason``.

Which one a given device needs is a property of its IOS-XE version, so it lives
on the Device record rather than being a global default.
"""

from __future__ import annotations

import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    PrivateFormat,
    pkcs12,
)

from app.ca.trust_anchors import complete_chain
from app.db.models import Pkcs12Profile

# Alphanumeric only: the value is typed into an IOS-XE exec command, where
# quoting and special characters are a reliable source of misery.
_PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def generate_pkcs12_password(length: int = 24) -> str:
    """A fresh password per issuance. Never reused, never stored on the device."""
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def _encryption(profile: Pkcs12Profile, password: bytes):
    if profile is Pkcs12Profile.legacy:
        return (
            PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(50000)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(password)
        )
    return BestAvailableEncryption(password)


def build_pkcs12(
    *,
    friendly_name: str,
    private_key_pem: bytes,
    fullchain_pem: str,
    password: str,
    profile: Pkcs12Profile = Pkcs12Profile.modern,
) -> bytes:
    """Package key + leaf + intermediates + trust anchor into a .p12.

    ACME fullchains usually omit the root. ``complete_chain`` appends a bundled
    ISRG root when the last cert is issued by one, so ``crypto pki import``
    gets a chain IOS can actually verify.
    """
    if not (fullchain_pem or "").strip():
        raise ValueError("fullchain contains no certificates")
    fullchain_pem = complete_chain(fullchain_pem)
    try:
        certs = x509.load_pem_x509_certificates(fullchain_pem.encode())
    except ValueError as exc:
        raise ValueError(f"fullchain contains no certificates: {exc}") from exc
    if not certs:
        raise ValueError("fullchain contains no certificates")

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    leaf, intermediates = certs[0], certs[1:]

    return pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode(),
        key=key,
        cert=leaf,
        cas=intermediates or None,
        encryption_algorithm=_encryption(profile, password.encode()),
    )


def verify_pkcs12(blob: bytes, password: str) -> tuple[str, int]:
    """Re-parse a bundle. Returns (leaf CN, number of chain certs).

    Cheap, but it catches a truncated or mis-encrypted bundle here rather than
    on the device, where the only symptom is a vague syslog line.
    """
    key, cert, additional = pkcs12.load_key_and_certificates(blob, password.encode())
    if key is None:
        raise ValueError("PKCS12 bundle contains no private key")
    if cert is None:
        raise ValueError("PKCS12 bundle contains no leaf certificate")
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    cn = str(cn_attrs[0].value) if cn_attrs else cert.subject.rfc4514_string()
    return cn, len(additional or [])
