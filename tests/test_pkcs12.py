"""PKCS12 profile tests.

The legacy profile is the one that matters operationally: IOS-XE trains that
reject an AES/SHA-256 bundle give no useful error, so the encoding has to be
verified here rather than on the device.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12

from app.db.models import Pkcs12Profile
from app.pkcs12_builder import (
    build_pkcs12,
    generate_pkcs12_password,
    verify_pkcs12,
)


@pytest.mark.parametrize("profile", [Pkcs12Profile.modern, Pkcs12Profile.legacy])
def test_builds_and_reparses(cert_chain, profile):
    key_pem, fullchain = cert_chain
    password = generate_pkcs12_password()

    blob = build_pkcs12(
        friendly_name="HT-WxCAutoCert-A",
        private_key_pem=key_pem,
        fullchain_pem=fullchain,
        password=password,
        profile=profile,
    )

    cn, chain_len = verify_pkcs12(blob, password)
    assert cn == "vg01.example.com"
    assert chain_len == 2  # intermediate + root travel with the leaf


@pytest.mark.parametrize("profile", [Pkcs12Profile.modern, Pkcs12Profile.legacy])
def test_key_and_leaf_are_present(cert_chain, profile):
    key_pem, fullchain = cert_chain
    password = generate_pkcs12_password()
    blob = build_pkcs12(
        friendly_name="tp",
        private_key_pem=key_pem,
        fullchain_pem=fullchain,
        password=password,
        profile=profile,
    )

    key, cert, cas = pkcs12.load_key_and_certificates(blob, password.encode())
    assert key is not None
    assert cert is not None
    assert len(cas) == 2


def test_legacy_profile_uses_sha1_mac(cert_chain):
    """The legacy bundle must carry a SHA-1 MAC, not OpenSSL 3's SHA-256.

    A SHA-256 MAC is the fingerprint of the profile that fails to import on
    older IOS-XE.
    """
    key_pem, fullchain = cert_chain
    password = generate_pkcs12_password()

    legacy = build_pkcs12(
        friendly_name="tp",
        private_key_pem=key_pem,
        fullchain_pem=fullchain,
        password=password,
        profile=Pkcs12Profile.legacy,
    )
    modern = build_pkcs12(
        friendly_name="tp",
        private_key_pem=key_pem,
        fullchain_pem=fullchain,
        password=password,
        profile=Pkcs12Profile.modern,
    )

    # OID 1.3.14.3.2.26 = sha1; 2.16.840.1.101.3.4.2.1 = sha256. The MAC
    # algorithm sits in the MacData trailer of the PFX.
    sha1_oid = bytes.fromhex("2b0e03021a")
    sha256_oid = bytes.fromhex("608648016503040201")

    assert sha1_oid in legacy
    assert sha1_oid not in modern
    assert sha256_oid in modern


def test_wrong_password_fails_verification(cert_chain):
    key_pem, fullchain = cert_chain
    blob = build_pkcs12(
        friendly_name="tp",
        private_key_pem=key_pem,
        fullchain_pem=fullchain,
        password="correct-horse",
        profile=Pkcs12Profile.modern,
    )
    with pytest.raises(ValueError):
        verify_pkcs12(blob, "wrong-password")


def test_password_is_shell_and_cli_safe():
    """The password is typed into an IOS-XE exec command; keep it alphanumeric."""
    for _ in range(50):
        password = generate_pkcs12_password()
        assert len(password) == 24
        assert password.isalnum()


def test_passwords_are_unique():
    assert len({generate_pkcs12_password() for _ in range(100)}) == 100


def test_rejects_empty_chain():
    with pytest.raises(ValueError, match="no certificates"):
        build_pkcs12(
            friendly_name="tp",
            private_key_pem=b"",
            fullchain_pem="",
            password="x",
            profile=Pkcs12Profile.modern,
        )
