"""PKCS12 profile tests.

The legacy profile is the one that matters operationally: IOS-XE trains that
reject an AES/SHA-256 bundle give no useful error, so the encoding has to be
verified here rather than on the device.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

from app.db.models import Pkcs12Profile
from app.issuance import materialize_pkcs12
from app.pkcs12_builder import (
    build_pkcs12,
    generate_pkcs12_password,
    verify_pkcs12,
)
from app.vault import aad_pkcs12, aad_pkcs12_password, aad_private_key


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


def test_pkcs12_includes_isrg_root_x1_when_acme_omits_it():
    """Generation Y fullchains stop at the YR cross-sign; the .p12 must still
    carry ISRG Root X1 so IOS has a trust anchor."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    yr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    standin = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def cert(subject_cn, issuer_cn, key, issuer_key, ca):
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_cn)]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )

    yr_by_x1 = cert("Root YR", "ISRG Root X1", yr_key, standin, True)
    yr1 = cert("YR1", "Root YR", inter_key, yr_key, True)
    leaf = cert("vg01.example.com", "YR1", leaf_key, inter_key, False)
    fullchain = "".join(
        c.public_bytes(serialization.Encoding.PEM).decode() for c in (leaf, yr1, yr_by_x1)
    )
    key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    password = generate_pkcs12_password()
    blob = build_pkcs12(
        friendly_name="tp",
        private_key_pem=key_pem,
        fullchain_pem=fullchain,
        password=password,
        profile=Pkcs12Profile.modern,
    )
    _key, _leaf, additional = pkcs12.load_key_and_certificates(blob, password.encode())
    cns = [
        c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        for c in (additional or [])
    ]
    assert "YR1" in cns
    assert "Root YR" in cns
    assert "ISRG Root X1" in cns


class _Dev:
    fqdn = "vg01.example.com"
    pkcs12_profile = Pkcs12Profile.modern
    trustpoint_a = "HT-WxCAutoCert-A"
    trustpoint_b = "HT-WxCAutoCert-B"
    active_trustpoint = None

    def idle_trustpoint(self):
        return self.trustpoint_a


def test_materialize_appends_x1_to_a_sealed_geny_bundle(box):
    """Certificates issued before complete_chain still download with X1."""
    import datetime

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    yr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    standin = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def cert(subject_cn, issuer_cn, key, issuer_key, ca):
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_cn)]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )

    yr_by_x1 = cert("Root YR", "ISRG Root X1", yr_key, standin, True)
    yr2 = cert("YR2", "Root YR", inter_key, yr_key, True)
    leaf = cert("vg01.example.com", "YR2", leaf_key, inter_key, False)
    fullchain = "".join(
        c.public_bytes(serialization.Encoding.PEM).decode() for c in (leaf, yr2, yr_by_x1)
    )
    key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    password = "HtAcPkcs12"
    stale = build_pkcs12(
        friendly_name="tp",
        private_key_pem=key_pem,
        fullchain_pem="".join(
            c.public_bytes(serialization.Encoding.PEM).decode() for c in (leaf, yr2)
        ),
        password=password,
        profile=Pkcs12Profile.modern,
    )
    _k, _l, stale_cas = pkcs12.load_key_and_certificates(stale, password.encode())
    stale_cns = [
        c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        for c in (stale_cas or [])
    ]
    assert "ISRG Root X1" not in stale_cns

    serial = "AABBCC"
    cert_row = type(
        "Cert",
        (),
        {
            "serial": serial,
            "fullchain_pem": fullchain,
            "target_trustpoint": "HT-WxCAutoCert-B",
            "pkcs12_profile": Pkcs12Profile.modern,
            "private_key_sealed": box.seal(key_pem, aad_private_key(_Dev.fqdn, serial)),
            "pkcs12_sealed": box.seal(stale, aad_pkcs12(_Dev.fqdn, serial)),
            "pkcs12_password_sealed": box.seal(
                password.encode(), aad_pkcs12_password(_Dev.fqdn, serial)
            ),
        },
    )()

    blob, out_pw = materialize_pkcs12(box, cert_row, _Dev())
    assert out_pw == password
    _key, _leaf, additional = pkcs12.load_key_and_certificates(blob, password.encode())
    cns = [
        c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        for c in (additional or [])
    ]
    assert "YR2" in cns
    assert "Root YR" in cns
    assert "ISRG Root X1" in cns


def test_materialize_falls_back_to_sealed_blob_without_a_chain(box):
    password = "secret"
    serial = "00"
    blob = b"not-a-real-p12"
    cert_row = type(
        "Cert",
        (),
        {
            "serial": serial,
            "fullchain_pem": "",
            "target_trustpoint": "HT-WxCAutoCert-A",
            "pkcs12_profile": Pkcs12Profile.modern,
            "private_key_sealed": b"",
            "pkcs12_sealed": box.seal(blob, aad_pkcs12(_Dev.fqdn, serial)),
            "pkcs12_password_sealed": box.seal(
                password.encode(), aad_pkcs12_password(_Dev.fqdn, serial)
            ),
        },
    )()
    out, pw = materialize_pkcs12(box, cert_row, _Dev())
    assert out == blob
    assert pw == password


