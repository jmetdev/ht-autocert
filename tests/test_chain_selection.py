"""Chain selection.

Let's Encrypt Generation Y defaults to EE ← YR ← Root YR (cross-signed by
ISRG Root X1). ACME omits X1 itself; we append the bundled root so a PKCS12
import on IOS has a trust anchor Webex actually knows.
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.ca.acme_provider import AcmeProvider, AcmeError, _chain_issuer_cn
from app.ca.trust_anchors import complete_chain


def _provider(preferred_chain=None) -> AcmeProvider:
    return AcmeProvider(
        directory_url="https://example.invalid/directory",
        contact_email="ops@example.com",
        solver=MagicMock(),
        account_store=MagicMock(),
        preferred_chain=preferred_chain,
    )


def _order(default_chain: str, alternates: list[str]):
    order = MagicMock()
    order.fullchain_pem = default_chain
    order.alternative_fullchains_pem = alternates
    return order


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _cert(subject_cn: str, issuer_cn: str, key, issuer_key, *, ca: bool):
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def _geny_chain_without_x1() -> tuple[bytes, str]:
    """Leaf + YR1 + Root YR cross-signed by X1 — what ACME actually returns."""
    yr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Cross-sign: subject is Root YR, issuer is ISRG Root X1 (we don't have X1's
    # key; the issuer *name* is what complete_chain matches on).
    x1_standin = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    yr_by_x1 = _cert("Root YR", "ISRG Root X1", yr_key, x1_standin, ca=True)
    yr1 = _cert("YR1", "Root YR", inter_key, yr_key, ca=True)
    leaf = _cert("vg01.example.com", "YR1", leaf_key, inter_key, ca=False)
    fullchain = "".join(_pem(c) for c in (leaf, yr1, yr_by_x1))
    key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_pem, fullchain


def test_reads_issuer_cn_from_top_of_chain(cert_chain):
    _, fullchain = cert_chain
    # Top cert is the self-signed root, so its issuer CN is its own subject.
    assert _chain_issuer_cn(fullchain) == "Test Root R1"


def test_empty_chain_raises():
    with pytest.raises(AcmeError, match="empty certificate chain"):
        _chain_issuer_cn("")


def test_default_chain_used_when_no_preference(cert_chain):
    _, fullchain = cert_chain
    provider = _provider()
    result = provider._select_chain("vg01", _order(fullchain, []), b"key")

    assert result.chain_issuer_cn == "Test Root R1"
    assert result.fullchain_pem == fullchain
    assert result.alternate_chain_issuers == ["Test Root R1"]


def test_preferred_alternate_chain_is_selected(cert_chain, monkeypatch):
    monkeypatch.setattr(
        "app.ca.acme_provider._chain_issuer_cn",
        lambda pem: {"A": "ISRG Root X1", "B": "ISRG Root YR"}[pem],
    )
    provider = _provider(preferred_chain="ISRG Root YR")

    result = provider._select_chain("vg01", _order("A", ["B"]), b"key")

    assert result.fullchain_pem == "B"
    assert result.chain_issuer_cn == "ISRG Root YR"
    assert result.alternate_chain_issuers == ["ISRG Root X1", "ISRG Root YR"]


def test_falls_back_to_default_when_preference_unavailable(cert_chain, monkeypatch):
    """The order must still complete -- just loudly, not silently."""
    monkeypatch.setattr(
        "app.ca.acme_provider._chain_issuer_cn",
        lambda pem: {"A": "ISRG Root X1", "B": "ISRG Root YR"}[pem],
    )
    provider = _provider(preferred_chain="DST Root CA X3")

    result = provider._select_chain("vg01", _order("A", ["B"]), b"key")

    assert result.fullchain_pem == "A"
    assert result.chain_issuer_cn == "ISRG Root X1"


def test_alternates_are_always_recorded(monkeypatch):
    monkeypatch.setattr(
        "app.ca.acme_provider._chain_issuer_cn",
        lambda pem: {"A": "Root A", "B": "Root B", "C": "Root C"}[pem],
    )
    provider = _provider()
    result = provider._select_chain("vg01", _order("A", ["B", "C"]), b"key")

    assert result.alternate_chain_issuers == ["Root A", "Root B", "Root C"]


def test_handles_none_alternates(cert_chain):
    _, fullchain = cert_chain
    order = MagicMock()
    order.fullchain_pem = fullchain
    order.alternative_fullchains_pem = None

    result = _provider()._select_chain("vg01", order, b"key")
    assert result.chain_issuer_cn == "Test Root R1"


def test_complete_chain_appends_isrg_root_x1():
    _, acme_chain = _geny_chain_without_x1()
    before = x509.load_pem_x509_certificates(acme_chain.encode())
    assert [c.subject.rfc4514_string() for c in before] == [
        "CN=vg01.example.com",
        "CN=YR1",
        "CN=Root YR",
    ]

    completed = complete_chain(acme_chain)
    after = x509.load_pem_x509_certificates(completed.encode())
    subjects = [c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value for c in after]
    assert subjects == ["vg01.example.com", "YR1", "Root YR", "ISRG Root X1"]
    assert _chain_issuer_cn(completed) == "ISRG Root X1"


def test_complete_chain_is_idempotent():
    _, acme_chain = _geny_chain_without_x1()
    once = complete_chain(acme_chain)
    assert complete_chain(once) == once


def test_complete_chain_leaves_unrelated_roots_alone(cert_chain):
    _, fullchain = cert_chain
    assert complete_chain(fullchain) == fullchain


def test_select_chain_stores_x1_on_the_preferred_path():
    _, acme_chain = _geny_chain_without_x1()
    result = _provider(preferred_chain="ISRG Root X1")._select_chain(
        "vg01", _order(acme_chain, []), b"key"
    )
    certs = x509.load_pem_x509_certificates(result.fullchain_pem.encode())
    subjects = [c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value for c in certs]
    assert "ISRG Root X1" in subjects
    assert result.chain_issuer_cn == "ISRG Root X1"
