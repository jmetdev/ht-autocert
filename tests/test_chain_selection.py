"""Chain selection.

Let's Encrypt is migrating from ISRG Root X1 to Root YR, and ZeroSSL presents a
different hierarchy again. Which chain ships to a gateway has to be a recorded
decision, because the failure mode is a peer silently refusing the certificate.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.ca.acme_provider import AcmeProvider, AcmeError, _chain_issuer_cn


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
    _, fullchain = cert_chain
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
