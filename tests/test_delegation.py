"""CNAME delegation detection.

DNS forbids a CNAME coexisting with other data at the same name. Where
``_acme-challenge.<host>`` is CNAME'd elsewhere (the acme-dns pattern), a TXT
written into the parent zone is accepted by the provider's API but never
served -- so the order validates against nothing and the run only fails at the
propagation timeout, with no indication of why.
"""

from unittest.mock import MagicMock

import pytest

from app.ca.acme_provider import AcmeError, AcmeProvider


def _provider(**kwargs) -> AcmeProvider:
    solver = MagicMock()
    solver.authoritative_nameservers.return_value = ["ns1.example.net"]
    return AcmeProvider(
        directory_url="https://acme.invalid/directory",
        contact_email="ops@example.com",
        solver=solver,
        account_store=MagicMock(),
        **kwargs,
    )


NAME = "_acme-challenge.vg01.husd.clients.example.com"
TARGET = "687fce46-dabb-483d-9bfb-b67c9db6f56e.auth.acme-dns.io"


def test_delegated_name_is_rejected_before_writing(monkeypatch):
    monkeypatch.setattr(
        "app.dns.propagation._resolve_ns_addresses", lambda ns, **kw: ["192.0.2.1"]
    )
    monkeypatch.setattr(
        "app.dns.propagation.detect_cname", lambda name, servers, **kw: TARGET
    )

    with pytest.raises(AcmeError) as exc:
        _provider()._reject_if_delegated(NAME)

    message = str(exc.value)
    assert TARGET in message
    assert "will not be served" in message
    # The two ways out are both named.
    assert "remove the CNAME" in message
    assert "acme-dns" in message


def test_undelegated_name_passes(monkeypatch):
    monkeypatch.setattr(
        "app.dns.propagation._resolve_ns_addresses", lambda ns, **kw: ["192.0.2.1"]
    )
    monkeypatch.setattr(
        "app.dns.propagation.detect_cname", lambda name, servers, **kw: None
    )

    _provider()._reject_if_delegated(NAME)  # must not raise


def test_probe_failure_never_blocks_issuance(monkeypatch):
    """The check is advisory; a broken probe must not stop a valid order."""

    def boom(*args, **kwargs):
        raise OSError("resolver unavailable")

    monkeypatch.setattr("app.dns.propagation._resolve_ns_addresses", boom)

    _provider()._reject_if_delegated(NAME)  # must not raise


def test_no_reachable_nameservers_skips_the_check(monkeypatch):
    monkeypatch.setattr(
        "app.dns.propagation._resolve_ns_addresses", lambda ns, **kw: []
    )
    called = []
    monkeypatch.setattr(
        "app.dns.propagation.detect_cname",
        lambda *a, **k: called.append(1) or TARGET,
    )

    _provider()._reject_if_delegated(NAME)
    assert called == []


def test_detect_cname_returns_target(monkeypatch):
    import dns.resolver

    from app.dns.propagation import detect_cname

    rdata = MagicMock()
    rdata.target = f"{TARGET}."
    monkeypatch.setattr(
        dns.resolver.Resolver, "resolve", lambda self, name, rdtype: [rdata]
    )

    assert detect_cname(NAME, ["192.0.2.1"]) == TARGET


def test_detect_cname_returns_none_when_absent(monkeypatch):
    import dns.resolver

    from app.dns.propagation import detect_cname

    def no_answer(self, name, rdtype):
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", no_answer)

    assert detect_cname(NAME, ["192.0.2.1"]) is None


# -- order deadline ----------------------------------------------------------


def test_order_deadline_is_naive():
    """The acme library polls with a bare datetime.datetime.now().

    An aware deadline raises "can't compare offset-naive and offset-aware
    datetimes" at finalization -- after the challenge has been answered and the
    DNS record cleaned up, so the order is already burnt.
    """
    import datetime as dt

    from app.ca.acme_provider import _order_deadline

    deadline = _order_deadline(300)

    assert deadline.tzinfo is None
    # Must be directly comparable with what the library uses.
    assert dt.datetime.now() < deadline


def test_order_deadline_respects_the_timeout():
    import datetime as dt

    from app.ca.acme_provider import _order_deadline

    remaining = (_order_deadline(120) - dt.datetime.now()).total_seconds()
    assert 115 < remaining <= 120


# -- rate limit translation --------------------------------------------------

RATE_LIMIT_DETAIL = (
    "There were too many requests of a given type :: too many certificates (5) "
    "already issued for this exact set of identifiers in the last 168h0m0s, "
    "retry after 2026-08-15 06:50:45 UTC: see https://letsencrypt.org/docs/rate-limits/"
)


def test_duplicate_certificate_limit_is_explained():
    from acme import messages

    from app.ca.acme_provider import RateLimitedError, _translate_acme_error

    exc = messages.Error(
        typ="urn:ietf:params:acme:error:rateLimited", detail=RATE_LIMIT_DETAIL
    )
    result = _translate_acme_error(exc, "vg01.example.com")

    assert isinstance(result, RateLimitedError)
    assert result.duplicate_limit is True
    assert result.retry_after == "2026-08-15 06:50:45 UTC"
    message = str(result)
    # The three things an operator needs: scope, that accounts don't help, when.
    assert "only affects this one gateway" in message
    assert "global across ACME accounts" in message
    assert "2026-08-15 06:50:45 UTC" in message


def test_other_rate_limits_are_passed_through():
    from acme import messages

    from app.ca.acme_provider import RateLimitedError, _translate_acme_error

    exc = messages.Error(
        typ="urn:ietf:params:acme:error:rateLimited",
        detail="too many certificates already issued for registered domain",
    )
    result = _translate_acme_error(exc, "vg01.example.com")

    assert isinstance(result, RateLimitedError)
    assert result.duplicate_limit is False


def test_non_rate_limit_errors_are_not_misreported():
    from acme import messages

    from app.ca.acme_provider import AcmeError, RateLimitedError, _translate_acme_error

    exc = messages.Error(
        typ="urn:ietf:params:acme:error:malformed", detail="bad CSR"
    )
    result = _translate_acme_error(exc, "vg01.example.com")

    assert isinstance(result, AcmeError)
    assert not isinstance(result, RateLimitedError)
    assert "bad CSR" in str(result)
