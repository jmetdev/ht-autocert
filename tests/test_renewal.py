"""Renewal decisions.

The Ansible version inferred these from certbot's stdout, which meant a device
whose import had failed stayed untouched until the CA next issued. These come
from stored state instead.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import (
    CAProfile,
    CertStatus,
    Certificate,
    Device,
    Pkcs12Profile,
    Tenant,
)
from app.issuance import latest_certificate, needs_renewal


@pytest.fixture
def fleet(session):
    ca = CAProfile(
        name="le-staging",
        directory_url="https://example.invalid/directory",
        contact_email="ops@example.com",
    )
    session.add(ca)
    session.commit()

    tenant = Tenant(
        slug="husd",
        name="Test Client",
        domain_suffix="husd.clients.example.com",
        ca_profile_id=ca.id,
        renew_before_days=30,
    )
    session.add(tenant)
    session.commit()

    device = Device(
        tenant_id=tenant.id,
        hostname="vg01",
        fqdn="vg01.husd.clients.example.com",
        mgmt_address="10.0.0.1",
    )
    session.add(device)
    session.commit()
    return session, tenant, device


def _add_cert(session, device, days_until_expiry: int, *, status=CertStatus.issued,
              serial="AA"):
    now = datetime.now(timezone.utc)
    cert = Certificate(
        device_id=device.id,
        ca_profile_id=1,
        serial=serial,
        fingerprint_sha256="00" * 32,
        subject_cn=device.fqdn,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=days_until_expiry),
        chain_issuer_cn="ISRG Root X1",
        fullchain_pem="",
        private_key_sealed=b"x",
        pkcs12_sealed=b"x",
        pkcs12_password_sealed=b"x",
        pkcs12_profile=Pkcs12Profile.modern,
        status=status,
    )
    session.add(cert)
    session.commit()
    return cert


def test_no_certificate_needs_issuance(fleet):
    session, tenant, device = fleet
    needed, reason, days = needs_renewal(session, device, tenant)
    assert needed is True
    assert days is None
    assert "no certificate" in reason


def test_fresh_certificate_is_skipped(fleet):
    session, tenant, device = fleet
    _add_cert(session, device, days_until_expiry=75)

    needed, reason, days = needs_renewal(session, device, tenant)
    assert needed is False
    assert days == 74  # not_after is 75 days out; whole days elapsed
    assert "valid for" in reason


def test_certificate_inside_threshold_renews(fleet):
    session, tenant, device = fleet
    _add_cert(session, device, days_until_expiry=20)

    needed, reason, days = needs_renewal(session, device, tenant)
    assert needed is True
    assert "threshold 30d" in reason


def test_expired_certificate_renews(fleet):
    session, tenant, device = fleet
    _add_cert(session, device, days_until_expiry=-5)

    needed, _, days = needs_renewal(session, device, tenant)
    assert needed is True
    assert days < 0


def test_boundary_at_threshold_renews(fleet):
    """A monthly cron plus a 30-day threshold left roughly one day of margin;
    the boundary must renew rather than skip."""
    session, tenant, device = fleet
    _add_cert(session, device, days_until_expiry=30)

    needed, _, _ = needs_renewal(session, device, tenant)
    assert needed is True


def test_tenant_threshold_is_respected(fleet):
    session, tenant, device = fleet
    _add_cert(session, device, days_until_expiry=40)
    assert needs_renewal(session, device, tenant)[0] is False

    tenant.renew_before_days = 45
    session.add(tenant)
    session.commit()
    assert needs_renewal(session, device, tenant)[0] is True


def test_latest_certificate_ignores_failed_records(fleet):
    session, tenant, device = fleet
    _add_cert(session, device, days_until_expiry=80, status=CertStatus.failed, serial="BB")
    good = _add_cert(session, device, days_until_expiry=10, serial="CC")

    assert latest_certificate(session, device).id == good.id
    assert needs_renewal(session, device, tenant)[0] is True


def test_latest_certificate_picks_furthest_expiry(fleet):
    session, tenant, device = fleet
    _add_cert(session, device, days_until_expiry=10, serial="OLD")
    newest = _add_cert(session, device, days_until_expiry=88, serial="NEW")

    assert latest_certificate(session, device).id == newest.id
    assert needs_renewal(session, device, tenant)[0] is False


def test_blue_green_trustpoint_alternates(fleet):
    _, _, device = fleet
    assert device.active_trustpoint is None
    assert device.idle_trustpoint() == "HT-WxCAutoCert-A"

    device.active_trustpoint = "HT-WxCAutoCert-A"
    assert device.idle_trustpoint() == "HT-WxCAutoCert-B"

    device.active_trustpoint = "HT-WxCAutoCert-B"
    assert device.idle_trustpoint() == "HT-WxCAutoCert-A"
