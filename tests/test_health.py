"""Health checks.

A lost or rotated master key must be detectable on demand. Without this it
surfaces at deployment time as an authentication failure deep in the vault,
which reads like data corruption rather than a key mismatch.
"""

import pytest

from app.config import Settings
from app.db.models import CAProfile, Device, Tenant
from app.devices.base import DeviceError
from app.devices.factory import (
    aad_device_secret,
    aad_tenant_secret,
    resolve_credentials,
)
from app.health import FAIL, OK, WARN, run_checks
from app.vault import SecretBox


def _settings(**kwargs) -> Settings:
    base = dict(
        master_key=SecretBox.generate_master_key(),
        cloudflare_api_token="cf-token",
        api_token="api-token",
    )
    base.update(kwargs)
    return Settings(**base)


def _status(report, name):
    return next(c.status for c in report.checks if c.name == name)


@pytest.fixture
def fleet(session, box):
    ca = CAProfile(name="le", directory_url="https://x.invalid", contact_email="a@b.c")
    session.add(ca)
    session.commit()
    tenant = Tenant(
        slug="husd", name="HUSD", domain_suffix="husd.clients.example.com",
        ca_profile_id=ca.id,
    )
    session.add(tenant)
    session.commit()
    device = Device(
        tenant_id=tenant.id, hostname="vg01", fqdn="vg01.example.com",
        mgmt_address="10.0.0.1",
    )
    session.add(device)
    session.commit()
    return session, tenant, device


# -- configuration -----------------------------------------------------------


def test_missing_master_key_fails_immediately(session, monkeypatch):
    # Settings falls back to HTAC_MASTER_KEY / HTAC_MASTER_KEY_FILE, so the
    # environment has to be genuinely empty for this to be an absent key.
    monkeypatch.delenv("HTAC_MASTER_KEY", raising=False)
    monkeypatch.delenv("HTAC_MASTER_KEY_FILE", raising=False)

    report = run_checks(session, _settings(master_key=""))
    assert _status(report, "master key") == FAIL
    assert report.failures == 1


def test_malformed_master_key_is_reported(session):
    report = run_checks(session, _settings(master_key="not-base64!!"))
    assert _status(report, "master key") == FAIL


def test_missing_cloudflare_token_fails(session):
    report = run_checks(session, _settings(cloudflare_api_token=""))
    assert _status(report, "cloudflare token") == FAIL


def test_missing_api_token_is_only_a_warning(session):
    """The CLI still works without it; only the console is affected."""
    report = run_checks(session, _settings(api_token=""))
    assert _status(report, "api token") == WARN
    assert report.failures == 0


# -- the key-mismatch case ---------------------------------------------------


def test_empty_datastore_passes(session):
    report = run_checks(session, _settings())
    assert _status(report, "sealed records") == OK
    assert report.failures == 0


def test_sealed_values_readable_under_the_same_key(fleet):
    """The healthy case: values sealed with the configured key all open."""
    session, tenant, device = fleet
    key_b64 = SecretBox.generate_master_key()
    box = SecretBox.from_b64(key_b64)

    tenant.default_username = "netadmin"
    tenant.default_password_sealed = box.seal(
        b"pw", aad_tenant_secret("husd", "password")
    )
    device.password_sealed = box.seal(
        b"devpw", aad_device_secret("vg01.example.com", "password")
    )
    session.add(tenant)
    session.add(device)
    session.commit()

    report = run_checks(session, _settings(master_key=key_b64))

    assert _status(report, "sealed records") == OK
    assert _status(report, "device credentials") == OK
    assert report.failures == 0


def test_rotated_master_key_is_detected(fleet, box):
    """Exactly the situation a lost .env file creates."""
    session, tenant, _ = fleet
    tenant.default_username = "netadmin"
    tenant.default_password_sealed = box.seal(
        b"pw", aad_tenant_secret("husd", "password")
    )
    session.add(tenant)
    session.commit()

    report = run_checks(session, _settings())  # a different, fresh master key

    assert _status(report, "sealed records") == FAIL
    detail = next(c for c in report.checks if c.name == "sealed records").detail
    assert "cannot be decrypted" in detail

    remedies = [c.remedy for c in report.checks if c.remedy]
    assert any("tenant set-credentials husd" in r for r in remedies)


def test_report_names_every_unreadable_record(fleet, box):
    session, tenant, device = fleet
    tenant.default_password_sealed = box.seal(b"a", aad_tenant_secret("husd", "password"))
    device.password_sealed = box.seal(
        b"b", aad_device_secret("vg01.example.com", "password")
    )
    device.enable_password_sealed = box.seal(
        b"c", aad_device_secret("vg01.example.com", "enable_password")
    )
    session.add(tenant)
    session.add(device)
    session.commit()

    report = run_checks(session, _settings())
    labels = [c.name.strip() for c in report.checks if c.status == FAIL]

    assert any("tenant[husd].default_password" in n for n in labels)
    assert any("device[vg01.example.com].password" in n for n in labels)
    assert any("device[vg01.example.com].enable_password" in n for n in labels)


# -- credential resolution ---------------------------------------------------


def test_undecryptable_credential_gives_an_actionable_error(fleet, box):
    """Not a bare vault authentication failure."""
    session, tenant, device = fleet
    tenant.default_username = "netadmin"
    tenant.default_password_sealed = box.seal(
        b"pw", aad_tenant_secret("husd", "password")
    )
    session.add(tenant)
    session.commit()

    other_key = SecretBox.from_b64(SecretBox.generate_master_key())
    with pytest.raises(DeviceError, match="HTAC_MASTER_KEY"):
        resolve_credentials(session, device, other_key)

    with pytest.raises(DeviceError, match="tenant set-credentials husd"):
        resolve_credentials(session, device, other_key)


def test_devices_without_credentials_are_warned_about(fleet):
    session, _, _ = fleet
    report = run_checks(session, _settings())
    assert _status(report, "device credentials") == WARN


def test_tenant_without_a_ca_profile_is_warned_about(fleet):
    session, tenant, _ = fleet
    tenant.ca_profile_id = None
    session.add(tenant)
    session.commit()

    report = run_checks(session, _settings())
    assert _status(report, "tenant CA profiles") == WARN


def test_certificate_fqdn_as_mgmt_address_is_warned_about(fleet):
    session, _, device = fleet
    device.mgmt_address = device.fqdn
    session.add(device)
    session.commit()

    report = run_checks(session, _settings())
    assert _status(report, "management addresses") == WARN
