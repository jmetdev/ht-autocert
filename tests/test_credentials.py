"""Credential resolution and the DB-level deployment path."""

import pytest

from app.db.models import (
    CAProfile,
    CertStatus,
    Certificate,
    Device,
    Pkcs12Profile,
    RunLog,
    RunStatus,
    Tenant,
)
from app.deployment import DeploymentService
from app.devices.base import DeviceError, TrustpointState
from app.devices.factory import (
    aad_device_secret,
    aad_tenant_secret,
    resolve_credentials,
)
from app.vault import SecretBox, aad_pkcs12, aad_pkcs12_password
from tests.test_deployment import CN, SERIAL, FakeTransport


@pytest.fixture
def fleet(session, box):
    ca = CAProfile(name="ca", directory_url="https://x.invalid", contact_email="a@b.c")
    session.add(ca)
    session.commit()

    tenant = Tenant(
        slug="husd", name="HUSD", domain_suffix="husd.clients.example.com",
        ca_profile_id=ca.id,
    )
    session.add(tenant)
    session.commit()

    device = Device(
        tenant_id=tenant.id, hostname="vg01", fqdn=CN, mgmt_address="10.0.0.1"
    )
    session.add(device)
    session.commit()
    return session, tenant, device


# -- credentials -------------------------------------------------------------


def test_device_credentials_take_precedence(fleet, box):
    session, tenant, device = fleet
    tenant.default_username = "tenant-user"
    tenant.default_password_sealed = box.seal(b"tenant-pw", aad_tenant_secret("husd", "password"))
    device.username = "device-user"
    device.password_sealed = box.seal(b"device-pw", aad_device_secret(CN, "password"))
    session.add(tenant)
    session.add(device)
    session.commit()

    assert resolve_credentials(session, device, box)[:2] == ("device-user", "device-pw")


def test_falls_back_to_tenant_defaults(fleet, box):
    session, tenant, device = fleet
    tenant.default_username = "tenant-user"
    tenant.default_password_sealed = box.seal(
        b"tenant-pw", aad_tenant_secret("husd", "password")
    )
    session.add(tenant)
    session.commit()

    assert resolve_credentials(session, device, box)[:2] == ("tenant-user", "tenant-pw")


def test_missing_credentials_give_an_actionable_error(fleet, box):
    session, _, device = fleet
    with pytest.raises(DeviceError, match="set-credentials"):
        resolve_credentials(session, device, box)


def test_enable_password_is_optional(fleet, box):
    session, _, device = fleet
    device.username = "u"
    device.password_sealed = box.seal(b"pw", aad_device_secret(CN, "password"))
    session.add(device)
    session.commit()
    assert resolve_credentials(session, device, box)[2] is None

    device.enable_password_sealed = box.seal(
        b"enablepw", aad_device_secret(CN, "enable_password")
    )
    session.add(device)
    session.commit()
    assert resolve_credentials(session, device, box)[2] == "enablepw"


def test_credentials_are_not_stored_in_plaintext(fleet, box):
    session, _, device = fleet
    device.password_sealed = box.seal(b"hunter2", aad_device_secret(CN, "password"))
    session.add(device)
    session.commit()
    assert b"hunter2" not in device.password_sealed


# -- DB-level deployment -----------------------------------------------------


@pytest.fixture
def issued_cert(fleet, box):
    session, _, device = fleet
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    cert = Certificate(
        device_id=device.id,
        ca_profile_id=1,
        serial=SERIAL,
        fingerprint_sha256="00" * 32,
        subject_cn=CN,
        not_before=now,
        not_after=now + timedelta(days=90),
        chain_issuer_cn="ISRG Root X1",
        fullchain_pem="",
        private_key_sealed=b"x",
        pkcs12_sealed=box.seal(b"p12-bytes", aad_pkcs12(CN, SERIAL)),
        pkcs12_password_sealed=box.seal(b"p12-password", aad_pkcs12_password(CN, SERIAL)),
        pkcs12_profile=Pkcs12Profile.modern,
        target_trustpoint="HT-WxCAutoCert-B",
    )
    session.add(cert)
    session.commit()
    return session, device, cert


def test_successful_deployment_updates_stored_state(issued_cert, box):
    session, device, cert = issued_cert
    transport = FakeTransport()
    service = DeploymentService(
        session, box, lambda d: _ctx(transport), public_base_url="http://htac.test"
    )

    result = service.deploy_device(device, cert)

    assert result.status == "deployed"
    assert device.active_trustpoint == "HT-WxCAutoCert-B"
    assert cert.status == CertStatus.deployed
    assert cert.deployed_at is not None


def test_failed_deployment_does_not_advance_active_trustpoint(issued_cert, box):
    session, device, cert = issued_cert
    transport = FakeTransport(import_result="reject")
    service = DeploymentService(
        session, box, lambda d: _ctx(transport), public_base_url="http://htac.test"
    )

    result = service.deploy_device(device, cert)

    assert result.status == "failed"
    assert device.active_trustpoint is None
    assert cert.status == CertStatus.issued


def test_deployment_is_recorded_in_the_run_log(issued_cert, box):
    from sqlmodel import select

    session, device, cert = issued_cert
    service = DeploymentService(
        session, box, lambda d: _ctx(FakeTransport()), public_base_url="http://htac.test"
    )
    service.deploy_device(device, cert)

    logs = session.exec(select(RunLog).where(RunLog.action == "deploy")).all()
    assert len(logs) == 1
    assert logs[0].status == RunStatus.success


def test_key_access_is_audited(issued_cert, box):
    from sqlmodel import select

    from app.db.models import AuditEvent

    session, device, cert = issued_cert
    service = DeploymentService(
        session, box, lambda d: _ctx(FakeTransport()), public_base_url="http://htac.test"
    )
    service.deploy_device(device, cert)

    events = session.exec(
        select(AuditEvent).where(AuditEvent.action == "p12.deploy")
    ).all()
    assert len(events) == 1
    assert events[0].subject == CN


def test_previous_certificate_is_superseded(issued_cert, box):
    from datetime import datetime, timedelta, timezone

    session, device, cert = issued_cert
    now = datetime.now(timezone.utc)
    old = Certificate(
        device_id=device.id, ca_profile_id=1, serial="OLD",
        fingerprint_sha256="11" * 32, subject_cn=CN,
        not_before=now - timedelta(days=60), not_after=now + timedelta(days=30),
        chain_issuer_cn="ISRG Root X1", fullchain_pem="",
        private_key_sealed=b"x", pkcs12_sealed=b"x", pkcs12_password_sealed=b"x",
        pkcs12_profile=Pkcs12Profile.modern, status=CertStatus.deployed,
    )
    session.add(old)
    session.commit()

    service = DeploymentService(
        session, box, lambda d: _ctx(FakeTransport()), public_base_url="http://htac.test"
    )
    service.deploy_device(device, cert)

    session.refresh(old)
    assert old.status == CertStatus.superseded


def test_deploys_into_the_certificate_target_trustpoint(issued_cert, box):
    session, device, cert = issued_cert
    device.active_trustpoint = "HT-WxCAutoCert-A"
    transport = FakeTransport(
        trustpoints={
            "HT-WxCAutoCert-A": TrustpointState(
                label="HT-WxCAutoCert-A", subject_cn=CN, serial="OLD", has_certificate=True
            )
        }
    )
    service = DeploymentService(
        session, box, lambda d: _ctx(transport), public_base_url="http://htac.test"
    )

    service.deploy_device(device, cert)
    assert ("import_pkcs12", "HT-WxCAutoCert-B", "htautocert.p12") in transport.calls


class _ctx:
    """Adapt FakeTransport to the context-manager the factory returns."""

    def __init__(self, transport):
        self.transport = transport

    def __enter__(self):
        return self.transport

    def __exit__(self, *exc_info):
        return False


# -- SSH host key pinning ----------------------------------------------------


def test_pinned_key_is_materialised_for_the_ssh_client(tmp_path):
    """A container has no ~/.ssh/known_hosts, so the key must travel with the
    device record."""
    from app.devices.ssh import IosXeSshTransport

    line = "10.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB"
    t = IosXeSshTransport("10.0.0.1", "u", "p", host_key=line)

    path = t._known_hosts_path()
    assert path is not None
    assert open(path).read().strip() == line
    assert oct(__import__("os").stat(path).st_mode)[-3:] == "600"

    t.close()


def test_temp_known_hosts_is_removed_on_close():
    import os

    from app.devices.ssh import IosXeSshTransport

    t = IosXeSshTransport("10.0.0.1", "u", "p", host_key="10.0.0.1 ssh-rsa AAAA")
    path = t._known_hosts_path()
    assert os.path.exists(path)

    t.close()
    assert not os.path.exists(path)


def test_no_pinned_key_falls_back_to_system_known_hosts():
    from app.devices.ssh import IosXeSshTransport

    t = IosXeSshTransport("10.0.0.1", "u", "p")
    assert t._known_hosts_path() is None


def test_explicit_known_hosts_file_wins():
    from app.devices.ssh import IosXeSshTransport

    t = IosXeSshTransport(
        "10.0.0.1", "u", "p", known_hosts_file="/etc/ssh/ssh_known_hosts",
        host_key="10.0.0.1 ssh-rsa AAAA",
    )
    assert t._known_hosts_path() == "/etc/ssh/ssh_known_hosts"


def test_build_transport_passes_the_pinned_key(fleet, box):
    from app.devices.factory import aad_tenant_secret, build_transport

    session, tenant, device = fleet
    tenant.default_username = "netadmin"
    tenant.default_password_sealed = box.seal(
        b"pw", aad_tenant_secret("husd", "password")
    )
    device.ssh_host_key = "10.0.0.1 ssh-rsa PINNEDKEY"
    session.add(tenant)
    session.add(device)
    session.commit()

    transport = build_transport(session, device, box)
    assert transport.host_key == "10.0.0.1 ssh-rsa PINNEDKEY"
    assert transport.strict_host_key is True


def test_doctor_warns_about_unpinned_devices(fleet, box):
    from app.config import Settings
    from app.health import WARN, run_checks

    session, tenant, device = fleet
    assert device.ssh_host_key is None

    report = run_checks(
        session,
        Settings(
            master_key=SecretBox.generate_master_key(),
            cloudflare_api_token="t",
            api_token="t",
        ),
    )
    check = next(c for c in report.checks if c.name == "ssh host keys")
    assert check.status == WARN
    assert "container" in check.remedy
