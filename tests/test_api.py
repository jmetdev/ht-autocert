"""API surface: auth, views, and the secrets boundary."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.deps import get_box, get_config, get_session
from app.config import Settings
from app.db.models import (
    CAProfile,
    CertStatus,
    Certificate,
    Device,
    Pkcs12Profile,
    Tenant,
)
from app.vault import aad_pkcs12, aad_pkcs12_password

TOKEN = "test-api-token"
CN = "vg01.husd.clients.example.com"
SERIAL = "0A1B2C3D"
P12_PASSWORD = "SuperSecretP12Password"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        master_key="",
        api_token=TOKEN,
        renewal_spread_days=0,
        schedule_enabled=False,
    )


@pytest.fixture
def seeded(session, box):
    ca = CAProfile(
        name="letsencrypt", directory_url="https://acme.invalid/d",
        contact_email="ops@example.com", preferred_chain="ISRG Root X1",
        account_uri="https://acme.invalid/acct/1",
    )
    session.add(ca)
    session.commit()

    tenant = Tenant(
        slug="husd", name="HUSD", domain_suffix="husd.clients.example.com",
        ca_profile_id=ca.id, renew_before_days=30,
    )
    session.add(tenant)
    session.commit()

    ok_device = Device(
        tenant_id=tenant.id, hostname="vg01", fqdn=CN, mgmt_address="10.0.0.1",
        active_trustpoint="HT-WxCAutoCert-A",
    )
    due_device = Device(
        tenant_id=tenant.id, hostname="vg02",
        fqdn="vg02.husd.clients.example.com", mgmt_address="10.0.0.2",
    )
    bare_device = Device(
        tenant_id=tenant.id, hostname="vg03",
        fqdn="vg03.husd.clients.example.com", mgmt_address="10.0.0.3",
    )
    session.add_all([ok_device, due_device, bare_device])
    session.commit()

    now = datetime.now(timezone.utc)

    def _cert(device, days, serial, status=CertStatus.deployed):
        return Certificate(
            device_id=device.id, ca_profile_id=ca.id, serial=serial,
            fingerprint_sha256="ab" * 32, subject_cn=device.fqdn,
            not_before=now - timedelta(days=1), not_after=now + timedelta(days=days),
            chain_issuer_cn="ISRG Root X1", fullchain_pem="-----BEGIN CERTIFICATE-----",
            private_key_sealed=box.seal(b"PRIVATE-KEY-MATERIAL", "k"),
            pkcs12_sealed=box.seal(b"p12", aad_pkcs12(device.fqdn, serial)),
            pkcs12_password_sealed=box.seal(
                P12_PASSWORD.encode(), aad_pkcs12_password(device.fqdn, serial)
            ),
            pkcs12_profile=Pkcs12Profile.modern, status=status,
            target_trustpoint="HT-WxCAutoCert-A",
        )

    session.add(_cert(ok_device, 75, SERIAL))
    session.add(_cert(due_device, 12, "BEEF"))
    session.commit()
    return session


@pytest.fixture
def client(seeded, box, settings):
    app = create_app()
    app.dependency_overrides[get_session] = lambda: seeded
    app.dependency_overrides[get_config] = lambda: settings
    app.dependency_overrides[get_box] = lambda: box
    with TestClient(app) as c:
        c.headers.update({"Authorization": f"Bearer {TOKEN}"})
        yield c


# -- auth --------------------------------------------------------------------


def test_requires_a_token(client):
    response = client.get("/api/devices", headers={"Authorization": ""})
    assert response.status_code == 401


def test_rejects_a_wrong_token(client):
    response = client.get("/api/devices", headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401


def test_api_fails_closed_when_no_token_is_configured(seeded, box):
    """An unconfigured deployment must refuse requests, not serve them openly."""
    app = create_app()
    app.dependency_overrides[get_session] = lambda: seeded
    app.dependency_overrides[get_config] = lambda: Settings(
        api_token="", schedule_enabled=False
    )
    app.dependency_overrides[get_box] = lambda: box
    with TestClient(app) as c:
        assert c.get("/api/devices").status_code == 503


def test_healthz_is_open(client):
    assert client.get("/healthz", headers={"Authorization": ""}).status_code == 200


# -- the secrets boundary ----------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/api/devices", f"/api/devices/{CN}", "/api/tenants", "/api/ca-profiles",
     "/api/summary", "/api/runs", "/api/audit"],
)
def test_no_endpoint_leaks_key_material(client, path):
    body = client.get(path).text
    for secret in ("PRIVATE-KEY-MATERIAL", P12_PASSWORD, "sealed", "_sealed"):
        assert secret not in body, f"{path} leaked {secret!r}"


def test_device_detail_exposes_metadata_but_not_bundles(client):
    payload = client.get(f"/api/devices/{CN}").json()
    cert = payload["certificates"][0]

    assert cert["serial"] == SERIAL
    assert cert["chain_issuer_cn"] == "ISRG Root X1"
    assert "pkcs12_sealed" not in cert
    assert "private_key_sealed" not in cert
    assert "fullchain_pem" not in cert


# -- views -------------------------------------------------------------------


def test_summary_classifies_the_fleet(client):
    payload = client.get("/api/summary").json()

    assert payload["devices"] == 3
    assert payload["tenants"] == 1
    assert payload["ok"] == 1
    assert payload["renew_due"] == 1
    assert payload["missing"] == 1
    assert payload["scheduler_enabled"] is False


def test_device_list_reports_state_and_trustpoints(client):
    devices = {d["fqdn"]: d for d in client.get("/api/devices").json()}

    ok = devices[CN]
    assert ok["state"] == "ok"
    assert ok["days_remaining"] == 74
    assert ok["active_trustpoint"] == "HT-WxCAutoCert-A"
    assert ok["idle_trustpoint"] == "HT-WxCAutoCert-B"

    assert devices["vg02.husd.clients.example.com"]["state"] == "renew_due"
    assert devices["vg03.husd.clients.example.com"]["state"] == "missing"


def test_device_list_filters_by_state(client):
    due = client.get("/api/devices", params={"state": "renew_due"}).json()
    assert [d["fqdn"] for d in due] == ["vg02.husd.clients.example.com"]


def test_device_list_filters_by_tenant(client):
    assert len(client.get("/api/devices", params={"tenant": "husd"}).json()) == 3
    assert client.get("/api/devices", params={"tenant": "nope"}).status_code == 404


def test_credentials_flag_is_reported_without_exposing_them(client):
    device = client.get(f"/api/devices/{CN}").json()
    assert device["has_credentials"] is False


def test_tenant_view_includes_ca_and_device_count(client):
    tenant = client.get("/api/tenants").json()[0]
    assert tenant["slug"] == "husd"
    assert tenant["ca_profile_name"] == "letsencrypt"
    assert tenant["device_count"] == 3


def test_ca_profile_reports_registration_without_the_account_key(client):
    profile = client.get("/api/ca-profiles").json()[0]
    assert profile["registered"] is True
    assert profile["uses_eab"] is False
    assert "account_key_sealed" not in profile


def test_unknown_device_is_404(client):
    assert client.get("/api/devices/nope.example.com").status_code == 404


# -- actions -----------------------------------------------------------------


def test_deploy_without_a_certificate_is_a_conflict(client):
    response = client.post("/api/devices/vg03.husd.clients.example.com/deploy")
    assert response.status_code == 409
    assert "No certificate" in response.json()["detail"]


def test_live_state_surfaces_device_errors_as_502(client, monkeypatch):
    from app.devices.base import DeviceError

    def boom(*args, **kwargs):
        raise DeviceError("connection refused")

    monkeypatch.setattr("app.api.routes.build_transport", boom)
    response = client.get(f"/api/devices/{CN}/live")
    assert response.status_code == 502
    assert "connection refused" in response.json()["detail"]


def test_live_state_refuses_the_certificate_fqdn_as_a_host(client, seeded):
    from sqlmodel import select

    from app.db.models import Device as D

    device = seeded.exec(select(D).where(D.fqdn == CN)).first()
    device.mgmt_address = CN
    seeded.add(device)
    seeded.commit()

    response = client.get(f"/api/devices/{CN}/live")
    assert response.status_code == 409
    assert "no management IP" in response.json()["detail"]
    assert "ACME" in response.json()["detail"]


def test_set_address_stores_an_ip_and_rejects_the_cert_fqdn(client, seeded):
    bad = client.put(f"/api/devices/{CN}/address?address={CN}")
    assert bad.status_code == 400

    ok = client.put(f"/api/devices/{CN}/address?address=10.40.8.10")
    assert ok.status_code == 200
    body = ok.json()
    assert body["mgmt_address"] == "10.40.8.10"
    assert body["has_mgmt_address"] is True


# -- Webex discovery ---------------------------------------------------------


class FakeInventory:
    """Stands in for Control Hub. Records the org each call was scoped to."""

    orgs: list = []
    trunks_by_org: dict = {}
    seen_orgs: list = []

    def __init__(self, token, **kwargs):
        self.token = token

    def organizations(self):
        return list(self.orgs)

    def trunks(self, org_id=None):
        FakeInventory.seen_orgs.append(org_id)
        return list(self.trunks_by_org.get(org_id, []))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


@pytest.fixture
def webex(monkeypatch, seeded, box):
    """A stored Webex token for the api-token principal, plus a fake Control Hub."""
    import app.webex_inventory as inventory_module
    from app.webex_inventory import DiscoveredGateway, WebexOrg
    from app.webex_session import store_token

    store_token(seeded, box, "api-token", "wx-access", None, 3600, "scopes")

    FakeInventory.seen_orgs = []
    FakeInventory.orgs = [
        WebexOrg(org_id="ORG-HUSD", display_name="Higley Unified"),
        WebexOrg(org_id="ORG-OTHER", display_name="Yuma Elementary"),
    ]
    FakeInventory.trunks_by_org = {
        "ORG-HUSD": [
            DiscoveredGateway(
                name="Dual Reg - VG400", trunk_id="T1", trunk_type="REGISTERING",
                device_type="Cisco CUBE Local Gateway", location="Phoenix",
            ),
            DiscoveredGateway(
                name="HQ CUBE", trunk_id="T2", trunk_type="CERTIFICATE_BASED",
                address="hq.husd.clients.example.com",
            ),
        ],
        "ORG-OTHER": [
            DiscoveredGateway(name="Other", trunk_id="T9", trunk_type="REGISTERING"),
        ],
    }
    monkeypatch.setattr(inventory_module, "WebexInventory", FakeInventory)
    return FakeInventory


def test_webex_calls_are_scoped_to_the_selected_org(client, webex):
    """A missing orgId would silently read the partner's own org, not the client's."""
    response = client.post("/api/webex/import?tenant=husd&org_id=ORG-HUSD")
    assert response.status_code == 200
    assert webex.seen_orgs == ["ORG-HUSD"]


def test_import_without_a_linked_org_is_refused(client, webex):
    response = client.post("/api/webex/import?tenant=husd")
    assert response.status_code == 400
    assert "not linked to a Webex organisation" in response.json()["detail"]


def test_import_falls_back_to_the_tenants_linked_org(client, webex, seeded):
    from sqlmodel import select

    from app.db.models import Tenant as T

    tenant = seeded.exec(select(T).where(T.slug == "husd")).first()
    tenant.webex_org_id = "ORG-HUSD"
    seeded.add(tenant)
    seeded.commit()

    assert client.post("/api/webex/import?tenant=husd").status_code == 200
    assert webex.seen_orgs == ["ORG-HUSD"]


def test_preview_marks_derived_names_and_does_not_create_devices(client, webex):
    before = len(client.get("/api/devices").json())
    body = client.post("/api/webex/import?tenant=husd&org_id=ORG-HUSD").json()

    assert body["applied"] is False and body["imported"] == 0
    by_name = {c["name"]: c for c in body["candidates"]}
    # Certificate-based trunk: Webex knows the name.
    assert by_name["HQ CUBE"]["fqdn_source"] == "webex"
    assert by_name["HQ CUBE"]["proposed_fqdn"] == "hq.husd.clients.example.com"
    # Registering trunk: derived from the tenant suffix, and slugified.
    assert by_name["Dual Reg - VG400"]["fqdn_source"] == "derived"
    assert (
        by_name["Dual Reg - VG400"]["proposed_fqdn"]
        == "dual-reg-vg400.husd.clients.example.com"
    )
    assert len(client.get("/api/devices").json()) == before


def test_imported_devices_are_disabled_so_the_scheduler_skips_them(client, webex, seeded):
    from sqlmodel import select

    from app.db.models import Device as D

    assert client.post(
        "/api/webex/import?tenant=husd&org_id=ORG-HUSD&apply=true"
    ).json()["imported"] == 2

    created = seeded.exec(select(D).where(D.hostname == "HQ CUBE")).first()
    assert created is not None
    assert created.enabled is False
    # Webex stored the SIP/certificate hostname, not an IOS management IP.
    assert created.mgmt_address == ""
    registering = seeded.exec(select(D).where(D.hostname == "Dual Reg - VG400")).first()
    assert registering is not None
    assert registering.mgmt_address == ""


def test_import_is_idempotent(client, webex):
    first = client.post("/api/webex/import?tenant=husd&org_id=ORG-HUSD&apply=true")
    assert first.json()["imported"] == 2

    second = client.post("/api/webex/import?tenant=husd&org_id=ORG-HUSD&apply=true")
    assert second.json()["imported"] == 0
    assert all(
        c["reason"] == "already in inventory"
        for c in second.json()["candidates"]
    )


def test_org_list_reports_which_tenant_each_org_is_linked_to(client, webex, seeded):
    from sqlmodel import select

    from app.db.models import Tenant as T

    tenant = seeded.exec(select(T).where(T.slug == "husd")).first()
    tenant.webex_org_id = "ORG-HUSD"
    seeded.add(tenant)
    seeded.commit()

    body = client.get("/api/webex/orgs").json()
    linked = {o["org_id"]: o["tenant_slug"] for o in body}
    assert linked == {"ORG-HUSD": "husd", "ORG-OTHER": None}


def test_an_org_cannot_be_linked_to_two_tenants(client, webex, seeded):
    from app.db.models import Tenant as T

    seeded.add(T(slug="other", name="Other", domain_suffix="other.example.com"))
    seeded.commit()

    assert client.put("/api/tenants/husd/webex-org?org_id=ORG-HUSD").status_code == 200
    clash = client.put("/api/tenants/other/webex-org?org_id=ORG-HUSD")
    assert clash.status_code == 409
    assert "already linked to tenant husd" in clash.json()["detail"]


def test_discovery_without_a_stored_webex_token_explains_why(client, seeded, monkeypatch):
    """Signing in with the API token gives no Webex token to read Control Hub with."""
    import app.webex_inventory as inventory_module

    monkeypatch.setattr(inventory_module, "WebexInventory", FakeInventory)
    response = client.get("/api/webex/orgs")
    assert response.status_code == 409
    assert "Sign out and sign in with Webex" in response.json()["detail"]
