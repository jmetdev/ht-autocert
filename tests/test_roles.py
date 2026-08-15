"""Role-based access control.

The gap this closes: with a domain allowlist, everyone at the company can sign
in. On an MSP console that can redeploy certificates to client voice gateways,
"works here" must not imply "may change production".
"""

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.deps import get_box, get_config, get_session
from app.auth import SESSION_COOKIE, derive_session_secret, sign_session
from app.config import Settings
from app.db.models import Operator, Role
from app.roles import parse_default_role, resolve_role
from app.vault import SecretBox

MASTER_KEY = SecretBox.generate_master_key()
STAFF = "receptionist@hyetechnetworks.com"
ENGINEER = "engineer@hyetechnetworks.com"
BOSS = "jmetcalf@hyetechnetworks.com"


def _settings(**kwargs) -> Settings:
    base = dict(
        master_key=MASTER_KEY,
        api_token="automation-token",
        webex_client_id="cid",
        webex_client_secret="csecret",
        webex_allowed_domains="hyetechnetworks.com",
        session_cookie_secure=False,
        schedule_enabled=False,
    )
    base.update(kwargs)
    return Settings(**base)


# -- role ordering -----------------------------------------------------------


def test_role_ordering():
    assert Role.admin.at_least(Role.operator)
    assert Role.operator.at_least(Role.viewer)
    assert not Role.viewer.at_least(Role.operator)
    assert not Role.operator.at_least(Role.admin)
    assert Role.viewer.at_least(Role.viewer)


def test_default_role_parsing():
    assert parse_default_role("none") is None
    assert parse_default_role("") is None
    assert parse_default_role("deny") is None
    assert parse_default_role("nonsense") is None  # unknown means deny
    assert parse_default_role("viewer") is Role.viewer
    assert parse_default_role("OPERATOR") is Role.operator


# -- resolution --------------------------------------------------------------


def test_signing_in_grants_nothing_by_default(session):
    """The whole point: domain membership alone must not confer access."""
    role, reason = resolve_role(session, STAFF, _settings())
    assert role is None
    assert "no role" in reason
    assert "operator add" in reason


def test_explicit_grant_is_honoured(session):
    session.add(Operator(email=ENGINEER, role=Role.operator))
    session.commit()
    role, _ = resolve_role(session, ENGINEER, _settings())
    assert role is Role.operator


def test_grant_lookup_is_case_insensitive(session):
    session.add(Operator(email=ENGINEER, role=Role.operator))
    session.commit()
    role, _ = resolve_role(session, ENGINEER.upper(), _settings())
    assert role is Role.operator


def test_disabled_grant_denies(session):
    session.add(Operator(email=ENGINEER, role=Role.admin, enabled=False))
    session.commit()
    role, reason = resolve_role(session, ENGINEER, _settings())
    assert role is None
    assert "disabled" in reason


def test_bootstrap_admin_works_before_any_grant_exists(session):
    role, reason = resolve_role(session, BOSS, _settings(bootstrap_admins=BOSS))
    assert role is Role.admin
    assert reason == "bootstrap admin"


def test_bootstrap_admin_outranks_a_lesser_grant(session):
    """Otherwise a mistaken downgrade could lock everyone out."""
    session.add(Operator(email=BOSS, role=Role.viewer))
    session.commit()
    role, _ = resolve_role(session, BOSS, _settings(bootstrap_admins=BOSS))
    assert role is Role.admin


def test_default_role_can_be_opened_up_deliberately(session):
    role, _ = resolve_role(session, STAFF, _settings(webex_default_role="viewer"))
    assert role is Role.viewer


def test_default_role_never_grants_write_by_accident(session):
    """A typo in the setting must not silently hand out operator."""
    role, _ = resolve_role(session, STAFF, _settings(webex_default_role="oprator"))
    assert role is None


# -- enforcement through the API --------------------------------------------


@pytest.fixture
def client(session):
    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_config] = lambda: _settings()
    app.dependency_overrides[get_box] = lambda: SecretBox.from_b64(MASTER_KEY)
    with TestClient(app) as c:
        yield c


def _sign_in(client, email: str):
    client.cookies.set(
        SESSION_COOKIE,
        sign_session({"email": email}, derive_session_secret(MASTER_KEY), 3600),
    )


def test_signed_in_without_a_grant_is_forbidden(client):
    _sign_in(client, STAFF)
    response = client.get("/api/devices")
    assert response.status_code == 403
    assert "no role" in response.json()["detail"]


def test_me_reports_no_access_rather_than_an_empty_console(client):
    _sign_in(client, STAFF)
    response = client.get("/auth/me")
    assert response.status_code == 403
    assert response.json()["authenticated"] is False


def test_viewer_can_read(client, session):
    session.add(Operator(email=STAFF, role=Role.viewer))
    session.commit()
    _sign_in(client, STAFF)

    assert client.get("/api/devices").status_code == 200
    assert client.get("/api/summary").status_code == 200
    assert client.get("/auth/me").json()["role"] == "viewer"


def test_viewer_cannot_issue_or_deploy(client, session):
    """Read access must not imply the ability to touch a client's gateway."""
    session.add(Operator(email=STAFF, role=Role.viewer))
    session.commit()
    _sign_in(client, STAFF)

    for path in (
        "/api/devices/vg01.example.com/issue",
        "/api/devices/vg01.example.com/deploy",
        "/api/cycle",
    ):
        response = client.post(path)
        assert response.status_code == 403, path
        assert "requires 'operator'" in response.json()["detail"]


def test_operator_passes_the_role_gate(client, session):
    """404 for the unknown device, not 403: the role check was satisfied."""
    session.add(Operator(email=ENGINEER, role=Role.operator))
    session.commit()
    _sign_in(client, ENGINEER)

    response = client.post("/api/devices/nosuchdevice.example.com/issue")
    assert response.status_code == 404


def test_api_token_retains_admin_for_automation(client):
    response = client.get(
        "/auth/me", headers={"Authorization": "Bearer automation-token"}
    )
    assert response.json()["role"] == "admin"


def test_revoking_a_grant_blocks_the_next_request(client, session):
    grant = Operator(email=ENGINEER, role=Role.operator)
    session.add(grant)
    session.commit()
    _sign_in(client, ENGINEER)
    assert client.get("/api/devices").status_code == 200

    grant.enabled = False
    session.add(grant)
    session.commit()

    # The session cookie is still cryptographically valid; the grant is not.
    assert client.get("/api/devices").status_code == 403
