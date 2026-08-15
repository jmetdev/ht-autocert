"""Webex OAuth sign-in, sessions, and the authorisation policy.

The distinction under test throughout: authenticating against Webex proves who
someone is, not that they are allowed to operate this fleet.
"""

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.deps import get_box, get_config, get_session
from app.auth import (
    SESSION_COOKIE,
    STATE_COOKIE,
    AuthError,
    WebexOAuth,
    WebexUser,
    derive_session_secret,
    is_authorised,
    new_state,
    sign_session,
    verify_session,
)
from app.config import Settings
from app.vault import SecretBox

MASTER_KEY = SecretBox.generate_master_key()
USER = WebexUser(
    email="jmetcalf@hyetechnetworks.com",
    display_name="J Metcalf",
    org_id="ORG123",
    person_id="PERSON123",
)


# -- session signing ---------------------------------------------------------


def test_session_roundtrip():
    secret = derive_session_secret(MASTER_KEY)
    token = sign_session({"email": USER.email}, secret, 3600)
    assert verify_session(token, secret)["email"] == USER.email


def test_session_rejects_a_different_key():
    token = sign_session({"email": USER.email}, derive_session_secret(MASTER_KEY), 3600)
    other = derive_session_secret(SecretBox.generate_master_key())
    assert verify_session(token, other) is None


def test_session_rejects_tampering():
    secret = derive_session_secret(MASTER_KEY)
    token = sign_session({"email": "user@example.com"}, secret, 3600)
    body, mac = token.split(".", 1)
    forged = f"{body[:-2]}XX.{mac}"
    assert verify_session(forged, secret) is None


def test_expired_session_is_rejected():
    secret = derive_session_secret(MASTER_KEY)
    token = sign_session({"email": USER.email}, secret, -1)
    assert verify_session(token, secret) is None


def test_session_secret_is_domain_separated():
    """A session key must not be usable as, or derivable from, the vault key."""
    import base64

    secret = derive_session_secret(MASTER_KEY)
    assert secret != base64.b64decode(MASTER_KEY)


def test_garbage_tokens_are_rejected():
    secret = derive_session_secret(MASTER_KEY)
    for junk in ("", "no-dot", "a.b", "....", "x" * 200):
        assert verify_session(junk, secret) is None


def test_state_tokens_are_unique():
    assert len({new_state() for _ in range(100)}) == 100


# -- authorisation policy ----------------------------------------------------


def test_no_policy_denies_everyone():
    """The critical default: any Webex user on earth can authenticate."""
    allowed, reason = is_authorised(USER, "", "", "")
    assert allowed is False
    assert "no access policy configured" in reason


def test_email_allowlist():
    assert is_authorised(USER, USER.email, "", "")[0] is True
    assert is_authorised(USER, "someone@else.com", "", "")[0] is False


def test_email_allowlist_is_case_insensitive():
    assert is_authorised(USER, "JMetcalf@HyeTechNetworks.com", "", "")[0] is True


def test_domain_allowlist():
    assert is_authorised(USER, "", "hyetechnetworks.com", "")[0] is True
    assert is_authorised(USER, "", "@hyetechnetworks.com", "")[0] is True
    assert is_authorised(USER, "", "example.com", "")[0] is False


def test_domain_allowlist_does_not_match_a_suffix():
    """'nothyetechnetworks.com' must not satisfy 'hyetechnetworks.com'."""
    impostor = WebexUser(
        email="attacker@nothyetechnetworks.com", display_name="x",
        org_id=None, person_id=None,
    )
    assert is_authorised(impostor, "", "hyetechnetworks.com", "")[0] is False


def test_org_id_allowlist():
    assert is_authorised(USER, "", "", "ORG123")[0] is True
    assert is_authorised(USER, "", "", "OTHERORG")[0] is False


def test_denial_reason_names_the_user():
    allowed, reason = is_authorised(USER, "", "example.com", "")
    assert allowed is False
    assert USER.email in reason


# -- OAuth client ------------------------------------------------------------


def _oauth(handler) -> WebexOAuth:
    return WebexOAuth(
        "cid", "csecret", "https://console.example.com/auth/callback",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_authorize_url_contains_state_and_scope():
    url = _oauth(lambda r: httpx.Response(200)).authorize_url("STATE123")
    assert "state=STATE123" in url
    assert "spark%3Apeople_read" in url
    assert "response_type=code" in url
    assert url.startswith("https://webexapis.com/v1/authorize")


def test_code_exchange_and_profile():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/access_token":
            return httpx.Response(200, json={"access_token": "AT"})
        return httpx.Response(
            200,
            json={
                "id": "PERSON123",
                "displayName": "J Metcalf",
                "userName": "jmetcalf@hyetechnetworks.com",
                "orgId": "ORG123",
            },
        )

    oauth = _oauth(handler)
    access_token, refresh_token, expires_in = oauth.exchange_code("CODE")
    assert (access_token, refresh_token) == ("AT", None)
    user = oauth.fetch_user(access_token)
    assert user.email == "jmetcalf@hyetechnetworks.com"
    assert user.org_id == "ORG123"


def test_rejected_code_raises():
    oauth = _oauth(lambda r: httpx.Response(400, json={"message": "bad code"}))
    with pytest.raises(AuthError, match="rejected the authorization code"):
        oauth.exchange_code("BAD")


def test_profile_without_email_is_rejected():
    def handler(request):
        if request.url.path == "/v1/access_token":
            return httpx.Response(200, json={"access_token": "AT"})
        return httpx.Response(200, json={"id": "X", "displayName": "No Email"})

    oauth = _oauth(handler)
    with pytest.raises(AuthError, match="no email"):
        oauth.fetch_user("AT")


# -- end to end through the app ---------------------------------------------


@pytest.fixture
def settings() -> Settings:
    return Settings(
        master_key=MASTER_KEY,
        api_token="automation-token",
        webex_client_id="cid",
        webex_client_secret="csecret",
        webex_redirect_uri="http://testserver/auth/callback",
        webex_allowed_domains="hyetechnetworks.com",
        session_cookie_secure=False,
        schedule_enabled=False,
    )


@pytest.fixture
def client(session, settings):
    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_config] = lambda: settings
    app.dependency_overrides[get_box] = lambda: SecretBox.from_b64(MASTER_KEY)
    with TestClient(app) as c:
        yield c


def test_auth_config_is_anonymous(client):
    body = client.get("/auth/config").json()
    assert body == {"webex_enabled": True, "token_enabled": True}


def test_login_redirects_to_webex_and_sets_state(client):
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"].startswith("https://webexapis.com/v1/authorize")
    assert STATE_COOKIE in response.cookies


def test_callback_rejects_a_mismatched_state(client):
    """Otherwise a third party could feed us a code from another flow."""
    client.cookies.set(STATE_COOKIE, "the-real-state")
    response = client.get(
        "/auth/callback?code=X&state=attacker-state", follow_redirects=False
    )
    assert response.status_code == 303
    assert "state+did+not+match" in response.headers["location"].replace("%20", "+")
    assert SESSION_COOKIE not in response.cookies


def test_callback_without_a_code_is_refused(client):
    client.cookies.set(STATE_COOKIE, "s")
    response = client.get("/auth/callback?state=s", follow_redirects=False)
    assert response.status_code == 303
    assert SESSION_COOKIE not in response.cookies


def test_me_is_401_when_anonymous(client):
    assert client.get("/auth/me").status_code == 401


def test_me_accepts_the_bearer_token(client):
    body = client.get(
        "/auth/me", headers={"Authorization": "Bearer automation-token"}
    ).json()
    assert body["authenticated"] is True
    assert body["method"] == "token"


def test_me_accepts_a_valid_session_cookie(client, settings, session):
    from app.db.models import Operator, Role

    session.add(Operator(email=USER.email, role=Role.operator))
    session.commit()

    token = sign_session(
        {"email": USER.email, "name": USER.display_name},
        derive_session_secret(MASTER_KEY),
        3600,
    )
    client.cookies.set(SESSION_COOKIE, token)
    body = client.get("/auth/me").json()

    assert body["authenticated"] is True
    assert body["method"] == "webex"
    assert body["email"] == USER.email


def test_api_accepts_a_session_cookie(client, session):
    from app.db.models import Operator, Role

    session.add(Operator(email=USER.email, role=Role.viewer))
    session.commit()

    token = sign_session(
        {"email": USER.email}, derive_session_secret(MASTER_KEY), 3600
    )
    client.cookies.set(SESSION_COOKIE, token)
    assert client.get("/api/devices").status_code == 200


def test_api_rejects_a_forged_session_cookie(client):
    forged = sign_session(
        {"email": "attacker@example.com"},
        derive_session_secret(SecretBox.generate_master_key()),
        3600,
    )
    client.cookies.set(SESSION_COOKIE, forged)
    assert client.get("/api/devices").status_code == 401


def test_api_rejects_an_expired_session_cookie(client):
    stale = sign_session(
        {"email": USER.email}, derive_session_secret(MASTER_KEY), -10
    )
    client.cookies.set(SESSION_COOKIE, stale)
    assert client.get("/api/devices").status_code == 401


def test_bearer_token_still_works_for_automation(client):
    response = client.get(
        "/api/devices", headers={"Authorization": "Bearer automation-token"}
    )
    assert response.status_code == 200


def test_logout_clears_the_session(client):
    token = sign_session({"email": USER.email}, derive_session_secret(MASTER_KEY), 3600)
    client.cookies.set(SESSION_COOKIE, token)

    response = client.post("/auth/logout")

    # Assert on what the server sent, not the test client's jar semantics.
    set_cookie = response.headers.get("set-cookie", "")
    assert SESSION_COOKIE in set_cookie
    assert 'Max-Age=0' in set_cookie or 'expires=Thu, 01 Jan 1970' in set_cookie.lower()


def test_api_fails_closed_with_no_auth_configured(session):
    """Neither Webex nor a token: refuse, never serve open."""
    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_config] = lambda: Settings(
        master_key=MASTER_KEY, api_token="", webex_client_id="",
        webex_client_secret="", schedule_enabled=False,
    )
    with TestClient(app) as c:
        assert c.get("/api/devices").status_code == 503


def test_session_cookie_is_httponly_and_lax(client, settings, monkeypatch):
    """The cookie authorises fleet-wide changes; JS must not be able to read it."""
    import app.api.auth_routes as ar

    class FakeOAuth:
        def __init__(self, *a, **k):
            pass

        def exchange_code(self, code):
            return "AT", "RT", 1209600

        def fetch_user(self, token):
            return USER

        def close(self):
            pass

    monkeypatch.setattr(ar, "WebexOAuth", FakeOAuth)
    client.cookies.set(STATE_COOKIE, "s")
    response = client.get("/auth/callback?code=C&state=s", follow_redirects=False)

    assert response.status_code == 303
    set_cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie.replace("Lax", "lax")


def test_unauthorised_domain_is_denied_at_callback(client, monkeypatch):
    import app.api.auth_routes as ar

    outsider = WebexUser(
        email="someone@gmail.com", display_name="Outsider", org_id="X", person_id="Y"
    )

    class FakeOAuth:
        def __init__(self, *a, **k):
            pass

        def exchange_code(self, code):
            return "AT", "RT", 1209600

        def fetch_user(self, token):
            return outsider

        def close(self):
            pass

    monkeypatch.setattr(ar, "WebexOAuth", FakeOAuth)
    client.cookies.set(STATE_COOKIE, "s")
    response = client.get("/auth/callback?code=C&state=s", follow_redirects=False)

    assert response.status_code == 303
    assert SESSION_COOKIE not in response.cookies
    assert "not+permitted" in response.headers["location"].replace("%20", "+")
