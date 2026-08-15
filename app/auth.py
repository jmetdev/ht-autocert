"""Webex OAuth sign-in and session handling.

Two authentication paths, deliberately:

* **Webex OAuth** for humans. Identity comes from Webex; the app never sees a
  password and there is no shared secret to circulate among operators.
* **Bearer token** for automation. The CLI, cron and scripts keep working
  without a browser.

Authorisation is separate from authentication and **fails closed**: a valid
Webex login is not sufficient. Without an explicit allowlist (email addresses,
domains, or a Webex org id) every login is refused, because any Webex user in
the world can authenticate against a public integration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

import httpx
import structlog

log = structlog.get_logger(__name__)

WEBEX_AUTHORIZE_URL = "https://webexapis.com/v1/authorize"
WEBEX_TOKEN_URL = "https://webexapis.com/v1/access_token"
WEBEX_ME_URL = "https://webexapis.com/v1/people/me"

# Identity only. Enough to sign in and nothing more.
WEBEX_SCOPE_IDENTITY = "spark:people_read"

# Reading org inventory needs admin scopes, and they only work when the
# signed-in user is a Webex administrator. Requesting a scope the integration
# was not registered with makes Webex reject the whole authorization, so these
# are opt-in via HTAC_WEBEX_SCOPES.
WEBEX_SCOPE_DEVICES = "spark-admin:devices_read"
WEBEX_SCOPE_TELEPHONY = "spark-admin:telephony_config_read"

WEBEX_SCOPE = WEBEX_SCOPE_IDENTITY

SESSION_COOKIE = "htac_session"
STATE_COOKIE = "htac_oauth_state"


class AuthError(RuntimeError):
    """Authentication or authorisation failure, safe to show a user."""


@dataclass(frozen=True)
class WebexUser:
    email: str
    display_name: str
    org_id: str | None
    person_id: str | None


# -- signed sessions ---------------------------------------------------------


def derive_session_secret(master_key_b64: str) -> bytes:
    """Derive the session-signing key from the master key.

    Keeps deployment to one secret. Domain-separated so a session cookie can
    never be confused with, or used to attack, sealed key material.
    """
    return hmac.new(
        base64.b64decode(master_key_b64), b"htac-session-signing-v1", hashlib.sha256
    ).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign_session(payload: dict, secret: bytes, ttl_seconds: int) -> str:
    body = dict(payload)
    body["exp"] = int(time.time()) + ttl_seconds
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    mac = hmac.new(secret, raw, hashlib.sha256).digest()
    return f"{_b64(raw)}.{_b64(mac)}"


def verify_session(token: str, secret: bytes) -> dict | None:
    """Return the payload, or None if the token is invalid or expired."""
    try:
        raw_b64, mac_b64 = token.split(".", 1)
        raw, mac = _unb64(raw_b64), _unb64(mac_b64)
    except Exception:  # noqa: BLE001 - any malformed token is simply invalid
        return None

    expected = hmac.new(secret, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        return None

    try:
        payload = json.loads(raw)
    except ValueError:
        return None

    if int(payload.get("exp", 0)) < time.time():
        return None
    return payload


def new_state() -> str:
    """CSRF token for the OAuth round trip."""
    return secrets.token_urlsafe(24)


# -- authorisation policy ----------------------------------------------------


def is_authorised(
    user: WebexUser, allowed_emails: str, allowed_domains: str, allowed_org_id: str
) -> tuple[bool, str]:
    """May this Webex user sign in at all?

    A coarse gate only. Passing it does not grant any ability to act -- see
    :func:`resolve_role`. With no policy configured this returns False:
    authenticating against Webex proves who someone is, not that they work here.
    """
    emails = {e.strip().lower() for e in allowed_emails.split(",") if e.strip()}
    domains = {d.strip().lower().lstrip("@") for d in allowed_domains.split(",") if d.strip()}
    org_id = allowed_org_id.strip()

    if not emails and not domains and not org_id:
        return False, (
            "no access policy configured; set HTAC_WEBEX_ALLOWED_DOMAINS, "
            "HTAC_WEBEX_ALLOWED_EMAILS or HTAC_WEBEX_ALLOWED_ORG_ID"
        )

    email = (user.email or "").lower()
    if org_id and user.org_id and user.org_id == org_id:
        return True, "org id matched"
    if email in emails:
        return True, "email allowlisted"
    if "@" in email and email.split("@", 1)[1] in domains:
        return True, "domain allowlisted"

    return False, f"{user.email} is not permitted to use this console"


def in_list(value: str, candidates: str) -> bool:
    return value.strip().lower() in {
        c.strip().lower() for c in candidates.split(",") if c.strip()
    }


# -- Webex OAuth -------------------------------------------------------------


class WebexOAuth:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        scopes: str | None = None,
        client: httpx.Client | None = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or WEBEX_SCOPE_IDENTITY
        self._client = client or httpx.Client(timeout=30.0)

    def authorize_url(self, state: str) -> str:
        from urllib.parse import urlencode

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": self.scopes,
            "state": state,
        }
        return f"{WEBEX_AUTHORIZE_URL}?{urlencode(params)}"

    def exchange_code(self, code: str) -> tuple[str, str | None, int]:
        """Return (access_token, refresh_token, expires_in_seconds)."""
        response = self._client.post(
            WEBEX_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": self.redirect_uri,
            },
        )
        if response.status_code >= 400:
            raise AuthError(
                f"Webex rejected the authorization code (HTTP {response.status_code})"
            )
        body = response.json()
        token = body.get("access_token")
        if not token:
            raise AuthError("Webex returned no access token")
        return token, body.get("refresh_token"), int(body.get("expires_in") or 0)

    def fetch_user(self, access_token: str) -> WebexUser:
        response = self._client.get(
            WEBEX_ME_URL, headers={"Authorization": f"Bearer {access_token}"}
        )
        if response.status_code >= 400:
            raise AuthError(f"could not read Webex profile (HTTP {response.status_code})")
        body = response.json()

        emails = body.get("emails") or []
        email = body.get("userName") or (emails[0] if emails else "")
        if not email:
            raise AuthError("Webex profile has no email address")

        return WebexUser(
            email=email,
            display_name=body.get("displayName") or email,
            org_id=body.get("orgId"),
            person_id=body.get("id"),
        )

    def close(self) -> None:
        self._client.close()
