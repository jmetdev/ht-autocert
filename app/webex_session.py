"""Storage for a signed-in user's Webex OAuth token.

The console reads Control Hub with the operator's own token rather than a
separate service credential. That keeps admin rights tied to a real person --
Webex records who read what, and revoking someone in Control Hub revokes their
access here too, with no second credential to remember to rotate.

The trade-off is that the token has to outlive the HTTP request that obtained
it, so it is sealed with the vault exactly like escrowed key material and never
leaves the server.
"""

from __future__ import annotations

from datetime import timedelta

import structlog
from sqlmodel import Session, select

from app.db.models import WebexToken, utcnow
from app.vault import SecretBox, VaultError, aad_webex_token

log = structlog.get_logger(__name__)


class WebexTokenError(RuntimeError):
    """No usable Webex token for this user. Message is shown to the operator."""


def store_token(
    session: Session,
    box: SecretBox,
    email: str,
    access_token: str,
    refresh_token: str | None,
    expires_in: int,
    scopes: str,
) -> None:
    email = email.lower()
    record = session.exec(
        select(WebexToken).where(WebexToken.email == email)
    ).first() or WebexToken(email=email, access_sealed=b"")

    record.access_sealed = box.seal(
        access_token.encode(), aad_webex_token(email, "access")
    )
    record.refresh_sealed = (
        box.seal(refresh_token.encode(), aad_webex_token(email, "refresh"))
        if refresh_token
        else None
    )
    record.expires_at = utcnow() + timedelta(seconds=expires_in) if expires_in else None
    record.scopes = scopes
    record.updated_at = utcnow()

    session.add(record)
    session.commit()
    log.info("webex.token_stored", email=email, expires_at=record.expires_at)


def load_token(session: Session, box: SecretBox, email: str) -> str:
    """Return the caller's Webex access token, or explain why there isn't one."""
    email = (email or "").lower()
    record = session.exec(select(WebexToken).where(WebexToken.email == email)).first()

    if record is None:
        raise WebexTokenError(
            "No Webex token stored for you. This happens when you signed in "
            "with an API token rather than Webex, or before Control Hub access "
            "was enabled. Sign out and sign in with Webex again."
        )
    try:
        access = box.open(record.access_sealed, aad_webex_token(email, "access")).decode()
        if not record.expired():
            return access
        if not record.refresh_sealed:
            raise WebexTokenError(
                "Your Webex token has expired and has no refresh token. Sign out "
                "and sign in again."
            )
        refresh = box.open(
            record.refresh_sealed, aad_webex_token(email, "refresh")
        ).decode()
    except VaultError as exc:
        raise WebexTokenError(
            "Your stored Webex token cannot be decrypted with the current "
            "master key. Sign out and sign in again."
        ) from exc

    # Refresh on demand so Control Hub discovery continues beyond the short
    # access-token lifetime without keeping a second service credential.
    from app.auth import AuthError, WebexOAuth
    from app.config import get_settings

    settings = get_settings()
    if not settings.webex_enabled:
        raise WebexTokenError(
            "Your Webex token expired and OAuth is not configured for refresh."
        )
    oauth = WebexOAuth(
        settings.webex_client_id,
        settings.webex_client_secret,
        settings.webex_redirect_uri,
        scopes=settings.webex_scope_string,
    )
    try:
        access, refresh, expires_in = oauth.refresh(refresh)
    except AuthError as exc:
        raise WebexTokenError(f"Webex token refresh failed: {exc}") from exc
    finally:
        oauth.close()
    store_token(
        session, box, email, access, refresh, expires_in, record.scopes or ""
    )
    return access


def forget_token(session: Session, email: str) -> None:
    """Drop the stored token, e.g. on sign-out."""
    record = session.exec(
        select(WebexToken).where(WebexToken.email == (email or "").lower())
    ).first()
    if record is not None:
        session.delete(record)
        session.commit()
