"""Webex OAuth sign-in routes.

Unauthenticated by design -- these are how a session is obtained.
"""

import structlog
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.api.deps import get_box, get_config, get_session
from app.auth import (
    SESSION_COOKIE,
    STATE_COOKIE,
    AuthError,
    WebexOAuth,
    derive_session_secret,
    is_authorised,
    new_state,
    sign_session,
    verify_session,
)
from app.config import Settings
from app.db.models import Role
from app.roles import resolve_role, touch_last_seen
from app.webex_session import forget_token, store_token

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _oauth(settings: Settings) -> WebexOAuth:
    return WebexOAuth(
        settings.webex_client_id,
        settings.webex_client_secret,
        settings.webex_redirect_uri,
        scopes=settings.webex_scope_string,
    )


def _error(message: str, status: int = 400) -> RedirectResponse:
    """Send failures back to the sign-in screen with a readable reason."""
    from urllib.parse import quote

    response = RedirectResponse(url=f"/?auth_error={quote(message)}", status_code=303)
    response.delete_cookie(STATE_COOKIE, path="/")
    return response


@router.get("/config")
def auth_config(settings: Settings = Depends(get_config)) -> dict:
    """What sign-in methods this deployment offers. Safe to call anonymously."""
    return {
        "webex_enabled": settings.webex_enabled,
        "token_enabled": bool(settings.api_token),
    }


@router.get("/login")
def login(settings: Settings = Depends(get_config)):
    if not settings.webex_enabled:
        return _error("Webex sign-in is not configured on this server")

    state = new_state()
    response = RedirectResponse(url=_oauth(settings).authorize_url(state), status_code=307)
    # The state is echoed back by Webex and compared against this cookie, so a
    # third party cannot feed us an authorization code from another flow.
    response.set_cookie(
        STATE_COOKIE,
        state,
        max_age=600,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/callback")
def callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
    settings: Settings = Depends(get_config),
    session=Depends(get_session),
    box=Depends(get_box),
):
    if error:
        return _error(error_description or error)
    if not settings.webex_enabled:
        return _error("Webex sign-in is not configured on this server")
    if not code or not state:
        return _error("Webex did not return an authorization code")

    expected = request.cookies.get(STATE_COOKIE)
    if not expected or state != expected:
        log.warning("auth.state_mismatch")
        return _error("Sign-in state did not match; please try again")

    oauth = _oauth(settings)
    try:
        access_token, refresh_token, expires_in = oauth.exchange_code(code)
        user = oauth.fetch_user(access_token)
    except AuthError as exc:
        log.warning("auth.webex_failed", error=str(exc))
        return _error(str(exc))
    finally:
        oauth.close()

    allowed, reason = is_authorised(
        user,
        settings.webex_allowed_emails,
        settings.webex_allowed_domains,
        settings.webex_allowed_org_id,
    )
    if not allowed:
        log.warning("auth.denied", email=user.email, reason=reason)
        return _error(reason, status=403)

    # Keep the token so Control Hub reads run as this operator rather than
    # under a separate service credential.
    try:
        store_token(
            session, box, user.email, access_token, refresh_token,
            expires_in, settings.webex_scope_string,
        )
    except Exception as exc:  # noqa: BLE001 - sign-in must not fail over this
        log.warning("webex.token_store_failed", email=user.email, error=str(exc))

    log.info("auth.signed_in", email=user.email, reason=reason)
    token = sign_session(
        {"email": user.email, "name": user.display_name, "org": user.org_id},
        derive_session_secret(settings.require_master_key()),
        settings.session_ttl_hours * 3600,
    )

    response = RedirectResponse(url="/fleet", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(STATE_COOKIE, path="/")
    return response


@router.post("/logout")
def logout(
    request: Request,
    settings: Settings = Depends(get_config),
    session=Depends(get_session),
) -> JSONResponse:
    # Drop the stored Webex token too: signing out should not leave an
    # admin-scoped credential sitting in the datastore.
    token = request.cookies.get(SESSION_COOKIE)
    if token and settings.master_key:
        payload = verify_session(token, derive_session_secret(settings.master_key))
        if payload and payload.get("email"):
            forget_token(session, payload["email"])

    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/me")
def me(
    request: Request,
    settings: Settings = Depends(get_config),
    session=Depends(get_session),
) -> JSONResponse:
    """Current session and role, or 401. Used by the console on load."""
    token = request.cookies.get(SESSION_COOKIE)
    if token and settings.master_key:
        payload = verify_session(token, derive_session_secret(settings.master_key))
        if payload:
            email = payload.get("email") or ""
            role, reason = resolve_role(session, email, settings)
            if role is None:
                # Signed in, but granted nothing. Say so plainly rather than
                # showing a console where every action fails.
                return JSONResponse(
                    {"authenticated": False, "email": email, "reason": reason},
                    status_code=403,
                )
            touch_last_seen(session, email)
            return JSONResponse(
                {
                    "authenticated": True,
                    "method": "webex",
                    "email": email,
                    "name": payload.get("name"),
                    "role": role.value,
                }
            )

    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer ") and settings.api_token:
        import hmac as _hmac

        if _hmac.compare_digest(header.split(" ", 1)[1].strip(), settings.api_token):
            return JSONResponse(
                {
                    "authenticated": True,
                    "method": "token",
                    "email": None,
                    "name": "API token",
                    "role": Role.admin.value,
                }
            )

    return JSONResponse({"authenticated": False}, status_code=401)
