"""Shared API dependencies: sessions, auth, and view assembly."""

from collections.abc import Iterator
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from sqlmodel import Session, select

from app.api.schemas import CertificateOut, DeviceOut
from app.config import Settings, get_settings
from app.db.models import CAProfile, CertStatus, Certificate, Device, Role, Tenant
from app.db.session import get_engine
from app.issuance import latest_certificate, needs_renewal, renewal_threshold
from app.vault import SecretBox


def get_session() -> Iterator[Session]:
    with Session(get_engine()) as session:
        yield session


def get_config() -> Settings:
    return get_settings()


def get_box(settings: Settings = Depends(get_config)) -> SecretBox:
    return SecretBox.from_b64(settings.require_master_key())


@dataclass
class Principal:
    """Who is making a request, and what they may do."""

    actor: str
    role: Role
    method: str  # "webex" | "token"


def require_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_config),
    session: Session = Depends(get_session),
) -> Principal:
    """Accept either a Webex session cookie or the automation bearer token.

    Fails closed: with neither Webex OAuth nor an API token configured, the API
    refuses every request rather than running open. Returns the actor, which is
    recorded in the audit log.
    """
    import hmac

    from app.auth import SESSION_COOKIE, derive_session_secret, verify_session
    from app.roles import resolve_role

    # 1. Browser session from Webex sign-in. Role comes from the grant table.
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie and settings.master_key:
        payload = verify_session(cookie, derive_session_secret(settings.master_key))
        if payload:
            email = payload.get("email") or "webex"
            role, reason = resolve_role(session, email, settings)
            if role is None:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
            return Principal(actor=email, role=role, method="webex")

    # 2. Bearer token for the CLI, cron and scripts. Holding the token is
    #    equivalent to server-side access, so it carries admin.
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization.split(" ", 1)[1].strip()
        # Constant-time; token length should not be observable.
        if settings.api_token and hmac.compare_digest(supplied, settings.api_token):
            return Principal(actor="api-token", role=Role.admin, method="token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )

    if not settings.api_token and not settings.webex_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No authentication is configured. Set HTAC_API_TOKEN, or a Webex "
                "integration, before using the API."
            ),
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sign in required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _require_role(required: Role):
    def dependency(principal: Principal = Depends(require_auth)) -> Principal:
        if not principal.role.at_least(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"{principal.actor} has role '{principal.role.value}'; this "
                    f"action requires '{required.value}' or higher"
                ),
            )
        return principal

    return dependency


require_viewer = _require_role(Role.viewer)
require_operator = _require_role(Role.operator)
require_admin = _require_role(Role.admin)


# -- view assembly -----------------------------------------------------------


def certificate_view(cert: Certificate) -> CertificateOut:
    return CertificateOut(
        id=cert.id,
        serial=cert.serial,
        subject_cn=cert.subject_cn,
        fingerprint_sha256=cert.fingerprint_sha256,
        not_before=cert.not_before,
        not_after=cert.not_after,
        chain_issuer_cn=cert.chain_issuer_cn,
        status=cert.status.value,
        pkcs12_profile=cert.pkcs12_profile.value,
        target_trustpoint=cert.target_trustpoint,
        created_at=cert.created_at,
        deployed_at=cert.deployed_at,
        days_remaining=cert.days_remaining(),
    )


def device_state(days: int | None, due: bool, has_cert: bool) -> str:
    if not has_cert:
        return "missing"
    if days is not None and days < 0:
        return "expired"
    return "renew_due" if due else "ok"


def device_view(
    session: Session, device: Device, settings: Settings, *, detail: bool = False
):
    from app.api.schemas import DeviceDetailOut

    tenant = session.get(Tenant, device.tenant_id)
    cert = latest_certificate(session, device)
    due, _, days = needs_renewal(
        session, device, tenant, spread_days=settings.renewal_spread_days
    )
    threshold = renewal_threshold(device, tenant, settings.renewal_spread_days)

    has_password = device.password_sealed is not None or (
        tenant is not None and tenant.default_password_sealed is not None
    )
    has_username = bool(device.username or (tenant and tenant.default_username))

    payload = dict(
        id=device.id,
        hostname=device.hostname,
        fqdn=device.fqdn,
        mgmt_address=device.mgmt_address,
        tenant_slug=tenant.slug if tenant else "",
        tenant_name=tenant.name if tenant else "",
        enabled=device.enabled,
        trustpoint_a=device.trustpoint_a,
        trustpoint_b=device.trustpoint_b,
        active_trustpoint=device.active_trustpoint,
        idle_trustpoint=device.idle_trustpoint(),
        pkcs12_profile=device.pkcs12_profile.value,
        revocation_check=device.revocation_check,
        has_credentials=bool(has_password and has_username),
        days_remaining=days,
        not_after=cert.not_after if cert else None,
        chain_issuer_cn=cert.chain_issuer_cn if cert else None,
        serial=cert.serial if cert else None,
        cert_status=cert.status.value if cert else None,
        renewal_threshold=threshold,
        renewal_due=due,
        state=device_state(days, due, cert is not None),
    )

    if not detail:
        return DeviceOut(**payload)

    history = session.exec(
        select(Certificate)
        .where(Certificate.device_id == device.id)
        .order_by(Certificate.created_at.desc())
    ).all()
    return DeviceDetailOut(
        **payload, certificates=[certificate_view(c) for c in history]
    )


def get_device_or_404(session: Session, fqdn: str) -> Device:
    device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
    if device is None:
        raise HTTPException(status_code=404, detail=f"No device with FQDN {fqdn}")
    return device


def ca_profile_view(profile: CAProfile):
    from app.api.schemas import CAProfileOut

    return CAProfileOut(
        id=profile.id,
        name=profile.name,
        directory_url=profile.directory_url,
        contact_email=profile.contact_email,
        preferred_chain=profile.preferred_chain,
        enabled=profile.enabled,
        uses_eab=profile.uses_eab,
        registered=profile.account_uri is not None,
    )


__all__ = [
    "get_session",
    "get_config",
    "get_box",
    "require_auth",
    "require_viewer",
    "require_operator",
    "require_admin",
    "Principal",
    "device_view",
    "certificate_view",
    "ca_profile_view",
    "get_device_or_404",
    "CertStatus",
]
