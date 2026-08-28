"""Admin inventory routes.

Every mutating HTAC CLI operation is available here under the admin role.
The CLI remains as an emergency path against the same inventory functions.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlmodel import Session, select

from app.api.deps import (
    ca_profile_view,
    device_view,
    get_box,
    get_config,
    get_device_or_404,
    get_session,
    require_admin,
    require_operator,
    require_viewer,
    tenant_view,
)
from app.api.schemas import (
    CAProfileCreate,
    CAProfileOut,
    CAProfileUpdate,
    CredentialsIn,
    DeviceCreate,
    DeviceOut,
    DeviceUpdate,
    DnsChallengeListOut,
    DnsChallengeOut,
    DoctorCheckOut,
    DoctorReportOut,
    HostKeyOut,
    OperatorCreate,
    OperatorOut,
    OperatorUpdate,
    SansIn,
    TenantCreate,
    TenantOut,
    TenantUpdate,
)
from app.config import Settings
from app.db.models import Operator, Role
from app.inventory import (
    InventoryError,
    LETSENCRYPT_PROD,
    create_ca_profile,
    create_device,
    create_tenant,
    delete_ca_profile,
    delete_device,
    delete_operator,
    delete_tenant,
    pin_host_key,
    preview_host_key,
    set_device_credentials,
    set_tenant_credentials,
    update_ca_profile,
    update_device,
    update_operator,
    update_tenant,
    upsert_operator,
)
from app.issuance import IssuanceService, latest_certificate
from app.vault import SecretBox

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/api", dependencies=[Depends(require_viewer)])


def _call(fn):
    try:
        return fn()
    except InventoryError as exc:
        log.error(
            "inventory.error",
            status=exc.status,
            detail=str(exc),
        )
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


# -- CA profiles -------------------------------------------------------------


@router.post("/ca-profiles", response_model=CAProfileOut)
def api_create_ca(
    body: CAProfileCreate,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    box: SecretBox = Depends(get_box),
) -> CAProfileOut:
    profile = _call(
        lambda: create_ca_profile(
            session,
            box,
            name=body.name,
            email=body.email,
            directory_url=body.directory_url or LETSENCRYPT_PROD,
            staging=body.staging,
            eab_kid=body.eab_kid,
            eab_hmac=body.eab_hmac,
            preferred_chain=body.preferred_chain,
        )
    )
    return ca_profile_view(profile)


@router.patch("/ca-profiles/{name}", response_model=CAProfileOut)
def api_update_ca(
    name: str,
    body: CAProfileUpdate,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    box: SecretBox = Depends(get_box),
) -> CAProfileOut:
    profile = _call(
        lambda: update_ca_profile(
            session,
            box,
            name,
            email=body.email,
            directory_url=body.directory_url,
            preferred_chain=body.preferred_chain,
            enabled=body.enabled,
            eab_kid=body.eab_kid,
            eab_hmac=body.eab_hmac,
            clear_eab=body.clear_eab,
        )
    )
    return ca_profile_view(profile)


@router.delete("/ca-profiles/{name}", status_code=204)
def api_delete_ca(
    name: str,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> None:
    _call(lambda: delete_ca_profile(session, name))


# -- tenants -----------------------------------------------------------------


@router.post("/tenants", response_model=TenantOut)
def api_create_tenant(
    body: TenantCreate,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> TenantOut:
    tenant = _call(
        lambda: create_tenant(
            session,
            slug=body.slug,
            name=body.name,
            domain_suffix=body.domain_suffix,
            ca=body.ca,
            renew_before_days=body.renew_before_days,
        )
    )
    return tenant_view(session, tenant)


@router.patch("/tenants/{slug}", response_model=TenantOut)
def api_update_tenant(
    slug: str,
    body: TenantUpdate,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> TenantOut:
    tenant = _call(
        lambda: update_tenant(
            session,
            slug,
            name=body.name,
            domain_suffix=body.domain_suffix,
            ca=body.ca,
            renew_before_days=body.renew_before_days,
            enabled=body.enabled,
        )
    )
    return tenant_view(session, tenant)


@router.delete("/tenants/{slug}", status_code=204)
def api_delete_tenant(
    slug: str,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> None:
    _call(lambda: delete_tenant(session, slug))


@router.put("/tenants/{slug}/credentials", status_code=204)
def api_tenant_credentials(
    slug: str,
    body: CredentialsIn,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    box: SecretBox = Depends(get_box),
) -> None:
    _call(
        lambda: set_tenant_credentials(
            session, box, slug, username=body.username, password=body.password
        )
    )


# -- devices -----------------------------------------------------------------


@router.post("/devices", response_model=DeviceOut)
def api_create_device(
    body: DeviceCreate,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
) -> DeviceOut:
    device = _call(
        lambda: create_device(
            session,
            tenant=body.tenant,
            hostname=body.hostname,
            fqdn=body.fqdn,
            address=body.address,
            ssh_port=body.ssh_port,
            trustpoint_a=body.trustpoint_a,
            trustpoint_b=body.trustpoint_b,
            active_trustpoint=body.active_trustpoint,
            pkcs12_profile=body.pkcs12_profile,
            extra_sans=body.extra_sans,
            enabled=body.enabled,
            revocation_check=body.revocation_check,
        )
    )
    return device_view(session, device, settings)


@router.patch("/devices/{fqdn}", response_model=DeviceOut)
def api_update_device(
    fqdn: str,
    body: DeviceUpdate,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
) -> DeviceOut:
    device = _call(
        lambda: update_device(
            session,
            fqdn,
            hostname=body.hostname,
            address=body.address,
            ssh_port=body.ssh_port,
            enabled=body.enabled,
            pkcs12_profile=body.pkcs12_profile,
            extra_sans=body.extra_sans,
            trustpoint_a=body.trustpoint_a,
            trustpoint_b=body.trustpoint_b,
            active_trustpoint=body.active_trustpoint,
            revocation_check=body.revocation_check,
            tenant=body.tenant,
        )
    )
    return device_view(session, device, settings)


@router.delete("/devices/{fqdn}", status_code=204)
def api_delete_device(
    fqdn: str,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> None:
    _call(lambda: delete_device(session, fqdn))


@router.put("/devices/{fqdn}/credentials", status_code=204)
def api_device_credentials(
    fqdn: str,
    body: CredentialsIn,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    box: SecretBox = Depends(get_box),
) -> None:
    _call(
        lambda: set_device_credentials(
            session,
            box,
            fqdn,
            username=body.username,
            password=body.password,
            enable_password=body.enable_password,
        )
    )


@router.put("/devices/{fqdn}/sans", response_model=DeviceOut)
def api_device_sans(
    fqdn: str,
    body: SansIn,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
) -> DeviceOut:
    device = _call(lambda: update_device(session, fqdn, extra_sans=body.sans))
    return device_view(session, device, settings)


@router.get("/devices/{fqdn}/host-key", response_model=HostKeyOut)
def api_preview_host_key(
    fqdn: str,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> HostKeyOut:
    preview = _call(lambda: preview_host_key(session, fqdn))
    return HostKeyOut(
        fqdn=preview.fqdn,
        address=preview.address,
        port=preview.port,
        key_type=preview.key_type,
        fingerprint=preview.fingerprint,
        already_pinned=preview.already_pinned,
        differs_from_pinned=preview.differs_from_pinned,
    )


@router.post("/devices/{fqdn}/trust", response_model=HostKeyOut)
def api_pin_host_key(
    fqdn: str,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> HostKeyOut:
    preview = _call(lambda: preview_host_key(session, fqdn))
    _call(lambda: pin_host_key(session, fqdn, preview.line))
    return HostKeyOut(
        fqdn=preview.fqdn,
        address=preview.address,
        port=preview.port,
        key_type=preview.key_type,
        fingerprint=preview.fingerprint,
        already_pinned=True,
        differs_from_pinned=False,
    )


@router.get("/devices/{fqdn}/pkcs12")
def api_download_pkcs12(
    fqdn: str,
    principal=Depends(require_operator),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
    box: SecretBox = Depends(get_box),
):
    """Download the current .p12. Password is the configured static PKCS12 password."""
    device = get_device_or_404(session, fqdn)
    cert = latest_certificate(session, device)
    if cert is None:
        raise HTTPException(status_code=409, detail=f"No certificate issued for {fqdn} yet")
    service = IssuanceService(session, settings, box)
    blob, _password = service.export_pkcs12(cert, device, actor=principal.actor)
    return Response(
        content=blob,
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{fqdn}.p12"'},
    )


# -- operators ---------------------------------------------------------------


@router.get("/operators", response_model=list[OperatorOut])
def api_list_operators(
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
) -> list[OperatorOut]:
    grants = session.exec(select(Operator).order_by(Operator.email)).all()
    out = [
        OperatorOut(
            email=g.email,
            role=g.role.value,
            display_name=g.display_name,
            enabled=g.enabled,
            last_seen_at=g.last_seen_at,
            added_by=g.added_by,
            source="grant",
        )
        for g in grants
    ]
    seen = {g.email for g in grants}
    for email in [b.strip().lower() for b in settings.bootstrap_admins.split(",") if b.strip()]:
        if email not in seen:
            out.append(
                OperatorOut(
                    email=email,
                    role=Role.admin.value,
                    enabled=True,
                    source="bootstrap",
                )
            )
    return sorted(out, key=lambda o: o.email)


@router.post("/operators", response_model=OperatorOut)
def api_create_operator(
    body: OperatorCreate,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> OperatorOut:
    grant, _ = _call(
        lambda: upsert_operator(
            session,
            body.email,
            role=body.role,
            display_name=body.display_name,
            added_by=principal.actor,
        )
    )
    return OperatorOut(
        email=grant.email,
        role=grant.role.value,
        display_name=grant.display_name,
        enabled=grant.enabled,
        last_seen_at=grant.last_seen_at,
        added_by=grant.added_by,
        source="grant",
    )


@router.patch("/operators/{email}", response_model=OperatorOut)
def api_update_operator(
    email: str,
    body: OperatorUpdate,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> OperatorOut:
    grant = _call(
        lambda: update_operator(
            session,
            email,
            role=body.role,
            display_name=body.display_name,
            enabled=body.enabled,
        )
    )
    return OperatorOut(
        email=grant.email,
        role=grant.role.value,
        display_name=grant.display_name,
        enabled=grant.enabled,
        last_seen_at=grant.last_seen_at,
        added_by=grant.added_by,
        source="grant",
    )


@router.delete("/operators/{email}", status_code=204)
def api_delete_operator(
    email: str,
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> None:
    _call(lambda: delete_operator(session, email))


# -- diagnostics -------------------------------------------------------------


@router.get("/doctor", response_model=DoctorReportOut)
def api_doctor(
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
) -> DoctorReportOut:
    from app.health import run_checks

    report = run_checks(session, settings)
    return DoctorReportOut(
        failures=report.failures,
        warnings=report.warnings,
        checks=[
            DoctorCheckOut(
                name=c.name, status=c.status, detail=c.detail, remedy=c.remedy
            )
            for c in report.checks
        ],
    )


@router.get("/dns/challenges", response_model=DnsChallengeListOut)
def api_dns_challenges(
    principal=Depends(require_admin),
    settings: Settings = Depends(get_config),
) -> DnsChallengeListOut:
    from app.dns.cloudflare import CloudflareSolver

    solver = CloudflareSolver(
        settings.require_cloudflare_token(), settings.cloudflare_zone
    )
    try:
        zone_id, _ = solver._resolve_zone()
        payload = solver._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"type": "TXT", "per_page": 100},
        )
        records = [
            DnsChallengeOut(name=r["name"], record_id=r["id"])
            for r in payload.get("result", [])
            if r["name"].startswith("_acme-challenge")
        ]
        return DnsChallengeListOut(zone=settings.cloudflare_zone, records=records)
    finally:
        solver.close()


@router.delete("/dns/challenges", response_model=DnsChallengeListOut)
def api_delete_dns_challenges(
    principal=Depends(require_admin),
    settings: Settings = Depends(get_config),
) -> DnsChallengeListOut:
    from app.dns.base import TxtRecord
    from app.dns.cloudflare import CloudflareSolver

    solver = CloudflareSolver(
        settings.require_cloudflare_token(), settings.cloudflare_zone
    )
    try:
        zone_id, _ = solver._resolve_zone()
        payload = solver._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"type": "TXT", "per_page": 100},
        )
        records = [
            r
            for r in payload.get("result", [])
            if r["name"].startswith("_acme-challenge")
        ]
        for record in records:
            solver.delete_txt(
                TxtRecord(name=record["name"], value="", record_id=record["id"])
            )
        return DnsChallengeListOut(
            zone=settings.cloudflare_zone,
            records=[
                DnsChallengeOut(name=r["name"], record_id=r["id"]) for r in records
            ],
            deleted=len(records),
        )
    finally:
        solver.close()
