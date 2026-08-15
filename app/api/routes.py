"""API routes.

Every mutating endpoint calls the same service objects the CLI uses, so there
is one implementation of issuance and deployment rather than two.
"""

from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
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
)
from app.api.schemas import (
    ActionResultOut,
    AuditEventOut,
    CAProfileOut,
    CycleSummaryOut,
    DeviceDetailOut,
    DeviceLiveStateOut,
    DeviceOut,
    RunLogOut,
    SummaryOut,
    TenantOut,
    TrustpointOut,
    WebexCandidateOut,
    WebexImportOut,
    WebexOrgOut,
)
from app.config import Settings
from app.db.models import AuditEvent, CAProfile, Device, RunLog, Tenant
from app.deployment import DeploymentService
from app.devices.base import DeviceError
from app.devices.factory import build_transport
from app.issuance import IssuanceService, latest_certificate
from app.vault import SecretBox

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/api", dependencies=[Depends(require_viewer)])


# -- dashboard ---------------------------------------------------------------


@router.get("/summary", response_model=SummaryOut)
def summary(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
) -> SummaryOut:
    devices = session.exec(select(Device)).all()
    views = [device_view(session, d, settings) for d in devices]

    soon = datetime.now(timezone.utc) + timedelta(days=14)
    expiring = sum(
        1
        for v in views
        if v.not_after
        and (v.not_after if v.not_after.tzinfo else v.not_after.replace(tzinfo=timezone.utc))
        <= soon
    )

    last = session.exec(
        select(RunLog).where(RunLog.action == "cycle").order_by(RunLog.started_at.desc())
    ).first()

    next_run = None
    from app.api.app import get_scheduler

    scheduler = get_scheduler()
    if scheduler is not None:
        job = scheduler.get_job("renewal-cycle")
        if job is not None:
            next_run = job.next_run_time

    return SummaryOut(
        devices=len(views),
        tenants=len(session.exec(select(Tenant)).all()),
        ok=sum(1 for v in views if v.state == "ok"),
        renew_due=sum(1 for v in views if v.state == "renew_due"),
        expired=sum(1 for v in views if v.state == "expired"),
        missing=sum(1 for v in views if v.state == "missing"),
        expiring_within_14d=expiring,
        last_run_at=last.started_at if last else None,
        last_run_status=last.status.value if last else None,
        next_run_at=next_run,
        scheduler_enabled=settings.schedule_enabled,
    )


# -- read --------------------------------------------------------------------


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(
    tenant: str | None = Query(default=None),
    state: str | None = Query(default=None),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
) -> list[DeviceOut]:
    stmt = select(Device)
    if tenant:
        t = session.exec(select(Tenant).where(Tenant.slug == tenant)).first()
        if t is None:
            raise HTTPException(status_code=404, detail=f"No tenant {tenant}")
        stmt = stmt.where(Device.tenant_id == t.id)

    views = [
        device_view(session, d, settings)
        for d in session.exec(stmt.order_by(Device.fqdn)).all()
    ]
    if state:
        views = [v for v in views if v.state == state]
    return views


@router.get("/devices/{fqdn}", response_model=DeviceDetailOut)
def get_device(
    fqdn: str,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
) -> DeviceDetailOut:
    device = get_device_or_404(session, fqdn)
    return device_view(session, device, settings, detail=True)


@router.get("/tenants", response_model=list[TenantOut])
def list_tenants(session: Session = Depends(get_session)) -> list[TenantOut]:
    out = []
    for tenant in session.exec(select(Tenant).order_by(Tenant.slug)).all():
        profile = (
            session.get(CAProfile, tenant.ca_profile_id)
            if tenant.ca_profile_id
            else None
        )
        count = len(
            session.exec(select(Device).where(Device.tenant_id == tenant.id)).all()
        )
        out.append(
            TenantOut(
                id=tenant.id,
                slug=tenant.slug,
                name=tenant.name,
                domain_suffix=tenant.domain_suffix,
                renew_before_days=tenant.renew_before_days,
                enabled=tenant.enabled,
                ca_profile_name=profile.name if profile else None,
                device_count=count,
            )
        )
    return out


@router.get("/ca-profiles", response_model=list[CAProfileOut])
def list_ca_profiles(session: Session = Depends(get_session)) -> list[CAProfileOut]:
    return [
        ca_profile_view(p) for p in session.exec(select(CAProfile).order_by(CAProfile.name)).all()
    ]


@router.get("/runs", response_model=list[RunLogOut])
def list_runs(
    limit: int = Query(default=100, le=500),
    fqdn: str | None = Query(default=None),
    session: Session = Depends(get_session),
) -> list[RunLogOut]:
    stmt = select(RunLog).order_by(RunLog.started_at.desc()).limit(limit)
    if fqdn:
        device = get_device_or_404(session, fqdn)
        stmt = (
            select(RunLog)
            .where(RunLog.device_id == device.id)
            .order_by(RunLog.started_at.desc())
            .limit(limit)
        )

    rows = session.exec(stmt).all()
    fqdn_by_id = {d.id: d.fqdn for d in session.exec(select(Device)).all()}
    return [
        RunLogOut(
            id=r.id,
            run_id=r.run_id,
            action=r.action,
            status=r.status.value,
            detail=r.detail,
            started_at=r.started_at,
            finished_at=r.finished_at,
            fqdn=fqdn_by_id.get(r.device_id),
        )
        for r in rows
    ]


@router.get("/audit", response_model=list[AuditEventOut])
def list_audit(
    limit: int = Query(default=100, le=500),
    session: Session = Depends(get_session),
) -> list[AuditEventOut]:
    rows = session.exec(
        select(AuditEvent).order_by(AuditEvent.at.desc()).limit(limit)
    ).all()
    return [AuditEventOut.model_validate(r) for r in rows]


# -- live device state -------------------------------------------------------


@router.get("/devices/{fqdn}/live", response_model=DeviceLiveStateOut)
def device_live_state(
    fqdn: str,
    session: Session = Depends(get_session),
    box: SecretBox = Depends(get_box),
) -> DeviceLiveStateOut:
    """Read certificate state directly from the gateway."""
    device = get_device_or_404(session, fqdn)
    try:
        with build_transport(session, device, box) as transport:
            state = transport.read_state()
    except DeviceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    cert = latest_certificate(session, device)
    matches = False
    note = None
    if cert is None:
        note = "No certificate issued for this device yet."
    else:
        bound = state.get(state.bound_trustpoint) if state.bound_trustpoint else None
        matches = bool(bound and bound.matches(cert.subject_cn, cert.serial))
        if not matches:
            note = (
                f"Device is serving {bound.serial if bound else 'nothing'}; "
                f"the latest issued certificate is {cert.serial}."
            )

    return DeviceLiveStateOut(
        fqdn=fqdn,
        bound_trustpoint=state.bound_trustpoint,
        trustpoints=[
            TrustpointOut(
                label=tp.label,
                subject_cn=tp.subject_cn,
                ca_subject_cn=tp.ca_subject_cn,
                serial=tp.serial,
                validity_end=tp.validity_end,
                has_certificate=tp.has_certificate,
                bound=tp.label == state.bound_trustpoint,
            )
            for tp in sorted(state.trustpoints.values(), key=lambda t: t.label)
        ],
        matches_expected=matches,
        note=note,
    )


# -- actions -----------------------------------------------------------------


@router.post("/devices/{fqdn}/issue", response_model=ActionResultOut)
def issue_device(
    fqdn: str,
    force: bool = Query(default=False),
    principal=Depends(require_operator),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_config),
    box: SecretBox = Depends(get_box),
) -> ActionResultOut:
    device = get_device_or_404(session, fqdn)
    service = IssuanceService(session, settings, box)
    results = service.run(
        [device],
        force=force,
        actor=principal.actor,
        spread_days=settings.renewal_spread_days,
    )
    result = results[0]
    return ActionResultOut(
        fqdn=result.fqdn, status=result.status, detail=result.detail
    )


@router.post("/devices/{fqdn}/deploy", response_model=ActionResultOut)
def deploy_device(
    fqdn: str,
    rebind: bool = Query(default=True, description="False stages without cutting over"),
    principal=Depends(require_operator),
    session: Session = Depends(get_session),
    box: SecretBox = Depends(get_box),
) -> ActionResultOut:
    device = get_device_or_404(session, fqdn)
    cert = latest_certificate(session, device)
    if cert is None:
        raise HTTPException(
            status_code=409, detail=f"No certificate issued for {fqdn} yet"
        )

    service = DeploymentService(
        session, box, lambda d: build_transport(session, d, box)
    )
    result = service.deploy_device(
        device,
        cert,
        rebind=rebind,
        revocation_check=device.revocation_check,
        actor=principal.actor,
    )
    return ActionResultOut(
        fqdn=result.fqdn,
        status=result.status,
        detail=result.detail,
        steps=result.steps,
    )


@router.post("/cycle", response_model=CycleSummaryOut)
def trigger_cycle(
    dry_run: bool = Query(default=False),
    deploy: bool = Query(default=True),
    principal=Depends(require_operator),
    settings: Settings = Depends(get_config),
) -> CycleSummaryOut:
    """Run the full renewal cycle now, as the scheduler would."""
    from app.scheduler import run_renewal_cycle

    summary = run_renewal_cycle(
        settings, dry_run=dry_run, deploy=deploy, actor=principal.actor
    )
    return CycleSummaryOut(**summary)


# -- Webex Control Hub -------------------------------------------------------


def _inventory(session: Session, box: SecretBox, actor: str):
    """Build a Control Hub client from the caller's own stored Webex token."""
    from app.webex_inventory import WebexInventory
    from app.webex_session import WebexTokenError, load_token

    try:
        token = load_token(session, box, actor)
    except WebexTokenError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return WebexInventory(token)


def _slugify(name: str) -> str:
    """Trunk name -> DNS label. Webex allows spaces and dots; hostnames do not."""
    cleaned = [c.lower() if c.isalnum() else "-" for c in name.strip()]
    label = "".join(cleaned).strip("-")
    while "--" in label:
        label = label.replace("--", "-")
    return label


@router.get("/webex/orgs", response_model=list[WebexOrgOut])
def webex_orgs(
    principal=Depends(require_viewer),
    session: Session = Depends(get_session),
    box: SecretBox = Depends(get_box),
) -> list[WebexOrgOut]:
    """Organisations the caller can administer, for the toolbar selector.

    Read with the caller's own token, so this lists exactly the customer orgs
    their Control Hub rights cover -- nothing is granted by this application.
    """
    from app.webex_inventory import WebexApiError

    with _inventory(session, box, principal.actor) as inventory:
        try:
            orgs = inventory.organizations()
        except WebexApiError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    linked = {
        t.webex_org_id: t.slug
        for t in session.exec(select(Tenant)).all()
        if t.webex_org_id
    }
    return [
        WebexOrgOut(
            org_id=o.org_id,
            display_name=o.display_name,
            tenant_slug=linked.get(o.org_id),
        )
        for o in orgs
    ]


@router.put("/tenants/{slug}/webex-org", response_model=TenantOut)
def link_webex_org(
    slug: str,
    org_id: str = Query(..., description="Webex organisation ID."),
    org_name: str | None = Query(None),
    principal=Depends(require_admin),
    session: Session = Depends(get_session),
) -> TenantOut:
    """Bind a tenant to a Webex organisation."""
    tenant = session.exec(select(Tenant).where(Tenant.slug == slug)).first()
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"No tenant {slug}")

    clash = session.exec(
        select(Tenant).where(Tenant.webex_org_id == org_id, Tenant.slug != slug)
    ).first()
    if clash is not None:
        raise HTTPException(
            status_code=409,
            detail=f"That Webex org is already linked to tenant {clash.slug}.",
        )

    tenant.webex_org_id = org_id
    tenant.webex_org_name = org_name
    session.add(tenant)
    session.commit()
    log.info("webex.org_linked", actor=principal.actor, tenant=slug, org_id=org_id)
    return TenantOut.model_validate(tenant, from_attributes=True)


@router.post("/webex/import", response_model=WebexImportOut)
def webex_import(
    tenant: str = Query(..., description="Tenant slug to attach devices to."),
    org_id: str | None = Query(None, description="Webex org. Defaults to the tenant's."),
    apply: bool = Query(False, description="Create devices. Previews by default."),
    principal=Depends(require_operator),
    session: Session = Depends(get_session),
    box: SecretBox = Depends(get_box),
) -> WebexImportOut:
    """Import gateways from Control Hub. Previews unless ``apply`` is set.

    Imported devices are created **disabled**. Webex records a registering
    trunk's name but not its management address, and never its SSH host key or
    credentials, so an imported row is a worklist entry rather than something
    ready to deploy. The scheduler skips disabled devices, so a half-populated
    import cannot be picked up by an unattended renewal.
    """
    from app.webex_inventory import WebexApiError

    t = session.exec(select(Tenant).where(Tenant.slug == tenant)).first()
    if t is None:
        raise HTTPException(status_code=404, detail=f"No tenant {tenant}")

    org_id = org_id or t.webex_org_id
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail=f"Tenant {tenant} is not linked to a Webex organisation. "
                   "Pick one in the toolbar, or link it in Settings.",
        )

    with _inventory(session, box, principal.actor) as inventory:
        try:
            found = inventory.trunks(org_id)
        except WebexApiError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    existing = {d.fqdn for d in session.exec(select(Device)).all()}
    seen: set[str] = set()
    candidates: list[WebexCandidateOut] = []
    importable: list[tuple] = []

    for gw in found:
        # Webex only records an address for certificate-based trunks. For a
        # registering trunk we derive the name from the tenant suffix, which an
        # operator must confirm before the device is enabled.
        if gw.fqdn:
            proposed, source = gw.fqdn, "webex"
        elif t.domain_suffix and _slugify(gw.name):
            proposed = f"{_slugify(gw.name)}.{t.domain_suffix}"
            source = "derived"
        else:
            proposed, source = None, "none"

        reason = None
        if not proposed:
            reason = "no address in Webex, and no tenant domain suffix to derive one"
        elif proposed in existing or proposed in seen:
            reason = "already in inventory"

        candidates.append(
            WebexCandidateOut(
                name=gw.name, trunk_id=gw.trunk_id, trunk_type=gw.trunk_type,
                device_type=gw.device_type, location=gw.location, status=gw.status,
                in_use=gw.in_use, address=gw.address, fqdn=gw.fqdn,
                proposed_fqdn=proposed, fqdn_source=source,
                importable=reason is None, reason=reason,
            )
        )
        if reason is None:
            seen.add(proposed)
            importable.append((gw, proposed))

    if apply:
        for gw, fqdn in importable:
            session.add(
                Device(
                    tenant_id=t.id,
                    hostname=gw.name,
                    fqdn=fqdn,
                    # Webex has no management address for a registering trunk.
                    # Seed it with the certificate name so the row is complete,
                    # and leave the device disabled until an operator confirms
                    # how the gateway is actually reached.
                    mgmt_address=gw.address or fqdn,
                    enabled=False,
                )
            )
        session.commit()
        log.info(
            "webex.imported", actor=principal.actor, tenant=tenant,
            org_id=org_id, count=len(importable),
        )

    return WebexImportOut(
        tenant=tenant, org_id=org_id, org_name=t.webex_org_name,
        found=len(found), imported=len(importable) if apply else 0,
        applied=apply, candidates=candidates,
    )
