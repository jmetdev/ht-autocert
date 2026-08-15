"""Scheduled renewal.

Runs daily rather than monthly. The Ansible cron ran on the 1st with a 30-day
renewal threshold, which on a 90-day certificate could leave a single day of
margin -- one failed run was an outage.

At ~50 gateways the fleet needs roughly 6 issuances a week, well under Let's
Encrypt's 50-per-registered-domain weekly limit. The scheduler's job is
therefore to avoid *clustering*, not to throttle: each device gets a stable
renewal offset (see :func:`app.issuance.renewal_threshold`) so gateways
provisioned on the same day drift apart over their first cycle.
"""

import uuid

import structlog
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlmodel import select

from app.config import Settings, get_settings
from app.db.models import Device, RunLog, RunStatus, Tenant, utcnow
from app.db.session import session_scope
from app.deployment import DeploymentService
from app.devices.factory import build_transport
from app.issuance import IssuanceService, latest_certificate, needs_renewal
from app.vault import SecretBox

log = structlog.get_logger(__name__)


def run_renewal_cycle(
    settings: Settings | None = None,
    *,
    dry_run: bool = False,
    deploy: bool = True,
    actor: str = "scheduler",
) -> dict:
    """One full pass: issue what is due, then deploy what was issued."""
    settings = settings or get_settings()
    box = SecretBox.from_b64(settings.require_master_key())
    run_id = uuid.uuid4().hex[:12]
    bound = log.bind(run_id=run_id)

    summary = {
        "run_id": run_id,
        "issued": 0,
        "skipped": 0,
        "failed": 0,
        "deployed": 0,
        "deploy_failed": 0,
        "details": [],
    }

    with session_scope() as session:
        devices = session.exec(
            select(Device).where(Device.enabled == True).order_by(Device.fqdn)  # noqa: E712
        ).all()

        due = []
        for device in devices:
            tenant = session.get(Tenant, device.tenant_id)
            if tenant is None or not tenant.enabled:
                continue
            needed, reason, _ = needs_renewal(
                session, device, tenant, spread_days=settings.renewal_spread_days
            )
            if needed:
                due.append(device)
            else:
                summary["skipped"] += 1

        bound.info(
            "scheduler.cycle_started",
            total=len(devices),
            due=len(due),
            dry_run=dry_run,
        )

        if not due:
            return summary

        issuance = IssuanceService(session, settings, box)
        results = issuance.run(
            due,
            dry_run=dry_run,
            actor=actor,
            spread_days=settings.renewal_spread_days,
            run_id=run_id,
        )

        issued_fqdns = []
        for result in results:
            summary["details"].append(
                {"fqdn": result.fqdn, "stage": "issue", "status": result.status,
                 "detail": result.detail}
            )
            if result.status == "issued":
                summary["issued"] += 1
                issued_fqdns.append(result.fqdn)
            elif result.status == "failed":
                summary["failed"] += 1
            else:
                summary["skipped"] += 1

        if dry_run or not deploy or not issued_fqdns:
            return summary

        deployment = DeploymentService(
            session, box, lambda d: build_transport(session, d, box)
        )
        for device in due:
            if device.fqdn not in issued_fqdns:
                continue
            cert = latest_certificate(session, device)
            if cert is None:
                continue
            result = deployment.deploy_device(
                device,
                cert,
                run_id=run_id,
                revocation_check=device.revocation_check,
                actor=actor,
            )
            summary["details"].append(
                {"fqdn": result.fqdn, "stage": "deploy", "status": result.status,
                 "detail": result.detail}
            )
            if result.status == "deployed":
                summary["deployed"] += 1
            else:
                summary["deploy_failed"] += 1

        session.add(
            RunLog(
                run_id=run_id,
                action="cycle",
                status=(
                    RunStatus.failed
                    if (summary["failed"] or summary["deploy_failed"])
                    else RunStatus.success
                ),
                detail=(
                    f"issued={summary['issued']} deployed={summary['deployed']} "
                    f"failed={summary['failed']} deploy_failed={summary['deploy_failed']}"
                ),
                finished_at=utcnow(),
            )
        )

    bound.info("scheduler.cycle_finished", **{
        k: v for k, v in summary.items() if k != "details"
    })
    return summary


def build_scheduler(settings: Settings | None = None) -> BackgroundScheduler:
    settings = settings or get_settings()
    scheduler = BackgroundScheduler(timezone="UTC")
    hour, _, minute = settings.schedule_time.partition(":")

    scheduler.add_job(
        run_renewal_cycle,
        CronTrigger(hour=int(hour), minute=int(minute or 0), timezone="UTC"),
        id="renewal-cycle",
        name="Daily certificate renewal",
        max_instances=1,      # never overlap runs
        coalesce=True,        # a missed run fires once, not once per miss
        misfire_grace_time=3600,
        replace_existing=True,
    )
    log.info(
        "scheduler.configured",
        schedule=f"daily at {settings.schedule_time} UTC",
        spread_days=settings.renewal_spread_days,
    )
    return scheduler
