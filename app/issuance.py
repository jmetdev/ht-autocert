"""Issuance orchestration.

Replaces play 1 of the Ansible playbook. The important behavioural change is
that renewal is decided from stored certificate metadata (and, from Phase 2,
from what the device actually reports) rather than from parsing certbot's
stdout -- so a device whose import failed is not invisible until the CA happens
to issue again.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlmodel import Session, select

from app.ca.acme_provider import AccountStore, AcmeProvider
from app.config import Settings
from app.db.models import (
    AuditEvent,
    CAProfile,
    CertStatus,
    Certificate,
    Device,
    RunLog,
    RunStatus,
    Tenant,
    utcnow,
)
from app.dns.cloudflare import CloudflareSolver
from app.pkcs12_builder import build_pkcs12, generate_pkcs12_password, verify_pkcs12
from app.vault import (
    SecretBox,
    aad_account_key,
    aad_eab,
    aad_pkcs12,
    aad_pkcs12_password,
    aad_private_key,
)

log = structlog.get_logger(__name__)


class DbAccountStore(AccountStore):
    """ACME account persistence backed by sealed columns on ``CAProfile``."""

    def __init__(self, session: Session, profile: CAProfile, box: SecretBox):
        self.session = session
        self.profile = profile
        self.box = box

    def load_account_key_pem(self) -> bytes | None:
        if not self.profile.account_key_sealed:
            return None
        return self.box.open(
            self.profile.account_key_sealed, aad_account_key(self.profile.name)
        )

    def save_account_key_pem(self, pem: bytes) -> None:
        self.profile.account_key_sealed = self.box.seal(
            pem, aad_account_key(self.profile.name)
        )
        self.session.add(self.profile)
        self.session.commit()

    def load_account_uri(self) -> str | None:
        return self.profile.account_uri

    def save_account_uri(self, uri: str) -> None:
        self.profile.account_uri = uri
        self.session.add(self.profile)
        self.session.commit()


@dataclass
class IssuanceResult:
    fqdn: str
    status: str  # issued | skipped | failed
    detail: str = ""
    certificate_id: int | None = None
    days_remaining: int | None = None


def latest_certificate(session: Session, device: Device) -> Certificate | None:
    stmt = (
        select(Certificate)
        .where(Certificate.device_id == device.id)
        .where(Certificate.status != CertStatus.failed)
        .order_by(Certificate.not_after.desc())
    )
    return session.exec(stmt).first()


def renewal_threshold(device: Device, tenant: Tenant, spread_days: int = 0) -> int:
    """Per-device renewal threshold, in days remaining.

    With ~50 gateways on 90-day certificates the fleet renews roughly every 60
    days, which is far below Let's Encrypt's 50-certs-per-registered-domain
    weekly limit. The risk is not the steady state but clustering: devices
    issued together renew together. A stable per-device offset derived from the
    FQDN spreads them deterministically -- no scheduling state to keep, and the
    same device always lands in the same slot.
    """
    if spread_days <= 0:
        return tenant.renew_before_days
    digest = hashlib.sha256(device.fqdn.encode()).digest()
    offset = int.from_bytes(digest[:4], "big") % spread_days
    return tenant.renew_before_days + offset


def needs_renewal(
    session: Session,
    device: Device,
    tenant: Tenant,
    now: datetime | None = None,
    spread_days: int = 0,
) -> tuple[bool, str, int | None]:
    """Decide whether ``device`` needs a new certificate.

    Returns (needed, reason, days_remaining).
    """
    current = latest_certificate(session, device)
    if current is None:
        return True, "no certificate on record", None

    threshold = renewal_threshold(device, tenant, spread_days)
    days = current.days_remaining(now)
    if days <= threshold:
        return True, f"expires in {days}d (threshold {threshold}d)", days
    return False, f"valid for {days}d", days


def _certificate_metadata(fullchain_pem: str) -> tuple[str, str, str, datetime, datetime]:
    leaf = x509.load_pem_x509_certificates(fullchain_pem.encode())[0]
    cn_attrs = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    cn = str(cn_attrs[0].value) if cn_attrs else leaf.subject.rfc4514_string()
    serial = format(leaf.serial_number, "X")
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    return cn, serial, fingerprint, leaf.not_valid_before_utc, leaf.not_valid_after_utc


class IssuanceService:
    def __init__(self, session: Session, settings: Settings, box: SecretBox):
        self.session = session
        self.settings = settings
        self.box = box

    # -- provider wiring ---------------------------------------------------

    def _provider(self, profile: CAProfile, solver: CloudflareSolver) -> AcmeProvider:
        eab_kid = eab_hmac = None
        if profile.uses_eab:
            eab_kid = self.box.open(
                profile.eab_kid_sealed, aad_eab(profile.name, "eab_kid")
            ).decode()
            eab_hmac = self.box.open(
                profile.eab_hmac_sealed, aad_eab(profile.name, "eab_hmac")
            ).decode()

        return AcmeProvider(
            directory_url=profile.directory_url,
            contact_email=profile.contact_email,
            solver=solver,
            account_store=DbAccountStore(self.session, profile, self.box),
            eab_kid=eab_kid,
            eab_hmac_key=eab_hmac,
            preferred_chain=profile.preferred_chain,
            propagation_timeout=self.settings.dns_propagation_timeout,
            poll_interval=self.settings.dns_poll_interval,
            order_timeout=self.settings.acme_order_timeout,
        )

    def _ca_profile_for(self, tenant: Tenant) -> CAProfile:
        if tenant.ca_profile_id is None:
            raise RuntimeError(
                f"tenant {tenant.slug!r} has no CA profile assigned"
            )
        profile = self.session.get(CAProfile, tenant.ca_profile_id)
        if profile is None or not profile.enabled:
            raise RuntimeError(
                f"CA profile for tenant {tenant.slug!r} is missing or disabled"
            )
        return profile

    # -- main entry point --------------------------------------------------

    def run(
        self,
        devices: list[Device],
        *,
        force: bool = False,
        dry_run: bool = False,
        actor: str = "cli",
        spread_days: int = 0,
        run_id: str | None = None,
    ) -> list[IssuanceResult]:
        run_id = run_id or uuid.uuid4().hex[:12]
        results: list[IssuanceResult] = []

        solver = CloudflareSolver(
            self.settings.require_cloudflare_token(), self.settings.cloudflare_zone
        )
        try:
            for device in devices:
                tenant = self.session.get(Tenant, device.tenant_id)
                bound = log.bind(run_id=run_id, fqdn=device.fqdn, tenant=tenant.slug)

                needed, reason, days = needs_renewal(
                    self.session, device, tenant, spread_days=spread_days
                )
                if not needed and not force:
                    bound.info("issuance.skipped", reason=reason)
                    results.append(
                        IssuanceResult(device.fqdn, "skipped", reason, days_remaining=days)
                    )
                    self._log_run(run_id, device, "issue", RunStatus.skipped, reason)
                    continue

                if dry_run:
                    detail = f"would issue: {reason}"
                    bound.info("issuance.dry_run", reason=reason)
                    results.append(
                        IssuanceResult(device.fqdn, "skipped", detail, days_remaining=days)
                    )
                    continue

                try:
                    cert = self._issue_one(device, tenant, solver, bound, actor)
                    results.append(
                        IssuanceResult(
                            device.fqdn,
                            "issued",
                            f"{reason}; chain {cert.chain_issuer_cn}",
                            certificate_id=cert.id,
                            days_remaining=cert.days_remaining(),
                        )
                    )
                    self._log_run(
                        run_id, device, "issue", RunStatus.success, cert.chain_issuer_cn
                    )
                except Exception as exc:  # noqa: BLE001 - one device must not stop the fleet
                    bound.error("issuance.failed", error=str(exc))
                    results.append(IssuanceResult(device.fqdn, "failed", str(exc)))
                    self._log_run(run_id, device, "issue", RunStatus.failed, str(exc))
        finally:
            solver.close()

        return results

    def _issue_one(
        self,
        device: Device,
        tenant: Tenant,
        solver: CloudflareSolver,
        bound,
        actor: str,
    ) -> Certificate:
        profile = self._ca_profile_for(tenant)
        provider = self._provider(profile, solver)

        bound.info("issuance.started", ca=profile.name, directory=profile.directory_url)
        issued = provider.issue(device.fqdn, device.key_type, sans=device.san_list())

        cn, serial, fingerprint, not_before, not_after = _certificate_metadata(
            issued.fullchain_pem
        )

        password = generate_pkcs12_password()
        p12 = build_pkcs12(
            friendly_name=device.idle_trustpoint(),
            private_key_pem=issued.private_key_pem,
            fullchain_pem=issued.fullchain_pem,
            password=password,
            profile=device.pkcs12_profile,
        )
        verified_cn, chain_len = verify_pkcs12(p12, password)
        bound.info(
            "pkcs12.built",
            profile=device.pkcs12_profile.value,
            cn=verified_cn,
            chain_certs=chain_len,
            bytes=len(p12),
        )

        cert = Certificate(
            device_id=device.id,
            ca_profile_id=profile.id,
            serial=serial,
            fingerprint_sha256=fingerprint,
            subject_cn=cn,
            not_before=not_before,
            not_after=not_after,
            chain_issuer_cn=issued.chain_issuer_cn,
            fullchain_pem=issued.fullchain_pem,
            private_key_sealed=self.box.seal(
                issued.private_key_pem, aad_private_key(device.fqdn, serial)
            ),
            pkcs12_sealed=self.box.seal(p12, aad_pkcs12(device.fqdn, serial)),
            pkcs12_password_sealed=self.box.seal(
                password.encode(), aad_pkcs12_password(device.fqdn, serial)
            ),
            pkcs12_profile=device.pkcs12_profile,
            target_trustpoint=device.idle_trustpoint(),
            status=CertStatus.issued,
        )
        self.session.add(cert)
        self.session.add(
            AuditEvent(
                actor=actor,
                action="key.escrow",
                subject=device.fqdn,
                detail=f"serial={serial} ca={profile.name}",
            )
        )
        self.session.commit()
        self.session.refresh(cert)

        bound.info(
            "issuance.completed",
            serial=serial,
            not_after=not_after.isoformat(),
            target_trustpoint=cert.target_trustpoint,
        )
        return cert

    def _log_run(
        self,
        run_id: str,
        device: Device,
        action: str,
        status: RunStatus,
        detail: str,
    ) -> None:
        self.session.add(
            RunLog(
                run_id=run_id,
                device_id=device.id,
                action=action,
                status=status,
                detail=detail[:2000],
                finished_at=utcnow(),
            )
        )
        self.session.commit()
