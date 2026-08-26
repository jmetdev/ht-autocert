"""Inventory mutations shared by the web API and the CLI.

The CLI stays as an emergency/backup path. Everything here is what the admin
console calls, so there is one implementation of "add a tenant" rather than two.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlmodel import Session, select

from app.db.models import (
    CAProfile,
    Certificate,
    Device,
    Operator,
    Pkcs12Profile,
    Role,
    RunLog,
    Tenant,
)
from app.devices.factory import aad_device_secret, aad_tenant_secret
from app.vault import SecretBox, aad_eab

LETSENCRYPT_PROD = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


class InventoryError(Exception):
    """Operator-facing failure. ``status`` is an HTTP status when raised from the API."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# -- helpers -----------------------------------------------------------------


def _ca_by_name(session: Session, name: str) -> CAProfile:
    profile = session.exec(select(CAProfile).where(CAProfile.name == name)).first()
    if profile is None:
        raise InventoryError(f"No CA profile named {name!r}", 404)
    return profile


def _tenant_by_slug(session: Session, slug: str) -> Tenant:
    tenant = session.exec(select(Tenant).where(Tenant.slug == slug)).first()
    if tenant is None:
        raise InventoryError(f"No tenant named {slug!r}", 404)
    return tenant


def _device_by_fqdn(session: Session, fqdn: str) -> Device:
    device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
    if device is None:
        raise InventoryError(f"No device with FQDN {fqdn!r}", 404)
    return device


def _parse_role(value: str) -> Role:
    try:
        return Role(value.strip().lower())
    except ValueError as exc:
        raise InventoryError(
            f"Unknown role {value!r}; use viewer, operator or admin", 400
        ) from exc


def _parse_pkcs12(value: str | Pkcs12Profile) -> Pkcs12Profile:
    if isinstance(value, Pkcs12Profile):
        return value
    try:
        return Pkcs12Profile(value.strip().lower())
    except ValueError as exc:
        raise InventoryError(
            f"Unknown PKCS12 profile {value!r}; use modern or legacy", 400
        ) from exc


# -- CA profiles -------------------------------------------------------------


def create_ca_profile(
    session: Session,
    box: SecretBox,
    *,
    name: str,
    email: str,
    directory_url: str = LETSENCRYPT_PROD,
    staging: bool = False,
    eab_kid: str | None = None,
    eab_hmac: str | None = None,
    preferred_chain: str | None = None,
) -> CAProfile:
    name = name.strip()
    if not name:
        raise InventoryError("CA profile name is required")
    if staging:
        directory_url = LETSENCRYPT_STAGING
    if (eab_kid is None) != (eab_hmac is None):
        raise InventoryError("eab_kid and eab_hmac must be given together")
    if session.exec(select(CAProfile).where(CAProfile.name == name)).first():
        raise InventoryError(f"CA profile {name!r} already exists", 409)

    profile = CAProfile(
        name=name,
        directory_url=directory_url,
        contact_email=email.strip(),
        preferred_chain=preferred_chain or None,
    )
    if eab_kid and eab_hmac:
        profile.eab_kid_sealed = box.seal(eab_kid.encode(), aad_eab(name, "eab_kid"))
        profile.eab_hmac_sealed = box.seal(
            eab_hmac.encode(), aad_eab(name, "eab_hmac")
        )
    session.add(profile)
    session.commit()
    session.refresh(profile)
    return profile


def update_ca_profile(
    session: Session,
    box: SecretBox,
    name: str,
    *,
    email: str | None = None,
    directory_url: str | None = None,
    preferred_chain: str | None = None,
    enabled: bool | None = None,
    eab_kid: str | None = None,
    eab_hmac: str | None = None,
    clear_eab: bool = False,
) -> CAProfile:
    profile = _ca_by_name(session, name)
    if email is not None:
        profile.contact_email = email.strip()
    if directory_url is not None:
        profile.directory_url = directory_url
    if preferred_chain is not None:
        profile.preferred_chain = preferred_chain or None
    if enabled is not None:
        profile.enabled = enabled
    if clear_eab:
        profile.eab_kid_sealed = None
        profile.eab_hmac_sealed = None
    elif eab_kid is not None or eab_hmac is not None:
        if not eab_kid or not eab_hmac:
            raise InventoryError("eab_kid and eab_hmac must be given together")
        profile.eab_kid_sealed = box.seal(
            eab_kid.encode(), aad_eab(profile.name, "eab_kid")
        )
        profile.eab_hmac_sealed = box.seal(
            eab_hmac.encode(), aad_eab(profile.name, "eab_hmac")
        )
    session.add(profile)
    session.commit()
    session.refresh(profile)
    return profile


def delete_ca_profile(session: Session, name: str) -> None:
    profile = _ca_by_name(session, name)
    in_use = session.exec(
        select(Tenant).where(Tenant.ca_profile_id == profile.id)
    ).first()
    if in_use is not None:
        raise InventoryError(
            f"CA profile {name!r} is still used by tenant {in_use.slug!r}", 409
        )
    session.delete(profile)
    session.commit()


# -- tenants -----------------------------------------------------------------


def create_tenant(
    session: Session,
    *,
    slug: str,
    name: str,
    domain_suffix: str,
    ca: str,
    renew_before_days: int = 30,
) -> Tenant:
    slug = slug.strip().lower()
    if not slug:
        raise InventoryError("Tenant slug is required")
    if session.exec(select(Tenant).where(Tenant.slug == slug)).first():
        raise InventoryError(f"Tenant {slug!r} already exists", 409)
    profile = _ca_by_name(session, ca)
    tenant = Tenant(
        slug=slug,
        name=name.strip(),
        domain_suffix=domain_suffix.strip(),
        ca_profile_id=profile.id,
        renew_before_days=renew_before_days,
    )
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    return tenant


def update_tenant(
    session: Session,
    slug: str,
    *,
    name: str | None = None,
    domain_suffix: str | None = None,
    ca: str | None = None,
    renew_before_days: int | None = None,
    enabled: bool | None = None,
) -> Tenant:
    tenant = _tenant_by_slug(session, slug)
    if name is not None:
        tenant.name = name.strip()
    if domain_suffix is not None:
        tenant.domain_suffix = domain_suffix.strip()
    if ca is not None:
        profile = _ca_by_name(session, ca)
        tenant.ca_profile_id = profile.id
    if renew_before_days is not None:
        tenant.renew_before_days = renew_before_days
    if enabled is not None:
        tenant.enabled = enabled
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    return tenant


def delete_tenant(session: Session, slug: str) -> None:
    tenant = _tenant_by_slug(session, slug)
    count = len(
        session.exec(select(Device).where(Device.tenant_id == tenant.id)).all()
    )
    if count:
        raise InventoryError(
            f"Tenant {slug!r} still has {count} device(s); delete those first",
            409,
        )
    session.delete(tenant)
    session.commit()


def set_tenant_webex_org(
    session: Session,
    slug: str,
    org_id: str,
    org_name: str | None = None,
) -> Tenant:
    tenant = _tenant_by_slug(session, slug)
    clash = session.exec(
        select(Tenant).where(Tenant.webex_org_id == org_id, Tenant.slug != slug)
    ).first()
    if clash is not None:
        raise InventoryError(
            f"That Webex org is already linked to tenant {clash.slug!r}.", 409
        )
    tenant.webex_org_id = org_id
    tenant.webex_org_name = org_name
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    return tenant


def clear_tenant_webex_org(session: Session, slug: str) -> Tenant:
    tenant = _tenant_by_slug(session, slug)
    tenant.webex_org_id = None
    tenant.webex_org_name = None
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    return tenant


def set_tenant_credentials(
    session: Session,
    box: SecretBox,
    slug: str,
    *,
    username: str,
    password: str,
) -> Tenant:
    tenant = _tenant_by_slug(session, slug)
    tenant.default_username = username.strip()
    tenant.default_password_sealed = box.seal(
        password.encode(), aad_tenant_secret(slug, "password")
    )
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    return tenant


# -- devices -----------------------------------------------------------------


def create_device(
    session: Session,
    *,
    tenant: str,
    hostname: str,
    fqdn: str,
    address: str,
    ssh_port: int = 22,
    trustpoint_a: str = "HT-WxCAutoCert-A",
    trustpoint_b: str = "HT-WxCAutoCert-B",
    active_trustpoint: str | None = None,
    pkcs12_profile: str | Pkcs12Profile = Pkcs12Profile.modern,
    extra_sans: list[str] | None = None,
    enabled: bool = False,
    revocation_check: str = "none",
) -> Device:
    t = _tenant_by_slug(session, tenant)
    fqdn = fqdn.strip().lower()
    if session.exec(select(Device).where(Device.fqdn == fqdn)).first():
        raise InventoryError(f"Device {fqdn!r} already exists", 409)
    extras = [s.strip() for s in (extra_sans or []) if s.strip() and s.strip() != fqdn]
    device = Device(
        tenant_id=t.id,
        hostname=hostname.strip(),
        fqdn=fqdn,
        mgmt_address=address.strip(),
        ssh_port=ssh_port,
        trustpoint_a=trustpoint_a,
        trustpoint_b=trustpoint_b,
        active_trustpoint=active_trustpoint or None,
        pkcs12_profile=_parse_pkcs12(pkcs12_profile),
        extra_sans=",".join(extras) or None,
        enabled=enabled,
        revocation_check=revocation_check,
    )
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


def update_device(
    session: Session,
    fqdn: str,
    *,
    hostname: str | None = None,
    address: str | None = None,
    ssh_port: int | None = None,
    enabled: bool | None = None,
    pkcs12_profile: str | Pkcs12Profile | None = None,
    extra_sans: list[str] | None = None,
    trustpoint_a: str | None = None,
    trustpoint_b: str | None = None,
    active_trustpoint: str | None = None,
    revocation_check: str | None = None,
    tenant: str | None = None,
) -> Device:
    device = _device_by_fqdn(session, fqdn)
    if hostname is not None:
        device.hostname = hostname.strip()
    if address is not None:
        device.mgmt_address = address.strip()
    if ssh_port is not None:
        device.ssh_port = ssh_port
    if enabled is not None:
        device.enabled = enabled
    if pkcs12_profile is not None:
        device.pkcs12_profile = _parse_pkcs12(pkcs12_profile)
    if extra_sans is not None:
        extras = [
            s.strip()
            for s in extra_sans
            if s.strip() and s.strip() != device.fqdn
        ]
        device.extra_sans = ",".join(extras) or None
    if trustpoint_a is not None:
        device.trustpoint_a = trustpoint_a
    if trustpoint_b is not None:
        device.trustpoint_b = trustpoint_b
    if active_trustpoint is not None:
        device.active_trustpoint = active_trustpoint or None
    if revocation_check is not None:
        device.revocation_check = revocation_check
    if tenant is not None:
        t = _tenant_by_slug(session, tenant)
        device.tenant_id = t.id
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


def delete_device(session: Session, fqdn: str) -> None:
    device = _device_by_fqdn(session, fqdn)
    for cert in session.exec(
        select(Certificate).where(Certificate.device_id == device.id)
    ).all():
        session.delete(cert)
    for run in session.exec(select(RunLog).where(RunLog.device_id == device.id)).all():
        run.device_id = None
        session.add(run)
    session.delete(device)
    session.commit()


def set_device_credentials(
    session: Session,
    box: SecretBox,
    fqdn: str,
    *,
    username: str,
    password: str,
    enable_password: str | None = None,
) -> Device:
    device = _device_by_fqdn(session, fqdn)
    device.username = username.strip()
    device.password_sealed = box.seal(
        password.encode(), aad_device_secret(fqdn, "password")
    )
    if enable_password:
        device.enable_password_sealed = box.seal(
            enable_password.encode(), aad_device_secret(fqdn, "enable_password")
        )
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


def pin_host_key(session: Session, fqdn: str, line: str) -> Device:
    device = _device_by_fqdn(session, fqdn)
    device.ssh_host_key = line.strip()
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


@dataclass
class HostKeyPreview:
    fqdn: str
    address: str
    port: int
    line: str
    key_type: str
    fingerprint: str
    already_pinned: bool
    differs_from_pinned: bool


def preview_host_key(session: Session, fqdn: str) -> HostKeyPreview:
    from app.devices.factory import fetch_host_key

    device = _device_by_fqdn(session, fqdn)
    try:
        line, key_type, fingerprint = fetch_host_key(device.mgmt_address, device.ssh_port)
    except Exception as exc:  # noqa: BLE001 - network failure, reported as-is
        raise InventoryError(
            f"Could not reach {device.mgmt_address}:{device.ssh_port} — {exc}",
            502,
        ) from exc
    existing = (device.ssh_host_key or "").strip()
    return HostKeyPreview(
        fqdn=device.fqdn,
        address=device.mgmt_address,
        port=device.ssh_port,
        line=line,
        key_type=key_type,
        fingerprint=fingerprint,
        already_pinned=bool(existing) and existing == line.strip(),
        differs_from_pinned=bool(existing) and existing != line.strip(),
    )


# -- operators ---------------------------------------------------------------


def upsert_operator(
    session: Session,
    email: str,
    *,
    role: str,
    display_name: str | None = None,
    added_by: str = "api",
) -> tuple[Operator, str]:
    address = email.strip().lower()
    parsed = _parse_role(role)
    existing = session.exec(select(Operator).where(Operator.email == address)).first()
    if existing:
        previous = existing.role.value
        existing.role = parsed
        existing.enabled = True
        if display_name:
            existing.display_name = display_name
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing, f"{address}: {previous} -> {parsed.value}"

    grant = Operator(
        email=address, role=parsed, display_name=display_name, added_by=added_by
    )
    session.add(grant)
    session.commit()
    session.refresh(grant)
    return grant, f"{address}: granted {parsed.value}"


def update_operator(
    session: Session,
    email: str,
    *,
    role: str | None = None,
    display_name: str | None = None,
    enabled: bool | None = None,
) -> Operator:
    address = email.strip().lower()
    grant = session.exec(select(Operator).where(Operator.email == address)).first()
    if grant is None:
        raise InventoryError(f"No grant for {address}", 404)
    if role is not None:
        grant.role = _parse_role(role)
    if display_name is not None:
        grant.display_name = display_name or None
    if enabled is not None:
        grant.enabled = enabled
    session.add(grant)
    session.commit()
    session.refresh(grant)
    return grant


def delete_operator(session: Session, email: str) -> None:
    address = email.strip().lower()
    grant = session.exec(select(Operator).where(Operator.email == address)).first()
    if grant is None:
        raise InventoryError(f"No grant for {address}", 404)
    session.delete(grant)
    session.commit()
