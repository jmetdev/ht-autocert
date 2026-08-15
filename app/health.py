"""Configuration and datastore health checks.

Exists because a lost or rotated master key is otherwise invisible until
something tries to use a sealed value -- which, for a device password, is at
deployment time, and for an ACME account key is mid-renewal. This surfaces it
on demand instead.
"""

from dataclasses import dataclass, field

from sqlmodel import Session, select

from app.config import Settings
from app.db.models import CAProfile, Certificate, Device, Tenant
from app.devices.factory import aad_device_secret, aad_tenant_secret
from app.vault import (
    SecretBox,
    VaultError,
    aad_account_key,
    aad_eab,
    aad_pkcs12,
    aad_pkcs12_password,
    aad_private_key,
)

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    remedy: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    @property
    def failures(self) -> int:
        return sum(1 for c in self.checks if c.status == FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == WARN)


def _sealed_records(session: Session):
    """Every sealed blob in the datastore, with the AAD needed to open it."""
    for profile in session.exec(select(CAProfile)).all():
        if profile.account_key_sealed:
            yield (f"ca_profile[{profile.name}].account_key",
                   profile.account_key_sealed, aad_account_key(profile.name),
                   f"./htac ca add --name {profile.name} ... (re-register)")
        if profile.eab_kid_sealed:
            yield (f"ca_profile[{profile.name}].eab_kid", profile.eab_kid_sealed,
                   aad_eab(profile.name, "eab_kid"),
                   f"re-add the CA profile {profile.name} with its EAB credentials")
        if profile.eab_hmac_sealed:
            yield (f"ca_profile[{profile.name}].eab_hmac", profile.eab_hmac_sealed,
                   aad_eab(profile.name, "eab_hmac"),
                   f"re-add the CA profile {profile.name} with its EAB credentials")

    for tenant in session.exec(select(Tenant)).all():
        if tenant.default_password_sealed:
            yield (f"tenant[{tenant.slug}].default_password",
                   tenant.default_password_sealed,
                   aad_tenant_secret(tenant.slug, "password"),
                   f"./htac tenant set-credentials {tenant.slug}")

    for device in session.exec(select(Device)).all():
        if device.password_sealed:
            yield (f"device[{device.fqdn}].password", device.password_sealed,
                   aad_device_secret(device.fqdn, "password"),
                   f"./htac device set-credentials {device.fqdn}")
        if device.enable_password_sealed:
            yield (f"device[{device.fqdn}].enable_password",
                   device.enable_password_sealed,
                   aad_device_secret(device.fqdn, "enable_password"),
                   f"./htac device set-credentials {device.fqdn}")

    devices = {d.id: d for d in session.exec(select(Device)).all()}
    for cert in session.exec(select(Certificate)).all():
        device = devices.get(cert.device_id)
        if device is None:
            continue
        remedy = f"./htac issue --fqdn {device.fqdn} --force  (re-issue)"
        yield (f"certificate[{device.fqdn}/{cert.serial}].private_key",
               cert.private_key_sealed, aad_private_key(device.fqdn, cert.serial),
               remedy)
        yield (f"certificate[{device.fqdn}/{cert.serial}].pkcs12",
               cert.pkcs12_sealed, aad_pkcs12(device.fqdn, cert.serial), remedy)
        yield (f"certificate[{device.fqdn}/{cert.serial}].pkcs12_password",
               cert.pkcs12_password_sealed,
               aad_pkcs12_password(device.fqdn, cert.serial), remedy)


def run_checks(session: Session, settings: Settings) -> Report:
    report = Report()

    # -- configuration ------------------------------------------------------
    if settings.master_key:
        try:
            box = SecretBox.from_b64(settings.master_key)
            report.checks.append(Check("master key", OK, "present and well-formed"))
        except VaultError as exc:
            report.checks.append(
                Check("master key", FAIL, str(exc),
                      "Generate a valid one with ./htac gen-master-key")
            )
            return report
    else:
        report.checks.append(
            Check("master key", FAIL, "HTAC_MASTER_KEY is not set",
                  "Set it in .env.htac, or run ./htac gen-master-key")
        )
        return report

    report.checks.append(
        Check("cloudflare token", OK if settings.cloudflare_api_token else FAIL,
              f"zone {settings.cloudflare_zone}"
              if settings.cloudflare_api_token
              else "HTAC_CLOUDFLARE_API_TOKEN is not set",
              "" if settings.cloudflare_api_token
              else "Create a Zone:DNS:Edit token and set it in .env.htac")
    )
    report.checks.append(
        Check("api token", OK if settings.api_token else WARN,
              "set" if settings.api_token
              else "HTAC_API_TOKEN is not set; the web console will refuse requests",
              "" if settings.api_token else "Set HTAC_API_TOKEN in .env.htac")
    )

    # -- can the master key open what is stored? ----------------------------
    unreadable: list[tuple[str, str]] = []
    checked = 0
    for label, blob, aad, remedy in _sealed_records(session):
        checked += 1
        try:
            box.open(blob, aad)
        except VaultError:
            unreadable.append((label, remedy))

    if checked == 0:
        report.checks.append(
            Check("sealed records", OK, "nothing sealed in the datastore yet")
        )
    elif unreadable:
        report.checks.append(
            Check(
                "sealed records", FAIL,
                f"{len(unreadable)} of {checked} cannot be decrypted with this "
                "master key",
                "Re-enter each of the values listed below",
            )
        )
        for label, remedy in unreadable:
            report.checks.append(Check(f"  {label}", FAIL, "unreadable", remedy))
    else:
        report.checks.append(
            Check("sealed records", OK, f"all {checked} open with this master key")
        )

    # -- inventory sanity ---------------------------------------------------
    devices = session.exec(select(Device)).all()
    no_creds = [
        d for d in devices
        if not d.password_sealed
        and not (
            (t := session.get(Tenant, d.tenant_id)) and t.default_password_sealed
        )
    ]
    if devices and no_creds:
        report.checks.append(
            Check("device credentials", WARN,
                  f"{len(no_creds)} of {len(devices)} device(s) have no password",
                  "./htac device set-credentials <fqdn>, or set a tenant default")
        )
    elif devices:
        report.checks.append(
            Check("device credentials", OK, f"all {len(devices)} device(s) configured")
        )

    unpinned = [
        d.fqdn for d in devices if d.strict_host_key and not d.ssh_host_key
    ]
    if unpinned:
        report.checks.append(
            Check(
                "ssh host keys", WARN,
                f"{len(unpinned)} device(s) rely on the local ~/.ssh/known_hosts",
                "./htac device trust <fqdn>  (required when running in a container)",
            )
        )
    elif devices:
        report.checks.append(
            Check("ssh host keys", OK, f"all {len(devices)} device(s) pinned")
        )

    from app.db.models import Operator

    grants = session.exec(select(Operator).where(Operator.enabled == True)).all()  # noqa: E712
    bootstrap = [b for b in settings.bootstrap_admins.split(",") if b.strip()]
    default_open = (settings.webex_default_role or "none").lower() not in (
        "none", "", "deny",
    )
    if settings.webex_enabled:
        if default_open:
            report.checks.append(
                Check(
                    "console access", WARN,
                    f"every signed-in user gets '{settings.webex_default_role}' "
                    "by default",
                    "Set HTAC_WEBEX_DEFAULT_ROLE=none and grant roles explicitly",
                )
            )
        elif not grants and not bootstrap:
            report.checks.append(
                Check(
                    "console access", WARN,
                    "Webex sign-in is on but nobody has a role, so every login "
                    "will be refused",
                    "./htac operator add <email> --role admin",
                )
            )
        else:
            report.checks.append(
                Check(
                    "console access", OK,
                    f"{len(grants)} grant(s), {len(bootstrap)} bootstrap admin(s)",
                )
            )

    orphans = [
        t.slug for t in session.exec(select(Tenant)).all() if t.ca_profile_id is None
    ]
    if orphans:
        report.checks.append(
            Check("tenant CA profiles", WARN,
                  f"no CA assigned: {', '.join(orphans)}",
                  "./htac tenant add ... --ca <profile>")
        )

    return report
