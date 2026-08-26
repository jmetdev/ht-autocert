"""Datastore schema.

Sensitive columns hold sealed blobs (see :mod:`app.vault`) rather than
plaintext, so the encryption survives backups, file copies and replicas -- and
each blob is cryptographically bound to the record it belongs to.
"""

from datetime import datetime, timezone
from enum import Enum

from sqlmodel import Field, SQLModel

# NOTE: deliberately no ``from __future__ import annotations`` here. SQLModel
# resolves column types from runtime annotations, and stringified annotations
# break its Relationship/foreign-key detection. Records are joined explicitly in
# the service layer instead of via ORM relationships.


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Pkcs12Profile(str, Enum):
    """Encryption profile for the generated .p12.

    ``modern`` is the OpenSSL 3 default (AES-256-CBC / PBKDF2-SHA256).
    ``legacy`` is 3DES/SHA1, which older IOS-XE trains require -- an import of
    a ``modern`` bundle on those releases fails with a bare
    ``%PKI-3-PKCS12_IMPORT_FAILURE ... Reason: Unknown reason``.
    """

    modern = "modern"
    legacy = "legacy"


class Role(str, Enum):
    """What a signed-in user may do.

    Separate from authentication: belonging to the company proves identity, not
    that someone should be able to reissue and redeploy certificates on client
    voice gateways.
    """

    viewer = "viewer"      # read fleet state, history, live device state
    operator = "operator"  # + issue, deploy, run the renewal cycle
    admin = "admin"        # + manage inventory, operators, and configuration

    def at_least(self, required: "Role") -> bool:
        order = {Role.viewer: 0, Role.operator: 1, Role.admin: 2}
        return order[self] >= order[required]


class Operator(SQLModel, table=True):
    """A person permitted to use the console, and at what level."""

    __tablename__ = "operator"

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    role: Role = Role.viewer
    display_name: str | None = None
    enabled: bool = True
    added_by: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    last_seen_at: datetime | None = None


class WebexToken(SQLModel, table=True):
    """A signed-in user's Webex OAuth token, sealed.

    Kept in its own table rather than on ``Operator`` so that token storage
    never interferes with role resolution, and so bootstrap admins -- who have
    no grant row -- can still use Control Hub features.

    This is an admin-scoped bearer credential, so it is sealed with the vault
    like any other secret and is never returned through the API.
    """

    __tablename__ = "webex_token"

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    access_sealed: bytes
    refresh_sealed: bytes | None = None
    expires_at: datetime | None = None
    scopes: str | None = None
    updated_at: datetime = Field(default_factory=utcnow)

    def expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        now = now or utcnow()
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires <= now


class CertStatus(str, Enum):
    issued = "issued"
    deployed = "deployed"
    superseded = "superseded"
    failed = "failed"


class RunStatus(str, Enum):
    running = "running"
    success = "success"
    failed = "failed"
    skipped = "skipped"


class CAProfile(SQLModel, table=True):
    """An ACME account against a specific CA directory."""

    __tablename__ = "ca_profile"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    directory_url: str
    contact_email: str

    # ZeroSSL (and Google Trust Services) require External Account Binding.
    eab_kid_sealed: bytes | None = None
    eab_hmac_sealed: bytes | None = None

    # Issuer CN of the chain to prefer when the CA offers alternates. Relevant
    # during Let's Encrypt's ISRG Root X1 -> Root YR migration.
    preferred_chain: str | None = None

    account_key_sealed: bytes | None = None
    account_uri: str | None = None

    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def uses_eab(self) -> bool:
        return self.eab_kid_sealed is not None and self.eab_hmac_sealed is not None


class Tenant(SQLModel, table=True):
    """A client. All tenants share one Cloudflare zone, but key material,
    device credentials and schedules are isolated per tenant."""

    __tablename__ = "tenant"

    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(unique=True, index=True)  # e.g. "husd"
    name: str
    domain_suffix: str  # e.g. "husd.clients.managedcollab.com"

    ca_profile_id: int | None = Field(default=None, foreign_key="ca_profile.id")
    renew_before_days: int = 30

    # Each client is its own Webex organisation, so discovery has to be
    # org-scoped. Storing the mapping means an import is attributable to a
    # tenant rather than depending on whichever org was selected at the time.
    webex_org_id: str | None = Field(default=None, index=True)
    webex_org_name: str | None = None

    # Default device credentials for this tenant; a Device may override.
    default_username: str | None = None
    default_password_sealed: bytes | None = None

    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)



class Device(SQLModel, table=True):
    """A voice gateway.

    Trustpoints are managed blue/green: a new certificate is imported into the
    inactive trustpoint, verified, and only then bound via
    ``sip-ua / crypto signaling default trustpoint``.
    """

    __tablename__ = "device"

    id: int | None = Field(default=None, primary_key=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)

    hostname: str
    fqdn: str = Field(unique=True, index=True)
    mgmt_address: str

    trustpoint_a: str = "HT-WxCAutoCert-A"
    trustpoint_b: str = "HT-WxCAutoCert-B"
    active_trustpoint: str | None = None

    pkcs12_profile: Pkcs12Profile = Pkcs12Profile.modern
    key_type: str = "rsa2048"

    # Additional SAN names, comma-separated. Beyond covering extra hostnames,
    # this changes the certificate's *identifier set*, which is the unit Let's
    # Encrypt's duplicate-certificate limit (5 per 7 days) is scoped to -- a
    # different set gets its own allowance.
    extra_sans: str | None = None

    # Credentials. Fall back to the tenant defaults when unset.
    username: str | None = None
    password_sealed: bytes | None = None
    enable_password_sealed: bytes | None = None

    ssh_port: int = 22
    # Pinned SSH host key, as a known_hosts line. Stored per device so the
    # application is self-contained: a container has no ~/.ssh/known_hosts, and
    # a shared file is not a per-device trust decision. Capture with
    # `htac device trust <fqdn>`.
    ssh_host_key: str | None = None
    filesystem: str = "bootflash:"
    # Host key checking defaults on; the Ansible config disabled it fleet-wide.
    strict_host_key: bool = True
    # revocation-check to assert on the trustpoint. The Webex template ships
    # 'crl', which Let's Encrypt certificates cannot satisfy.
    revocation_check: str = "none"
    # Cisco Catalyst 8200 platforms expose certificate state through IOS-XE
    # RESTCONF. Prefer it; SSH is retained only for PKCS12 import operations
    # which do not have a native YANG action.
    use_restconf: bool = True
    restconf_port: int = 443

    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)


    def san_list(self) -> list[str]:
        """Every name the certificate should cover, primary first."""
        names = [self.fqdn]
        for extra in (self.extra_sans or "").split(","):
            extra = extra.strip()
            if extra and extra not in names:
                names.append(extra)
        return names

    def idle_trustpoint(self) -> str:
        """The trustpoint to import into next."""
        if self.active_trustpoint == self.trustpoint_a:
            return self.trustpoint_b
        return self.trustpoint_a


class Certificate(SQLModel, table=True):
    """An issued certificate plus its escrowed key material."""

    __tablename__ = "certificate"

    id: int | None = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True)
    ca_profile_id: int = Field(foreign_key="ca_profile.id")

    serial: str = Field(index=True)
    fingerprint_sha256: str
    subject_cn: str
    not_before: datetime
    not_after: datetime = Field(index=True)

    # Which chain was actually shipped -- so a root rollover is visible rather
    # than something discovered when a peer stops trusting the gateway.
    chain_issuer_cn: str

    fullchain_pem: str
    private_key_sealed: bytes
    pkcs12_sealed: bytes
    pkcs12_password_sealed: bytes
    pkcs12_profile: Pkcs12Profile

    status: CertStatus = CertStatus.issued
    target_trustpoint: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    deployed_at: datetime | None = None


    def days_remaining(self, now: datetime | None = None) -> int:
        now = now or utcnow()
        not_after = self.not_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        return (not_after - now).days


class RunLog(SQLModel, table=True):
    """One issuance/deployment attempt for one device."""

    __tablename__ = "run_log"

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True)
    device_id: int | None = Field(default=None, foreign_key="device.id")
    action: str
    status: RunStatus = RunStatus.running
    detail: str | None = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None


class AuditEvent(SQLModel, table=True):
    """Append-only record of access to escrowed key material."""

    __tablename__ = "audit_event"

    id: int | None = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow, index=True)
    actor: str
    action: str  # e.g. "key.export", "key.decrypt", "p12.export"
    subject: str  # e.g. the FQDN
    detail: str | None = None
