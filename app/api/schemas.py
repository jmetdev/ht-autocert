"""API response models.

These are an allow-list, not a filter: every field the API can return is named
here explicitly. Sealed columns (``*_sealed``), PKCS12 bundles and passwords
have no representation at this boundary at all, so a future field added to a
table cannot leak through the API by accident.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TenantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    slug: str
    name: str
    domain_suffix: str
    renew_before_days: int
    enabled: bool
    ca_profile_name: str | None = None
    device_count: int = 0
    webex_org_id: str | None = None
    webex_org_name: str | None = None


class CAProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    directory_url: str
    contact_email: str
    preferred_chain: str | None
    enabled: bool
    uses_eab: bool
    registered: bool


class CertificateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    serial: str
    subject_cn: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    chain_issuer_cn: str
    status: str
    pkcs12_profile: str
    target_trustpoint: str | None
    created_at: datetime
    deployed_at: datetime | None
    days_remaining: int


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    fqdn: str
    mgmt_address: str
    has_mgmt_address: bool
    tenant_slug: str
    tenant_name: str
    enabled: bool

    trustpoint_a: str
    trustpoint_b: str
    active_trustpoint: str | None
    idle_trustpoint: str
    pkcs12_profile: str
    revocation_check: str
    has_credentials: bool

    # Derived certificate state
    days_remaining: int | None = None
    not_after: datetime | None = None
    chain_issuer_cn: str | None = None
    serial: str | None = None
    cert_status: str | None = None
    renewal_threshold: int
    renewal_due: bool
    state: str  # ok | renew_due | expired | missing


class DeviceDetailOut(DeviceOut):
    certificates: list[CertificateOut] = []


class TrustpointOut(BaseModel):
    label: str
    subject_cn: str | None
    ca_subject_cn: str | None = None
    serial: str | None
    validity_end: datetime | None
    has_certificate: bool
    bound: bool


class DeviceLiveStateOut(BaseModel):
    fqdn: str
    bound_trustpoint: str | None
    trustpoints: list[TrustpointOut]
    matches_expected: bool
    note: str | None = None


class RunLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: str
    action: str
    status: str
    detail: str | None
    started_at: datetime
    finished_at: datetime | None
    fqdn: str | None = None


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    actor: str
    action: str
    subject: str
    detail: str | None


class SummaryOut(BaseModel):
    devices: int
    tenants: int
    ok: int
    renew_due: int
    expired: int
    missing: int
    expiring_within_14d: int
    last_run_at: datetime | None
    last_run_status: str | None
    next_run_at: datetime | None
    scheduler_enabled: bool


class WebexOrgOut(BaseModel):
    org_id: str
    display_name: str
    tenant_slug: str | None = None  # tenant already linked to this org, if any


class WebexCandidateOut(BaseModel):
    name: str
    trunk_id: str
    trunk_type: str
    device_type: str | None = None
    location: str | None = None
    status: str | None = None
    in_use: bool = False

    # What Webex knows, versus what we would actually use.
    address: str | None = None
    fqdn: str | None = None
    proposed_fqdn: str | None = None
    fqdn_source: str  # "webex" | "derived" | "none"

    importable: bool
    reason: str | None = None


class WebexImportOut(BaseModel):
    tenant: str
    org_id: str
    org_name: str | None = None
    found: int
    imported: int
    applied: bool
    candidates: list[WebexCandidateOut] = []


class ActionResultOut(BaseModel):
    fqdn: str
    status: str
    detail: str = ""
    steps: list[str] = []


class CycleSummaryOut(BaseModel):
    run_id: str
    issued: int
    skipped: int
    failed: int
    deployed: int
    deploy_failed: int
    details: list[dict] = []
