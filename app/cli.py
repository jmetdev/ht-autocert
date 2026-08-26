"""Command line interface.

Everything here calls the same service layer the Phase 3 web API will use, so
the UI stays a thin client rather than a reimplementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from sqlmodel import select

from app.config import get_settings
from app.db.models import CAProfile, Device, Pkcs12Profile, Tenant
from app.db.session import init_db, session_scope
from app.devices.base import management_host, mgmt_from_discovery
from app.issuance import IssuanceService, latest_certificate, needs_renewal
from app.logging import configure_logging
from app.vault import SecretBox, aad_eab

app = typer.Typer(help="Certificate lifecycle automation for Cisco IOS-XE voice gateways.")
ca_app = typer.Typer(help="Manage certificate authority profiles.")
tenant_app = typer.Typer(help="Manage tenants (clients).")
device_app = typer.Typer(help="Manage voice gateways.")
app.add_typer(ca_app, name="ca")
app.add_typer(tenant_app, name="tenant")
app.add_typer(device_app, name="device")

LETSENCRYPT_PROD = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
ZEROSSL = "https://acme.zerossl.com/v2/DV90"


def _box() -> SecretBox:
    return SecretBox.from_b64(get_settings().require_master_key())


def _setup() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)


@app.callback()
def main() -> None:
    _setup()


# -- setup -------------------------------------------------------------------


@app.command("init")
def init() -> None:
    """Create the database schema."""
    init_db()
    typer.echo(f"Schema ready at {get_settings().database_url}")


@app.command("migrate")
def migrate_cmd() -> None:
    """Add columns introduced by a newer version to an existing database."""
    from app.db.migrate import migrate

    applied = migrate()
    if applied:
        for column in applied:
            typer.echo(f"added {column}")
    else:
        typer.echo("Schema already up to date.")


dns_app = typer.Typer(help="Inspect and clean up DNS-01 challenge records.")
app.add_typer(dns_app, name="dns")


@dns_app.command("challenges")
def dns_challenges(
    delete: bool = typer.Option(
        False, "--delete", help="Remove the records found. Lists only by default."
    ),
) -> None:
    """List leftover _acme-challenge TXT records in the managed zone.

    A run killed mid-validation cannot execute its cleanup, so challenge
    records can outlive the order that created them. They are inert, but they
    accumulate.
    """
    from app.dns.cloudflare import CloudflareSolver
    from app.dns.base import TxtRecord

    settings = get_settings()
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
            r for r in payload.get("result", [])
            if r["name"].startswith("_acme-challenge")
        ]

        if not records:
            typer.secho(
                f"No _acme-challenge records in {settings.cloudflare_zone}.",
                fg="green",
            )
            return

        typer.echo(f"{len(records)} challenge record(s) in {settings.cloudflare_zone}:")
        for record in records:
            typer.echo(f"  {record['name']}")

        if not delete:
            typer.echo()
            typer.secho("Re-run with --delete to remove them.", fg="cyan")
            return

        for record in records:
            solver.delete_txt(
                TxtRecord(name=record["name"], value="", record_id=record["id"])
            )
        typer.secho(f"Deleted {len(records)} record(s).", fg="green")
    finally:
        solver.close()


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8000, help="Bind port."),
    reload: bool = typer.Option(False, help="Auto-reload on code changes."),
) -> None:
    """Run the web console and the renewal scheduler.

    Binds to localhost by default -- the console can issue and deploy across the
    whole fleet, so exposing it needs to be a deliberate choice.
    """
    import uvicorn

    settings = get_settings()
    if not settings.api_token and not settings.webex_enabled:
        typer.secho(
            "No authentication configured; the API would refuse every request.",
            fg="red",
        )
        typer.echo(
            "Set HTAC_API_TOKEN, or a Webex integration "
            "(HTAC_WEBEX_CLIENT_ID / HTAC_WEBEX_CLIENT_SECRET), then re-run."
        )
        raise typer.Exit(1)

    dist = Path(__file__).resolve().parent.parent / "web" / "dist"
    if not dist.is_dir():
        typer.secho(f"No built frontend at {dist}", fg="yellow")
        typer.echo("The SPA is built into the Docker image. Rebuild with: docker compose build")
        typer.echo("The API will still serve on its own.")

    typer.secho(f"Console:   http://{host}:{port}/", fg="green")
    typer.secho(f"API docs:  http://{host}:{port}/docs", fg="green")
    if settings.webex_enabled:
        typer.echo(f"Sign-in:   Webex OAuth -> {settings.webex_redirect_uri}")
        if not (
            settings.webex_allowed_emails
            or settings.webex_allowed_domains
            or settings.webex_allowed_org_id
        ):
            typer.secho(
                "  WARNING: no Webex access policy set, so every sign-in will be "
                "denied. Set HTAC_WEBEX_ALLOWED_DOMAINS.",
                fg="yellow",
            )
    if settings.api_token:
        typer.echo("Sign-in:   API token (grep HTAC_API_TOKEN .env.htac)")
    typer.echo(
        f"Scheduler: {'enabled' if settings.schedule_enabled else 'disabled'}"
        + (f", daily at {settings.schedule_time} UTC" if settings.schedule_enabled else "")
    )
    uvicorn.run("app.api.app:app", host=host, port=port, reload=reload)


operator_app = typer.Typer(help="Manage who may use the web console.")
app.add_typer(operator_app, name="operator")


@operator_app.command("add")
def operator_add(
    email: str = typer.Argument(..., help="Webex email address."),
    role: str = typer.Option("viewer", help="viewer | operator | admin"),
    name: str = typer.Option(None, help="Display name, for the access review."),
) -> None:
    """Grant console access.

    Signing in with Webex proves identity; this decides what someone can do.
    Without a grant a user can authenticate and still do nothing.
    """
    from app.db.models import Operator, Role

    try:
        parsed = Role(role.strip().lower())
    except ValueError:
        typer.secho(f"Unknown role {role!r}; use viewer, operator or admin", fg="red")
        raise typer.Exit(1) from None

    address = email.strip().lower()
    with session_scope() as session:
        existing = session.exec(
            select(Operator).where(Operator.email == address)
        ).first()
        if existing:
            previous = existing.role.value
            existing.role = parsed
            existing.enabled = True
            if name:
                existing.display_name = name
            session.add(existing)
            message = f"{address}: {previous} -> {parsed.value}"
        else:
            session.add(
                Operator(
                    email=address, role=parsed, display_name=name, added_by="cli"
                )
            )
            message = f"{address}: granted {parsed.value}"

    typer.secho(message, fg="green")
    if parsed is not Role.viewer:
        typer.echo(
            "This role can issue and deploy certificates on client gateways."
            if parsed is Role.operator
            else "This role can issue, deploy, and change who else has access."
        )


@operator_app.command("list")
def operator_list() -> None:
    from app.db.models import Operator

    settings = get_settings()
    with session_scope() as session:
        grants = session.exec(select(Operator).order_by(Operator.email)).all()

    bootstrap = [b.strip() for b in settings.bootstrap_admins.split(",") if b.strip()]
    for email in bootstrap:
        typer.secho(f"{email:40} admin      (bootstrap, from config)", fg="yellow")

    if not grants:
        typer.echo("No explicit grants." if bootstrap else "No console access granted.")
    for g in grants:
        seen = g.last_seen_at.strftime("%Y-%m-%d") if g.last_seen_at else "never"
        state = "" if g.enabled else "  DISABLED"
        typer.echo(f"{g.email:40} {g.role.value:10} last seen {seen}{state}")

    default = settings.webex_default_role
    typer.echo()
    if default and default.lower() not in ("none", "", "deny"):
        typer.secho(
            f"Anyone passing the sign-in gate gets '{default}' by default "
            f"(HTAC_WEBEX_DEFAULT_ROLE).",
            fg="yellow",
        )
    else:
        typer.echo("Users without a grant have no access (HTAC_WEBEX_DEFAULT_ROLE=none).")


@operator_app.command("remove")
def operator_remove(
    email: str = typer.Argument(..., help="Webex email address."),
    disable: bool = typer.Option(
        False, "--disable", help="Keep the record but revoke access."
    ),
) -> None:
    """Revoke console access."""
    from app.db.models import Operator

    address = email.strip().lower()
    with session_scope() as session:
        grant = session.exec(select(Operator).where(Operator.email == address)).first()
        if grant is None:
            typer.secho(f"No grant for {address}", fg="red")
            raise typer.Exit(1)
        if disable:
            grant.enabled = False
            session.add(grant)
        else:
            session.delete(grant)

    typer.secho(
        f"{address}: {'disabled' if disable else 'removed'}", fg="green"
    )
    typer.echo(
        "Existing sessions remain valid until they expire "
        "(HTAC_SESSION_TTL_HOURS)."
    )


webex_app = typer.Typer(help="Read gateway inventory from Webex Control Hub.")
app.add_typer(webex_app, name="webex")


def _webex_token(token: str | None) -> str:
    if token:
        return token.strip()
    import os

    env = os.environ.get("WEBEX_TOKEN", "").strip()
    if env:
        return env
    typer.secho("No Webex token supplied.", fg="red")
    typer.echo(
        "Pass --token, or set WEBEX_TOKEN. A personal access token from\n"
        "https://developer.webex.com/docs/getting-started (valid ~12h) is "
        "enough to probe."
    )
    raise typer.Exit(1)


@webex_app.command("orgs")
def webex_orgs(
    token: str = typer.Option(None, help="Webex access token. Or set WEBEX_TOKEN."),
) -> None:
    """List the Webex organisations this token administers.

    Each client is its own organisation, so a tenant has to be linked to one
    before its gateways can be discovered.
    """
    from app.webex_inventory import WebexApiError, WebexInventory

    with WebexInventory(_webex_token(token)) as inventory:
        try:
            orgs = inventory.organizations()
        except WebexApiError as exc:
            typer.secho(str(exc), fg="red")
            raise typer.Exit(1) from None

    with session_scope() as session:
        linked = {
            t.webex_org_id: t.slug
            for t in session.exec(select(Tenant)).all()
            if t.webex_org_id
        }

    for org in orgs:
        tenant = linked.get(org.org_id)
        mark = f"-> {tenant}" if tenant else ""
        typer.secho(f"  {org.display_name:52} {mark}", fg="green" if tenant else None)
        typer.echo(f"    {org.org_id}")

    typer.echo(f"\n{len(orgs)} organisation(s), {len(linked)} linked to a tenant.")
    typer.echo("Link one with:  ./htac tenant set-webex-org <slug> --org-id <id>")


@webex_app.command("trunks")
def webex_trunks(
    org_id: str = typer.Option(None, help="Webex org ID. Defaults to --tenant's."),
    tenant: str = typer.Option(None, help="Tenant slug, to resolve the org."),
    token: str = typer.Option(None, help="Webex access token. Or set WEBEX_TOKEN."),
) -> None:
    """List the trunks (Local Gateways) in a Webex organisation."""
    from app.webex_inventory import WebexApiError, WebexInventory

    org_id = _resolve_org(org_id, tenant)

    with WebexInventory(_webex_token(token)) as inventory:
        try:
            found = inventory.trunks(org_id)
        except WebexApiError as exc:
            typer.secho(str(exc), fg="red")
            raise typer.Exit(1) from None

    if not found:
        typer.secho("No trunks in that organisation.", fg="yellow")
        return

    for gw in found:
        typer.secho(f"  {gw.name:34} {gw.trunk_type:18} {gw.status or '-'}", bold=True)
        typer.echo(f"    {gw.device_type or 'unknown device'}   location: {gw.location or '-'}")
        if gw.fqdn:
            typer.echo(f"    certificate name: {gw.fqdn}   domain: {gw.domain or '-'}")
        else:
            typer.echo("    no address in Webex (registering trunks do not record one)")

    typer.echo(f"\n{len(found)} trunk(s).")


def _resolve_org(org_id: str | None, tenant: str | None) -> str:
    if org_id:
        return org_id
    if not tenant:
        typer.secho("Pass --org-id or --tenant.", fg="red")
        raise typer.Exit(1)
    with session_scope() as session:
        t = session.exec(select(Tenant).where(Tenant.slug == tenant)).first()
        if t is None:
            typer.secho(f"No tenant named {tenant!r}", fg="red")
            raise typer.Exit(1)
        if not t.webex_org_id:
            typer.secho(
                f"Tenant {tenant} is not linked to a Webex organisation.\n"
                "Run  ./htac webex orgs  then  ./htac tenant set-webex-org "
                f"{tenant} --org-id <id>",
                fg="red",
            )
            raise typer.Exit(1)
        return t.webex_org_id


@webex_app.command("import")
def webex_import(
    tenant: str = typer.Option(..., help="Tenant slug to attach devices to."),
    org_id: str = typer.Option(None, help="Webex org ID. Defaults to the tenant's."),
    token: str = typer.Option(None, help="Webex access token. Or set WEBEX_TOKEN."),
    apply: bool = typer.Option(
        False, "--apply", help="Create the devices. Lists them by default."
    ),
) -> None:
    """Import gateways from Control Hub into the device inventory.

    Devices are created **disabled**. Webex records a registering trunk's name
    but not its management address, so an import is a worklist rather than a
    deployable device -- set the address, credentials and host key, then enable.
    """
    from app.webex_inventory import WebexApiError, WebexInventory

    org_id = _resolve_org(org_id, tenant)

    with WebexInventory(_webex_token(token)) as inventory:
        try:
            found = inventory.trunks(org_id)
        except WebexApiError as exc:
            typer.secho(str(exc), fg="red")
            raise typer.Exit(1) from None

    if not found:
        typer.secho("No trunks in that organisation.", fg="yellow")
        return

    with session_scope() as session:
        t = session.exec(select(Tenant).where(Tenant.slug == tenant)).first()
        if t is None:
            typer.secho(f"No tenant named {tenant!r}", fg="red")
            raise typer.Exit(1)
        existing = {d.fqdn for d in session.exec(select(Device)).all()}
        suffix = t.domain_suffix

    typer.echo(f"{len(found)} trunk(s) in {org_id}:\n")
    importable: list = []
    seen: set[str] = set()
    derived = 0

    for gw in found:
        if gw.fqdn:
            fqdn, source = gw.fqdn, "webex"
        elif suffix and _slug(gw.name):
            fqdn, source = f"{_slug(gw.name)}.{suffix}", "derived"
        else:
            fqdn, source = None, "none"

        problem = None
        if not fqdn:
            problem = "no address in Webex and no tenant domain suffix"
        elif fqdn in existing or fqdn in seen:
            problem = "already in inventory"

        if problem:
            typer.secho(f"  skip   {gw.name:34} {problem}", fg="yellow")
        else:
            note = "from Webex" if source == "webex" else "derived - confirm"
            typer.secho(f"  add    {fqdn:48} {note}", fg="green")
            seen.add(fqdn)
            derived += source == "derived"
            importable.append((gw, fqdn))

    if not importable:
        typer.echo("\nNothing to import.")
        return

    if not apply:
        typer.echo(f"\nRe-run with --apply to create {len(importable)} device(s).")
        return

    with session_scope() as session:
        t = session.exec(select(Tenant).where(Tenant.slug == tenant)).first()
        for gw, fqdn in importable:
            session.add(
                Device(
                    tenant_id=t.id,
                    hostname=gw.name,
                    fqdn=fqdn,
                    mgmt_address=mgmt_from_discovery(gw.address, fqdn),
                    enabled=False,
                )
            )
    typer.secho(f"\nCreated {len(importable)} device(s), all disabled.", fg="green")
    if derived:
        typer.secho(
            f"{derived} FQDN(s) were derived from the tenant suffix, not read "
            "from Webex. Confirm each one before enabling.",
            fg="yellow",
        )
    typer.echo(
        "Next: ./htac device set-address <fqdn> --address <mgmt-ip>  "
        "then  ./htac device trust <fqdn>  and  ./htac device set-credentials <fqdn>"
    )


def _slug(name: str) -> str:
    """Trunk name -> DNS label. Webex allows spaces and dots; hostnames do not."""
    label = "".join(c.lower() if c.isalnum() else "-" for c in name.strip()).strip("-")
    while "--" in label:
        label = label.replace("--", "-")
    return label


@app.command("doctor")
def doctor() -> None:
    """Check configuration, and that the master key opens everything stored.

    A lost or rotated HTAC_MASTER_KEY is otherwise invisible until a deployment
    or renewal tries to use a sealed value.
    """
    from app.health import FAIL, OK, WARN, run_checks

    settings = get_settings()
    with session_scope() as session:
        report = run_checks(session, settings)

    symbols = {OK: ("[ ok ]", "green"), WARN: ("[warn]", "yellow"), FAIL: ("[fail]", "red")}
    for check in report.checks:
        symbol, colour = symbols[check.status]
        typer.secho(f"{symbol} {check.name:44} {check.detail}", fg=colour)
        if check.remedy:
            typer.secho(f"       -> {check.remedy}", fg="cyan")

    typer.echo()
    if report.failures:
        typer.secho(
            f"{report.failures} failure(s), {report.warnings} warning(s).", fg="red"
        )
        raise typer.Exit(1)
    if report.warnings:
        typer.secho(f"{report.warnings} warning(s).", fg="yellow")
    else:
        typer.secho("All checks passed.", fg="green")


@app.command("gen-master-key")
def gen_master_key() -> None:
    """Print a fresh master key for HTAC_MASTER_KEY.

    Store it in a secrets manager. Losing it makes every escrowed private key
    in the database unrecoverable.
    """
    typer.echo(SecretBox.generate_master_key())


# -- CA profiles -------------------------------------------------------------


@ca_app.command("add")
def ca_add(
    name: str = typer.Option(..., help="Local name, e.g. 'letsencrypt-prod'."),
    email: str = typer.Option(..., help="Contact address for expiry notices."),
    directory_url: str = typer.Option(
        LETSENCRYPT_PROD, help="ACME directory URL."
    ),
    staging: bool = typer.Option(False, help="Shorthand for the LE staging directory."),
    eab_kid: str = typer.Option(None, help="EAB key id (required by ZeroSSL)."),
    eab_hmac: str = typer.Option(None, help="EAB HMAC key (required by ZeroSSL)."),
    preferred_chain: str = typer.Option(
        None, help="Issuer CN of the chain to prefer, e.g. 'ISRG Root X1'."
    ),
) -> None:
    """Register a CA profile."""
    if staging:
        directory_url = LETSENCRYPT_STAGING

    if (eab_kid is None) != (eab_hmac is None):
        typer.secho("--eab-kid and --eab-hmac must be given together", fg="red")
        raise typer.Exit(1)

    box = _box()
    with session_scope() as session:
        if session.exec(select(CAProfile).where(CAProfile.name == name)).first():
            typer.secho(f"CA profile {name!r} already exists", fg="red")
            raise typer.Exit(1)

        profile = CAProfile(
            name=name,
            directory_url=directory_url,
            contact_email=email,
            preferred_chain=preferred_chain,
        )
        if eab_kid and eab_hmac:
            profile.eab_kid_sealed = box.seal(eab_kid.encode(), aad_eab(name, "eab_kid"))
            profile.eab_hmac_sealed = box.seal(
                eab_hmac.encode(), aad_eab(name, "eab_hmac")
            )
        session.add(profile)

    typer.echo(f"Added CA profile {name!r} -> {directory_url}")


@ca_app.command("list")
def ca_list() -> None:
    with session_scope() as session:
        profiles = session.exec(select(CAProfile)).all()
        if not profiles:
            typer.echo("No CA profiles configured.")
            return
        for p in profiles:
            flags = []
            if p.uses_eab:
                flags.append("EAB")
            if p.account_uri:
                flags.append("registered")
            if p.preferred_chain:
                flags.append(f"chain={p.preferred_chain}")
            typer.echo(f"{p.name:24} {p.directory_url}  [{', '.join(flags) or '-'}]")


# -- tenants -----------------------------------------------------------------


@tenant_app.command("add")
def tenant_add(
    slug: str = typer.Option(..., help="Short identifier, e.g. 'husd'."),
    name: str = typer.Option(..., help="Client name."),
    domain_suffix: str = typer.Option(..., help="e.g. husd.clients.managedcollab.com"),
    ca: str = typer.Option(..., help="CA profile name."),
    renew_before_days: int = typer.Option(30, help="Renewal threshold."),
) -> None:
    with session_scope() as session:
        profile = session.exec(select(CAProfile).where(CAProfile.name == ca)).first()
        if profile is None:
            typer.secho(f"No CA profile named {ca!r}", fg="red")
            raise typer.Exit(1)
        session.add(
            Tenant(
                slug=slug,
                name=name,
                domain_suffix=domain_suffix,
                ca_profile_id=profile.id,
                renew_before_days=renew_before_days,
            )
        )
    typer.echo(f"Added tenant {slug!r} ({domain_suffix}) using CA {ca!r}")


@tenant_app.command("set-ca")
def tenant_set_ca(
    slug: str = typer.Argument(..., help="Tenant slug."),
    ca: str = typer.Option(..., help="CA profile name."),
) -> None:
    """Repoint a tenant at a different CA profile.

    Affects the *next* issuance only; certificates already on record keep the
    chain they were issued with.
    """
    with session_scope() as session:
        tenant = session.exec(select(Tenant).where(Tenant.slug == slug)).first()
        if tenant is None:
            typer.secho(f"No tenant named {slug!r}", fg="red")
            raise typer.Exit(1)
        profile = session.exec(select(CAProfile).where(CAProfile.name == ca)).first()
        if profile is None:
            typer.secho(f"No CA profile named {ca!r}", fg="red")
            raise typer.Exit(1)

        previous = session.get(CAProfile, tenant.ca_profile_id)
        # Read what we need before the session closes.
        previous_name = previous.name if previous else "(none)"
        directory_url = profile.directory_url
        tenant.ca_profile_id = profile.id
        session.add(tenant)

    typer.echo(f"Tenant {slug!r}: {previous_name} -> {ca}")
    if "staging" not in directory_url:
        typer.secho(
            "This is a production CA. The next issuance consumes real rate "
            "limit against the registered domain.",
            fg="yellow",
        )


@tenant_app.command("set-webex-org")
def tenant_set_webex_org(
    slug: str = typer.Argument(..., help="Tenant slug."),
    org_id: str = typer.Option(..., "--org-id", help="Webex organisation ID."),
    org_name: str = typer.Option(None, help="Display name, for the UI."),
) -> None:
    """Bind a tenant to its Webex organisation.

    Discovery is org-scoped, and each client is a separate organisation, so
    this mapping is what makes an import attributable to a tenant.
    """
    with session_scope() as session:
        tenant = session.exec(select(Tenant).where(Tenant.slug == slug)).first()
        if tenant is None:
            typer.secho(f"No tenant named {slug!r}", fg="red")
            raise typer.Exit(1)

        clash = session.exec(
            select(Tenant).where(Tenant.webex_org_id == org_id, Tenant.slug != slug)
        ).first()
        if clash is not None:
            typer.secho(
                f"That Webex org is already linked to tenant {clash.slug!r}.",
                fg="red",
            )
            raise typer.Exit(1)

        previous = tenant.webex_org_id or "(none)"
        tenant.webex_org_id = org_id
        tenant.webex_org_name = org_name
        session.add(tenant)

    typer.echo(f"Tenant {slug!r}: {previous} -> {org_id}")


@tenant_app.command("list")
def tenant_list() -> None:
    with session_scope() as session:
        for t in session.exec(select(Tenant)).all():
            count = len(session.exec(select(Device).where(Device.tenant_id == t.id)).all())
            typer.echo(f"{t.slug:12} {t.domain_suffix:45} {count} device(s)")


# -- devices -----------------------------------------------------------------


@device_app.command("add")
def device_add(
    tenant: str = typer.Option(..., help="Tenant slug."),
    hostname: str = typer.Option(..., help="e.g. brg-vgw-01"),
    fqdn: str = typer.Option(..., help="Certificate CN / SAN."),
    address: str = typer.Option(..., help="Management IP or hostname."),
    ssh_port: int = typer.Option(
        22, help="SSH port. Use a local forwarder port with the cloudflared overlay."
    ),
    trustpoint_a: str = typer.Option("HT-WxCAutoCert-A"),
    trustpoint_b: str = typer.Option("HT-WxCAutoCert-B"),
    active_trustpoint: str = typer.Option(
        None, help="Trustpoint currently bound in 'sip-ua crypto signaling'."
    ),
    p12_profile: Pkcs12Profile = typer.Option(
        Pkcs12Profile.modern, help="'legacy' for IOS-XE trains that reject AES p12."
    ),
) -> None:
    with session_scope() as session:
        t = session.exec(select(Tenant).where(Tenant.slug == tenant)).first()
        if t is None:
            typer.secho(f"No tenant named {tenant!r}", fg="red")
            raise typer.Exit(1)
        if not management_host(address, fqdn):
            typer.secho(
                "Management address must be the gateway's reachable IP (or an "
                "internal hostname), not the certificate FQDN. That name is for "
                "ACME only and has no A record.",
                fg="red",
            )
            raise typer.Exit(1)
        session.add(
            Device(
                tenant_id=t.id,
                hostname=hostname,
                fqdn=fqdn,
                mgmt_address=address,
                ssh_port=ssh_port,
                trustpoint_a=trustpoint_a,
                trustpoint_b=trustpoint_b,
                active_trustpoint=active_trustpoint,
                pkcs12_profile=p12_profile,
            )
        )
    typer.echo(f"Added device {fqdn} ({address}) to tenant {tenant!r}")


# -- operations --------------------------------------------------------------


@app.command("status")
def status() -> None:
    """Show every device with its current certificate state."""
    with session_scope() as session:
        devices = session.exec(select(Device).order_by(Device.fqdn)).all()
        if not devices:
            typer.echo("No devices configured.")
            return

        typer.echo(
            f"{'FQDN':45} {'TENANT':10} {'DAYS':>5}  {'TRUSTPOINT':22} {'CHAIN':24} STATE"
        )
        for d in devices:
            tenant = session.get(Tenant, d.tenant_id)
            cert = latest_certificate(session, d)
            needed, reason, days = needs_renewal(session, d, tenant)
            if cert is None:
                days_s, chain, state = "-", "-", "no certificate"
            else:
                days_s = str(days)
                chain = cert.chain_issuer_cn[:24]
                state = "renew due" if needed else "ok"
            colour = "red" if cert is None else ("yellow" if needed else "green")
            typer.secho(
                f"{d.fqdn:45} {tenant.slug:10} {days_s:>5}  "
                f"{(d.active_trustpoint or '-'):22} {chain:24} {state}",
                fg=colour,
            )


@app.command("issue")
def issue(
    fqdn: str = typer.Option(None, help="Single device. Omit to process all enabled."),
    tenant: str = typer.Option(None, help="Limit to one tenant slug."),
    force: bool = typer.Option(False, help="Issue even if not near expiry."),
    dry_run: bool = typer.Option(False, help="Report what would happen, change nothing."),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the production --force confirmation."
    ),
) -> None:
    """Obtain or renew certificates."""
    settings = get_settings()
    box = _box()

    with session_scope() as session:
        stmt = select(Device).where(Device.enabled == True)  # noqa: E712
        if fqdn:
            stmt = stmt.where(Device.fqdn == fqdn)
        if tenant:
            t = session.exec(select(Tenant).where(Tenant.slug == tenant)).first()
            if t is None:
                typer.secho(f"No tenant named {tenant!r}", fg="red")
                raise typer.Exit(1)
            stmt = stmt.where(Device.tenant_id == t.id)

        devices = session.exec(stmt.order_by(Device.fqdn)).all()
        if not devices:
            typer.secho("No matching devices.", fg="yellow")
            raise typer.Exit(1)

        # Re-issuing the same name repeatedly is what exhausts Let's Encrypt's
        # duplicate-certificate limit (5 per exact name set per week), and
        # --force is the only way to get there during normal operation.
        if force and not dry_run and not yes:
            production = sorted(
                {
                    p.name
                    for d in devices
                    if (t := session.get(Tenant, d.tenant_id))
                    and (p := session.get(CAProfile, t.ca_profile_id))
                    and "staging" not in p.directory_url
                }
            )
            if production:
                typer.secho(
                    f"--force will issue {len(devices)} certificate(s) from a "
                    f"production CA ({', '.join(production)}).",
                    fg="yellow",
                )
                typer.echo(
                    "Let's Encrypt allows 5 per exact name per 7 days; repeated "
                    "forced issuance is what exhausts it. Use --staging profiles "
                    "for testing."
                )
                typer.confirm("Continue?", abort=True)

        service = IssuanceService(session, settings, box)
        results = service.run(devices, force=force, dry_run=dry_run)

    failed = 0
    for r in results:
        colour = {"issued": "green", "skipped": "blue", "failed": "red"}[r.status]
        typer.secho(f"{r.status:8} {r.fqdn:45} {r.detail}", fg=colour)
        if r.status == "failed":
            failed += 1

    if failed:
        typer.secho(f"\n{failed} device(s) failed.", fg="red")
        raise typer.Exit(1)


@app.command("export-p12")
def export_p12(
    fqdn: str = typer.Argument(..., help="Device FQDN."),
    out: Path = typer.Option(None, help="Output path. Defaults to ./<fqdn>.p12"),
    show_password: bool = typer.Option(
        False, help="Print the bundle password to stdout."
    ),
) -> None:
    """Write the current .p12 to disk for the Phase 1 Ansible hand-off.

    The password is the configured static PKCS12 password (HTAC_PKCS12_PASSWORD).
    """
    settings = get_settings()
    box = _box()

    with session_scope() as session:
        device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
        if device is None:
            typer.secho(f"No device with FQDN {fqdn!r}", fg="red")
            raise typer.Exit(1)
        cert = latest_certificate(session, device)
        if cert is None:
            typer.secho(f"No certificate on record for {fqdn}", fg="red")
            raise typer.Exit(1)

        service = IssuanceService(session, settings, box)
        blob, password = service.export_pkcs12(cert, device)
        # Read before the session closes.
        serial = cert.serial
        target_trustpoint = cert.target_trustpoint

    target = out or Path(f"{fqdn}.p12")
    target.write_bytes(blob)
    target.chmod(0o600)
    typer.echo(f"Wrote {target} ({len(blob)} bytes, serial {serial})")
    typer.echo(f"Target trustpoint: {target_trustpoint}")
    if show_password:
        typer.echo(f"Password: {password}")
    else:
        typer.echo("Re-run with --show-password to print the bundle password.")


@device_app.command("set-credentials")
def device_set_credentials(
    fqdn: str = typer.Argument(..., help="Device FQDN."),
    username: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
    enable_password: str = typer.Option(
        None, help="Only if enable is separate from the login password."
    ),
) -> None:
    """Store SSH credentials for one device (sealed in the datastore)."""
    from app.devices.factory import aad_device_secret

    box = _box()
    with session_scope() as session:
        device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
        if device is None:
            typer.secho(f"No device with FQDN {fqdn!r}", fg="red")
            raise typer.Exit(1)
        device.username = username
        device.password_sealed = box.seal(
            password.encode(), aad_device_secret(fqdn, "password")
        )
        if enable_password:
            device.enable_password_sealed = box.seal(
                enable_password.encode(), aad_device_secret(fqdn, "enable_password")
            )
        session.add(device)
    typer.echo(f"Credentials stored for {fqdn}")


@device_app.command("set-address")
def device_set_address(
    fqdn: str = typer.Argument(..., help="Device FQDN (certificate name)."),
    address: str = typer.Option(..., help="Reachable management IP or internal hostname."),
) -> None:
    """Set the IOS management address used for RESTCONF and SSH.

    Distinct from the certificate FQDN, which exists only for ACME DNS-01 and
    has no A record.
    """
    host = management_host(address, fqdn)
    if not host:
        typer.secho(
            "Management address must be a reachable IP (or internal hostname), "
            "not the certificate FQDN.",
            fg="red",
        )
        raise typer.Exit(1)
    with session_scope() as session:
        device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
        if device is None:
            typer.secho(f"No device with FQDN {fqdn!r}", fg="red")
            raise typer.Exit(1)
        previous = management_host(device.mgmt_address, device.fqdn) or "(none)"
        device.mgmt_address = host
        session.add(device)
    typer.echo(f"{fqdn}: {previous} -> {host}")


@tenant_app.command("set-credentials")
def tenant_set_credentials(
    slug: str = typer.Argument(..., help="Tenant slug."),
    username: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
) -> None:
    """Store default SSH credentials for a tenant's gateways."""
    from app.devices.factory import aad_tenant_secret

    box = _box()
    with session_scope() as session:
        tenant = session.exec(select(Tenant).where(Tenant.slug == slug)).first()
        if tenant is None:
            typer.secho(f"No tenant named {slug!r}", fg="red")
            raise typer.Exit(1)
        tenant.default_username = username
        tenant.default_password_sealed = box.seal(
            password.encode(), aad_tenant_secret(slug, "password")
        )
        session.add(tenant)
    typer.echo(f"Default credentials stored for tenant {slug!r}")


@device_app.command("set-sans")
def device_set_sans(
    fqdn: str = typer.Argument(..., help="Device FQDN (always the primary name)."),
    san: list[str] = typer.Option(
        None, "--san", help="Additional SAN. Repeatable. Omit to clear."
    ),
) -> None:
    """Set additional SAN names for a device's certificate.

    Beyond covering extra hostnames, this changes the certificate's identifier
    set -- the unit Let's Encrypt scopes its duplicate-certificate limit to
    (5 per set per 7 days). A different set has its own allowance, so adding a
    SAN is a legitimate way to issue when that limit is exhausted, without
    changing CA.
    """
    with session_scope() as session:
        device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
        if device is None:
            typer.secho(f"No device with FQDN {fqdn!r}", fg="red")
            raise typer.Exit(1)

        extras = [s.strip() for s in (san or []) if s.strip() and s.strip() != fqdn]
        device.extra_sans = ",".join(extras) or None
        session.add(device)
        names = device.san_list()

    typer.echo(f"{fqdn} certificate will cover {len(names)} name(s):")
    for index, name in enumerate(names):
        typer.echo(f"  {'primary' if index == 0 else 'SAN    '}  {name}")


@device_app.command("trust")
def device_trust(
    fqdn: str = typer.Argument(..., help="Device FQDN."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation."),
) -> None:
    """Pin a device's SSH host key.

    Stores the key with the device record rather than relying on the invoking
    user's ~/.ssh/known_hosts, which does not exist in a container. Compare the
    fingerprint against the device (``show crypto key mypubkey rsa``, or your
    build records) before accepting.
    """
    from app.devices.factory import fetch_host_key

    with session_scope() as session:
        device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
        if device is None:
            typer.secho(f"No device with FQDN {fqdn!r}", fg="red")
            raise typer.Exit(1)
        address, port = management_host(device.mgmt_address, device.fqdn), device.ssh_port
        existing = device.ssh_host_key

    if not address:
        typer.secho(
            f"{fqdn}: no management IP set. The certificate FQDN is for ACME "
            f"only. Set one with: ./htac device set-address {fqdn} --address <ip>",
            fg="red",
        )
        raise typer.Exit(1)

    try:
        line, key_type, fingerprint = fetch_host_key(address, port)
    except Exception as exc:  # noqa: BLE001 - network failure, reported as-is
        typer.secho(f"Could not reach {address}:{port} -- {exc}", fg="red")
        raise typer.Exit(1) from exc

    typer.echo(f"{fqdn} ({address}:{port})")
    typer.echo(f"  key type:    {key_type}")
    typer.echo(f"  fingerprint: {fingerprint}")

    if existing and existing.strip() == line.strip():
        typer.secho("Already pinned; unchanged.", fg="green")
        return
    if existing:
        typer.secho(
            "WARNING: a different host key is already pinned for this device. "
            "Either the device was replaced or reimaged, or this connection is "
            "being intercepted.",
            fg="red",
        )

    if not yes:
        typer.confirm("Pin this key?", abort=True)

    with session_scope() as session:
        device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
        device.ssh_host_key = line
        session.add(device)

    typer.secho(f"Pinned {key_type} host key for {fqdn}", fg="green")


@device_app.command("inspect")
def device_inspect(
    fqdn: str = typer.Argument(..., help="Device FQDN."),
) -> None:
    """Read live certificate state from a gateway."""
    from app.devices.base import DeviceError
    from app.devices.factory import build_transport

    box = _box()
    with session_scope() as session:
        device = session.exec(select(Device).where(Device.fqdn == fqdn)).first()
        if device is None:
            typer.secho(f"No device with FQDN {fqdn!r}", fg="red")
            raise typer.Exit(1)

        try:
            with build_transport(session, device, box) as transport:
                state = transport.read_state()
        except DeviceError as exc:
            typer.secho(str(exc), fg="red")
            raise typer.Exit(1) from exc

    typer.echo(f"Bound trustpoint: {state.bound_trustpoint or '(none)'}")
    if not state.trustpoints:
        typer.echo("No trustpoints reported.")
        return
    for label, tp in sorted(state.trustpoints.items()):
        marker = "*" if label == state.bound_trustpoint else " "
        expiry = (
            f" expires={tp.validity_end.date().isoformat()}"
            if tp.has_certificate and tp.validity_end
            else ""
        )
        typer.echo(f" {marker} {label:26} {tp.describe()}{expiry}")


@app.command("deploy")
def deploy(
    fqdn: str = typer.Option(None, help="Single device. Omit to process all enabled."),
    tenant: str = typer.Option(None, help="Limit to one tenant slug."),
    no_rebind: bool = typer.Option(
        False, help="Import and verify, but leave sip-ua pointing at the old trustpoint."
    ),
    force: bool = typer.Option(
        False, help="Deploy even if the device already reports this certificate."
    ),
) -> None:
    """Install the current certificate on gateways, blue/green."""
    from app.deployment import DeploymentService
    from app.devices.factory import build_transport

    box = _box()

    with session_scope() as session:
        stmt = select(Device).where(Device.enabled == True)  # noqa: E712
        if fqdn:
            stmt = stmt.where(Device.fqdn == fqdn)
        if tenant:
            t = session.exec(select(Tenant).where(Tenant.slug == tenant)).first()
            if t is None:
                typer.secho(f"No tenant named {tenant!r}", fg="red")
                raise typer.Exit(1)
            stmt = stmt.where(Device.tenant_id == t.id)

        devices = session.exec(stmt.order_by(Device.fqdn)).all()
        if not devices:
            typer.secho("No matching devices.", fg="yellow")
            raise typer.Exit(1)

        service = DeploymentService(
            session,
            box,
            lambda d: build_transport(session, d, box),
            public_base_url=get_settings().public_base_url,
        )

        results = []
        for device in devices:
            cert = latest_certificate(session, device)
            if cert is None:
                typer.secho(f"skipped  {device.fqdn:45} no certificate issued", fg="blue")
                continue
            if cert.status.value == "deployed" and not force:
                typer.secho(
                    f"skipped  {device.fqdn:45} serial {cert.serial} already deployed",
                    fg="blue",
                )
                continue
            results.append(
                service.deploy_device(
                    device,
                    cert,
                    rebind=not no_rebind,
                    revocation_check=device.revocation_check,
                )
            )

    failed = 0
    for r in results:
        colour = {
            "deployed": "green",
            "rolled_back": "yellow",
            "failed": "red",
            "skipped": "blue",
        }[r.status]
        typer.secho(f"{r.status:12} {r.fqdn:45} {r.detail}", fg=colour)
        for step in r.steps:
            typer.echo(f"             - {step}")
        if r.status in ("failed", "rolled_back"):
            failed += 1

    if failed:
        typer.secho(f"\n{failed} device(s) did not complete.", fg="red")
        raise typer.Exit(1)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
