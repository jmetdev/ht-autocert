"""CLI behaviour, focused on the session-lifetime trap.

Reading an ORM attribute after ``session_scope`` exits raises
DetachedInstanceError *after* the write has already committed -- the change
lands and the command still exits non-zero with a traceback. Exercising the
commands end to end is the only thing that catches it.
"""

from typer.testing import CliRunner

from app.cli import app

runner = CliRunner()


def _run(*args):
    return runner.invoke(app, list(args))


def _seed():
    assert _run("init").exit_code == 0
    assert _run(
        "ca", "add", "--name", "le-staging",
        "--email", "ops@example.com", "--staging",
    ).exit_code == 0
    assert _run(
        "ca", "add", "--name", "le-prod",
        "--email", "ops@example.com",
        "--preferred-chain", "ISRG Root X1",
    ).exit_code == 0
    assert _run(
        "tenant", "add", "--slug", "husd", "--name", "HUSD",
        "--domain-suffix", "husd.clients.example.com", "--ca", "le-staging",
    ).exit_code == 0


def test_set_ca_reports_the_transition_without_detaching():
    _seed()

    result = _run("tenant", "set-ca", "husd", "--ca", "le-prod")

    assert result.exit_code == 0, result.output
    assert "DetachedInstanceError" not in result.output
    assert "le-staging -> le-prod" in result.output


def test_switching_to_production_warns():
    _seed()
    result = _run("tenant", "set-ca", "husd", "--ca", "le-prod")
    assert "production CA" in result.output


def test_switching_to_staging_does_not_warn():
    _seed()
    _run("tenant", "set-ca", "husd", "--ca", "le-prod")
    result = _run("tenant", "set-ca", "husd", "--ca", "le-staging")
    assert result.exit_code == 0
    assert "production CA" not in result.output


def test_set_ca_actually_persists():
    _seed()
    _run("tenant", "set-ca", "husd", "--ca", "le-prod")

    result = _run("ca", "list")
    assert "le-prod" in result.output

    from sqlmodel import select

    from app.db.models import CAProfile, Tenant
    from app.db.session import session_scope

    with session_scope() as session:
        tenant = session.exec(select(Tenant).where(Tenant.slug == "husd")).first()
        profile = session.get(CAProfile, tenant.ca_profile_id)
        assert profile.name == "le-prod"


def test_unknown_tenant_is_rejected():
    _seed()
    result = _run("tenant", "set-ca", "nope", "--ca", "le-prod")
    assert result.exit_code == 1
    assert "No tenant" in result.output


def test_unknown_ca_is_rejected():
    _seed()
    result = _run("tenant", "set-ca", "husd", "--ca", "nope")
    assert result.exit_code == 1
    assert "No CA profile" in result.output


def test_status_and_doctor_run_clean():
    _seed()
    assert _run("status").exit_code == 0
    # doctor exits 1 on warnings-free failures only; here nothing is sealed.
    assert "DetachedInstanceError" not in _run("doctor").output


def test_attributes_survive_commit():
    """The systemic guard: session_scope must not expire on commit."""
    from app.db.models import CAProfile
    from app.db.session import init_db, session_scope

    init_db()
    with session_scope() as session:
        profile = CAProfile(
            name="probe", directory_url="https://x.invalid", contact_email="a@b.c"
        )
        session.add(profile)

    # Outside the block, after commit, with the session closed.
    assert profile.name == "probe"
    assert profile.directory_url == "https://x.invalid"


# -- production --force guard ------------------------------------------------


def _seed_with_device(ca="le-prod"):
    _seed()
    assert _run("tenant", "set-ca", "husd", "--ca", ca).exit_code == 0
    assert _run(
        "device", "add", "--tenant", "husd", "--hostname", "vg01",
        "--fqdn", "vg01.husd.clients.example.com", "--address", "10.0.0.1",
    ).exit_code == 0


def test_force_against_production_requires_confirmation():
    """Repeated forced issuance is what exhausts the duplicate-cert limit."""
    _seed_with_device("le-prod")

    result = runner.invoke(app, ["issue", "--force"], input="n\n")

    assert result.exit_code != 0
    assert "production CA" in result.output
    assert "5 per exact name" in result.output


def test_force_confirmation_can_be_skipped():
    _seed_with_device("le-prod")
    # --dry-run stops before any network call; the guard must not fire.
    result = runner.invoke(app, ["issue", "--force", "--dry-run"])
    assert "Continue?" not in result.output


def test_force_against_staging_is_not_gated():
    _seed_with_device("le-staging")
    result = runner.invoke(app, ["issue", "--force", "--dry-run"])
    assert "production CA" not in result.output


def test_unforced_issue_is_not_gated():
    _seed_with_device("le-prod")
    result = runner.invoke(app, ["issue", "--dry-run"])
    assert "production CA" not in result.output


def test_device_add_rejects_the_certificate_fqdn_as_address():
    _seed()
    result = _run(
        "device", "add", "--tenant", "husd", "--hostname", "vg01",
        "--fqdn", "vg01.husd.clients.example.com",
        "--address", "vg01.husd.clients.example.com",
    )
    assert result.exit_code != 0
    assert "not the certificate FQDN" in result.output


def test_set_address_persists_without_detaching():
    _seed_with_device("le-staging")
    result = _run(
        "device", "set-address", "vg01.husd.clients.example.com",
        "--address", "10.40.8.10",
    )
    assert result.exit_code == 0, result.output
    assert "DetachedInstanceError" not in result.output
    assert "10.40.8.10" in result.output

    from sqlmodel import select

    from app.db.models import Device
    from app.db.session import session_scope

    with session_scope() as session:
        device = session.exec(
            select(Device).where(Device.fqdn == "vg01.husd.clients.example.com")
        ).first()
        assert device.mgmt_address == "10.40.8.10"
