"""Role resolution.

Kept apart from :mod:`app.auth` because it answers a different question.
``is_authorised`` decides whether someone may sign in; this decides what they
may then do. Domain membership alone grants nothing: an MSP's whole staff
should not be able to redeploy certificates on client voice gateways.

Precedence, highest first:

1. **Bootstrap admins** -- configured emails, so a fresh deployment is reachable
   before any grant exists.
2. **Explicit grant** in the ``operator`` table.
3. **Default role** for a user who passed the sign-in gate but has no grant.
   Defaults to nothing at all.
"""

from __future__ import annotations

import structlog
from sqlmodel import Session, select

from app.auth import in_list
from app.config import Settings
from app.db.models import Operator, Role, utcnow

log = structlog.get_logger(__name__)


def parse_default_role(value: str) -> Role | None:
    """Interpret HTAC_WEBEX_DEFAULT_ROLE. Anything unrecognised means none."""
    candidate = (value or "").strip().lower()
    if candidate in ("", "none", "no", "false", "deny"):
        return None
    try:
        return Role(candidate)
    except ValueError:
        log.warning("roles.unknown_default", value=value)
        return None


def resolve_role(
    session: Session, email: str, settings: Settings
) -> tuple[Role | None, str]:
    """Return (role, reason) for a signed-in user. ``None`` means no access."""
    email = (email or "").strip().lower()
    if not email:
        return None, "no email on session"

    if in_list(email, settings.bootstrap_admins):
        return Role.admin, "bootstrap admin"

    grant = session.exec(select(Operator).where(Operator.email == email)).first()
    if grant is not None:
        if not grant.enabled:
            return None, f"access for {email} is disabled"
        return grant.role, f"granted {grant.role.value}"

    default = parse_default_role(settings.webex_default_role)
    if default is not None:
        return default, f"default role {default.value}"

    return None, (
        f"{email} can sign in but has no role. Grant one with: "
        f"./htac operator add {email} --role viewer"
    )


def touch_last_seen(session: Session, email: str) -> None:
    """Record activity, so stale grants are visible when reviewing access."""
    grant = session.exec(
        select(Operator).where(Operator.email == (email or "").lower())
    ).first()
    if grant is not None:
        grant.last_seen_at = utcnow()
        session.add(grant)
        session.commit()
