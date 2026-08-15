"""Renewal spreading and scheduler configuration.

The Ansible cron ran monthly against a fixed 30-day threshold. On a 90-day
certificate that could leave a single day of margin, and it renewed the whole
fleet in one burst.
"""

from collections import Counter

import pytest

from app.config import Settings
from app.db.models import Device, Tenant
from app.issuance import renewal_threshold
from app.scheduler import build_scheduler

FLEET = [f"brg-vgw-{i:02d}.husd.clients.managedcollab.com" for i in range(1, 51)]


def _device(fqdn: str) -> Device:
    return Device(tenant_id=1, hostname=fqdn.split(".")[0], fqdn=fqdn,
                  mgmt_address="10.0.0.1")


@pytest.fixture
def tenant() -> Tenant:
    return Tenant(slug="husd", name="HUSD", domain_suffix="husd.clients.example.com",
                  renew_before_days=30)


def test_no_spread_gives_the_plain_threshold(tenant):
    assert renewal_threshold(_device(FLEET[0]), tenant, spread_days=0) == 30


def test_threshold_is_stable_for_a_device(tenant):
    """The same gateway must always land in the same slot, with no stored state."""
    device = _device(FLEET[0])
    values = {renewal_threshold(device, tenant, 21) for _ in range(50)}
    assert len(values) == 1


def test_threshold_stays_within_the_spread_window(tenant):
    for fqdn in FLEET:
        value = renewal_threshold(_device(fqdn), tenant, 21)
        assert 30 <= value < 51


def test_spread_distributes_the_fleet(tenant):
    """A same-day bulk provision must not renew as one burst."""
    counts = Counter(renewal_threshold(_device(f), tenant, 21) for f in FLEET)
    assert len(counts) >= 10          # spread across many distinct days
    assert max(counts.values()) <= 10  # no single day dominates


def test_spread_respects_the_tenant_threshold(tenant):
    tenant.renew_before_days = 45
    for fqdn in FLEET:
        assert renewal_threshold(_device(fqdn), tenant, 21) >= 45


def test_peak_weekly_issuance_stays_under_the_rate_limit(tenant):
    """50 gateways issued on the same day, simulated over two years.

    Let's Encrypt allows 50 certificates per registered domain per week, and
    every tenant shares managedcollab.com.
    """
    validity = 90
    expiry = {f: validity for f in FLEET}
    per_week: Counter = Counter()

    for day in range(730):
        for fqdn in FLEET:
            if expiry[fqdn] - day <= renewal_threshold(_device(fqdn), tenant, 21):
                expiry[fqdn] = day + validity
                per_week[day // 7] += 1

    peak = max(per_week.values())
    assert peak < 25, f"peak week issued {peak} certificates"


def test_scheduler_is_configured_daily_and_non_overlapping():
    scheduler = build_scheduler(
        Settings(master_key="", schedule_time="02:00", renewal_spread_days=21)
    )
    job = scheduler.get_job("renewal-cycle")

    assert job is not None
    assert job.max_instances == 1  # a slow run must not overlap the next
    assert job.coalesce is True    # a missed run fires once, not once per miss
    assert "hour='2'" in str(job.trigger)


def test_schedule_time_is_configurable():
    scheduler = build_scheduler(Settings(master_key="", schedule_time="23:30"))
    trigger = str(scheduler.get_job("renewal-cycle").trigger)
    assert "hour='23'" in trigger
    assert "minute='30'" in trigger
