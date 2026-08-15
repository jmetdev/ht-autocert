"""Webex Control Hub discovery.

The payloads here mirror what the live API actually returned during discovery
against a partner org, not what the docs imply. Two of those facts are what the
production code is built around, so they are asserted directly: the trunk list
carries no address, and a registering trunk has no address anywhere.
"""

import httpx
import pytest

from app.webex_inventory import (
    TRUNK_CERTIFICATE_BASED,
    TRUNK_REGISTERING,
    WebexApiError,
    WebexInventory,
)

# Shapes taken from live responses.
REGISTERING_SUMMARY = {
    "id": "TRUNK-REG",
    "name": "Dual Reg - VG400",
    "location": {"id": "LOC1", "name": "Phoenix-CALL"},
    "inUse": True,
    "trunkType": TRUNK_REGISTERING,
    "isRestrictedToDedicatedInstance": False,
}
REGISTERING_DETAIL = {
    **REGISTERING_SUMMARY,
    "deviceType": "Cisco CUBE Local Gateway",
    "status": "unknown",
    "maxConcurrentCalls": 250,
    # No address / domain / port: Webex does not record them for this type.
    "outboundProxy": {
        "sipAccessServiceType": "Local Gateway",
        "outboundProxy": "da07.sipconnect-us.bcld.webex.com",
    },
}

CERT_SUMMARY = {
    "id": "TRUNK-CERT",
    "name": "HQ CUBE",
    "location": {"id": "LOC2", "name": "HQ"},
    "inUse": True,
    "trunkType": TRUNK_CERTIFICATE_BASED,
    "isRestrictedToDedicatedInstance": False,
}
CERT_DETAIL = {
    **CERT_SUMMARY,
    "deviceType": "Cisco Unified Border Element",
    "status": "online",
    "address": "VG01.Husd.Clients.ManagedCollab.com",
    "domain": "husd.clients.managedcollab.com",
    "port": 8934,
}


def _inventory(handler) -> WebexInventory:
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, base_url="https://webexapis.com/v1")
    return WebexInventory("token", client=client)


def _trunk_handler(summaries, details, *, expect_org=None, calls=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request.url)
        if expect_org is not None:
            assert request.url.params.get("orgId") == expect_org
        path = request.url.path
        if path.endswith("/trunks"):
            return httpx.Response(200, json={"trunks": summaries})
        trunk_id = path.rsplit("/", 1)[-1]
        if trunk_id in details:
            return httpx.Response(200, json=details[trunk_id])
        return httpx.Response(404, json={"message": "not found"})

    return handler


def test_certificate_based_trunk_yields_an_fqdn():
    inv = _inventory(_trunk_handler([CERT_SUMMARY], {"TRUNK-CERT": CERT_DETAIL}))
    (gateway,) = inv.trunks()

    assert gateway.certificate_based
    assert gateway.device_type == "Cisco Unified Border Element"
    assert gateway.port == 8934
    # Normalised to lower case: certificate names are compared case-insensitively
    # but stored as DNS labels.
    assert gateway.fqdn == "vg01.husd.clients.managedcollab.com"


def test_registering_trunk_has_no_fqdn():
    """The finding that shapes the importer: Webex records no address here."""
    inv = _inventory(_trunk_handler([REGISTERING_SUMMARY], {"TRUNK-REG": REGISTERING_DETAIL}))
    (gateway,) = inv.trunks()

    assert gateway.trunk_type == TRUNK_REGISTERING
    assert not gateway.certificate_based
    assert gateway.address is None
    assert gateway.fqdn is None
    # Still identifiable, which is what makes it worth importing at all.
    assert gateway.name == "Dual Reg - VG400"
    assert gateway.device_type == "Cisco CUBE Local Gateway"
    assert gateway.location == "Phoenix-CALL"


def test_detail_call_is_made_because_the_list_omits_addresses():
    calls: list = []
    inv = _inventory(
        _trunk_handler(
            [CERT_SUMMARY, REGISTERING_SUMMARY],
            {"TRUNK-CERT": CERT_DETAIL, "TRUNK-REG": REGISTERING_DETAIL},
            calls=calls,
        )
    )
    inv.trunks()

    # One list call plus one detail call per trunk.
    assert len(calls) == 3
    assert any(str(c).endswith("TRUNK-CERT") for c in calls)


def test_org_id_is_passed_to_every_call():
    """Each client is a separate org; an unscoped call reads the wrong tenant."""
    inv = _inventory(
        _trunk_handler(
            [CERT_SUMMARY], {"TRUNK-CERT": CERT_DETAIL}, expect_org="ORG-HUSD"
        )
    )
    assert inv.trunks("ORG-HUSD")


def test_a_broken_detail_call_does_not_hide_the_other_trunks():
    inv = _inventory(
        _trunk_handler(
            [CERT_SUMMARY, REGISTERING_SUMMARY],
            {"TRUNK-CERT": CERT_DETAIL},  # REG's detail 404s
        )
    )
    found = inv.trunks()

    assert [g.name for g in found] == ["HQ CUBE", "Dual Reg - VG400"]
    assert found[1].device_type is None  # degraded to the summary


def test_ip_address_is_not_treated_as_a_certificate_name():
    detail = {**CERT_DETAIL, "address": "10.42.0.9"}
    inv = _inventory(_trunk_handler([CERT_SUMMARY], {"TRUNK-CERT": detail}))
    (gateway,) = inv.trunks()

    assert gateway.address == "10.42.0.9"
    assert gateway.fqdn is None


def test_organizations_are_listed_for_the_selector():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "items": [
                    {"id": "ORG-B", "displayName": "Yuma Elementary"},
                    {"id": "ORG-A", "displayName": "Higley Unified"},
                ]
            },
        )

    orgs = _inventory(handler).organizations()
    assert [o.display_name for o in orgs] == ["Higley Unified", "Yuma Elementary"]


@pytest.mark.parametrize(
    "status,fragment",
    [
        (401, "Sign out and sign in again"),
        (403, "spark-admin:telephony_config_read"),
        (404, "not available for this organisation"),
        (500, "HTTP 500"),
    ],
)
def test_errors_explain_what_to_do(status, fragment):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"message": "nope"})

    with pytest.raises(WebexApiError) as exc:
        _inventory(handler).trunks()
    assert fragment in str(exc.value)
