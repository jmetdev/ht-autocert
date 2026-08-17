"""Certificate FQDN is ACME-only; management IP is a separate field."""

from app.devices.base import (
    is_ip_address,
    management_host,
    mgmt_from_discovery,
    require_management_host,
    DeviceError,
)


def test_cert_fqdn_is_not_a_management_host():
    fqdn = "brg-vgw.husd.clients.managedcollab.com"
    assert management_host(fqdn, fqdn) is None
    assert management_host("", fqdn) is None
    assert management_host("10.40.8.10", fqdn) == "10.40.8.10"


def test_webex_sip_hostname_is_not_copied_as_mgmt():
    fqdn = "hq.husd.clients.example.com"
    assert mgmt_from_discovery(fqdn, fqdn) == ""
    assert mgmt_from_discovery("10.1.2.3", fqdn) == "10.1.2.3"
    assert mgmt_from_discovery(None, fqdn) == ""


def test_require_management_host_explains_the_acme_trap():
    fqdn = "vg01.example.com"
    try:
        require_management_host(fqdn, fqdn)
        raise AssertionError("expected DeviceError")
    except DeviceError as exc:
        assert "no management IP" in str(exc)
        assert "set-address" in str(exc)


def test_ipv6_is_accepted():
    assert is_ip_address("2001:db8::1")
    assert management_host("2001:db8::1", "vg01.example.com") == "2001:db8::1"
