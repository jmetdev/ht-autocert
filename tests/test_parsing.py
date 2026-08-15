"""Parsers for IOS-XE show output, against realistic captures."""

from datetime import timezone

from app.devices.parsing import (
    build_state,
    parse_bound_trustpoint,
    parse_certificates,
    parse_configured_trustpoints,
    parse_ios_date,
)

CERTIFICATES_OUTPUT = """
Certificate
  Status: Available
  Certificate Serial Number (hex): 03A1B2C3D4E5F60718293A4B5C6D7E8F
  Certificate Usage: General Purpose
  Issuer:
    cn=R11
    o=Let's Encrypt
    c=US
  Subject:
    Name: brg-vgw-01.husd.clients.managedcollab.com
    cn=brg-vgw-01.husd.clients.managedcollab.com
  Validity Date:
    start date: 12:00:00 UTC Aug 1 2026
    end   date: 12:00:00 UTC Oct 30 2026
  Associated Trustpoints: HT-WxCAutoCert-A

CA Certificate
  Status: Available
  Certificate Serial Number (hex): 00FF11
  Certificate Usage: Signature
  Issuer:
    cn=ISRG Root X1
    o=Internet Security Research Group
  Subject:
    cn=R11
    o=Let's Encrypt
  Validity Date:
    start date: 00:00:00 UTC Mar 13 2024
    end   date: 00:00:00 UTC Mar 12 2027
  Associated Trustpoints: HT-WxCAutoCert-A
"""

SIGNALING_OUTPUT = " crypto signaling default trustpoint HT-WxCAutoCert-A\n"

TRUSTPOINT_OUTPUT = """crypto pki trustpoint HT-WxCAutoCert-A
crypto pki trustpoint HT-WxCAutoCert-B
crypto pki trustpoint SLA-TrustPoint
"""


def test_parses_identity_certificate():
    states = parse_certificates(CERTIFICATES_OUTPUT)
    tp = states["HT-WxCAutoCert-A"]

    assert tp.has_certificate is True
    assert tp.subject_cn == "brg-vgw-01.husd.clients.managedcollab.com"
    assert tp.serial == "03A1B2C3D4E5F60718293A4B5C6D7E8F"
    assert tp.validity_end.year == 2026
    assert tp.validity_end.month == 10
    assert tp.validity_end.day == 30
    assert tp.validity_end.tzinfo == timezone.utc


def test_ca_certificate_does_not_overwrite_identity():
    """The CA cert in the same trustpoint has the issuer's subject; using it
    would make the device look like it holds the wrong certificate."""
    states = parse_certificates(CERTIFICATES_OUTPUT)
    assert states["HT-WxCAutoCert-A"].subject_cn != "R11"


def test_subject_cn_is_not_taken_from_issuer():
    states = parse_certificates(CERTIFICATES_OUTPUT)
    assert states["HT-WxCAutoCert-A"].subject_cn.startswith("brg-vgw-01")


def test_serial_matching_is_case_and_padding_insensitive():
    tp = parse_certificates(CERTIFICATES_OUTPUT)["HT-WxCAutoCert-A"]
    cn = "brg-vgw-01.husd.clients.managedcollab.com"

    assert tp.matches(cn, "03a1b2c3d4e5f60718293a4b5c6d7e8f") is True
    assert tp.matches(cn, "3A1B2C3D4E5F60718293A4B5C6D7E8F") is True
    assert tp.matches(cn, "DEADBEEF") is False
    assert tp.matches("other.example.com", "03A1B2C3D4E5F60718293A4B5C6D7E8F") is False


def test_trustpoint_without_certificate_does_not_match():
    from app.devices.base import TrustpointState

    tp = TrustpointState(label="HT-WxCAutoCert-B")
    assert tp.matches("anything", "AA") is False


def test_parses_bound_trustpoint():
    assert parse_bound_trustpoint(SIGNALING_OUTPUT) == "HT-WxCAutoCert-A"


def test_no_binding_returns_none():
    assert parse_bound_trustpoint("") is None
    assert parse_bound_trustpoint(" sip-ua\n transport tcp tls v1.2\n") is None


def test_parses_configured_trustpoints():
    assert parse_configured_trustpoints(TRUSTPOINT_OUTPUT) == [
        "HT-WxCAutoCert-A",
        "HT-WxCAutoCert-B",
        "SLA-TrustPoint",
    ]


def test_build_state_includes_empty_trustpoints():
    """The idle trustpoint usually has no certificate yet; it must still be
    visible so the deployer knows whether to clear it first."""
    state = build_state(CERTIFICATES_OUTPUT, SIGNALING_OUTPUT, TRUSTPOINT_OUTPUT)

    assert state.bound_trustpoint == "HT-WxCAutoCert-A"
    assert set(state.trustpoints) == {
        "HT-WxCAutoCert-A",
        "HT-WxCAutoCert-B",
        "SLA-TrustPoint",
    }
    assert state.get("HT-WxCAutoCert-B").has_certificate is False


def test_parses_ios_dates():
    parsed = parse_ios_date("12:00:00 UTC Oct 30 2026")
    assert (parsed.year, parsed.month, parsed.day) == (2026, 10, 30)
    assert parse_ios_date("00:00:00 GMT Mar 12 2027").month == 3
    assert parse_ios_date("nonsense") is None


def test_empty_output_is_handled():
    state = build_state("", "", "")
    assert state.trustpoints == {}
    assert state.bound_trustpoint is None


# -- trustpoint label splitting ----------------------------------------------

REAL_DEVICE_TRUSTPOINT_LINES = """
Certificate
  Status: Available
  Certificate Serial Number (hex): 04770159361449080E61
  Subject:
    cn=C8200L-1N-4T
  Validity Date:
    end   date: 12:00:00 UTC Aug 9 2099
  Associated Trustpoints: CISCO_IDEVID_SUDI Trustpool

CA Certificate
  Status: Available
  Certificate Serial Number (hex): 01
  Subject:
    cn=Some Root
  Validity Date:
    end   date: 12:00:00 UTC Jan 1 2030
  Associated Trustpoints: Trustpool SLA-TrustPoint
"""


def test_trustpool_marker_is_not_treated_as_a_trustpoint():
    """A C8200L reports 'Associated Trustpoints: CISCO_IDEVID_SUDI Trustpool'.

    Splitting on commas alone produced a trustpoint literally named
    "CISCO_IDEVID_SUDI Trustpool".
    """
    states = parse_certificates(REAL_DEVICE_TRUSTPOINT_LINES)

    assert "CISCO_IDEVID_SUDI" in states
    assert "SLA-TrustPoint" in states
    assert not any("Trustpool" in label for label in states)


def test_labels_split_on_commas_and_whitespace():
    from app.devices.parsing import _split_trustpoint_labels

    assert _split_trustpoint_labels("A, B") == ["A", "B"]
    assert _split_trustpoint_labels("A B") == ["A", "B"]
    assert _split_trustpoint_labels("A, B C") == ["A", "B", "C"]
    assert _split_trustpoint_labels("  ") == []


def test_duplicate_labels_are_collapsed():
    from app.devices.parsing import _split_trustpoint_labels

    assert _split_trustpoint_labels("A A, A") == ["A"]


def test_real_gateway_trustpoint_still_parses():
    """The one that matters must survive the stricter splitting."""
    states = parse_certificates(CERTIFICATES_OUTPUT)
    tp = states["HT-WxCAutoCert-A"]
    assert tp.subject_cn == "brg-vgw-01.husd.clients.managedcollab.com"
    assert tp.has_certificate is True


# -- CA vs identity certificates ---------------------------------------------

CHAIN_OUTPUT = """
Certificate
  Status: Available
  Certificate Serial Number (hex): 05EAF798D5FD61E25D88FB6B61675724E8EF
  Subject:
    Name: brg-vgw-01.husd.clients.managedcollab.com
    cn=brg-vgw-01.husd.clients.managedcollab.com
  Issuer:
    cn=YR1
  Validity Date:
    end   date: 18:13:46 UTC Nov 12 2026
  Associated Trustpoints: HT-WxCAutoCert-A

CA Certificate
  Status: Available
  Certificate Serial Number (hex): 00AA
  Subject:
    cn=YR1
  Issuer:
    cn=Root YR
  Validity Date:
    end   date: 00:00:00 UTC Mar 12 2027
  Associated Trustpoints: HT-WxCAutoCert-A

CA Certificate
  Status: Available
  Certificate Serial Number (hex): 00BB
  Subject:
    cn=Root YR
  Issuer:
    cn=ISRG Root X1
  Validity Date:
    end   date: 00:00:00 UTC Sep 2 2028
  Associated Trustpoints: HT-WxCAutoCert-A-rrr1
"""


def test_identity_and_ca_certs_are_kept_separate():
    """The identity trustpoint holds both; the CA subject must not overwrite it."""
    states = parse_certificates(CHAIN_OUTPUT)
    tp = states["HT-WxCAutoCert-A"]

    assert tp.has_certificate is True
    assert tp.subject_cn == "brg-vgw-01.husd.clients.managedcollab.com"
    assert tp.ca_subject_cn == "YR1"


def test_derived_trustpoint_reports_its_ca_not_no_certificate():
    """`-rrrN` holds a CA cert. Reporting '(no certificate)' is simply wrong."""
    tp = parse_certificates(CHAIN_OUTPUT)["HT-WxCAutoCert-A-rrr1"]

    assert tp.has_certificate is False
    assert tp.ca_subject_cn == "Root YR"
    assert tp.describe() == "CA certificate: Root YR"


def test_describe_covers_all_three_states():
    from app.devices.base import TrustpointState

    identity = TrustpointState(
        label="A", subject_cn="vg01.example.com", serial="AA", has_certificate=True
    )
    ca_only = TrustpointState(label="A-rrr1", ca_subject_cn="Root YR")
    empty = TrustpointState(label="B")

    assert identity.describe() == "cn=vg01.example.com serial=AA"
    assert ca_only.describe() == "CA certificate: Root YR"
    assert empty.describe() == "(no certificate)"


def test_ca_only_trustpoint_never_matches_an_identity():
    """Guards the deployment verification: a CA cert is not proof of import."""
    tp = parse_certificates(CHAIN_OUTPUT)["HT-WxCAutoCert-A-rrr1"]
    assert tp.matches("Root YR", "00BB") is False
