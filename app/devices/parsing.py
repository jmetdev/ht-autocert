"""Parsers for IOS-XE ``show`` output.

Used when RESTCONF is unavailable, and as the cross-check when it is. Kept
separate from the transport so it can be tested against captured output
without a device.
"""

import re
from datetime import datetime, timezone

from app.devices.base import DeviceState, TrustpointState

# "Certificate Serial Number (hex): 03A1B2C3"
_SERIAL_RE = re.compile(r"Certificate Serial Number.*?:\s*([0-9A-Fa-f]+)")
# "  end   date: 12:00:00 UTC Oct 30 2026"  (variable internal spacing)
_END_DATE_RE = re.compile(r"end\s+date:\s*(.+?)\s*$", re.MULTILINE)
_START_DATE_RE = re.compile(r"start\s+date:\s*(.+?)\s*$", re.MULTILINE)
_TRUSTPOINTS_RE = re.compile(r"Associated Trustpoints:\s*(.+?)\s*$", re.MULTILINE)
_STATUS_RE = re.compile(r"Status:\s*(\S+)")
# "crypto signaling default trustpoint HT-WxCAutoCert"
_SIGNALING_RE = re.compile(
    r"crypto\s+signaling\s+(?:default|remote-addr\s+\S+\s+\S+)\s+trustpoint\s+(\S+)"
)
_TRUSTPOINT_DEF_RE = re.compile(r"^\s*crypto pki trustpoint\s+(\S+)", re.MULTILINE)


def parse_ios_date(value: str) -> datetime | None:
    """Parse ``12:00:00 UTC Oct 30 2026``.

    The timezone token is dropped and the result treated as UTC -- ``%Z`` is
    unreliable across platforms, and IOS-XE reports UTC here.
    """
    value = value.strip()
    # Drop an alphabetic timezone token wherever it appears.
    cleaned = re.sub(r"\b(UTC|GMT)\b", "", value).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    for fmt in ("%H:%M:%S %b %d %Y", "%H:%M:%S %b %Y", "%b %d %Y %H:%M:%S"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _split_trustpoint_labels(value: str) -> list[str]:
    """Split an ``Associated Trustpoints:`` value into trustpoint names.

    IOS-XE separates multiple trustpoints with commas *or* whitespace, and
    appends a bare ``Trustpool`` marker for trustpool-sourced certificates.
    Splitting on commas alone yields names like
    ``"CISCO_IDEVID_SUDI Trustpool"``. Trustpoint names cannot contain spaces,
    so splitting on both is safe.
    """
    labels: list[str] = []
    for chunk in value.replace(",", " ").split():
        label = chunk.strip()
        # Not a trustpoint; a marker meaning the cert came from the trustpool.
        if not label or label.lower() == "trustpool":
            continue
        if label not in labels:
            labels.append(label)
    return labels


def _split_certificate_blocks(output: str) -> list[str]:
    """Split ``show crypto pki certificates`` into per-certificate blocks."""
    blocks: list[str] = []
    current: list[str] = []
    header = re.compile(r"^(CA )?Certificate\b", re.IGNORECASE)

    for line in output.splitlines():
        if header.match(line.strip()) and not line.startswith(" "):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def parse_certificates(output: str) -> dict[str, TrustpointState]:
    """Build trustpoint state from ``show crypto pki certificates``.

    Only end-entity certificates are recorded; a trustpoint's CA certificate
    carries the issuer's subject, which would otherwise be mistaken for the
    gateway's identity.
    """
    states: dict[str, TrustpointState] = {}

    for block in _split_certificate_blocks(output):
        tp_match = _TRUSTPOINTS_RE.search(block)
        if not tp_match:
            continue
        is_ca = block.strip().lower().startswith("ca certificate")

        for label in _split_trustpoint_labels(tp_match.group(1)):
            state = states.setdefault(label, TrustpointState(label=label))

            if is_ca:
                # Record the CA's subject separately -- it is not this
                # trustpoint's identity, and treating it as one makes a
                # trustpoint look like it was issued to its own issuer.
                state.ca_subject_cn = _extract_subject_cn(block) or state.ca_subject_cn
                continue

            status = _STATUS_RE.search(block)
            serial = _SERIAL_RE.search(block)
            end = _END_DATE_RE.search(block)
            start = _START_DATE_RE.search(block)

            state.subject_cn = _extract_subject_cn(block)
            state.serial = serial.group(1).upper() if serial else None
            state.validity_start = parse_ios_date(start.group(1)) if start else None
            state.validity_end = parse_ios_date(end.group(1)) if end else None
            state.has_certificate = bool(
                status and status.group(1).lower() == "available"
            )

    return states


def _extract_subject_cn(block: str) -> str | None:
    """Pull ``cn=`` out of the Subject stanza only, not the Issuer stanza."""
    lines = block.splitlines()
    in_subject = False
    for line in lines:
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("subject:"):
            in_subject = True
            continue
        if low.startswith(("issuer:", "validity date:", "associated trustpoints:")):
            in_subject = False
            continue
        if not in_subject:
            continue
        if low.startswith("name:"):
            return stripped.split(":", 1)[1].strip()
        match = re.match(r"cn\s*=\s*(.+)", stripped, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def parse_bound_trustpoint(output: str) -> str | None:
    """Extract the trustpoint bound under ``sip-ua``."""
    match = _SIGNALING_RE.search(output)
    return match.group(1) if match else None


def parse_configured_trustpoints(output: str) -> list[str]:
    """Trustpoint names present in running-config, certificate or not."""
    return _TRUSTPOINT_DEF_RE.findall(output)


def build_state(
    certificates_output: str,
    signaling_output: str,
    trustpoint_output: str = "",
) -> DeviceState:
    trustpoints = parse_certificates(certificates_output)
    for label in parse_configured_trustpoints(trustpoint_output):
        trustpoints.setdefault(label, TrustpointState(label=label))

    return DeviceState(
        trustpoints=trustpoints,
        bound_trustpoint=parse_bound_trustpoint(signaling_output),
        raw={
            "certificates": certificates_output,
            "signaling": signaling_output,
            "trustpoints": trustpoint_output,
        },
    )
