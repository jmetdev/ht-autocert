"""RESTCONF reader for certificate state.

``Cisco-IOS-XE-crypto-pki-oper`` gives structured certificate state, which beats
screen-scraping ``show`` output when the device has RESTCONF enabled. It is
read-only here: PKI enrollment and import are exec-level operations with no
clean YANG RPC, so those stay on the SSH transport.

Requires ``restconf`` and ``ip http secure-server`` on the device.
"""

from datetime import datetime, timezone

import httpx
import structlog

from app.devices.base import DeviceError, DeviceState, TrustpointState

log = structlog.get_logger(__name__)

OPER_PATH = (
    "/restconf/data/Cisco-IOS-XE-crypto-pki-oper:crypto-pki-oper-data/crypto-pki-bundle"
)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _subject_cn(subject_name: str | None) -> str | None:
    """Pull CN out of an RFC4514-ish or ``cn=x`` subject string."""
    if not subject_name:
        return None
    for part in subject_name.replace("/", ",").split(","):
        part = part.strip()
        if part.lower().startswith("cn="):
            return part[3:].strip()
    return subject_name.strip() or None


class RestconfReader:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 443,
        verify: bool | str = False,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ):
        self.host = host
        self._client = client or httpx.Client(
            base_url=f"https://{host}:{port}",
            auth=(username, password),
            headers={"Accept": "application/yang-data+json"},
            # Gateways typically present the very certificate this tool
            # manages, so verification is opt-in per device.
            verify=verify,
            timeout=timeout,
        )

    def read_state(self) -> DeviceState:
        try:
            response = self._client.get(OPER_PATH)
        except httpx.HTTPError as exc:
            raise DeviceError(f"{self.host}: RESTCONF request failed: {exc}") from exc

        if response.status_code == 404:
            # Model not present on this train; caller should fall back to CLI.
            raise DeviceError(
                f"{self.host}: crypto-pki-oper model not available (HTTP 404)"
            )
        if response.status_code >= 400:
            raise DeviceError(
                f"{self.host}: RESTCONF returned HTTP {response.status_code}"
            )

        payload = response.json()
        bundles = payload.get(
            "Cisco-IOS-XE-crypto-pki-oper:crypto-pki-bundle", []
        ) or payload.get("crypto-pki-bundle", [])
        if isinstance(bundles, dict):
            bundles = [bundles]

        trustpoints: dict[str, TrustpointState] = {}
        for bundle in bundles:
            label = bundle.get("label")
            if not label:
                continue
            certs = bundle.get("cert", [])
            if isinstance(certs, dict):
                certs = [certs]

            state = TrustpointState(label=label)
            for cert in certs:
                cn = _subject_cn(cert.get("subject-name"))
                # Skip the CA certificate in the bundle; we want the identity.
                if cn and cn == label:
                    continue
                state = TrustpointState(
                    label=label,
                    subject_cn=cn,
                    serial=(cert.get("serial-number") or "").upper() or None,
                    validity_start=_parse_timestamp(cert.get("validity-start")),
                    validity_end=_parse_timestamp(cert.get("validity-end")),
                    has_certificate=True,
                )
                break
            trustpoints[label] = state

        log.debug("device.restconf_state", host=self.host, trustpoints=sorted(trustpoints))
        # sip-ua binding is config, not oper data; the caller merges it in.
        return DeviceState(trustpoints=trustpoints, bound_trustpoint=None)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "RestconfReader":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
