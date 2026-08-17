"""RESTCONF reader for certificate and SIP trustpoint state.

``Cisco-IOS-XE-crypto-pki-oper`` gives structured certificate state without
screen-scraping ``show`` output. CSR/PKCS12 import operations are not exposed by
the IOS-XE native YANG
models, so deployment retains a narrowly scoped SSH compatibility path. Normal
inventory and verification reads use the structured API.

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
SIP_UA_PATH = "/restconf/data/Cisco-IOS-XE-native:native/sip-ua/crypto/signaling"


def _is_webui_html(response: httpx.Response) -> bool:
    """True when HTTPS is Cisco WebUI, not RESTCONF.

    RESTCONF 404s are ``application/yang-data+json`` with ietf-restconf:errors.
    An HTML 404 from openresty means the ``restconf`` feature is not enabled.
    """
    ctype = (response.headers.get("content-type") or "").lower()
    if "html" in ctype:
        return True
    server = (response.headers.get("server") or "").lower()
    if "openresty" in server or "cisco" in server:
        return True
    body = response.text.lstrip()[:32].lower()
    return body.startswith("<!doctype") or body.startswith("<html")


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
            if _is_webui_html(response):
                server = response.headers.get("server") or "http"
                raise DeviceError(
                    f"{self.host}: RESTCONF is not enabled ({server} returned "
                    "HTML 404 for /restconf). Enable it with: restconf"
                )
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

        bound = self._read_bound_trustpoint()
        log.debug(
            "device.restconf_state", host=self.host,
            trustpoints=sorted(trustpoints), bound=bound,
        )
        return DeviceState(trustpoints=trustpoints, bound_trustpoint=bound)

    def _read_bound_trustpoint(self) -> str | None:
        """Read ``sip-ua crypto signaling`` from the native configuration API."""
        try:
            response = self._client.get(SIP_UA_PATH)
        except httpx.HTTPError as exc:
            raise DeviceError(f"{self.host}: RESTCONF request failed: {exc}") from exc
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise DeviceError(
                f"{self.host}: RESTCONF returned HTTP {response.status_code} "
                "while reading the SIP trustpoint binding"
            )
        payload = response.json()
        signaling = payload.get("Cisco-IOS-XE-native:signaling", payload.get("signaling", payload))

        def find_trustpoint(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.split(":")[-1] == "trustpoint" and isinstance(child, str):
                        return child
                    found = find_trustpoint(child)
                    if found:
                        return found
            elif isinstance(value, list):
                for child in value:
                    found = find_trustpoint(child)
                    if found:
                        return found
            return None

        return find_trustpoint(signaling)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "RestconfReader":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
