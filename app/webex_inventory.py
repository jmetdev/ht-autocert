"""Read gateway inventory from Webex Control Hub.

In Webex's data model there is no "gateway" resource. A Local Gateway is the
premises end of a **trunk**, so ``/telephony/config/premisePstn/trunks`` is the
only place an enrolled gateway appears. (Confirmed against the wxc-sdk: every
method mentioning a local gateway lives under ``telephony.prem_pstn.trunk``.
``/devices`` holds phones and room endpoints, not gateways.)

Two properties of that API shape the code here:

* **The list response has no addresses.** ``GET .../trunks`` returns only id,
  name, location, inUse and trunkType. ``address``/``domain``/``port`` exist
  only on the per-trunk detail call, so discovery is list-then-fan-out.
* **Only certificate-based trunks carry an FQDN.** A ``REGISTERING`` trunk
  authenticates with a SIP username and password and has no address recorded in
  Webex at all. For those, Control Hub can tell us a gateway *exists* and what
  it is called, but not the name its certificate must carry -- that is derived
  from the tenant's domain suffix and confirmed by an operator.

Each client is a separate Webex organisation, so every call is org-scoped. A
token with partner rights sees the customer orgs it manages via
:meth:`WebexInventory.organizations`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import structlog

log = structlog.get_logger(__name__)

WEBEX_API = "https://webexapis.com/v1"
TRUNKS_PATH = "/telephony/config/premisePstn/trunks"
ORGS_PATH = "/organizations"

#: Scopes the calls in this module need.
SCOPE_TRUNKS = "spark-admin:telephony_config_read"
SCOPE_ORGS = "spark-admin:organizations_read"

#: Trunk types, as returned by Webex.
TRUNK_REGISTERING = "REGISTERING"
TRUNK_CERTIFICATE_BASED = "CERTIFICATE_BASED"


class WebexApiError(RuntimeError):
    """A Control Hub call failed. The message is shown to the operator."""


@dataclass
class WebexOrg:
    org_id: str
    display_name: str


@dataclass
class DiscoveredGateway:
    """One trunk's premises end, normalised."""

    name: str
    trunk_id: str
    trunk_type: str
    org_id: str | None = None
    device_type: str | None = None
    location: str | None = None
    status: str | None = None
    in_use: bool = False

    # Populated by Webex only for certificate-based trunks.
    address: str | None = None
    domain: str | None = None
    port: int | None = None

    raw: dict = field(default_factory=dict)

    @property
    def certificate_based(self) -> bool:
        return self.trunk_type == TRUNK_CERTIFICATE_BASED

    @property
    def fqdn(self) -> str | None:
        """The name Webex expects on this gateway's certificate, if it knows one.

        Webex stores the SBC address and the domain separately. The address is
        the hostname peers connect to, so that is what the certificate must
        match; a bare IP is not a certificate name and is rejected here.
        """
        address = (self.address or "").strip()
        if not address or "." not in address:
            return None
        if address.replace(".", "").isdigit():  # dotted-quad, not a hostname
            return None
        return address.lower()


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _trunk_summary(item: dict, org_id: str | None) -> DiscoveredGateway | None:
    name = (item.get("name") or "").strip()
    trunk_id = item.get("id")
    if not name or not trunk_id:
        return None
    return DiscoveredGateway(
        name=name,
        trunk_id=trunk_id,
        trunk_type=item.get("trunkType") or "",
        org_id=org_id,
        location=_as_dict(item.get("location")).get("name"),
        in_use=bool(item.get("inUse")),
        raw=item,
    )


class WebexInventory:
    def __init__(self, access_token: str, *, client: httpx.Client | None = None):
        self._client = client or httpx.Client(
            base_url=WEBEX_API,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )

    # -- plumbing ------------------------------------------------------------

    def _get(self, path: str, *, scope: str, **params) -> dict:
        params = {k: v for k, v in params.items() if v is not None}
        try:
            response = self._client.get(path, params=params)
        except httpx.HTTPError as exc:
            raise WebexApiError(f"Could not reach Webex: {exc}") from exc

        if response.status_code == 200:
            try:
                return response.json()
            except ValueError as exc:
                raise WebexApiError(
                    f"{path} returned a non-JSON response"
                ) from exc

        # Turn Webex's error envelope into something an operator can act on.
        try:
            message = response.json().get("message") or ""
        except ValueError:
            message = response.text[:200]

        if response.status_code == 401:
            raise WebexApiError(
                "Webex rejected your token. Sign out and sign in again."
            )
        if response.status_code == 403:
            raise WebexApiError(
                f"Your Webex token lacks the {scope} scope, or your admin "
                f"rights do not cover this organisation. ({message})"
            )
        if response.status_code == 404:
            raise WebexApiError(
                f"{path} is not available for this organisation. ({message})"
            )
        raise WebexApiError(f"Webex returned HTTP {response.status_code}: {message}")

    # -- reads ---------------------------------------------------------------

    def organizations(self) -> list[WebexOrg]:
        """Organisations this token can administer, own org first."""
        body = self._get(ORGS_PATH, scope=SCOPE_ORGS)
        orgs = [
            WebexOrg(org_id=item["id"], display_name=item.get("displayName") or item["id"])
            for item in body.get("items", [])
            if item.get("id")
        ]
        orgs.sort(key=lambda o: o.display_name.lower())
        return orgs

    def trunks(self, org_id: str | None = None) -> list[DiscoveredGateway]:
        """Every trunk in the organisation, each enriched with its detail call.

        The list endpoint omits address, domain and device type, so one detail
        call per trunk is unavoidable. A detail call that fails degrades to the
        summary rather than failing the whole discovery -- a single trunk in a
        bad state should not hide the other 49.
        """
        body = self._get(TRUNKS_PATH, scope=SCOPE_TRUNKS, orgId=org_id, max=1000)
        items = body.get("trunks") or body.get("items") or []

        found: list[DiscoveredGateway] = []
        for item in items:
            gateway = _trunk_summary(item, org_id)
            if gateway is None:
                continue
            try:
                self._enrich(gateway, org_id)
            except WebexApiError as exc:
                log.warning(
                    "webex.trunk_detail_failed",
                    trunk=gateway.name,
                    error=str(exc),
                )
            found.append(gateway)
        return found

    def _enrich(self, gateway: DiscoveredGateway, org_id: str | None) -> None:
        detail = self._get(
            f"{TRUNKS_PATH}/{gateway.trunk_id}", scope=SCOPE_TRUNKS, orgId=org_id
        )
        gateway.device_type = detail.get("deviceType")
        gateway.status = detail.get("status")
        gateway.address = detail.get("address")
        gateway.domain = detail.get("domain")
        gateway.port = detail.get("port")
        gateway.trunk_type = detail.get("trunkType") or gateway.trunk_type
        location = _as_dict(detail.get("location")).get("name")
        if location:
            gateway.location = location
        gateway.raw = detail

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "WebexInventory":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
