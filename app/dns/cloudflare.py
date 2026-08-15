"""Cloudflare DNS-01 solver.

All tenants live under one zone (``managedcollab.com``), so a single
Zone:DNS:Edit token covers the whole fleet and the zone id is resolved once
per process.
"""

from __future__ import annotations

import httpx
import structlog

from app.dns.base import TxtRecord

log = structlog.get_logger(__name__)

API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareError(RuntimeError):
    pass


class CloudflareSolver:
    def __init__(
        self,
        api_token: str,
        zone: str,
        *,
        ttl: int = 60,
        client: httpx.Client | None = None,
    ):
        self._zone = zone
        self._ttl = ttl
        self._zone_id: str | None = None
        self._nameservers: list[str] | None = None
        self._client = client or httpx.Client(
            base_url=API_BASE,
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    # -- internals ---------------------------------------------------------

    def _request(self, method: str, url: str, **kwargs) -> dict:
        resp = self._client.request(method, url, **kwargs)
        try:
            payload = resp.json()
        except ValueError:
            raise CloudflareError(
                f"{method} {url} returned non-JSON (HTTP {resp.status_code})"
            ) from None

        if not payload.get("success", False):
            errors = payload.get("errors") or [{"message": resp.text}]
            detail = "; ".join(
                f"{e.get('code', '?')}: {e.get('message', '')}" for e in errors
            )
            raise CloudflareError(f"{method} {url} failed -- {detail}")
        return payload

    def _resolve_zone(self) -> tuple[str, list[str]]:
        if self._zone_id is None:
            payload = self._request("GET", "/zones", params={"name": self._zone})
            results = payload.get("result") or []
            if not results:
                raise CloudflareError(
                    f"zone {self._zone!r} not visible to this API token -- check "
                    "the token has Zone:DNS:Edit on it"
                )
            self._zone_id = results[0]["id"]
            self._nameservers = results[0].get("name_servers") or []
            log.debug("cloudflare.zone_resolved", zone=self._zone, id=self._zone_id)
        return self._zone_id, (self._nameservers or [])

    # -- DnsSolver ---------------------------------------------------------

    def create_txt(self, name: str, value: str) -> TxtRecord:
        zone_id, _ = self._resolve_zone()
        if not name.endswith(self._zone):
            raise CloudflareError(
                f"refusing to create {name!r}: outside managed zone {self._zone!r}"
            )
        payload = self._request(
            "POST",
            f"/zones/{zone_id}/dns_records",
            json={
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": self._ttl,
                "comment": "ht-autocert ACME DNS-01 (transient)",
            },
        )
        record_id = payload["result"]["id"]
        log.info("dns.txt_created", name=name, record_id=record_id)
        return TxtRecord(name=name, value=value, record_id=record_id)

    def delete_txt(self, record: TxtRecord) -> None:
        zone_id, _ = self._resolve_zone()
        try:
            self._request("DELETE", f"/zones/{zone_id}/dns_records/{record.record_id}")
            log.info("dns.txt_deleted", name=record.name, record_id=record.record_id)
        except CloudflareError as exc:
            # Cleanup runs in a finally block; a already-gone record must not
            # mask the original failure.
            log.warning("dns.txt_delete_failed", name=record.name, error=str(exc))

    def authoritative_nameservers(self) -> list[str]:
        _, nameservers = self._resolve_zone()
        return nameservers

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "CloudflareSolver":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
