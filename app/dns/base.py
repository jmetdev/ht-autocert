"""DNS-01 solver interface.

Cloudflare is the only implementation today, but the protocol keeps a second
provider (Route 53, Azure DNS) from requiring changes to the ACME code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class TxtRecord:
    name: str
    value: str
    record_id: str


class DnsSolver(Protocol):
    def create_txt(self, name: str, value: str) -> TxtRecord:
        """Create a TXT record and return a handle for later cleanup."""

    def delete_txt(self, record: TxtRecord) -> None:
        """Remove a previously created TXT record. Must not raise on 404."""

    def authoritative_nameservers(self) -> list[str]:
        """Nameserver hostnames to poll when confirming propagation."""
