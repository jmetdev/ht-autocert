"""Certificate provider interface.

ACME covers Let's Encrypt and ZeroSSL, which is the whole requirement today.
The protocol exists so a non-ACME CA (DigiCert CertCentral, an internal ADCS)
can be added later without touching the orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class IssuedCertificate:
    """Result of an issuance. ``private_key_pem`` is escrowed by the caller."""

    fqdn: str
    private_key_pem: bytes
    fullchain_pem: str
    chain_issuer_cn: str
    alternate_chain_issuers: list[str]


class CertProvider(Protocol):
    def issue(self, fqdn: str, key_type: str) -> IssuedCertificate:
        """Obtain a certificate for ``fqdn``, generating and returning the key."""
