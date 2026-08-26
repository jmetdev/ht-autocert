"""Well-known trust anchors appended when ACME omits the root.

Let's Encrypt's default Generation Y chain is::

    EE ← YR1/YR2 ← Root YR (cross-signed by ISRG Root X1)

The ACME download includes the YR cross-sign (issuer CN ``ISRG Root X1``) but
not X1 itself — browsers already have that root. Cisco ``crypto pki import``
of a PKCS12 does not: without the X1 *certificate* in the CA bag the gateway
has YR and nothing it trusts, which is what ``--preferred-chain "ISRG Root X1"``
is trying to avoid.

Appending the matching self-signed root (matched on the last cert's issuer CN)
completes the bag without changing which chain ACME selected.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

log = structlog.get_logger(__name__)

_PEM_FILES = ("isrgrootx1.pem", "isrg-root-x2.pem")


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if attrs:
        return str(attrs[0].value)
    return name.rfc4514_string()


@lru_cache(maxsize=1)
def bundled_roots() -> dict[str, x509.Certificate]:
    """Subject CN → self-signed root, loaded from ``app/ca/certs``."""
    out: dict[str, x509.Certificate] = {}
    certs_dir = files("app.ca").joinpath("certs")
    for name in _PEM_FILES:
        pem = certs_dir.joinpath(name).read_bytes()
        cert = x509.load_pem_x509_certificate(pem)
        out[_cn(cert.subject)] = cert
    return out


def complete_chain(fullchain_pem: str) -> str:
    """Append a bundled root if the chain chains up to it but omits the cert."""
    if not (fullchain_pem or "").strip():
        return fullchain_pem
    try:
        certs = list(x509.load_pem_x509_certificates(fullchain_pem.encode()))
    except ValueError:
        return fullchain_pem
    if not certs:
        return fullchain_pem

    roots = bundled_roots()
    seen = {cert.fingerprint(hashes.SHA256()) for cert in certs}
    appended: list[str] = []

    while True:
        top = certs[-1]
        issuer_cn = _cn(top.issuer)
        if issuer_cn == _cn(top.subject):
            break
        root = roots.get(issuer_cn)
        if root is None:
            break
        fingerprint = root.fingerprint(hashes.SHA256())
        if fingerprint in seen:
            break
        certs.append(root)
        seen.add(fingerprint)
        appended.append(issuer_cn)

    if appended:
        log.info("acme.trust_anchor_appended", roots=appended)
        return "".join(
            cert.public_bytes(serialization.Encoding.PEM).decode() for cert in certs
        )
    return fullchain_pem
