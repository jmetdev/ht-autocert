"""Confirm a TXT record is visible before asking the CA to validate.

The Ansible version slept a fixed ``--dns-cloudflare-propagation-seconds 25``
and hoped. That is simultaneously too slow on a good day and too short on a bad
one. Here we query the zone's own authoritative nameservers until every one of
them returns the expected value, which is both faster in the common case and
actually correct in the slow case.
"""

from __future__ import annotations

import time

import dns.exception
import dns.rdatatype
import dns.resolver
import structlog

log = structlog.get_logger(__name__)


class PropagationTimeout(RuntimeError):
    pass


def _candidate_addresses(nameserver: str) -> list[str]:
    """All A/AAAA addresses for one authoritative nameserver hostname."""
    addresses: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = dns.resolver.resolve(nameserver, rdtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            continue
        addresses.extend(r.address for r in answer)
    return addresses


def _is_reachable(address: str, zone_hint: str, timeout: float) -> bool:
    """Cheap liveness probe so unreachable addresses are excluded up front."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [address]
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        resolver.resolve(zone_hint, dns.rdatatype.SOA)
        return True
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError):
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # It answered, which is all we are testing for.
        return True


def _resolve_ns_addresses(
    nameservers: list[str], zone_hint: str = ".", probe_timeout: float = 3.0
) -> list[str]:
    """One *reachable* address per authoritative nameserver.

    Two things this deliberately avoids:

    * **Unreachable address families.** A host with no IPv6 route still gets
      AAAA records back for Cloudflare's nameservers. Including those makes the
      "all servers agree" check unsatisfiable, so propagation never completes
      and the run appears to hang until the timeout.
    * **Anycast duplicates.** Each nameserver hostname resolves to several
      addresses fronting the same zone data; querying one is sufficient and
      keeps a poll round fast.
    """
    chosen: list[str] = []
    for nameserver in nameservers:
        candidates = _candidate_addresses(nameserver)
        if not candidates:
            log.warning("dns.nameserver_unresolvable", nameserver=nameserver)
            continue
        for address in candidates:
            if _is_reachable(address, zone_hint, probe_timeout):
                chosen.append(address)
                log.debug("dns.nameserver_selected", nameserver=nameserver,
                          address=address)
                break
        else:
            log.warning(
                "dns.nameserver_unreachable",
                nameserver=nameserver,
                tried=len(candidates),
            )
    return chosen


def detect_cname(name: str, servers: list[str], timeout: float = 5.0) -> str | None:
    """Return the CNAME target at ``name``, if one exists.

    The acme-dns pattern delegates ``_acme-challenge.<host>`` to a dedicated
    server via CNAME, so the ACME client never needs write access to the real
    zone. Where that delegation exists, a TXT written into the parent zone is
    inert: DNS forbids a CNAME coexisting with other data at the same name, so
    the authoritative answer stays the CNAME and the CA follows it elsewhere.

    Detecting this is the difference between a clear error and an order that
    validates against nothing.
    """
    for server in servers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.lifetime = timeout
        resolver.timeout = timeout
        try:
            answer = resolver.resolve(name, dns.rdatatype.CNAME)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            continue
        for rdata in answer:
            return str(rdata.target).rstrip(".")
    return None


def _txt_values(server: str, name: str, timeout: float = 5.0) -> set[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = resolver.resolve(name, dns.rdatatype.TXT)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.Timeout, dns.resolver.NoNameservers):
        return set()
    values: set[str] = set()
    for rdata in answer:
        # TXT rdata is a sequence of length-prefixed strings; join and strip.
        values.add(b"".join(rdata.strings).decode())
    return values


def wait_for_txt(
    name: str,
    expected: str,
    nameservers: list[str],
    *,
    timeout: int = 300,
    interval: int = 5,
    sleep=time.sleep,
    monotonic=time.monotonic,
) -> float:
    """Block until every authoritative nameserver serves ``expected``.

    Returns the elapsed seconds. Raises :class:`PropagationTimeout` otherwise.
    """
    zone_hint = name.split(".", 1)[1] if "." in name else name
    servers = _resolve_ns_addresses(nameservers, zone_hint=zone_hint)
    if not servers:
        raise PropagationTimeout(
            f"no reachable authoritative nameserver among {nameservers}. "
            "Outbound DNS on UDP/53 to these hosts appears to be blocked, or "
            "the addresses returned are on an unroutable address family."
        )

    started = monotonic()
    deadline = started + timeout
    outstanding = set(servers)
    log.info(
        "dns.awaiting_propagation", name=name, nameservers=len(servers),
        timeout=timeout,
    )

    rounds = 0
    while True:
        rounds += 1
        for server in list(outstanding):
            if expected in _txt_values(server, name):
                outstanding.discard(server)

        if not outstanding:
            elapsed = monotonic() - started
            log.info("dns.propagated", name=name, seconds=round(elapsed, 1),
                     nameservers=len(servers))
            return elapsed

        if monotonic() >= deadline:
            raise PropagationTimeout(
                f"TXT {name} did not propagate to {len(outstanding)} of "
                f"{len(servers)} authoritative nameservers within {timeout}s"
            )

        # Info, not debug: this can legitimately take minutes, and silence here
        # is indistinguishable from a hang.
        log.info(
            "dns.propagation_pending",
            name=name,
            pending=len(outstanding),
            of=len(servers),
            round=rounds,
            elapsed=round(monotonic() - started, 1),
        )
        sleep(interval)
