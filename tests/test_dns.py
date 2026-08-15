"""Cloudflare solver and propagation checking."""

from __future__ import annotations

import httpx
import pytest

from app.dns.base import TxtRecord
from app.dns.cloudflare import CloudflareError, CloudflareSolver
from app.dns.propagation import PropagationTimeout, wait_for_txt

ZONE = "managedcollab.com"
ZONE_ID = "zone123"


def _transport(handler):
    return httpx.MockTransport(handler)


def _solver(handler, **kwargs) -> CloudflareSolver:
    client = httpx.Client(
        base_url="https://api.cloudflare.com/client/v4",
        transport=_transport(handler),
    )
    return CloudflareSolver("token", ZONE, client=client, **kwargs)


def test_creates_and_deletes_txt():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/client/v4/zones":
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "result": [
                        {
                            "id": ZONE_ID,
                            "name_servers": ["ns1.example.net", "ns2.example.net"],
                        }
                    ],
                },
            )
        if request.method == "POST":
            return httpx.Response(
                200, json={"success": True, "result": {"id": "rec456"}}
            )
        return httpx.Response(200, json={"success": True, "result": {"id": "rec456"}})

    solver = _solver(handler)
    record = solver.create_txt(f"_acme-challenge.vg01.husd.clients.{ZONE}", "token-value")

    assert record.record_id == "rec456"
    solver.delete_txt(record)
    assert ("DELETE", f"/client/v4/zones/{ZONE_ID}/dns_records/rec456") in calls


def test_zone_is_resolved_once():
    zone_lookups = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/client/v4/zones":
            zone_lookups.append(1)
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "result": [{"id": ZONE_ID, "name_servers": ["ns1.example.net"]}],
                },
            )
        return httpx.Response(200, json={"success": True, "result": {"id": "r"}})

    solver = _solver(handler)
    solver.create_txt(f"a.{ZONE}", "v1")
    solver.create_txt(f"b.{ZONE}", "v2")
    solver.authoritative_nameservers()

    assert len(zone_lookups) == 1


def test_refuses_records_outside_the_managed_zone():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"success": True, "result": [{"id": ZONE_ID, "name_servers": []}]},
        )

    solver = _solver(handler)
    with pytest.raises(CloudflareError, match="outside managed zone"):
        solver.create_txt("_acme-challenge.evil.example.org", "value")


def test_unknown_zone_raises_actionable_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "result": []})

    solver = _solver(handler)
    with pytest.raises(CloudflareError, match="Zone:DNS:Edit"):
        solver.create_txt(f"x.{ZONE}", "v")


def test_api_errors_are_surfaced():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "success": False,
                "errors": [{"code": 9109, "message": "Invalid access token"}],
            },
        )

    solver = _solver(handler)
    with pytest.raises(CloudflareError, match="Invalid access token"):
        solver.create_txt(f"x.{ZONE}", "v")


def test_delete_failure_does_not_raise():
    """Cleanup runs in a finally block and must not mask the original error."""
    state = {"zone_done": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/client/v4/zones":
            state["zone_done"] = True
            return httpx.Response(
                200,
                json={"success": True, "result": [{"id": ZONE_ID, "name_servers": []}]},
            )
        return httpx.Response(
            404, json={"success": False, "errors": [{"code": 81044, "message": "gone"}]}
        )

    solver = _solver(handler)
    solver.delete_txt(TxtRecord(name="x", value="v", record_id="missing"))
    assert state["zone_done"] is True


# -- propagation -------------------------------------------------------------


def test_wait_for_txt_returns_once_all_servers_agree(monkeypatch):
    monkeypatch.setattr(
        "app.dns.propagation._resolve_ns_addresses", lambda ns, **kw: ["192.0.2.1", "192.0.2.2"]
    )
    seen = {"192.0.2.1": 0, "192.0.2.2": 0}

    def fake_txt(server, name, timeout=5.0):
        seen[server] += 1
        # Second server lags by one poll.
        if server == "192.0.2.2" and seen[server] < 2:
            return set()
        return {"expected-value"}

    monkeypatch.setattr("app.dns.propagation._txt_values", fake_txt)

    ticks = []
    elapsed = wait_for_txt(
        "_acme-challenge.vg01.example.com",
        "expected-value",
        ["ns1.example.net"],
        timeout=60,
        interval=1,
        sleep=ticks.append,
        monotonic=lambda: float(len(ticks)),
    )

    assert elapsed >= 0
    assert len(ticks) == 1  # exactly one poll interval, not a fixed 25s sleep


def test_wait_for_txt_times_out(monkeypatch):
    monkeypatch.setattr(
        "app.dns.propagation._resolve_ns_addresses", lambda ns, **kw: ["192.0.2.1"]
    )
    monkeypatch.setattr("app.dns.propagation._txt_values", lambda *a, **k: set())

    clock = {"t": 0.0}

    def fake_sleep(_):
        clock["t"] += 5.0

    with pytest.raises(PropagationTimeout, match="did not propagate"):
        wait_for_txt(
            "_acme-challenge.vg01.example.com",
            "value",
            ["ns1.example.net"],
            timeout=10,
            interval=5,
            sleep=fake_sleep,
            monotonic=lambda: clock["t"],
        )


def test_wait_for_txt_ignores_stale_values(monkeypatch):
    """A leftover TXT from a previous order must not satisfy the check."""
    monkeypatch.setattr(
        "app.dns.propagation._resolve_ns_addresses", lambda ns, **kw: ["192.0.2.1"]
    )
    monkeypatch.setattr(
        "app.dns.propagation._txt_values", lambda *a, **k: {"old-value"}
    )
    clock = {"t": 0.0}

    with pytest.raises(PropagationTimeout):
        wait_for_txt(
            "_acme-challenge.vg01.example.com",
            "new-value",
            ["ns1.example.net"],
            timeout=5,
            interval=5,
            sleep=lambda _: clock.__setitem__("t", clock["t"] + 5),
            monotonic=lambda: clock["t"],
        )


def test_no_reachable_nameservers_fails_fast(monkeypatch):
    """Rather than polling a list of unreachable addresses until the timeout."""
    monkeypatch.setattr("app.dns.propagation._resolve_ns_addresses", lambda ns, **kw: [])
    with pytest.raises(PropagationTimeout, match="no reachable authoritative"):
        wait_for_txt("x", "v", ["ns1.example.net"])


def test_unreachable_address_family_is_excluded(monkeypatch):
    """A host with no IPv6 route still gets AAAA records for the nameservers.

    Including unreachable addresses in the "all servers agree" check makes it
    unsatisfiable, so the run appears to hang until the timeout.
    """
    from app.dns.propagation import _resolve_ns_addresses

    v4, v6 = "192.0.2.10", "2001:db8::10"
    monkeypatch.setattr(
        "app.dns.propagation._candidate_addresses", lambda ns: [v6, v4]
    )
    monkeypatch.setattr(
        "app.dns.propagation._is_reachable",
        lambda address, zone_hint, timeout: address == v4,
    )

    assert _resolve_ns_addresses(["ns1.example.net"]) == [v4]


def test_one_address_per_nameserver(monkeypatch):
    """Anycast means several addresses front the same zone data; one is enough."""
    from app.dns.propagation import _resolve_ns_addresses

    monkeypatch.setattr(
        "app.dns.propagation._candidate_addresses",
        lambda ns: [f"192.0.2.{ns[2]}1", f"192.0.2.{ns[2]}2"],
    )
    monkeypatch.setattr(
        "app.dns.propagation._is_reachable", lambda *a, **k: True
    )

    assert _resolve_ns_addresses(["ns1.example.net", "ns2.example.net"]) == [
        "192.0.2.11",
        "192.0.2.21",
    ]


def test_nameserver_with_no_reachable_address_is_skipped(monkeypatch):
    from app.dns.propagation import _resolve_ns_addresses

    monkeypatch.setattr("app.dns.propagation._candidate_addresses", lambda ns: ["a", "b"])
    monkeypatch.setattr("app.dns.propagation._is_reachable", lambda *a, **k: False)

    assert _resolve_ns_addresses(["ns1.example.net"]) == []
