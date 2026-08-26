"""HTTP bundle store used to stage PKCS12 files for gateway copy."""

from app.bundle_store import BundleStore


def test_put_and_get_round_trip():
    store = BundleStore(ttl_seconds=60)
    token = store.put(b"p12-bytes", filename="htautocert.p12")
    found = store.get(token)
    assert found == (b"p12-bytes", "htautocert.p12")


def test_unknown_token_is_none():
    assert BundleStore().get("nope") is None


def test_consume_removes_the_slot():
    store = BundleStore()
    token = store.put(b"once")
    assert store.get(token, consume=True)[0] == b"once"
    assert store.get(token) is None


def test_discard_drops_the_slot():
    store = BundleStore()
    token = store.put(b"x")
    store.discard(token)
    assert store.get(token) is None


def test_expired_slot_is_gone(monkeypatch):
    class Clock:
        now = 0.0

        def __call__(self):
            return self.now

    clock = Clock()
    monkeypatch.setattr("app.bundle_store.time.monotonic", clock)
    store = BundleStore(ttl_seconds=5)
    token = store.put(b"old")
    clock.now = 10.0
    assert store.get(token) is None
