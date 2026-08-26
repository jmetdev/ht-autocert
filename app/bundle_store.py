"""Short-lived PKCS12 download tokens for gateway HTTP fetch.

SCP onto IOS-XE is unreliable (ip scp server, VRF, prompt handling). The
deployer instead parks the bundle here and tells the router to ``copy`` it
over HTTP. The token *is* the credential: the path is unguessable, the slot
expires, and a successful fetch can consume it.

This process is single-worker (one uvicorn in the container), so an in-memory
dict is enough. A restart mid-deploy just fails that run; the next deploy
mints a new token.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

DEFAULT_TTL_SECONDS = 600


@dataclass
class _Slot:
    data: bytes
    filename: str
    expires_at: float
    consumed: bool = False


class BundleStore:
    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._slots: dict[str, _Slot] = {}

    def put(self, data: bytes, filename: str = "htautocert.p12") -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge_locked()
            self._slots[token] = _Slot(
                data=data,
                filename=filename,
                expires_at=time.monotonic() + self._ttl,
            )
        return token

    def get(self, token: str, *, consume: bool = False) -> tuple[bytes, str] | None:
        now = time.monotonic()
        with self._lock:
            slot = self._slots.get(token)
            if slot is None or slot.consumed or slot.expires_at <= now:
                if slot is not None:
                    self._slots.pop(token, None)
                return None
            if consume:
                slot.consumed = True
                data, filename = slot.data, slot.filename
                self._slots.pop(token, None)
                return data, filename
            return slot.data, slot.filename

    def discard(self, token: str) -> None:
        with self._lock:
            self._slots.pop(token, None)

    def _purge_locked(self) -> None:
        now = time.monotonic()
        expired = [
            key
            for key, slot in self._slots.items()
            if slot.consumed or slot.expires_at <= now
        ]
        for key in expired:
            self._slots.pop(key, None)


_store: BundleStore | None = None
_store_lock = threading.Lock()


def get_bundle_store() -> BundleStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = BundleStore()
        return _store


def reset_bundle_store() -> None:
    """Test hook."""
    global _store
    with _store_lock:
        _store = BundleStore()
