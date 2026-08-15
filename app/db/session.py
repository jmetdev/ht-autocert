"""Engine and session management."""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

from app.config import get_settings

_engine = None


def get_engine(database_url: str | None = None):
    global _engine
    if _engine is not None and database_url is None:
        return _engine

    url = database_url or get_settings().database_url

    if url.startswith("sqlite:///") and ":memory:" not in url:
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(url, echo=False)

    if url.startswith("sqlite"):
        # Foreign keys are off by default in SQLite; without this, a tenant
        # delete would silently orphan devices and their escrowed keys.
        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _record):  # pragma: no cover - driver callback
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    if database_url is None:
        _engine = engine
    return engine


def init_db(database_url: str | None = None) -> None:
    import app.db.models  # noqa: F401 - register tables

    SQLModel.metadata.create_all(get_engine(database_url))


@contextmanager
def session_scope(database_url: str | None = None) -> Iterator[Session]:
    # expire_on_commit=False: SQLAlchemy otherwise expires every loaded
    # attribute at commit, so reading `obj.name` after the block exits raises
    # DetachedInstanceError. That turns a successful write into a traceback
    # while the change has already landed -- the worst of both worlds.
    with Session(get_engine(database_url), expire_on_commit=False) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def reset_engine() -> None:
    """Test hook."""
    global _engine
    _engine = None
