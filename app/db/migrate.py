"""Additive schema migration for SQLite.

``SQLModel.metadata.create_all`` creates missing tables but never adds columns
to existing ones, so a database created before Phase 2 needs the new device
credential and transport columns. Adding a nullable column with a default is
safe and non-destructive; anything beyond that should become a real migration
tool before this carries production data.
"""

import structlog
from sqlalchemy import inspect, text
from sqlmodel import SQLModel

from app.db.session import get_engine

log = structlog.get_logger(__name__)

_SQLITE_TYPES = {
    "INTEGER": "INTEGER",
    "VARCHAR": "VARCHAR",
    "BLOB": "BLOB",
    "BOOLEAN": "BOOLEAN",
    "DATETIME": "DATETIME",
}


def _column_sql(column) -> str:
    type_name = column.type.__class__.__name__.upper()
    sql_type = _SQLITE_TYPES.get(type_name, "VARCHAR")

    default = ""
    if column.default is not None and getattr(column.default, "is_scalar", False):
        value = column.default.arg
        if isinstance(value, bool):
            default = f" DEFAULT {1 if value else 0}"
        elif isinstance(value, (int, float)):
            default = f" DEFAULT {value}"
        elif isinstance(value, str):
            default = f" DEFAULT '{value}'"
    return f"{column.name} {sql_type}{default}"


def migrate(database_url: str | None = None) -> list[str]:
    """Add any columns present in the models but missing from the database."""
    import app.db.models  # noqa: F401 - register tables

    engine = get_engine(database_url)
    SQLModel.metadata.create_all(engine)

    inspector = inspect(engine)
    applied: list[str] = []

    with engine.begin() as conn:
        for table_name, table in SQLModel.metadata.tables.items():
            if table_name not in inspector.get_table_names():
                continue
            existing = {c["name"] for c in inspector.get_columns(table_name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                if not column.nullable and column.default is None:
                    log.warning(
                        "migrate.skipped_non_nullable",
                        table=table_name,
                        column=column.name,
                    )
                    continue
                statement = (
                    f"ALTER TABLE {table_name} ADD COLUMN {_column_sql(column)}"
                )
                conn.execute(text(statement))
                applied.append(f"{table_name}.{column.name}")
                log.info("migrate.column_added", table=table_name, column=column.name)

    return applied
