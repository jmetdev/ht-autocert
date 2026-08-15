"""structlog configuration.

Human-readable by default for interactive runs; JSON when
``HTAC_LOG_JSON=true`` so the scheduler's output is ingestable.
"""

from __future__ import annotations

import logging

import structlog


def configure_logging(level: str = "info", json_output: bool = False) -> None:
    logging.basicConfig(
        format="%(message)s", level=getattr(logging, level.upper(), logging.INFO)
    )
    renderer = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )
