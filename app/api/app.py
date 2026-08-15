"""FastAPI application: API, scheduler lifecycle, and the built SPA."""

from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.auth_routes import router as auth_router
from app.api.routes import router
from app.config import get_settings
from app.db.session import init_db
from app.logging import configure_logging

log = structlog.get_logger(__name__)

_scheduler = None

# Vite build output, mounted when present.
WEB_DIST = Path(__file__).resolve().parent.parent.parent / "web" / "dist"


def get_scheduler():
    return _scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scheduler
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    init_db()

    if settings.schedule_enabled:
        from app.scheduler import build_scheduler

        _scheduler = build_scheduler(settings)
        _scheduler.start()
        log.info("api.scheduler_started")
    else:
        log.info("api.scheduler_disabled")

    yield

    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ht-wxcautocert",
        description="Certificate lifecycle automation for Cisco IOS-XE voice gateways",
        version="0.3.0",
        lifespan=lifespan,
    )

    if settings.api_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[o.strip() for o in settings.api_cors_origins.split(",") if o.strip()],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(auth_router)
    app.include_router(router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok"}

    if WEB_DIST.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=WEB_DIST / "assets"),
            name="assets",
        )

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            """Serve the SPA, letting client-side routing handle deep links."""
            candidate = WEB_DIST / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(WEB_DIST / "index.html")
    else:
        log.warning("api.web_dist_missing", path=str(WEB_DIST))

    return app


app = create_app()
