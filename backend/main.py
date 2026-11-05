from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend import __version__
from backend.api import (
    assessments_router,
    auth_router,
    dashboard_router,
    findings_router,
    mitre_router,
    modules_router,
    notifications_router,
    platform_router,
    plugins_router,
    reports_router,
    targets_router,
)
from backend.core.config import get_settings
from backend.core.exceptions import install_error_handlers
from backend.core.logging import configure_logging, request_id_ctx
from backend.core.rate_limit import RateLimitMiddleware
from backend.database.session import close_db, init_db
from backend.services.cache import cache
from backend.services.queue import assessment_queue
from backend.services.seed import seed_database

logger = logging.getLogger("ares.api")
settings = get_settings()
configure_logging(settings.debug)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_runtime_safety()
    await init_db()
    await cache.connect()
    await seed_database()
    await assessment_queue.start()
    logger.info(
        "DARKBYTE ARES %s started in %s mode (demo=%s, workers=%s)",
        __version__,
        settings.app_env,
        settings.demo_mode,
        assessment_queue.worker_count,
    )
    try:
        yield
    finally:
        await assessment_queue.stop()
        await cache.close()
        await close_db()
        logger.info("DARKBYTE ARES stopped")


app = FastAPI(
    title="DARKBYTE ARES API",
    description=(
        "Authorized security assessment platform. Every operation is scoped to a verified "
        "target authorization record and recorded in an append-only audit chain."
    ),
    version=__version__,
    contact={"name": "DarkByteHunter", "url": "https://github.com/darkbytehunter"},
    license_info={"name": "MIT"},
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    openapi_tags=[
        {"name": "Authentication", "description": "Registration, sessions and profile."},
        {"name": "Targets & Authorization", "description": "Explicit scope and verification records."},
        {"name": "Assessments", "description": "Scoped assessment lifecycle."},
        {"name": "Findings", "description": "Evidence-backed results and triage."},
        {"name": "Modules & Tools", "description": "Module catalog, CVSS and password audit."},
        {"name": "Dashboard", "description": "Aggregated posture and activity."},
        {"name": "Reports", "description": "PDF, HTML and JSON deliverables."},
        {"name": "MITRE ATT&CK", "description": "Bundled ATT&CK data and coverage."},
        {"name": "Plugins", "description": "Administrator-gated local extensions."},
        {"name": "Notifications", "description": "Per-user operational notifications."},
        {"name": "Platform", "description": "Health, settings and audit assurance."},
    ],
)

app.add_middleware(RateLimitMiddleware)


@app.middleware("http")
async def observability_headers(request: Request, call_next):
    request_id = request.headers.get("x-request-id", "").strip()[:64] or uuid.uuid4().hex
    request_id_ctx.set(request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "Unhandled request failure",
            extra={"event": "request.error", "method": request.method, "path": request.url.path},
        )
        raise
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    logger.info(
        "request",
        extra={
            "event": "request.complete",
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
    )
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "Content-Disposition"],
    max_age=600,
)

install_error_handlers(app)

API_PREFIX = "/api/v1"
for api_router in (
    auth_router,
    targets_router,
    assessments_router,
    findings_router,
    dashboard_router,
    reports_router,
    modules_router,
    mitre_router,
    plugins_router,
    notifications_router,
    platform_router,
):
    app.include_router(api_router, prefix=API_PREFIX)


@app.get("/health", include_in_schema=False)
async def root_health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "environment": settings.app_env,
        "demo_mode": settings.demo_mode,
    }


@app.get("/api/health", include_in_schema=False)
async def api_health() -> dict:
    return await root_health()


@app.get("/", include_in_schema=False)
async def root() -> JSONResponse:
    return JSONResponse(
        {
            "name": "DARKBYTE ARES",
            "version": __version__,
            "tagline": "ONE FRAMEWORK. COMPLETE RED TEAM OPERATIONS.",
            "docs": "/docs",
            "health": "/health",
            "api": API_PREFIX,
            "notice": "Authorized security testing only. Every assessment requires a verified target record.",
        }
    )
