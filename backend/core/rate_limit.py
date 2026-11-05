from __future__ import annotations

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from backend.core.config import get_settings
from backend.services.cache import cache


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Coarse per-IP request limiting; sensitive endpoints have tighter limits."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()
        path = request.url.path
        if (
            request.method == "OPTIONS"
            or path in {"/docs", "/redoc", "/openapi.json"}
            or path.endswith("/health")
        ):
            return await call_next(request)
        ip = request.client.host if request.client else "unknown"
        count = await cache.incr_window(f"ip:{ip}", 60)
        if count > settings.rate_limit_per_minute:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": {
                        "code": "rate_limited",
                        "message": "Request rate limit exceeded. Slow down and retry shortly.",
                        "details": {"limit": settings.rate_limit_per_minute, "window_seconds": 60},
                    }
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(settings.rate_limit_per_minute),
                    "X-RateLimit-Remaining": "0",
                },
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, settings.rate_limit_per_minute - count))
        return response


async def enforce_active_scan_limit(user_id: str) -> None:
    from backend.core.exceptions import AresError

    settings = get_settings()
    count = await cache.incr_window(f"active:{user_id}", 60)
    if count > settings.active_scan_rate_limit:
        raise AresError(
            "Active assessment rate limit reached. Wait before starting another scan.",
            status_code=429,
            code="active_rate_limited",
            details={"limit_per_minute": settings.active_scan_rate_limit},
        )
