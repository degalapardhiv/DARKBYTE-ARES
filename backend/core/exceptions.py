from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException


class AresError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status_code: int = 400,
        code: str = "ares_error",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.code = code
        self.details = details or {}
        super().__init__(message)


class NotFoundError(AresError):
    def __init__(self, resource: str, identifier: str = "") -> None:
        super().__init__(
            f"{resource} not found." + (f" ({identifier})" if identifier else ""),
            status_code=404,
            code="not_found",
        )


class AuthorizationError(AresError):
    def __init__(self, message: str = "Target is not authorized for this operation.") -> None:
        super().__init__(message, status_code=403, code="target_not_authorized")


class ScopeViolation(AresError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=422, code="scope_violation")


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AresError)
    async def ares_error_handler(_: Request, exc: AresError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Normalise FastAPI/Starlette HTTP errors into the same envelope as
        # AresError so clients have a single error contract.
        detail = exc.detail
        if isinstance(detail, dict):
            code = str(detail.get("code", "http_error"))
            message = str(detail.get("message") or detail.get("detail") or "Request failed.")
            details = detail.get("details")
        else:
            code = "http_error"
            message = str(detail) if detail else "Request failed."
            details = None
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": code, "message": message, "details": details}},
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted values: password-audit payloads and auth requests
        # may contain plaintext secrets. Location, type and message are enough.
        details = [
            {
                "loc": list(error.get("loc", [])),
                "type": error.get("type", "value_error"),
                "msg": str(error.get("msg", "Invalid value"))[:300],
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request validation failed.",
                    "details": details,
                }
            },
        )

    @app.exception_handler(IntegrityError)
    async def integrity_handler(_: Request, _exc: IntegrityError) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "conflict",
                    "message": "The resource conflicts with an existing record.",
                    "details": {},
                }
            },
        )
