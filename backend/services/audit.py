from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.models import AuditLog, User


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _iso_utc(value: datetime) -> str:
    """Canonical timestamp used in the hash input.

    SQLite drops timezone information on retrieval, so both write and verify
    paths normalize to UTC before serializing. Without this the hash chain
    would appear valid in Postgres but break on the default development DB.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.isoformat()


async def append_audit(
    db: AsyncSession,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    actor: User | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditLog:
    """Append a tamper-evident entry to the audit chain.

    Postgres takes a transaction-scoped advisory lock so concurrent requests
    cannot fork the chain. Other backends rely on serialized writes.
    """
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(81234017)"))

    previous = (
        await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    ).scalar_one_or_none()
    prev_hash = previous.entry_hash if previous else "GENESIS"
    now = datetime.now(UTC)
    body = {
        "ts": _iso_utc(now),
        "actor_id": actor.id if actor else None,
        "actor_email": actor.email if actor else None,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "details": _safe_details(details or {}),
        "prev_hash": prev_hash,
    }
    entry_hash = hashlib.sha256((prev_hash + _canonical(body)).encode()).hexdigest()
    entry = AuditLog(
        created_at=now,
        actor_id=actor.id if actor else None,
        actor_email=actor.email if actor else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        details=body["details"],
        ip_address=request.client.host if request and request.client else None,
        user_agent=(request.headers.get("user-agent", "")[:400] if request else None),
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    return entry


def _safe_details(details: dict[str, Any]) -> dict[str, Any]:
    forbidden = {
        "password",
        "new_password",
        "current_password",
        "test_passwords",
        "hashes",
        "wordlist",
        "token",
        "access_token",
        "secret",
        "authorization",
    }
    clean: dict[str, Any] = {}
    for key, value in details.items():
        if key.lower() in forbidden:
            clean[key] = "[redacted]"
        elif isinstance(value, dict):
            clean[key] = _safe_details(value)
        elif isinstance(value, list):
            clean[key] = value[:20]
        elif isinstance(value, str):
            clean[key] = value[:500]
        else:
            clean[key] = value
    return clean


async def verify_audit_chain(db: AsyncSession, limit: int = 1000) -> dict[str, Any]:
    rows = (
        await db.execute(select(AuditLog).order_by(AuditLog.id.asc()).limit(limit))
    ).scalars().all()
    previous = "GENESIS"
    broken_at: int | None = None
    for row in rows:
        body = {
            "ts": _iso_utc(row.created_at),
            "actor_id": row.actor_id,
            "actor_email": row.actor_email,
            "action": row.action,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "outcome": row.outcome,
            "details": row.details,
            "prev_hash": row.prev_hash,
        }
        expected = hashlib.sha256((previous + _canonical(body)).encode()).hexdigest()
        if row.prev_hash != previous or row.entry_hash != expected:
            broken_at = row.id
            break
        previous = row.entry_hash
    return {
        "valid": broken_at is None,
        "checked": len(rows),
        "broken_at": broken_at,
        "head": previous,
    }
