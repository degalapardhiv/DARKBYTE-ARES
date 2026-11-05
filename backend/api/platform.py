from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend import __version__
from backend.auth.dependencies import get_current_user, require_roles
from backend.core.config import get_settings
from backend.database.session import get_db
from backend.models.models import AuditLog, User
from backend.schemas.schemas import ALL_MODULES, SettingsUpdate, UserAdminUpdate, UserOut
from backend.services.audit import append_audit, verify_audit_chain
from backend.services.cache import cache
from backend.services.queue import queue_status

router = APIRouter(tags=["Platform"])


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)) -> dict:
    settings = get_settings()
    database = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        database = "unavailable"
    queue = await queue_status()
    healthy = database == "ok"
    return {
        "status": "ok" if healthy else "degraded",
        "version": __version__,
        "environment": settings.app_env,
        "demo_mode": settings.demo_mode,
        "database": database,
        "redis": cache.status,
        "queue_workers": queue["workers"],
        "queue": queue,
        "time": datetime.now(UTC).isoformat(),
    }


@router.get("/platform/info")
async def platform_info(user: User = Depends(get_current_user)) -> dict:
    settings = get_settings()
    return {
        "name": settings.app_name,
        "version": __version__,
        "tagline": "ONE FRAMEWORK. COMPLETE RED TEAM OPERATIONS.",
        "environment": settings.app_env,
        "demo_mode": settings.demo_mode,
        "role": user.role,
        "modules": list(ALL_MODULES),
        "safety": {
            "require_verified_targets": settings.require_verified_targets,
            "max_scan_hosts": settings.max_scan_hosts,
            "max_ports_per_scan": settings.max_ports_per_scan,
            "max_concurrent_assessments": settings.max_concurrent_assessments,
            "assessment_timeout_seconds": settings.assessment_timeout_seconds,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
            "active_scan_rate_limit": settings.active_scan_rate_limit,
            "allow_private_targets": settings.allow_private_targets,
            "allow_loopback_lab": settings.allow_loopback_lab,
            "lab_mode": settings.lab_mode,
            "immutable_audit": True,
        },
        "policy": {
            "authorization": "Every assessment requires a verified target record with an explicit action allowlist and unexpired authorization.",
            "audit": "Audit entries are append-only and protected by a SHA-256 hash chain.",
            "red_team": "Tabletop planning only. No technique execution, malware, credential theft or uncontrolled denial of service.",
            "demo": "Demonstration records are labelled is_demo=true and are rejected when APP_ENV=production.",
        },
    }


@router.get("/settings")
async def get_settings_view(user: User = Depends(get_current_user)) -> dict:
    settings = get_settings()
    return {
        "user": UserOut.model_validate(user),
        "preferences": user.preferences or {},
        "platform": {
            "environment": settings.app_env,
            "demo_mode": settings.demo_mode,
            "version": __version__,
            "reports_retention": "Operator-managed; report files are stored under the configured reports directory.",
            "registration_enabled": settings.allow_registration,
        },
    }


@router.patch("/settings")
async def update_settings(
    payload: SettingsUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    merged = {**(user.preferences or {}), **payload.preferences}
    user.preferences = merged
    await append_audit(
        db,
        action="settings.updated",
        resource_type="user",
        resource_id=user.id,
        actor=user,
        details={"preference_keys": sorted(payload.preferences)},
        request=request,
    )
    await db.commit()
    await db.refresh(user)
    return {"preferences": user.preferences, "user": UserOut.model_validate(user)}


@router.get("/audit")
async def audit_log(
    action: str | None = Query(default=None, max_length=80),
    resource_type: str | None = Query(default=None, max_length=40),
    outcome: str | None = Query(default=None, max_length=16),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    conditions = []
    if action:
        conditions.append(AuditLog.action == action)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if outcome:
        conditions.append(AuditLog.outcome == outcome)
    total = (
        await db.execute(select(func.count()).select_from(AuditLog).where(*conditions))
    ).scalar_one()
    rows = (
        await db.execute(
            select(AuditLog)
            .where(*conditions)
            .order_by(AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return {
        "items": [
            {
                "id": row.id,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "actor_id": row.actor_id,
                "actor_email": row.actor_email,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "outcome": row.outcome,
                "details": row.details,
                "ip_address": row.ip_address,
                "prev_hash": row.prev_hash,
                "entry_hash": row.entry_hash,
            }
            for row in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/audit/verify")
async def audit_verify(
    _: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await verify_audit_chain(db)


@router.get("/users")
async def list_users(
    _: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    rows = (await db.execute(select(User).order_by(User.created_at.asc()))).scalars().all()
    return {"items": [UserOut.model_validate(row) for row in rows], "total": len(rows)}


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str,
    payload: UserAdminUpdate,
    request: Request,
    admin: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "User not found."},
        )
    changes = payload.model_dump(exclude_unset=True)
    if user.id == admin.id and (changes.get("role") not in (None, "admin") or changes.get("is_active") is False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "self_lockout", "message": "You cannot remove your own administrator access."},
        )
    for field, value in changes.items():
        setattr(user, field, value)
    await append_audit(
        db,
        action="user.updated",
        resource_type="user",
        resource_id=user.id,
        actor=admin,
        details={"fields": changes},
        request=request,
    )
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)
