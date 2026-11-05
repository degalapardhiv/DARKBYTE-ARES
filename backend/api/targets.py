from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import get_current_user, require_roles
from backend.database.session import get_db
from backend.models.models import Assessment, Target, User
from backend.schemas.schemas import (
    TargetCreate,
    TargetOut,
    TargetReject,
    TargetUpdate,
    TargetVerify,
)
from backend.services.audit import append_audit
from backend.services.authorization import verify_target_admin

router = APIRouter(prefix="/targets", tags=["Targets & Authorization"])

SCOPE_FIELDS = {"allowed_actions", "authorization_expires", "authorization_ref", "authorized_by", "environment"}


@router.get("")
async def list_targets(
    q: str | None = Query(default=None, max_length=160),
    status_filter: str | None = Query(default=None, alias="status", max_length=24),
    target_type: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    conditions = []
    if q:
        needle = f"%{q.strip()}%"
        conditions.append(
            or_(Target.name.ilike(needle), Target.value.ilike(needle), Target.authorization_ref.ilike(needle))
        )
    if status_filter:
        conditions.append(Target.status == status_filter)
    if target_type:
        conditions.append(Target.target_type == target_type)
    total = (
        await db.execute(select(func.count()).select_from(Target).where(*conditions))
    ).scalar_one()
    rows = (
        await db.execute(
            select(Target).where(*conditions).order_by(Target.created_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return {
        "items": [TargetOut.model_validate(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    duplicate = (
        await db.execute(
            select(Target).where(Target.value == payload.value, Target.target_type == payload.target_type)
        )
    ).scalar_one_or_none()
    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "target_exists", "message": "A target with this type and value already exists."},
        )
    target = Target(
        name=payload.name.strip(),
        target_type=payload.target_type,
        value=payload.value,
        environment=payload.environment,
        authorization_ref=payload.authorization_ref.strip(),
        authorized_by=payload.authorized_by.strip(),
        authorization_expires=payload.authorization_expires,
        allowed_actions=payload.allowed_actions,
        status="pending",
        notes=payload.notes,
        is_demo=False,
        created_by=user.id,
    )
    db.add(target)
    await db.flush()
    await append_audit(
        db,
        action="target.created",
        resource_type="target",
        resource_id=target.id,
        actor=user,
        details={
            "name": target.name,
            "target_type": target.target_type,
            "environment": target.environment,
            "authorization_ref": target.authorization_ref,
            "allowed_actions": target.allowed_actions,
        },
        request=request,
    )
    await db.commit()
    await db.refresh(target)
    return TargetOut.model_validate(target)


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(
    target_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Target not found."},
        )
    return TargetOut.model_validate(target)


@router.patch("/{target_id}", response_model=TargetOut)
async def update_target(
    target_id: str,
    payload: TargetUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Target not found."},
        )
    if user.role != "admin" and target.created_by != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "forbidden", "message": "You can only edit targets you created."},
        )
    if target.status == "verified" and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "verified_scope", "message": "Verified scope can only be changed by an administrator."},
        )

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        return TargetOut.model_validate(target)
    scope_changed = bool(set(updates) & SCOPE_FIELDS)
    for field, value in updates.items():
        if isinstance(value, str):
            value = value.strip()
        setattr(target, field, value)
    if scope_changed and target.status == "verified":
        target.status = "pending"
        target.verified_by = None
        target.verified_at = None
    await append_audit(
        db,
        action="target.updated",
        resource_type="target",
        resource_id=target.id,
        actor=user,
        details={"fields": sorted(updates), "scope_changed": scope_changed, "status": target.status},
        request=request,
    )
    await db.commit()
    await db.refresh(target)
    return TargetOut.model_validate(target)


@router.post("/{target_id}/verify", response_model=TargetOut)
async def verify_target(
    target_id: str,
    payload: TargetVerify,
    request: Request,
    user: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    await verify_target_admin(user)
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Target not found."},
        )
    if target.status == "verified" and not payload.note:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "already_verified", "message": "This target is already verified."},
        )
    target.allowed_actions = payload.allowed_actions
    target.authorization_expires = payload.authorization_expires
    target.status = "verified"
    target.verified_by = user.email
    target.verified_at = datetime.now(UTC)
    if payload.note:
        target.notes = (target.notes + "\n\nVerification note: " + payload.note).strip()[:4000]
    await append_audit(
        db,
        action="target.verified",
        resource_type="target",
        resource_id=target.id,
        actor=user,
        details={
            "authorization_ref": target.authorization_ref,
            "allowed_actions": target.allowed_actions,
            "authorization_expires": (
                target.authorization_expires.isoformat() if target.authorization_expires else None
            ),
        },
        request=request,
    )
    await db.commit()
    await db.refresh(target)
    return TargetOut.model_validate(target)


@router.post("/{target_id}/reject", response_model=TargetOut)
async def reject_target(
    target_id: str,
    payload: TargetReject,
    request: Request,
    user: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    await verify_target_admin(user)
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Target not found."},
        )
    target.status = "rejected"
    target.verified_by = user.email
    target.verified_at = datetime.now(UTC)
    target.notes = (target.notes + "\n\nRejection: " + payload.reason).strip()[:4000]
    await append_audit(
        db,
        action="target.rejected",
        resource_type="target",
        resource_id=target.id,
        actor=user,
        outcome="failure",
        details={"reason": payload.reason},
        request=request,
    )
    await db.commit()
    await db.refresh(target)
    return TargetOut.model_validate(target)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_target(
    target_id: str,
    request: Request,
    user: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Target not found."},
        )
    assessments = (
        await db.execute(select(func.count()).select_from(Assessment).where(Assessment.target_id == target_id))
    ).scalar_one()
    if assessments:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "target_in_use",
                "message": "Assessments reference this target. Archive or delete them first.",
            },
        )
    snapshot = {"name": target.name, "value": target.value, "status": target.status}
    await db.delete(target)
    await append_audit(
        db,
        action="target.deleted",
        resource_type="target",
        resource_id=target_id,
        actor=user,
        details=snapshot,
        request=request,
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
