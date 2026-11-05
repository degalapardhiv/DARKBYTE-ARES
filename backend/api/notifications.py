from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import get_current_user
from backend.database.session import get_db
from backend.models.models import Notification, User
from backend.schemas.schemas import NotificationOut
from backend.services.audit import append_audit

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("")
async def list_notifications(
    unread_only: bool = False,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    conditions = [Notification.user_id == user.id]
    if unread_only:
        conditions.append(Notification.read.is_(False))
    total = (
        await db.execute(select(func.count()).select_from(Notification).where(*conditions))
    ).scalar_one()
    unread = (
        await db.execute(
            select(func.count())
            .select_from(Notification)
            .where(Notification.user_id == user.id, Notification.read.is_(False))
        )
    ).scalar_one()
    rows = (
        await db.execute(
            select(Notification)
            .where(*conditions)
            .order_by(Notification.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return {
        "items": [NotificationOut.model_validate(row) for row in rows],
        "total": total,
        "unread": unread,
        "limit": limit,
        "offset": offset,
    }


@router.post("/read-all")
async def read_all_notifications(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    result = await db.execute(
        update(Notification)
        .where(Notification.user_id == user.id, Notification.read.is_(False))
        .values(read=True)
    )
    await append_audit(
        db,
        action="notifications.read_all",
        resource_type="notification",
        actor=user,
        details={"updated": result.rowcount or 0},
        request=request,
    )
    await db.commit()
    return {"updated": int(result.rowcount or 0)}


@router.post("/{notification_id}/read", response_model=NotificationOut)
async def read_notification(
    notification_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> NotificationOut:
    notification = await db.get(Notification, notification_id)
    if not notification or notification.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Notification not found."},
        )
    notification.read = True
    await db.commit()
    await db.refresh(notification)
    return NotificationOut.model_validate(notification)


@router.delete("/{notification_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_notification(
    notification_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    notification = await db.get(Notification, notification_id)
    if not notification or notification.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Notification not found."},
        )
    await db.delete(notification)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
