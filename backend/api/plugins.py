from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import get_current_user, require_roles
from backend.database.session import get_db
from backend.models.models import User
from backend.schemas.schemas import PluginRunRequest
from backend.services.audit import append_audit
from backend.services.plugins import list_plugins, run_plugin, set_plugin_enabled

router = APIRouter(prefix="/plugins", tags=["Plugins"])


@router.get("")
async def plugins(
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    items = await list_plugins(db)
    return {
        "items": items,
        "total": len(items),
        "policy": "Trusted local code only. Plugins are disabled by default and require an administrator to enable.",
    }


@router.post("/{plugin_id}/enable")
async def enable_plugin(
    plugin_id: str,
    request: Request,
    user: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await set_plugin_enabled(db, plugin_id, True, user)
    await append_audit(
        db,
        action="plugin.enabled",
        resource_type="plugin",
        resource_id=plugin_id,
        actor=user,
        details={"plugin_id": plugin_id},
        request=request,
    )
    await db.commit()
    return result


@router.post("/{plugin_id}/disable")
async def disable_plugin(
    plugin_id: str,
    request: Request,
    user: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await set_plugin_enabled(db, plugin_id, False, user)
    await append_audit(
        db,
        action="plugin.disabled",
        resource_type="plugin",
        resource_id=plugin_id,
        actor=user,
        details={"plugin_id": plugin_id},
        request=request,
    )
    await db.commit()
    return result


@router.post("/{plugin_id}/run")
async def execute_plugin(
    plugin_id: str,
    payload: PluginRunRequest,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await run_plugin(db, plugin_id, payload.assessment_id, user)
    await append_audit(
        db,
        action="plugin.executed",
        resource_type="plugin",
        resource_id=plugin_id,
        actor=user,
        details={"plugin_id": plugin_id, "assessment_id": payload.assessment_id},
        request=request,
    )
    await db.commit()
    return {"plugin_id": plugin_id, "assessment_id": payload.assessment_id, "result": result}
