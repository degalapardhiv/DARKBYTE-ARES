from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import get_current_user
from backend.database.session import get_db
from backend.models.models import Finding, User
from integrations.mitre_attack.loader import (
    MODULE_TECHNIQUE_MAP,
    build_coverage,
    get_tactics,
    get_technique,
    get_techniques,
    metadata,
)

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


@router.get("/tactics")
async def tactics(_: User = Depends(get_current_user)) -> dict:
    return {
        "items": get_tactics(),
        "total": len(get_tactics()),
        "source": metadata(),
    }


@router.get("/techniques")
async def techniques(
    query: str | None = Query(default=None, max_length=120),
    tactic: str | None = Query(default=None, max_length=80),
    include_subtechniques: bool = False,
    limit: int = Query(default=60, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(get_current_user),
) -> dict:
    items, total = get_techniques(
        query=query,
        tactic=tactic,
        include_subtechniques=include_subtechniques,
        limit=limit,
        offset=offset,
    )
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "source": metadata(),
    }


@router.get("/techniques/{technique_id}")
async def technique_detail(
    technique_id: str,
    _: User = Depends(get_current_user),
) -> dict:
    technique = get_technique(technique_id)
    if not technique:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "ATT&CK technique not found."},
        )
    return {**technique, "source": metadata()}


@router.get("/coverage")
async def coverage(
    assessment_id: str | None = Query(default=None, max_length=64),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    conditions = [Finding.technique_ids.is_not(None)]
    if assessment_id:
        conditions.append(Finding.assessment_id == assessment_id)
    rows = (
        await db.execute(select(Finding.technique_ids).where(*conditions).limit(10000))
    ).scalars().all()
    observed: set[str] = set()
    for row in rows:
        for technique_id in row or []:
            if isinstance(technique_id, str) and technique_id.startswith("T"):
                observed.add(technique_id)
    result = build_coverage(observed)
    result["assessment_id"] = assessment_id
    result["module_techniques"] = MODULE_TECHNIQUE_MAP
    return result
