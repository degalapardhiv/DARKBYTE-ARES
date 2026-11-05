from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.serializers import assessment_out, finding_out
from backend.auth.dependencies import get_current_user, require_roles
from backend.core.rate_limit import enforce_active_scan_limit
from backend.database.session import get_db
from backend.models.models import Assessment, Finding, Report, ScanJob, User
from backend.schemas.schemas import (
    AssessmentCreate,
    AssessmentOut,
    FindingOut,
    FindingUpdate,
)
from backend.services.audit import append_audit
from backend.services.authorization import ensure_target_authorized
from backend.services.queue import assessment_queue

router = APIRouter(prefix="/assessments", tags=["Assessments"])
findings_router = APIRouter(prefix="/findings", tags=["Findings"])

MODULE_LABELS = {
    "recon": "Reconnaissance",
    "network": "Network Scan",
    "web": "Web Security",
    "vulnerability": "Vulnerability Review",
    "osint": "OSINT",
    "password": "Password Audit",
    "active_directory": "AD Audit",
    "cloud": "Cloud Audit",
    "api_security": "API Security",
    "red_team": "Red Team Simulator",
}


def _can_manage(user: User, assessment: Assessment) -> bool:
    return user.role == "admin" or assessment.created_by == user.id


async def _load_assessment(db: AsyncSession, assessment_id: str) -> Assessment:
    assessment = (
        await db.execute(
            select(Assessment)
            .options(selectinload(Assessment.target), selectinload(Assessment.owner))
            .where(Assessment.id == assessment_id)
        )
    ).scalar_one_or_none()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Assessment not found."},
        )
    return assessment


@router.get("")
async def list_assessments(
    q: str | None = Query(default=None, max_length=200),
    status_filter: str | None = Query(default=None, alias="status", max_length=24),
    module: str | None = Query(default=None, max_length=40),
    target_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    conditions = []
    if q:
        needle = f"%{q.strip()}%"
        conditions.append(or_(Assessment.name.ilike(needle), Assessment.module.ilike(needle)))
    if status_filter:
        conditions.append(Assessment.status == status_filter)
    if module:
        conditions.append(Assessment.module == module)
    if target_id:
        conditions.append(Assessment.target_id == target_id)
    total = (
        await db.execute(select(func.count()).select_from(Assessment).where(*conditions))
    ).scalar_one()
    rows = (
        await db.execute(
            select(Assessment)
            .options(selectinload(Assessment.target))
            .where(*conditions)
            .order_by(Assessment.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return {
        "items": [assessment_out(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=AssessmentOut, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    payload: AssessmentCreate,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> AssessmentOut:
    if payload.module == "password":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "password_endpoint_required",
                "message": "Password auditing is processed synchronously at /api/v1/tools/password-audit so plaintext is never queued or stored.",
            },
        )
    target = await ensure_target_authorized(db, payload.target_id, payload.module, user=user)
    await enforce_active_scan_limit(user.id)
    assessment = Assessment(
        name=(payload.name or f"{target.name} · {MODULE_LABELS[payload.module]}").strip()[:200],
        module=payload.module,
        target_id=target.id,
        config=payload.config,
        status="draft",
        progress=0,
        summary={},
        risk_score=0.0,
        is_demo=target.is_demo,
        created_by=user.id,
    )
    db.add(assessment)
    await db.flush()
    await append_audit(
        db,
        action="assessment.created",
        resource_type="assessment",
        resource_id=assessment.id,
        actor=user,
        details={
            "module": payload.module,
            "target_id": target.id,
            "target_value": target.value,
            "start": payload.start,
            "config": payload.config,
        },
        request=request,
    )
    if payload.start:
        await assessment_queue.enqueue(db, assessment)
    else:
        await db.commit()
    loaded = await _load_assessment(db, assessment.id)
    return assessment_out(loaded)


@router.get("/{assessment_id}", response_model=AssessmentOut)
async def get_assessment(
    assessment_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AssessmentOut:
    assessment = await _load_assessment(db, assessment_id)
    return assessment_out(assessment)


@router.post("/{assessment_id}/run", response_model=AssessmentOut)
async def run_assessment(
    assessment_id: str,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> AssessmentOut:
    assessment = await _load_assessment(db, assessment_id)
    if not _can_manage(user, assessment):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "forbidden", "message": "Only the assessment owner or an administrator can run it."},
        )
    if assessment.module == "password":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "password_endpoint_required", "message": "Use the password audit tool endpoint."},
        )
    if assessment.status in {"queued", "running"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "assessment_in_progress", "message": "This assessment is already queued or running."},
        )
    await ensure_target_authorized(db, assessment.target_id, assessment.module, user=user)
    await enforce_active_scan_limit(user.id)
    await append_audit(
        db,
        action="assessment.queued",
        resource_type="assessment",
        resource_id=assessment.id,
        actor=user,
        details={"module": assessment.module, "target_id": assessment.target_id, "rerun": assessment.status == "completed"},
        request=request,
    )
    await assessment_queue.enqueue(db, assessment)
    loaded = await _load_assessment(db, assessment_id)
    return assessment_out(loaded)


@router.post("/{assessment_id}/cancel", response_model=AssessmentOut)
async def cancel_assessment(
    assessment_id: str,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> AssessmentOut:
    assessment = await _load_assessment(db, assessment_id)
    if not _can_manage(user, assessment):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "forbidden", "message": "Only the assessment owner or an administrator can cancel it."},
        )
    job = (
        await db.execute(select(ScanJob).where(ScanJob.assessment_id == assessment.id))
    ).scalar_one_or_none()
    if assessment.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "already_running", "message": "A running assessment cannot be cancelled from the API."},
        )
    if assessment.status != "queued" or not job or job.status != "queued":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "not_cancellable", "message": "Only a queued assessment can be cancelled."},
        )
    job.status = "cancelled"
    job.finished_at = datetime.now(UTC)
    assessment.status = "cancelled"
    assessment.progress = 0
    assessment.finished_at = datetime.now(UTC)
    await append_audit(
        db,
        action="assessment.cancelled",
        resource_type="assessment",
        resource_id=assessment.id,
        actor=user,
        details={"module": assessment.module},
        request=request,
    )
    await db.commit()
    loaded = await _load_assessment(db, assessment_id)
    return assessment_out(loaded)


@router.delete("/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_assessment(
    assessment_id: str,
    request: Request,
    user: User = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    assessment = await _load_assessment(db, assessment_id)
    if assessment.status in {"queued", "running"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "assessment_in_progress", "message": "Cancel or wait for the assessment to finish first."},
        )
    reports = (
        await db.execute(select(Report).where(Report.assessment_id == assessment.id))
    ).scalars().all()
    for report in reports:
        try:
            path = Path(report.file_path).resolve()
            if path.is_file():
                path.unlink()
        except OSError:
            pass
        await db.delete(report)
    await db.execute(delete(Finding).where(Finding.assessment_id == assessment.id))
    await db.execute(delete(ScanJob).where(ScanJob.assessment_id == assessment.id))
    snapshot = {"name": assessment.name, "module": assessment.module, "target_id": assessment.target_id}
    await db.delete(assessment)
    await append_audit(
        db,
        action="assessment.deleted",
        resource_type="assessment",
        resource_id=assessment_id,
        actor=user,
        details=snapshot,
        request=request,
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{assessment_id}/findings")
async def assessment_findings(
    assessment_id: str,
    severity: str | None = Query(default=None, max_length=16),
    finding_status: str | None = Query(default=None, alias="status", max_length=24),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _load_assessment(db, assessment_id)
    conditions = [Finding.assessment_id == assessment_id]
    if severity:
        conditions.append(Finding.severity == severity)
    if finding_status:
        conditions.append(Finding.status == finding_status)
    total = (
        await db.execute(select(func.count()).select_from(Finding).where(*conditions))
    ).scalar_one()
    rank = case(
        (Finding.severity == "critical", 5),
        (Finding.severity == "high", 4),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 2),
        else_=1,
    )
    rows = (
        await db.execute(
            select(Finding)
            .where(*conditions)
            .order_by(rank.desc(), Finding.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return {
        "items": [finding_out(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@findings_router.get("")
async def list_findings(
    q: str | None = Query(default=None, max_length=200),
    severity: str | None = Query(default=None, max_length=16),
    finding_status: str | None = Query(default=None, alias="status", max_length=24),
    module: str | None = Query(default=None, max_length=40),
    assessment_id: str | None = Query(default=None, max_length=64),
    target_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    conditions = []
    if q:
        needle = f"%{q.strip()}%"
        conditions.append(or_(Finding.title.ilike(needle), Finding.cve_id.ilike(needle)))
    if severity:
        conditions.append(Finding.severity == severity)
    if finding_status:
        conditions.append(Finding.status == finding_status)
    if module:
        conditions.append(Finding.module == module)
    if assessment_id:
        conditions.append(Finding.assessment_id == assessment_id)
    if target_id:
        conditions.append(Finding.target_id == target_id)
    total = (
        await db.execute(select(func.count()).select_from(Finding).where(*conditions))
    ).scalar_one()
    rank = case(
        (Finding.severity == "critical", 5),
        (Finding.severity == "high", 4),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 2),
        else_=1,
    )
    rows = (
        await db.execute(
            select(Finding)
            .where(*conditions)
            .order_by(rank.desc(), Finding.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return {
        "items": [finding_out(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@findings_router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingOut:
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Finding not found."},
        )
    return finding_out(finding)


@findings_router.patch("/{finding_id}", response_model=FindingOut)
async def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> FindingOut:
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Finding not found."},
        )
    previous = finding.status
    finding.status = payload.status
    await append_audit(
        db,
        action="finding.status_updated",
        resource_type="finding",
        resource_id=finding.id,
        actor=user,
        details={"from": previous, "to": payload.status, "assessment_id": finding.assessment_id},
        request=request,
    )
    await db.commit()
    await db.refresh(finding)
    return finding_out(finding)
