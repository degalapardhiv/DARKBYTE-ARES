from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import get_current_user, require_roles
from backend.core.config import get_settings
from backend.database.session import get_db
from backend.models.models import Assessment, Report, User
from backend.schemas.schemas import ReportCreate, ReportOut
from backend.services.audit import append_audit
from backend.services.reporting import generate_report

router = APIRouter(prefix="/reports", tags=["Reports"])


def _safe_download_name(report: Report) -> str:
    base = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in report.title).strip("-")
    base = base[:100] or "ares-report"
    suffix = "." + report.format
    return base if base.lower().endswith(suffix) else base + suffix


@router.get("")
async def list_reports(
    assessment_id: str | None = Query(default=None, max_length=64),
    fmt: str | None = Query(default=None, max_length=8),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    conditions = []
    if assessment_id:
        conditions.append(Report.assessment_id == assessment_id)
    if fmt:
        conditions.append(Report.format == fmt)
    total = (
        await db.execute(select(func.count()).select_from(Report).where(*conditions))
    ).scalar_one()
    rows = (
        await db.execute(
            select(Report).where(*conditions).order_by(Report.created_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return {
        "items": [ReportOut.model_validate(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
async def create_report(
    payload: ReportCreate,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    assessment = (
        await db.execute(
            select(Assessment)
            .options(selectinload(Assessment.target), selectinload(Assessment.findings))
            .where(Assessment.id == payload.assessment_id)
        )
    ).scalar_one_or_none()
    if not assessment or not assessment.target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Assessment not found."},
        )
    report = await generate_report(
        db,
        assessment=assessment,
        target=assessment.target,
        findings=assessment.findings,
        user=user,
        fmt=payload.format,
        title=payload.title,
    )
    await append_audit(
        db,
        action="report.generated",
        resource_type="report",
        resource_id=report.id,
        actor=user,
        details={
            "assessment_id": assessment.id,
            "format": report.format,
            "size_bytes": report.size_bytes,
            "is_demo": report.is_demo,
        },
        request=request,
    )
    await db.commit()
    await db.refresh(report)
    return ReportOut.model_validate(report)


@router.get("/{report_id}", response_model=ReportOut)
async def get_report(
    report_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Report not found."},
        )
    return ReportOut.model_validate(report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Report not found."},
        )
    settings = get_settings()
    reports_root = Path(settings.reports_dir).resolve()
    path = Path(report.file_path).resolve()
    if reports_root != path.parent and reports_root not in path.parents:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "unsafe_path", "message": "Report path is outside the reports directory."},
        )
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "file_missing", "message": "Report file is no longer available."},
        )
    await append_audit(
        db,
        action="report.downloaded",
        resource_type="report",
        resource_id=report.id,
        actor=user,
        details={"format": report.format, "is_demo": report.is_demo},
        request=request,
    )
    await db.commit()
    media = {
        "pdf": "application/pdf",
        "html": "text/html; charset=utf-8",
        "json": "application/json",
    }.get(report.format, "application/octet-stream")
    return FileResponse(
        path,
        media_type=media,
        filename=_safe_download_name(report),
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(_safe_download_name(report))}"},
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_report(
    report_id: str,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Report not found."},
        )
    if user.role != "admin" and report.created_by != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "forbidden", "message": "Only the report creator or an administrator can delete it."},
        )
    try:
        path = Path(report.file_path).resolve()
        if path.is_file():
            path.unlink()
    except OSError:
        pass
    snapshot = {"title": report.title, "format": report.format, "assessment_id": report.assessment_id}
    await db.delete(report)
    await append_audit(
        db,
        action="report.deleted",
        resource_type="report",
        resource_id=report_id,
        actor=user,
        details=snapshot,
        request=request,
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
