from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.serializers import assessment_out, finding_out
from backend.auth.dependencies import get_current_user
from backend.database.session import get_db
from backend.models.models import Assessment, AuditLog, Finding, Notification, Report, Target, User
from backend.schemas.schemas import ALL_MODULES
from backend.services.cache import cache
from integrations.mitre_attack.loader import build_coverage

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

SEVERITIES = ("critical", "high", "medium", "low", "info")
CACHE_KEY = "dashboard:overview"


async def _count(db: AsyncSession, model, *conditions) -> int:
    return int(
        (await db.execute(select(func.count()).select_from(model).where(*conditions))).scalar_one()
    )


def _trend(rows: list[tuple[datetime, float]]) -> list[dict]:
    today = datetime.now(UTC).date()
    buckets: dict[str, list[float]] = {
        (today - timedelta(days=offset)).isoformat(): [] for offset in range(13, -1, -1)
    }
    for created_at, risk_score in rows:
        day = created_at.date().isoformat() if created_at else None
        if day in buckets:
            buckets[day].append(float(risk_score or 0))
    return [
        {
            "date": day,
            "assessments": len(scores),
            "risk_score": round(sum(scores) / len(scores), 1) if scores else None,
        }
        for day, scores in buckets.items()
    ]


async def _build_overview(db: AsyncSession) -> dict:
    now = datetime.now(UTC)
    severity_rows = dict(
        (
            await db.execute(select(Finding.severity, func.count()).group_by(Finding.severity))
        ).all()
    )
    severity_counts = {level: int(severity_rows.get(level, 0)) for level in SEVERITIES}

    module_assessment_counts = dict(
        (
            await db.execute(select(Assessment.module, func.count()).group_by(Assessment.module))
        ).all()
    )
    module_risk = dict(
        (
            await db.execute(
                select(Assessment.module, func.avg(Assessment.risk_score))
                .where(Assessment.status == "completed")
                .group_by(Assessment.module)
            )
        ).all()
    )
    module_finding_counts = dict(
        (
            await db.execute(select(Finding.module, func.count()).group_by(Finding.module))
        ).all()
    )

    recent = (
        await db.execute(
            select(Assessment)
            .options(selectinload(Assessment.target))
            .order_by(Assessment.created_at.desc())
            .limit(6)
        )
    ).scalars().all()

    rank = case(
        (Finding.severity == "critical", 5),
        (Finding.severity == "high", 4),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 2),
        else_=1,
    )
    top_findings = (
        await db.execute(
            select(Finding)
            .where(Finding.status == "open")
            .order_by(rank.desc(), Finding.cvss_score.desc().nullslast(), Finding.created_at.desc())
            .limit(5)
        )
    ).scalars().all()

    trend_rows = (
        await db.execute(
            select(Assessment.created_at, Assessment.risk_score)
            .where(
                Assessment.status == "completed",
                Assessment.created_at >= now - timedelta(days=14),
            )
            .order_by(Assessment.created_at.asc())
        )
    ).all()

    activity = (
        await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(8))
    ).scalars().all()

    technique_ids: set[str] = set()
    for row in (
        await db.execute(select(Finding.technique_ids).where(Finding.technique_ids.is_not(None)).limit(5000))
    ).scalars().all():
        for technique_id in row or []:
            if isinstance(technique_id, str) and technique_id.startswith("T"):
                technique_ids.add(technique_id)
    coverage = build_coverage(technique_ids)

    last_week = await _count(
        db, Assessment, Assessment.created_at >= now - timedelta(days=7)
    )
    prior_week = await _count(
        db,
        Assessment,
        Assessment.created_at >= now - timedelta(days=14),
        Assessment.created_at < now - timedelta(days=7),
    )

    stats = {
        "total_assessments": await _count(db, Assessment),
        "completed_assessments": await _count(db, Assessment, Assessment.status == "completed"),
        "active_assessments": await _count(
            db, Assessment, Assessment.status.in_(["queued", "running"])
        ),
        "total_findings": sum(severity_counts.values()),
        "open_findings": await _count(db, Finding, Finding.status == "open"),
        "critical_findings": severity_counts["critical"],
        "high_findings": severity_counts["high"],
        "verified_targets": await _count(db, Target, Target.status == "verified"),
        "pending_targets": await _count(db, Target, Target.status == "pending"),
        "reports": await _count(db, Report),
        "avg_risk": round(
            float(
                (
                    await db.execute(
                        select(func.avg(Assessment.risk_score)).where(Assessment.status == "completed")
                    )
                ).scalar_one()
                or 0
            ),
            1,
        ),
        "assessments_last_7_days": last_week,
        "assessments_prior_7_days": prior_week,
    }

    payload = {
        "stats": stats,
        "severity": [
            {"name": level, "value": count} for level, count in severity_counts.items()
        ],
        "risk_trend": _trend(list(trend_rows)),
        "modules": [
            {
                "module": module,
                "assessments": int(module_assessment_counts.get(module, 0)),
                "findings": int(module_finding_counts.get(module, 0)),
                "avg_risk": round(float(module_risk.get(module) or 0), 1),
            }
            for module in ALL_MODULES
        ],
        "recent_assessments": [
            assessment_out(row).model_dump(mode="json") for row in recent
        ],
        "top_findings": [finding_out(row).model_dump(mode="json") for row in top_findings],
        "activity": [
            {
                "id": row.id,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "outcome": row.outcome,
                "actor": row.actor_email or "system",
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in activity
        ],
        "mitre": {
            "covered": coverage["covered"],
            "total": coverage["total"],
            "percentage": coverage["percentage"],
            "tactics": [
                {
                    "id": tactic["id"],
                    "name": tactic["name"],
                    "shortname": tactic["shortname"],
                    "covered": tactic["covered"],
                    "total": tactic["total"],
                    "percentage": tactic["percentage"],
                }
                for tactic in coverage["tactics"]
            ],
        },
    }
    return payload


@router.get("")
async def dashboard_overview(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    cached = await cache.get(CACHE_KEY)
    payload = copy.deepcopy(cached) if cached else await _build_overview(db)
    if cached is None:
        await cache.set(CACHE_KEY, payload, ttl=20)
    payload["stats"]["unread_notifications"] = await _count(
        db, Notification, Notification.user_id == user.id, Notification.read.is_(False)
    )
    return payload


@router.get("/activity")
async def activity_feed(
    limit: int = 25,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    limit = max(1, min(limit, 100))
    rows = (
        await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))
    ).scalars().all()
    return {
        "items": [
            {
                "id": row.id,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "outcome": row.outcome,
                "actor": row.actor_email or "system",
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ],
        "total": len(rows),
    }
