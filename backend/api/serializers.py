from __future__ import annotations

from typing import Any

from backend.models.models import Assessment, Finding
from backend.schemas.schemas import AssessmentOut, FindingOut


def assessment_out(assessment: Assessment) -> AssessmentOut:
    payload = AssessmentOut.model_validate(assessment)
    target = getattr(assessment, "target", None)
    if target is not None:
        payload.target_name = target.name
        payload.target_value = target.value
    return payload


def finding_out(finding: Finding) -> FindingOut:
    return FindingOut.model_validate(finding)


def page(items: list[Any], total: int, limit: int, offset: int) -> dict[str, Any]:
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
