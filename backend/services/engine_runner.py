from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import get_settings
from backend.core.exceptions import AuthorizationError
from backend.models.models import Assessment
from backend.services.authorization import validate_target_record
from engines.base import EngineResult, RunContext

ENGINE_MODULES = {
    "recon": "engines.reconnaissance.engine",
    "network": "engines.network_scanner.engine",
    "web": "engines.web_security.engine",
    "vulnerability": "engines.vulnerability.engine",
    "osint": "engines.osint.engine",
    "active_directory": "engines.active_directory.engine",
    "cloud": "engines.cloud_security.engine",
    "api_security": "engines.api_security.engine",
    "red_team": "engines.red_team_simulator.engine",
}


def target_payload(target) -> dict[str, Any]:
    return {
        "id": target.id,
        "name": target.name,
        "target_type": target.target_type,
        "value": target.value,
        "environment": target.environment,
        "authorization_ref": target.authorization_ref,
        "allowed_actions": list(target.allowed_actions or []),
        "is_demo": target.is_demo,
    }


async def run_engine(
    db: AsyncSession,
    assessment: Assessment,
    target,
    *,
    config: dict[str, Any] | None = None,
) -> EngineResult:
    """Execute one engine with defense-in-depth scope validation and a hard timeout."""
    settings = get_settings()
    validate_target_record(target, assessment.module, settings=settings)
    if assessment.module not in ENGINE_MODULES:
        raise AuthorizationError(f"Engine '{assessment.module}' cannot be executed by the queue.")
    module_name = ENGINE_MODULES[assessment.module]
    module = __import__(module_name, fromlist=["run"])
    context = RunContext(
        settings=settings,
        target=target_payload(target),
        is_demo=assessment.is_demo,
    )
    effective_config = config if config is not None else assessment.config
    try:
        result = await asyncio.wait_for(
            module.run(context, effective_config),
            timeout=settings.assessment_timeout_seconds,
        )
    except TimeoutError as exc:
        raise RuntimeError(
            f"Engine exceeded the {settings.assessment_timeout_seconds}s assessment timeout."
        ) from exc
    if not isinstance(result, EngineResult):
        raise RuntimeError("Engine returned an invalid result.")
    return result
