from __future__ import annotations

from datetime import UTC, datetime

from backend.core.config import get_settings
from backend.core.exceptions import AuthorizationError, NotFoundError
from backend.models.models import Target, User

MODULE_ACTION: dict[str, str] = {
    "recon": "recon",
    "network": "network_scan",
    "web": "web_scan",
    "vulnerability": "vulnerability_lookup",
    "osint": "osint",
    "password": "password_audit",
    "active_directory": "config_audit",
    "cloud": "cloud_audit",
    "api_security": "api_scan",
    "red_team": "simulation",
}

MODULE_TARGET_TYPES: dict[str, set[str]] = {
    "recon": {"domain"},
    "network": {"ip", "cidr"},
    "web": {"url", "domain"},
    "vulnerability": {"domain", "url", "local"},
    "osint": {"domain"},
    "password": {"password_policy", "local"},
    "active_directory": {"ad_config", "local"},
    "cloud": {"cloud_account", "local"},
    "api_security": {"api", "url"},
    "red_team": {
        "domain", "ip", "cidr", "url", "api", "cloud_account",
        "ad_config", "password_policy", "local",
    },
}


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def validate_target_record(target: Target, module: str, *, settings=None) -> None:
    settings = settings or get_settings()
    if module not in MODULE_ACTION:
        raise AuthorizationError("Unknown assessment module.")
    if settings.require_verified_targets and target.status != "verified":
        raise AuthorizationError(
            f"Target '{target.name}' is {target.status}. An administrator must verify the written authorization before assessment."
        )
    if target.is_demo and settings.is_production:
        raise AuthorizationError("Demo targets are disabled in production.")
    expiry = _aware(target.authorization_expires)
    if expiry and expiry <= datetime.now(UTC):
        raise AuthorizationError("The authorization record for this target has expired.")
    action = MODULE_ACTION[module]
    if action not in (target.allowed_actions or []):
        raise AuthorizationError(
            f"The scope allowlist does not permit '{action}' for target '{target.name}'."
        )
    if target.target_type not in MODULE_TARGET_TYPES[module]:
        allowed = ", ".join(sorted(MODULE_TARGET_TYPES[module]))
        raise AuthorizationError(
            f"Module '{module}' requires target type(s): {allowed}. Target is {target.target_type}."
        )


async def ensure_target_authorized(
    db,
    target_id: str,
    module: str,
    *,
    user: User | None = None,
    settings=None,
) -> Target:
    target = await db.get(Target, target_id)
    if not target:
        raise NotFoundError("Target", target_id)
    validate_target_record(target, module, settings=settings)
    return target


async def verify_target_admin(user: User) -> None:
    if user.role != "admin":
        raise AuthorizationError("Only an administrator can verify or reject target authorization.")
