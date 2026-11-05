from __future__ import annotations

from backend.api.assessments import findings_router, router as assessments_router
from backend.api.auth import router as auth_router
from backend.api.dashboard import router as dashboard_router
from backend.api.mitre import router as mitre_router
from backend.api.modules import router as modules_router
from backend.api.notifications import router as notifications_router
from backend.api.platform import router as platform_router
from backend.api.plugins import router as plugins_router
from backend.api.reports import router as reports_router
from backend.api.targets import router as targets_router

__all__ = [
    "assessments_router",
    "auth_router",
    "dashboard_router",
    "findings_router",
    "mitre_router",
    "modules_router",
    "notifications_router",
    "platform_router",
    "plugins_router",
    "reports_router",
    "targets_router",
]
