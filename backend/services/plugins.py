from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import select

from backend.core.exceptions import AresError, NotFoundError
from backend.models.models import Assessment, PluginState, User

PLUGINS_DIR = Path(__file__).resolve().parents[2] / "plugins"
ALLOWED_PERMISSIONS = {"read:findings", "read:assessment", "export:summary"}
MAX_RESULT_BYTES = 100_000


def _manifest_paths() -> list[Path]:
    if not PLUGINS_DIR.exists():
        return []
    return sorted(PLUGINS_DIR.glob("*/plugin.json"))


def _load_manifest(path: Path) -> dict[str, Any] | None:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    required = {"id", "name", "version", "description", "entrypoint", "permissions"}
    if not required.issubset(manifest):
        return None
    plugin_id = str(manifest["id"])
    if not plugin_id.replace("-", "").replace("_", "").isalnum() or len(plugin_id) > 80:
        return None
    entrypoint = str(manifest["entrypoint"])
    if ":" not in entrypoint:
        return None
    filename, function = entrypoint.split(":", 1)
    if "/" in filename or "\\" in filename or ".." in filename or not filename.endswith(".py"):
        return None
    if not function.replace("_", "").isalnum():
        return None
    if not set(manifest["permissions"]).issubset(ALLOWED_PERMISSIONS):
        return None
    manifest["_path"] = str(path.parent)
    manifest["_entry_file"] = filename
    manifest["_entry_function"] = function
    return manifest


def discover_plugins() -> list[dict[str, Any]]:
    manifests = []
    for path in _manifest_paths():
        manifest = _load_manifest(path)
        if manifest:
            manifests.append(manifest)
    return manifests


async def list_plugins(db) -> list[dict[str, Any]]:
    states = {
        state.plugin_id: state
        for state in (await db.execute(select(PluginState))).scalars().all()
    }
    output = []
    for manifest in discover_plugins():
        state = states.get(manifest["id"])
        enabled = state.enabled if state else bool(manifest.get("enabled_default", False))
        output.append(
            {
                "id": manifest["id"],
                "name": manifest["name"],
                "version": manifest["version"],
                "description": manifest["description"],
                "author": manifest.get("author", "unknown"),
                "permissions": manifest["permissions"],
                "enabled": enabled,
                "path": f"plugins/{Path(manifest['_path']).name}",
                "min_ares_version": manifest.get("min_ares_version"),
            }
        )
    return output


async def set_plugin_enabled(db, plugin_id: str, enabled: bool, user: User) -> dict[str, Any]:
    manifest = next((item for item in discover_plugins() if item["id"] == plugin_id), None)
    if not manifest:
        raise NotFoundError("Plugin", plugin_id)
    state = await db.get(PluginState, plugin_id)
    if state:
        state.enabled = enabled
        state.enabled_by = user.email
    else:
        state = PluginState(plugin_id=plugin_id, enabled=enabled, enabled_by=user.email)
        db.add(state)
    await db.commit()
    return {"id": plugin_id, "enabled": enabled, "enabled_by": user.email}


def _execute_plugin(manifest: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    path = Path(manifest["_path"]) / manifest["_entry_file"]
    if PLUGINS_DIR.resolve() not in path.resolve().parents:
        raise AresError("Plugin path escaped the plugin directory.", status_code=400)
    module_name = f"ares_plugin_{manifest['id']}_{manifest['version'].replace('.', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise AresError("Plugin could not be loaded.", status_code=500)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        function = getattr(module, manifest["_entry_function"], None)
        if not callable(function):
            raise AresError("Plugin entrypoint is not callable.", status_code=500)
        result = function(context)
    finally:
        sys.modules.pop(module_name, None)
    if not isinstance(result, dict):
        raise AresError("Plugin result must be an object.", status_code=500)
    encoded = json.dumps(result, default=str)
    if len(encoded.encode()) > MAX_RESULT_BYTES:
        raise AresError("Plugin result exceeds the 100 KB cap.", status_code=500)
    return json.loads(encoded)


async def run_plugin(db, plugin_id: str, assessment_id: str, user: User) -> dict[str, Any]:
    manifest = next((item for item in discover_plugins() if item["id"] == plugin_id), None)
    if not manifest:
        raise NotFoundError("Plugin", plugin_id)
    state = await db.get(PluginState, plugin_id)
    enabled = state.enabled if state else bool(manifest.get("enabled_default", False))
    if not enabled:
        raise AresError("Plugin is disabled. An administrator must enable it first.", status_code=403)
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise NotFoundError("Assessment", assessment_id)
    from backend.models.models import Finding

    findings = (
        await db.execute(select(Finding).where(Finding.assessment_id == assessment_id))
    ).scalars().all()
    context = {
        "assessment_id": assessment.id,
        "assessment": {
            "name": assessment.name,
            "module": assessment.module,
            "status": assessment.status,
            "risk_score": assessment.risk_score,
            "summary": assessment.summary,
            "is_demo": assessment.is_demo,
        },
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "cvss_score": finding.cvss_score,
                "cve_id": finding.cve_id,
                "status": finding.status,
                "technique_ids": finding.technique_ids,
            }
            for finding in findings
        ],
        "requested_by": {"id": user.id, "name": user.name, "role": user.role},
    }
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_execute_plugin, manifest, context),
            timeout=10,
        )
    except TimeoutError as exc:
        raise AresError("Plugin execution timed out.", status_code=504) from exc
    return result
