from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import httpx

from backend.core.config import get_settings
from backend.services.cache import cache


class NVDUnavailable(Exception):
    pass


def _cvss_from_metrics(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        vector = data.get("vectorString")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return (float(score) if score is not None else None, vector, severity)
    return None, None, None


def normalize_nvd_item(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = [entry.get("value", "") for entry in cve.get("descriptions", []) if entry.get("lang") == "en"]
    metrics = cve.get("metrics", {})
    score, vector, severity = _cvss_from_metrics(metrics)
    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                weaknesses.append(desc["value"])
    references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")][:10]
    return {
        "cve_id": cve_id,
        "title": (descriptions[0][:160] + ("…" if len(descriptions[0]) > 160 else "")) if descriptions else cve_id,
        "description": descriptions[0] if descriptions else "No English description supplied by NVD.",
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": (severity or "").lower() or None,
        "cwe": ", ".join(sorted(set(weaknesses))[:6]),
        "published": cve.get("published", ""),
        "references": references,
        "keywords": [],
        "remediation": "Apply the vendor remediation from the referenced advisory, verify exposure, and monitor for exploitation.",
        "source": "nvd",
    }


class NVDClient:
    def __init__(self) -> None:
        self._last_request = 0.0

    async def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        settings = get_settings()
        key = "nvd:" + hashlib.sha256(
            (settings.nvd_api_url + repr(sorted(params.items()))).encode()
        ).hexdigest()
        cached = await cache.get(key)
        if cached is not None:
            return cached
        delay = 0.7 if settings.nvd_api_key else 6.2
        elapsed = time.monotonic() - self._last_request
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        headers = {"User-Agent": "DARKBYTE-ARES/1.0 vulnerability-lookup"}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(25.0), headers=headers) as client:
                response = await client.get(settings.nvd_api_url, params=params)
                self._last_request = time.monotonic()
                if response.status_code in {403, 429}:
                    raise NVDUnavailable("NVD rate limit reached; configure NVD_API_KEY or retry later.")
                if response.status_code >= 400:
                    raise NVDUnavailable(f"NVD returned HTTP {response.status_code}.")
                payload = response.json()
        except NVDUnavailable:
            raise
        except Exception as exc:
            raise NVDUnavailable(f"NVD request failed: {type(exc).__name__}.") from exc
        await cache.set(key, payload, ttl=settings.cache_ttl_seconds)
        return payload

    async def search(self, *, keyword: str, max_results: int = 20) -> list[dict[str, Any]]:
        payload = await self._get(
            {"keywordSearch": keyword[:120], "resultsPerPage": min(max_results, 50)}
        )
        return [normalize_nvd_item(item) for item in payload.get("vulnerabilities", [])]

    async def by_cve(self, cve_id: str) -> dict[str, Any] | None:
        payload = await self._get({"cveId": cve_id, "resultsPerPage": 1})
        items = payload.get("vulnerabilities", [])
        return normalize_nvd_item(items[0]) if items else None


nvd_client = NVDClient()
