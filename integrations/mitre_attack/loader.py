from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_PATH = Path(__file__).resolve().parent / "data" / "techniques.json"

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

MODULE_TECHNIQUE_MAP: dict[str, list[str]] = {
    "recon": ["T1590", "T1592", "T1595", "T1596"],
    "network": ["T1046", "T1133"],
    "web": ["T1190", "T1590"],
    "vulnerability": ["T1190", "T1595"],
    "osint": ["T1590", "T1592", "T1596"],
    "api_security": ["T1190", "T1078"],
    "red_team": ["T1566", "T1204", "T1078", "T1046", "T1087", "T1003", "T1021", "T1562", "T1486"],
}


@lru_cache
def _load() -> dict[str, Any]:
    with DATA_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def metadata() -> dict[str, Any]:
    return _load()["metadata"]


def get_tactics() -> list[dict[str, Any]]:
    tactics = _load()["tactics"]
    return sorted(
        tactics,
        key=lambda item: TACTIC_ORDER.index(item.get("shortname", ""))
        if item.get("shortname") in TACTIC_ORDER
        else 99,
    )


def get_techniques(
    *,
    query: str | None = None,
    tactic: str | None = None,
    include_subtechniques: bool = False,
    limit: int = 250,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    techniques = _load()["techniques"]
    if not include_subtechniques:
        techniques = [item for item in techniques if not item.get("subtechnique")]
    if tactic:
        techniques = [item for item in techniques if tactic in item.get("tactics", [])]
    if query:
        needle = query.lower()
        techniques = [
            item
            for item in techniques
            if needle in item.get("id", "").lower()
            or needle in item.get("name", "").lower()
            or needle in item.get("description", "").lower()
        ]
    total = len(techniques)
    return techniques[offset : offset + limit], total


def get_technique(technique_id: str) -> dict[str, Any] | None:
    needle = technique_id.upper()
    return next((item for item in _load()["techniques"] if item["id"] == needle), None)


def build_coverage(covered_ids: list[str] | set[str]) -> dict[str, Any]:
    covered = {item.upper() for item in covered_ids if item.startswith("T")}
    expanded = set(covered)
    for technique_id in list(covered):
        if "." in technique_id:
            expanded.add(technique_id.split(".", 1)[0])
    techniques = [item for item in _load()["techniques"] if not item.get("subtechnique")]
    tactics = get_tactics()
    rows = []
    total_covered = 0
    for tactic in tactics:
        tactic_techniques = [item for item in techniques if tactic["shortname"] in item.get("tactics", [])]
        hit = [item for item in tactic_techniques if item["id"] in expanded]
        total_covered += len(hit)
        rows.append(
            {
                "id": tactic["id"],
                "name": tactic["name"],
                "shortname": tactic["shortname"],
                "total": len(tactic_techniques),
                "covered": len(hit),
                "percentage": round((len(hit) / len(tactic_techniques)) * 100, 1) if tactic_techniques else 0,
                "covered_ids": [item["id"] for item in hit][:50],
            }
        )
    return {
        "covered": len(expanded & {item["id"] for item in techniques}),
        "total": len(techniques),
        "percentage": round((len(expanded & {item["id"] for item in techniques}) / len(techniques)) * 100, 1)
        if techniques
        else 0,
        "tactics": rows,
        "observed_technique_ids": sorted(covered),
        "source": metadata(),
    }
