"""Reference ARES plugin: read-only severity aggregation.

Plugins run in the ARES process and must be trusted, reviewed code. They are
disabled by default and can only be enabled by an administrator.
"""
from __future__ import annotations

from typing import Any

LEVELS = ("critical", "high", "medium", "low", "info")


def run(context: dict[str, Any]) -> dict[str, Any]:
    findings = context.get("findings", [])
    counts = {level: 0 for level in LEVELS}
    for finding in findings:
        severity = finding.get("severity", "info")
        if severity in counts:
            counts[severity] += 1
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    top = sorted(
        findings,
        key=lambda item: (rank.get(item.get("severity", "info"), 0), item.get("cvss_score") or 0),
        reverse=True,
    )[:5]
    return {
        "plugin": "severity_summary",
        "assessment_id": context.get("assessment_id"),
        "severity_counts": counts,
        "total_findings": len(findings),
        "top_findings": [
            {
                "title": item.get("title"),
                "severity": item.get("severity"),
                "cvss_score": item.get("cvss_score"),
                "cve_id": item.get("cve_id"),
            }
            for item in top
        ],
        "recommendation": "Remediate critical and high findings first; validate fixes with a scoped retest.",
    }
