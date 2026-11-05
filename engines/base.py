from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_CVSS = {"info": 0.0, "low": 3.1, "medium": 5.5, "high": 8.1, "critical": 9.6}
CVSS_SEVERITY = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
)


def severity_for_cvss(score: float) -> str:
    for threshold, label in CVSS_SEVERITY:
        if score >= threshold:
            return label
    return "info"


def risk_from_findings(findings: list["FindingDraft"]) -> float:
    """Blend worst-case, breadth and CVSS into a 0–100 risk score."""
    if not findings:
        return 0.0
    scores = [
        finding.cvss_score if finding.cvss_score is not None else SEVERITY_CVSS.get(finding.severity, 0.0)
        for finding in findings
    ]
    max_score = max(scores)
    avg = sum(scores) / len(scores)
    weighted_count = sum(max(0.0, score - 2.0) for score in scores)
    breadth = min(20.0, math.log2(1 + weighted_count) * 5.0)
    score = (max_score / 10.0) * 60.0 + (avg / 10.0) * 20.0 + breadth
    return round(min(100.0, max(0.0, score)), 1)


@dataclass
class FindingDraft:
    title: str
    description: str
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_id: str | None = None
    references: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    status: str = "open"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"invalid severity: {self.severity}")
        if self.cvss_score is None:
            self.cvss_score = SEVERITY_CVSS[self.severity]
        else:
            self.cvss_score = round(float(self.cvss_score), 1)
            if self.severity == "info" and self.cvss_score > 0:
                self.severity = severity_for_cvss(self.cvss_score)

    def to_dict(self, *, is_demo: bool = False) -> dict[str, Any]:
        return {
            "title": self.title[:300],
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cve_id": self.cve_id,
            "references": self.references[:20],
            "technique_ids": self.technique_ids[:20],
            "status": self.status,
            "is_demo": is_demo,
        }


@dataclass
class EngineResult:
    findings: list[FindingDraft] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    engine: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int = 0

    def finalize(self, engine: str) -> "EngineResult":
        self.engine = engine
        self.duration_ms = int((datetime.now(UTC) - self.started_at).total_seconds() * 1000)
        self.summary = {
            **self.summary,
            "engine": engine,
            "finding_count": len(self.findings),
            "findings_by_severity": self.severity_counts(),
            "risk_score": self.risk_score,
            "duration_ms": self.duration_ms,
            "completed_at": datetime.now(UTC).isoformat(),
        }
        return self

    @property
    def risk_score(self) -> float:
        return risk_from_findings(self.findings)

    def severity_counts(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts


@dataclass
class RunContext:
    settings: Any
    target: dict[str, Any]
    is_demo: bool = False
    demo_payload: dict[str, Any] | None = None

    @property
    def environment(self) -> str:
        return self.target.get("environment", "lab")

    @property
    def allow_private(self) -> bool:
        return bool(self.settings.allow_private_targets) and self.environment in {"lab", "staging"}

    @property
    def allow_loopback(self) -> bool:
        return bool(self.settings.allow_loopback_lab) and self.environment == "lab"

    @property
    def is_lab(self) -> bool:
        return self.environment == "lab"
