from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.serializers import assessment_out
from backend.auth.dependencies import get_current_user, require_roles
from backend.core.config import get_settings
from backend.core.rate_limit import enforce_active_scan_limit
from backend.database.session import get_db
from backend.models.models import Assessment, Finding, Notification, User
from backend.schemas.schemas import (
    ALL_MODULES,
    MODULE_CONFIG_SCHEMAS,
    CvssRequest,
    PasswordAuditRequest,
    PasswordAuditResponse,
)
from backend.services.audit import append_audit
from backend.services.authorization import ensure_target_authorized
from engines.base import RunContext
from engines.common import parse_cvss_v3
from engines.password_audit import engine as password_engine
from integrations.mitre_attack.loader import MODULE_TECHNIQUE_MAP

router = APIRouter(tags=["Modules & Tools"])

MODULE_CATALOG: dict[str, dict[str, Any]] = {
    "recon": {
        "name": "Reconnaissance",
        "short": "External asset discovery and attack-surface mapping.",
        "description": "DNS inventory, subdomain discovery, WHOIS metadata, TLS certificate review and bounded HTTP fingerprinting. Passive-first, explicitly scoped.",
        "category": "Discovery",
        "icon": "Radar",
        "accent": "#00E5FF",
        "action": "recon",
        "target_types": ["domain"],
        "capabilities": ["DNS records", "Subdomain inventory", "WHOIS", "TLS certificate", "HTTP fingerprint"],
    },
    "network": {
        "name": "Network Scanner",
        "short": "Bounded TCP service inventory for authorized ranges.",
        "description": "TCP connect scanning with hard host, port and concurrency ceilings. Optional Nmap XML ingestion for lab environments. Risky exposed services are prioritized.",
        "category": "Discovery",
        "icon": "Network",
        "accent": "#00FF88",
        "action": "network_scan",
        "target_types": ["ip", "cidr"],
        "capabilities": ["TCP connect", "Service identification", "Banner metadata", "Topology map", "Nmap XML"],
    },
    "web": {
        "name": "Web Security",
        "short": "OWASP-aligned, non-destructive web baseline.",
        "description": "Security headers, TLS configuration, cookie flags, exposed sensitive files and safe reflection probes. Injection probes remain lab-gated and disabled by default.",
        "category": "Application",
        "icon": "Globe",
        "accent": "#7C3AED",
        "action": "web_scan",
        "target_types": ["url", "domain"],
        "capabilities": ["OWASP mapping", "Security headers", "TLS review", "Cookie flags", "Sensitive files"],
    },
    "vulnerability": {
        "name": "Vulnerability Intelligence",
        "short": "CVE correlation with CVSS v3 scoring.",
        "description": "NVD API queries plus a bundled, dated real-data snapshot for offline resilience. Results are scored with CVSS v3 base metrics and mapped to CWE identifiers.",
        "category": "Intelligence",
        "icon": "ShieldAlert",
        "accent": "#FF3B5C",
        "action": "vulnerability_lookup",
        "target_types": ["domain", "url", "local"],
        "capabilities": ["CVE search", "CVSS v3.1", "CWE mapping", "NVD snapshot", "Offline mode"],
    },
    "osint": {
        "name": "OSINT",
        "short": "Passive public-source intelligence with evidence hashes.",
        "description": "DNS, WHOIS, certificate transparency and authorized public-document metadata. Document bytes are never stored; SHA-256 evidence hashes preserve provenance.",
        "category": "Intelligence",
        "icon": "Fingerprint",
        "accent": "#00E5FF",
        "action": "osint",
        "target_types": ["domain"],
        "capabilities": ["Certificate transparency", "DNS intelligence", "WHOIS", "Document metadata", "Evidence hashing"],
    },
    "password": {
        "name": "Password Audit",
        "short": "Local strength and offline hash hygiene review.",
        "description": "Runs entirely in memory. Plaintext and hashes are never persisted or returned in results. No credential store, domain controller or authentication endpoint is contacted.",
        "category": "Identity",
        "icon": "KeyRound",
        "accent": "#FFB020",
        "action": "password_audit",
        "target_types": ["password_policy", "local"],
        "capabilities": ["Strength scoring", "Policy review", "Offline dictionary audit", "MFA posture", "No plaintext persistence"],
    },
    "active_directory": {
        "name": "Active Directory Audit",
        "short": "Read-only AD configuration posture analysis.",
        "description": "Accepts an exported AD configuration snapshot and reviews password policy, Kerberos, privileged groups and delegation posture. No LDAP connection is made.",
        "category": "Identity",
        "icon": "Building2",
        "accent": "#8B5CF6",
        "action": "config_audit",
        "target_types": ["ad_config", "local"],
        "capabilities": ["Password policy", "Kerberos posture", "Privileged groups", "Delegation review", "Read-only"],
    },
    "cloud": {
        "name": "Cloud Security",
        "short": "Read-only AWS, Azure and GCP configuration review.",
        "description": "Reviews exported configuration snapshots for public storage, weak IAM, logging gaps and network exposure. No cloud credentials are requested or stored.",
        "category": "Cloud",
        "icon": "CloudCog",
        "accent": "#22D3EE",
        "action": "cloud_audit",
        "target_types": ["cloud_account", "local"],
        "capabilities": ["Public storage", "IAM review", "Logging coverage", "Network exposure", "Multi-cloud"],
    },
    "api_security": {
        "name": "API Security",
        "short": "Safe API exposure, auth and CORS baseline.",
        "description": "Bounded GET/OPTIONS probes on authorized origins, anonymous exposure observation, security headers, CORS policy and limited rate-limit evidence. No authorization bypass is attempted.",
        "category": "Application",
        "icon": "Braces",
        "accent": "#A855F7",
        "action": "api_scan",
        "target_types": ["api", "url"],
        "capabilities": ["Anonymous exposure", "CORS policy", "Security headers", "Rate-limit evidence", "Endpoint inventory"],
    },
    "red_team": {
        "name": "Red Team Simulator",
        "short": "Tabletop attack-chain and detection planning.",
        "description": "ATT&CK-mapped tabletop exercises only. ARES does not execute techniques, deploy malware, steal credentials or generate adversary traffic.",
        "category": "Operations",
        "icon": "Swords",
        "accent": "#FF3B5C",
        "action": "simulation",
        "target_types": [
            "domain", "ip", "cidr", "url", "api", "cloud_account",
            "ad_config", "password_policy", "local",
        ],
        "capabilities": ["ATT&CK mapping", "Scenario planning", "Detection requirements", "Tabletop only", "No execution"],
    },
}


@router.get("/modules")
async def list_modules(_: User = Depends(get_current_user)) -> dict:
    items = []
    for module in ALL_MODULES:
        meta = MODULE_CATALOG[module]
        schema_model = MODULE_CONFIG_SCHEMAS.get(module)
        items.append(
            {
                "id": module,
                **meta,
                "techniques": MODULE_TECHNIQUE_MAP.get(module, []),
                "config_schema": schema_model.model_json_schema() if schema_model else None,
                "synchronous_tool": module == "password",
            }
        )
    return {"items": items, "total": len(items)}


@router.get("/modules/{module_id}")
async def get_module(module_id: str, _: User = Depends(get_current_user)) -> dict:
    if module_id not in MODULE_CATALOG:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Module not found."},
        )
    schema_model = MODULE_CONFIG_SCHEMAS.get(module_id)
    return {
        "id": module_id,
        **MODULE_CATALOG[module_id],
        "techniques": MODULE_TECHNIQUE_MAP.get(module_id, []),
        "config_schema": schema_model.model_json_schema() if schema_model else None,
        "synchronous_tool": module_id == "password",
    }


@router.post("/tools/cvss")
async def calculate_cvss(
    payload: CvssRequest,
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        result = parse_cvss_v3(payload.vector)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "invalid_cvss_vector", "message": str(exc)},
        ) from exc
    return {
        "vector": result.vector,
        "score": result.score,
        "severity": result.severity,
        "standard": "CVSS v3.x base",
        "reference": "https://www.first.org/cvss/calculator/3.1",
    }


@router.post("/tools/password-audit", response_model=PasswordAuditResponse)
async def password_audit(
    payload: PasswordAuditRequest,
    request: Request,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> PasswordAuditResponse:
    settings = get_settings()
    target = await ensure_target_authorized(db, payload.target_id, "password", user=user)
    await enforce_active_scan_limit(user.id)
    context = RunContext(
        settings=settings,
        target={
            "id": target.id,
            "name": target.name,
            "target_type": target.target_type,
            "value": target.value,
            "environment": target.environment,
            "authorization_ref": target.authorization_ref,
            "allowed_actions": list(target.allowed_actions or []),
            "is_demo": target.is_demo,
        },
        is_demo=target.is_demo,
    )
    engine_config = {
        "policy": payload.policy.model_dump(mode="json"),
        "test_passwords": payload.test_passwords,
        "hashes": payload.hashes,
        "hash_algorithm": payload.hash_algorithm,
        "wordlist": payload.wordlist,
    }
    try:
        result = await password_engine.run(context, engine_config)
    except Exception as exc:  # noqa: BLE001 - return a safe, non-sensitive failure
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "password_audit_failed",
                "message": f"Password audit could not be completed: {type(exc).__name__}.",
            },
        ) from exc

    # Deliberately persist only aggregate metadata. Inputs and results that could
    # reveal a submitted secret remain in memory for this request only.
    safe_config = {
        "policy": payload.policy.model_dump(mode="json"),
        "hash_algorithm": payload.hash_algorithm,
        "test_password_count": len(payload.test_passwords),
        "hash_count": len(payload.hashes),
        "wordlist_count": len(payload.wordlist),
    }
    assessment = Assessment(
        name=f"{target.name} · Password Audit",
        module="password",
        target_id=target.id,
        config=safe_config,
        status="completed",
        progress=100,
        summary=result.summary,
        risk_score=result.risk_score,
        is_demo=target.is_demo,
        created_by=user.id,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )
    db.add(assessment)
    await db.flush()
    for draft in result.findings:
        payload_dict = draft.to_dict(is_demo=target.is_demo)
        db.add(
            Finding(
                assessment_id=assessment.id,
                target_id=target.id,
                module="password",
                title=payload_dict["title"],
                description=payload_dict["description"],
                severity=payload_dict["severity"],
                cvss_score=payload_dict["cvss_score"],
                cvss_vector=payload_dict["cvss_vector"],
                cve_id=payload_dict["cve_id"],
                evidence=payload_dict["evidence"],
                remediation=payload_dict["remediation"],
                references=payload_dict["references"],
                technique_ids=payload_dict["technique_ids"],
                status="open",
                is_demo=target.is_demo,
            )
        )
    db.add(
        Notification(
            user_id=user.id,
            title=f"Password audit complete · {target.name}",
            message=(
                f"{len(result.findings)} finding(s). Inputs were processed in memory and were not persisted."
            ),
            level="success",
            link=f"/assessments/{assessment.id}",
            is_demo=target.is_demo,
        )
    )
    await append_audit(
        db,
        action="password.audit_completed",
        resource_type="assessment",
        resource_id=assessment.id,
        actor=user,
        details={
            "target_id": target.id,
            "test_password_count": len(payload.test_passwords),
            "hash_count": len(payload.hashes),
            "findings": len(result.findings),
            "plaintext_persisted": False,
        },
        request=request,
    )
    await db.commit()
    loaded = (
        await db.execute(
            select(Assessment)
            .options(selectinload(Assessment.target))
            .where(Assessment.id == assessment.id)
        )
    ).scalar_one()

    return PasswordAuditResponse(
        assessment=assessment_out(loaded),
        strength=result.summary.get("strength", []),
        hash_audit=result.summary.get("hash_audit", {}),
        policy_findings=result.summary.get("policy_findings", []),
    )
