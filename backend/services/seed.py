from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.core.config import get_settings
from backend.core.security import hash_password
from backend.database.session import async_session_factory
from backend.models.models import (
    Assessment,
    Finding,
    Notification,
    Target,
    User,
)
from backend.services.audit import append_audit
from backend.services.reporting import generate_report

logger = logging.getLogger("ares.seed")


def _demo_finding(**kwargs) -> dict:
    kwargs["is_demo"] = True
    kwargs.setdefault("status", "open")
    kwargs.setdefault("technique_ids", [])
    kwargs.setdefault("references", [])
    kwargs.setdefault("evidence", {"dataset": "DARKBYTE ARES demonstration data", "live": False})
    return kwargs


async def seed_database() -> None:
    settings = get_settings()
    async with async_session_factory() as db:
        if settings.demo_mode:
            already = (
                await db.execute(select(Assessment).where(Assessment.is_demo.is_(True)).limit(1))
            ).scalar_one_or_none()
            if already:
                return
            await _seed_demo(db)
            return
        existing = (await db.execute(select(User).limit(1))).scalar_one_or_none()
        if existing:
            return
        if (
            settings.admin_password
            and settings.admin_password != "Ares!Admin2026"
            and len(settings.admin_password) >= 12
        ):
            admin = User(
                email=settings.admin_email,
                name="ARES Administrator",
                password_hash=hash_password(settings.admin_password),
                role="admin",
                is_demo=False,
            )
            db.add(admin)
            await db.commit()
            logger.info("Initial administrator created for %s", settings.admin_email)
        else:
            logger.warning(
                "No users exist. Set a strong ADMIN_PASSWORD or run scripts/create_admin.py before deployment."
            )


async def _seed_demo(db) -> None:
    settings = get_settings()
    now = datetime.now(UTC)
    admin = (await db.execute(select(User).where(User.email == settings.admin_email))).scalar_one_or_none()
    if not admin:
        admin = User(
            email=settings.admin_email,
            name="Ares Administrator",
            password_hash=hash_password(settings.admin_password),
            role="admin",
            is_demo=True,
            preferences={"notifications": True, "compactMode": False, "defaultEnvironment": "lab"},
        )
        db.add(admin)
        await db.flush()
    analyst = (await db.execute(select(User).where(User.email == settings.analyst_email))).scalar_one_or_none()
    if not analyst:
        analyst = User(
            email=settings.analyst_email,
            name="Morgan Vale",
            password_hash=hash_password(settings.analyst_password),
            role="analyst",
            is_demo=True,
            preferences={"notifications": True, "compactMode": False, "defaultEnvironment": "lab"},
        )
        db.add(analyst)
        await db.flush()

    expires = now + timedelta(days=120)
    web_target = Target(
        name="Ares Demo · Public Web",
        target_type="domain",
        value="demo.example.com",
        environment="lab",
        authorization_ref="LAB-ARES-2026-001",
        authorized_by="DarkByteHunter Security Lab",
        authorization_expires=expires,
        allowed_actions=["recon", "web_scan", "vulnerability_lookup", "osint", "simulation"],
        status="verified",
        verified_by=admin.email,
        verified_at=now - timedelta(days=14),
        notes="Demo scope for screenshots and workflow validation. demo.example.com is reserved and is never scanned by the seed process.",
        is_demo=True,
        created_by=analyst.id,
    )
    edge_target = Target(
        name="Ares Demo · Edge Range",
        target_type="cidr",
        value="192.0.2.0/28",
        environment="lab",
        authorization_ref="LAB-ARES-2026-002",
        authorized_by="DarkByteHunter Security Lab",
        authorization_expires=expires,
        allowed_actions=["network_scan", "simulation"],
        status="verified",
        verified_by=admin.email,
        verified_at=now - timedelta(days=12),
        notes="Documentation range (RFC 5737) used only for demo visualization. No live scan is performed for this record.",
        is_demo=True,
        created_by=analyst.id,
    )
    api_target = Target(
        name="Ares Demo · Partner API",
        target_type="api",
        value="https://api.demo.example.com",
        environment="lab",
        authorization_ref="LAB-ARES-2026-003",
        authorized_by="DarkByteHunter Security Lab",
        authorization_expires=expires,
        allowed_actions=["api_scan", "vulnerability_lookup", "simulation"],
        status="verified",
        verified_by=admin.email,
        verified_at=now - timedelta(days=8),
        notes="Demo API scope; no live requests are sent during seeding.",
        is_demo=True,
        created_by=analyst.id,
    )
    local_target = Target(
        name="Ares Demo · Local Audit Workspace",
        target_type="local",
        value="local-audit",
        environment="lab",
        authorization_ref="LAB-ARES-2026-004",
        authorized_by="DarkByteHunter Security Lab",
        authorization_expires=expires,
        allowed_actions=["password_audit", "config_audit", "cloud_audit", "simulation"],
        status="verified",
        verified_by=admin.email,
        verified_at=now - timedelta(days=3),
        notes="Local-only data for password, AD and cloud snapshot analysis demonstrations.",
        is_demo=True,
        created_by=analyst.id,
    )
    db.add_all([web_target, edge_target, api_target, local_target])
    await db.flush()

    assessments: list[Assessment] = []

    recon = Assessment(
        name="External Attack Surface · demo.example.com",
        module="recon",
        target_id=web_target.id,
        config={"include_subdomains": True, "include_whois": True, "include_tls": True, "include_http": True},
        status="completed",
        progress=100,
        summary={
            "domain": "demo.example.com",
            "assets": [
                {"id": "root", "label": "demo.example.com", "type": "domain", "value": "demo.example.com", "risk": "info"},
                {"id": "sub-api", "label": "api.demo.example.com", "type": "subdomain", "value": "203.0.113.22", "risk": "info"},
                {"id": "sub-staging", "label": "staging.demo.example.com", "type": "subdomain", "value": "203.0.113.41", "risk": "medium"},
                {"id": "sub-dev", "label": "dev.demo.example.com", "type": "subdomain", "value": "203.0.113.43", "risk": "medium"},
                {"id": "mx-1", "label": "10 mail.demo.example.com", "type": "mx", "value": "mail.demo.example.com", "risk": "info"},
                {"id": "tech", "label": "nginx, React", "type": "technology", "value": "https", "risk": "info"},
            ],
            "asset_count": 6,
            "subdomains": [
                {"label": "api", "hostname": "api.demo.example.com", "addresses": ["203.0.113.22"]},
                {"label": "staging", "hostname": "staging.demo.example.com", "addresses": ["203.0.113.41"]},
                {"label": "dev", "hostname": "dev.demo.example.com", "addresses": ["203.0.113.43"]},
            ],
            "dns_record_counts": {"A": 1, "AAAA": 1, "MX": 1, "NS": 2, "TXT": 1},
            "risk_score": 44.8,
        },
        risk_score=44.8,
        is_demo=True,
        created_by=analyst.id,
        created_at=now - timedelta(days=2, hours=5),
        started_at=now - timedelta(days=2, hours=4, minutes=50),
        finished_at=now - timedelta(days=2, hours=4, minutes=42),
    )
    network = Assessment(
        name="Edge Range · TCP Service Inventory",
        module="network",
        target_id=edge_target.id,
        config={"ports": [22, 80, 443, 445, 3306, 6379, 8080], "engine": "tcp", "max_hosts": 16},
        status="completed",
        progress=100,
        summary={
            "network": "192.0.2.0/28",
            "hosts_scanned": 4,
            "ports_tested": 7,
            "open_services": 7,
            "hosts": [
                {"address": "192.0.2.11", "hostnames": ["edge-a.demo.example.com"], "open_port_count": 3, "services": [{"port": 22, "service": "ssh", "protocol": "tcp"}, {"port": 443, "service": "https", "protocol": "tcp"}, {"port": 8080, "service": "http-alt", "protocol": "tcp"}]},
                {"address": "192.0.2.12", "hostnames": ["edge-b.demo.example.com"], "open_port_count": 2, "services": [{"port": 445, "service": "smb", "protocol": "tcp"}, {"port": 6379, "service": "redis", "protocol": "tcp"}]},
                {"address": "192.0.2.15", "hostnames": ["db.demo.example.com"], "open_port_count": 2, "services": [{"port": 3306, "service": "mysql", "protocol": "tcp"}, {"port": 22, "service": "ssh", "protocol": "tcp"}]},
            ],
            "topology": {
                "nodes": [
                    {"id": "assessment", "label": "192.0.2.0/28", "type": "root", "risk": "info"},
                    {"id": "host-0", "label": "192.0.2.11", "type": "host", "risk": "info", "open_ports": 3},
                    {"id": "host-0-443", "label": "443/https", "type": "service", "risk": "info"},
                    {"id": "host-0-22", "label": "22/ssh", "type": "service", "risk": "info"},
                    {"id": "host-0-8080", "label": "8080/http-alt", "type": "service", "risk": "info"},
                    {"id": "host-1", "label": "192.0.2.12", "type": "host", "risk": "critical", "open_ports": 2},
                    {"id": "host-1-445", "label": "445/smb", "type": "service", "risk": "high"},
                    {"id": "host-1-6379", "label": "6379/redis", "type": "service", "risk": "critical"},
                    {"id": "host-2", "label": "192.0.2.15", "type": "host", "risk": "high", "open_ports": 2},
                    {"id": "host-2-3306", "label": "3306/mysql", "type": "service", "risk": "high"},
                    {"id": "host-2-22", "label": "22/ssh", "type": "service", "risk": "info"},
                ],
                "edges": [
                    {"source": "assessment", "target": "host-0"}, {"source": "host-0", "target": "host-0-443"},
                    {"source": "host-0", "target": "host-0-22"}, {"source": "host-0", "target": "host-0-8080"},
                    {"source": "assessment", "target": "host-1"}, {"source": "host-1", "target": "host-1-445"},
                    {"source": "host-1", "target": "host-1-6379"}, {"source": "assessment", "target": "host-2"},
                    {"source": "host-2", "target": "host-2-3306"}, {"source": "host-2", "target": "host-2-22"},
                ],
            },
            "scan": {"engine": "tcp"},
            "risk_score": 87.0,
        },
        risk_score=87.0,
        is_demo=True,
        created_by=analyst.id,
        created_at=now - timedelta(days=1, hours=8),
        started_at=now - timedelta(days=1, hours=7, minutes=58),
        finished_at=now - timedelta(days=1, hours=7, minutes=50),
    )
    web = Assessment(
        name="Public Web · OWASP Baseline",
        module="web",
        target_id=web_target.id,
        config={"include_tls": True, "include_headers": True, "include_misconfig": True, "reflection_probe": False, "sqli_probe": False},
        status="completed",
        progress=100,
        summary={
            "url": "https://demo.example.com/",
            "reachable": True,
            "status_code": 200,
            "header_checks_passed": 3,
            "header_checks_total": 7,
            "tls": {"available": True, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "issuer": {"organizationName": "Ares Demo Lab"}},
            "owasp": {"mapping": "A05:2021 Security Misconfiguration, A02:2021 Cryptographic Failures", "reference": "https://owasp.org/www-project-top-ten/"},
            "risk_score": 58.0,
        },
        risk_score=58.0,
        is_demo=True,
        created_by=analyst.id,
        created_at=now - timedelta(days=1, hours=2),
        started_at=now - timedelta(days=1, hours=1, minutes=58),
        finished_at=now - timedelta(days=1, hours=1, minutes=55),
    )
    vulnerability = Assessment(
        name="Known CVE Review · Public Web Stack",
        module="vulnerability",
        target_id=web_target.id,
        config={"keywords": ["log4j", "spring"], "cve_ids": [], "include_live_nvd": False, "include_bundled_snapshot": True},
        status="completed",
        progress=100,
        summary={
            "query": {"keywords": ["log4j", "spring"]},
            "sources": {"bundled_snapshot": {"retrieved": True, "returned": 2, "snapshot_date": "2025-01-15"}},
            "matches": 2,
            "cvss_distribution": {"critical": 2},
            "risk_score": 92.0,
        },
        risk_score=92.0,
        is_demo=True,
        created_by=analyst.id,
        created_at=now - timedelta(hours=20),
        started_at=now - timedelta(hours=19, minutes=58),
        finished_at=now - timedelta(hours=19, minutes=57),
    )
    api = Assessment(
        name="Partner API · Authentication & CORS Baseline",
        module="api_security",
        target_id=api_target.id,
        config={"endpoints": ["/v1/users", "/v1/orders", "/health"], "include_auth_checks": True, "include_cors_check": True, "include_rate_limit_check": True},
        status="completed",
        progress=100,
        summary={
            "base_url": "https://api.demo.example.com/",
            "reachable": True,
            "endpoint_count": 3,
            "endpoints": [
                {"path": "/v1/users", "status_code": 200, "content_type": "application/json", "bytes": 1840},
                {"path": "/v1/orders", "status_code": 401, "content_type": "application/json", "bytes": 122},
                {"path": "/health", "status_code": 200, "content_type": "application/json", "bytes": 32},
            ],
            "cors": {"allow_origin": "https://ares.invalid", "allow_credentials": "true"},
            "rate_limit": {"tested": True, "requests": 6, "statuses": [200, 200, 200, 200, 200, 200], "observed_429": False},
            "risk_score": 62.0,
        },
        risk_score=62.0,
        is_demo=True,
        created_by=admin.id,
        created_at=now - timedelta(hours=9),
        started_at=now - timedelta(hours=8, minutes=58),
        finished_at=now - timedelta(hours=8, minutes=55),
    )
    osint = Assessment(
        name="Public Intelligence · Brand Surface",
        module="osint",
        target_id=web_target.id,
        config={"include_crtsh": True, "include_whois": True, "include_dns": True},
        status="completed",
        progress=100,
        summary={
            "domain": "demo.example.com",
            "evidence": [
                {"type": "dns_inventory", "source": "DNS", "sha256": "9f1c8d4b6e35a923d7c8eb0a5b1d4f0e0f7b3c2a1d4e6f8091a2b3c4d5e6f708", "summary": {"A": 1, "MX": 1, "TXT": 1}},
                {"type": "certificate_transparency", "source": "crt.sh", "sha256": "2a7d4e9c0b1f3e5a6c8d0f2b4a6c8e0d1f3b5a7c9e0d2f4a6b8c0d1e3f5a7b9c", "summary": {"names": 27, "certificates": 14}},
            ],
            "evidence_count": 2,
            "certificate_transparency": {"available": True, "unique_names": 27, "certificates": 14},
            "risk_score": 31.0,
        },
        risk_score=31.0,
        is_demo=True,
        created_by=analyst.id,
        created_at=now - timedelta(days=3, hours=3),
        started_at=now - timedelta(days=3, hours=2, minutes=59),
        finished_at=now - timedelta(days=3, hours=2, minutes=55),
    )
    red_team = Assessment(
        name="Purple Team Tabletop · Discovery",
        module="red_team",
        target_id=local_target.id,
        config={"scenario": "discovery", "technique_ids": ["T1059.001"], "objective": "Validate discovery telemetry and alert quality."},
        status="completed",
        progress=100,
        summary={
            "scenario": "discovery",
            "scenario_name": "Internal discovery detection exercise",
            "mode": "controlled-tabletop",
            "steps": [
                {"step": 1, "technique_id": "T1046", "technique": "Network service discovery", "simulation_mode": "tabletop-only"},
                {"step": 2, "technique_id": "T1087", "technique": "Account discovery", "simulation_mode": "tabletop-only"},
                {"step": 3, "technique_id": "T1082", "technique": "System information discovery", "simulation_mode": "tabletop-only"},
                {"step": 4, "technique_id": "T1018", "technique": "Remote system discovery", "simulation_mode": "tabletop-only"},
            ],
            "coverage_claim": "Planning and detection requirements only; no technique execution.",
            "risk_score": 26.0,
        },
        risk_score=26.0,
        is_demo=True,
        created_by=admin.id,
        created_at=now - timedelta(hours=5),
        started_at=now - timedelta(hours=4, minutes=58),
        finished_at=now - timedelta(hours=4, minutes=56),
    )
    active = Assessment(
        name="Continuous Surface Sweep · demo.example.com",
        module="recon",
        target_id=web_target.id,
        config={"include_subdomains": True, "include_whois": True, "include_tls": True, "include_http": True},
        status="running",
        progress=62,
        summary={"demo_progress": True, "asset_count": 11},
        risk_score=0,
        is_demo=True,
        created_by=analyst.id,
        created_at=now - timedelta(minutes=22),
        started_at=now - timedelta(minutes=21),
    )
    assessments = [recon, network, web, vulnerability, api, osint, red_team, active]
    db.add_all(assessments)
    await db.flush()

    findings: list[Finding] = []

    def add(
        assessment: Assessment,
        target_id: str,
        module: str,
        title: str,
        description: str,
        severity: str,
        cvss: float,
        remediation: str,
        evidence: dict,
        techniques: list[str] | None = None,
        cve: str | None = None,
        vector: str | None = None,
        references: list[str] | None = None,
    ):
        findings.append(
            Finding(
                assessment_id=assessment.id,
                target_id=target_id,
                module=module,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss,
                cvss_vector=vector,
                cve_id=cve,
                evidence=evidence,
                remediation=remediation,
                references=references or [],
                technique_ids=techniques or [],
                status="open",
                is_demo=True,
            )
        )

    add(
        web, web_target.id, "web",
        "Content-Security-Policy header is missing",
        "The demo marketing application returns no Content-Security-Policy. A strict CSP reduces the impact of injected scripts and third-party supply-chain compromise.",
        "medium", 5.3,
        "Define a restrictive CSP without unsafe-inline/unsafe-eval; deploy in report-only mode, validate reports, then enforce.",
        {"url": "https://demo.example.com/", "header": "Content-Security-Policy", "observed": None, "demo": True},
        ["T1190"], references=["https://owasp.org/www-project-secure-headers/"],
    )
    add(
        web, web_target.id, "web",
        "HSTS is not enforced",
        "Strict-Transport-Security is absent despite HTTPS being available. Downgrade and SSL-stripping protections are therefore incomplete.",
        "medium", 4.9,
        "Send Strict-Transport-Security with a validated max-age and includeSubDomains; add preload after reviewing subdomains.",
        {"url": "https://demo.example.com/", "header": "Strict-Transport-Security", "observed": None, "demo": True},
        ["T1040"], references=["https://owasp.org/www-project-secure-headers/"],
    )
    add(
        web, web_target.id, "web",
        "Clickjacking protection is not configured",
        "Neither X-Frame-Options nor CSP frame-ancestors is present on the primary application response.",
        "medium", 5.4,
        "Set X-Frame-Options: DENY and enforce CSP frame-ancestors 'none'.",
        {"url": "https://demo.example.com/", "x-frame-options": None, "csp": None, "demo": True},
        ["T1190"],
    )
    add(
        web, web_target.id, "web",
        "Server banner discloses technology details",
        "The edge response advertises nginx/1.24.0, reducing attacker reconnaissance effort when combined with public CVE data.",
        "low", 3.7,
        "Suppress version tokens and maintain an aggressive patch cadence for the edge tier.",
        {"server": "nginx/1.24.0", "x-powered-by": "Express", "demo": True},
        ["T1592"],
    )
    add(
        network, edge_target.id, "network",
        "Unauthenticated Redis service exposed",
        "A Redis service responds on TCP/6379 within the edge range. Exposed Redis commonly permits data theft or remote compromise when authentication is absent.",
        "critical", 9.8,
        "Bind Redis to private interfaces, require ACL authentication and TLS, disable dangerous commands, and restrict source ranges.",
        {"host": "192.0.2.12", "port": 6379, "service": "redis", "demo": True},
        ["T1046", "T1133"], references=["https://redis.io/docs/latest/operate/oss_and_stack/management/security/"],
    )
    add(
        network, edge_target.id, "network",
        "SMB exposed on an edge host",
        "TCP/445 is reachable from the assessed subnet. SMB is a frequent lateral-movement and credential-relay path.",
        "high", 8.1,
        "Block SMB at network boundaries, require SMB signing, disable SMBv1, and enforce tiered administration.",
        {"host": "192.0.2.12", "port": 445, "service": "smb", "demo": True},
        ["T1021.002"], references=["https://attack.mitre.org/techniques/T1021/002/"],
    )
    add(
        network, edge_target.id, "network",
        "Database service reachable from edge range",
        "TCP/3306 responds on the database host. Database ports should be restricted to application subnets and never exposed broadly.",
        "high", 7.5,
        "Restrict MySQL to application security groups, require TLS and strong authentication, and audit inbound rules.",
        {"host": "192.0.2.15", "port": 3306, "service": "mysql", "demo": True},
        ["T1046", "T1133"],
    )
    add(
        vulnerability, web_target.id, "vulnerability",
        "CVE-2021-44228 — Apache Log4j2 remote code execution (Log4Shell)",
        "JNDI lookup handling in the affected demo component permits remote code execution. This is a real NVD record used in a clearly labelled demonstration dataset.",
        "critical", 10.0,
        "Upgrade Log4j to 2.17.1+ (2.12.4 for Java 7), remove JNDI lookups, and hunt for exploitation indicators.",
        {"source": "bundled-nvd-snapshot", "published": "2021-12-10", "cwe": "CWE-20, CWE-400, CWE-502", "demo": True},
        ["T1190"], cve="CVE-2021-44228", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    )
    add(
        vulnerability, web_target.id, "vulnerability",
        "CVE-2022-22965 — Spring Framework data binding RCE (Spring4Shell)",
        "A vulnerable Spring Framework version is associated with the demo application. The real CVE record is included from the NVD snapshot.",
        "critical", 9.8,
        "Upgrade Spring Framework to 5.3.18+/5.2.20+ and verify all embedded dependencies.",
        {"source": "bundled-nvd-snapshot", "published": "2022-04-01", "cwe": "CWE-94", "demo": True},
        ["T1190"], cve="CVE-2022-22965", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
    )
    add(
        recon, web_target.id, "recon",
        "Potentially sensitive subdomain exposed: staging",
        "staging.demo.example.com resolves publicly and appears in the demo asset inventory. Non-production environments frequently lack production controls.",
        "medium", 5.3,
        "Protect non-production environments with SSO/VPN, remove stale DNS, and monitor certificate transparency.",
        {"hostname": "staging.demo.example.com", "addresses": ["203.0.113.41"], "demo": True},
        ["T1595", "T1590"],
    )
    add(
        recon, web_target.id, "recon",
        "SPF policy not published",
        "No v=spf1 TXT record was present for the demo domain. Receiver-side sender validation is therefore unavailable.",
        "medium", 5.3,
        "Publish a narrow SPF policy ending in -all and review authorized senders quarterly.",
        {"record": "TXT", "control": "SPF", "demo": True},
        ["T1590"], references=["https://www.rfc-editor.org/rfc/rfc7208"],
    )
    add(
        api, api_target.id, "api_security",
        "Potentially sensitive API endpoint returned data without authentication",
        "GET /v1/users returned HTTP 200 JSON without an Authorization header in the demo API exercise. The endpoint should be explicitly public or protected.",
        "high", 7.5,
        "Require authentication and object-level authorization, deny-by-default, and add contract tests covering anonymous requests.",
        {"path": "/v1/users", "status_code": 200, "content_type": "application/json", "demo": True},
        ["T1190", "T1078"], references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    )
    add(
        api, api_target.id, "api_security",
        "CORS reflects arbitrary origins with credentials",
        "The demo API reflected https://ares.invalid and allowed credentials, enabling cross-origin data theft if combined with an authenticated browser session.",
        "high", 8.1,
        "Use a strict origin allowlist and never reflect arbitrary origins with credentials.",
        {"allow_origin": "https://ares.invalid", "allow_credentials": "true", "demo": True},
        ["T1190", "T1539"],
    )
    add(
        api, api_target.id, "api_security",
        "No rate limiting observed in a limited API probe",
        "Six spaced requests to the demo endpoint did not return HTTP 429. The result is advisory and does not prove absence of rate limiting.",
        "low", 3.7,
        "Enforce per-identity and per-IP limits with structured 429 responses and monitoring.",
        {"requests": 6, "observed_429": False, "demo": True},
        ["T1110"],
    )
    add(
        osint, web_target.id, "osint",
        "Public certificate transparency expands asset inventory",
        "27 unique DNS names were observed in certificate transparency for the demo domain, including assets not present in the approved inventory.",
        "info", 0.0,
        "Reconcile discovered names with the asset register and decommission stale services.",
        {"unique_names": 27, "certificates": 14, "source": "crt.sh", "demo": True},
        ["T1596", "T1590"],
    )
    add(
        red_team, local_target.id, "red_team",
        "Detection exercise required for T1046 — Network service discovery",
        "Tabletop simulation only. Confirm that network sweeps produce a correlated alert and document expected telemetry.",
        "low", 3.1,
        "Tune IDS aggregation for internal port sweeps and validate in an isolated lab before claiming coverage.",
        {"simulation": True, "mode": "tabletop-only", "action_executed": False, "demo": True},
        ["T1046"], references=["https://attack.mitre.org/techniques/T1046/"],
    )
    add(
        red_team, local_target.id, "red_team",
        "Detection exercise required for T1087 — Account discovery",
        "Tabletop simulation only. Validate thresholds for directory enumeration and alert enrichment.",
        "low", 3.1,
        "Create a detection for anomalous directory queries and test with synthetic lab identities.",
        {"simulation": True, "mode": "tabletop-only", "action_executed": False, "demo": True},
        ["T1087"], references=["https://attack.mitre.org/techniques/T1087/"],
    )
    add(
        web, web_target.id, "web",
        "Security header evaluation completed",
        "The baseline recorded 3 of 7 expected browser security headers. This informational item preserves the coverage snapshot for trend analysis.",
        "info", 0.0,
        "Track header coverage over time and enforce standards through infrastructure-as-code policy.",
        {"checks_passed": 3, "checks_total": 7, "demo": True},
        [],
    )
    db.add_all(findings)

    db.add_all(
        [
            Notification(
                user_id=admin.id,
                title="Critical exposure requires triage",
                message="The demo edge range exposes Redis and SMB. Review the network assessment and assign remediation owners.",
                level="critical",
                read=False,
                link="/assessments",
                is_demo=True,
            ),
            Notification(
                user_id=admin.id,
                title="Weekly exposure report ready",
                message="The latest internal exposure report is available for download.",
                level="info",
                read=False,
                link="/reports",
                is_demo=True,
            ),
            Notification(
                user_id=analyst.id,
                title="Assessment completed",
                message="Known CVE Review · Public Web Stack completed with 2 matching CVEs.",
                level="success",
                read=True,
                link="/assessments",
                is_demo=True,
            ),
        ]
    )
    await db.commit()

    # Reports are generated from the same demo dataset so downloads work immediately.
    try:
        for assessment_id, fmt, title in [
            (web.id, "pdf", "External Web Baseline · Executive Report"),
            (network.id, "html", "Edge Range Exposure · Technical Report"),
        ]:
            loaded = (
                await db.execute(
                    select(Assessment)
                    .options(selectinload(Assessment.target), selectinload(Assessment.findings))
                    .where(Assessment.id == assessment_id)
                )
            ).scalar_one()
            await generate_report(
                db,
                assessment=loaded,
                target=loaded.target,
                findings=loaded.findings,
                user=admin,
                fmt=fmt,
                title=title,
            )
    except Exception:
        logger.exception("Demo report generation failed; dashboard remains functional.")

    await append_audit(
        db,
        action="demo.seed",
        resource_type="workspace",
        actor=admin,
        details={"assessments": len(assessments), "findings": len(findings), "demo": True},
    )
    await db.commit()
    logger.info("Demo workspace seeded with %s assessments and %s findings", len(assessments), len(findings))
