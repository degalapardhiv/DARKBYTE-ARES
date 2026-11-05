from __future__ import annotations

import asyncio
from urllib.parse import urljoin

from engines.base import EngineResult, FindingDraft, RunContext
from engines.common import SafeFetchError, safe_fetch
from engines.web_security.engine import analyze_security_headers

SENSITIVE_HINTS = {"admin", "internal", "user", "account", "billing", "token", "config", "debug", "actuator"}


async def run(context: RunContext, config: dict) -> EngineResult:
    target = context.target
    base_url = str(target["value"]).rstrip("/") + "/"
    result = EngineResult()
    timeout = float(config.get("timeout", 7.0))
    endpoints = config.get("endpoints") or ["/", "/health", "/api"]

    headers_checked = 0
    try:
        baseline = await safe_fetch(base_url, context, timeout=timeout, max_bytes=500_000, allow_redirects=True)
        header_findings, checks = analyze_security_headers(
            baseline["headers"], is_https=baseline["final_url"].startswith("https://")
        )
        result.findings.extend(header_findings)
        headers_checked = len(checks)
    except SafeFetchError as exc:
        result.findings.append(
            FindingDraft(
                title="API base endpoint could not be assessed",
                description="The scoped API request failed before checks could complete.",
                severity="info",
                evidence={"url": base_url, "error": str(exc)},
                remediation="Verify that the API is reachable from the assessment node and that the scope is correct.",
            )
        )
        result.summary = {"base_url": base_url, "reachable": False, "error": str(exc), "endpoints": []}
        return result.finalize("api_security")

    inventory: list[dict] = []
    unauthenticated: list[dict] = []
    for path in endpoints:
        url = urljoin(base_url, path.lstrip("/"))
        try:
            response = await safe_fetch(url, context, timeout=timeout, max_bytes=200_000)
            content_type = response["headers"].get("content-type", "")
            entry = {
                "path": path,
                "status_code": response["status_code"],
                "content_type": content_type[:100],
                "bytes": response["body_bytes"],
                "server": response["headers"].get("server"),
            }
            inventory.append(entry)
            sensitive = any(hint in path.lower() for hint in SENSITIVE_HINTS)
            if response["status_code"] in {200, 201, 202, 204} and not any(
                hint in path.lower() for hint in {"health", "status", "public", "docs"}
            ):
                unauthenticated.append({**entry, "sensitive_path_hint": sensitive})
        except Exception as exc:
            inventory.append({"path": path, "status_code": None, "error": type(exc).__name__})
        await asyncio.sleep(0.2)

    if unauthenticated and config.get("include_auth_checks", True):
        if any(item["sensitive_path_hint"] for item in unauthenticated):
            result.findings.append(
                FindingDraft(
                    title="Potentially sensitive API endpoint returned data without authentication",
                    description="A GET request without credentials returned a success response for an endpoint whose name suggests sensitive functionality. Confirm whether the resource is intentionally public.",
                    severity="high",
                    cvss_score=7.5,
                    evidence={"endpoints": unauthenticated[:8], "note": "No authentication bypass was attempted."},
                    remediation="Enforce authentication and object-level authorization, return 401/403 by default, and add contract tests for every route.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                    technique_ids=["T1190", "T1078"],
                )
            )
        else:
            result.findings.append(
                FindingDraft(
                    title="API endpoints respond without authentication",
                    description="Several endpoints returned success to anonymous GET requests. Public endpoints are acceptable only when explicitly intended.",
                    severity="low",
                    cvss_score=3.1,
                    evidence={"endpoints": unauthenticated[:8]},
                    remediation="Confirm the public contract, keep sensitive fields out of anonymous responses, and document exposure.",
                    technique_ids=["T1190"],
                )
            )

    cors: dict = {}
    if config.get("include_cors_check", True):
        origin = "https://ares.invalid"
        try:
            cors_response = await safe_fetch(
                base_url,
                context,
                timeout=timeout,
                max_bytes=64_000,
                method="OPTIONS",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization",
                },
            )
            allow_origin = cors_response["headers"].get("access-control-allow-origin")
            allow_credentials = cors_response["headers"].get("access-control-allow-credentials", "")
            cors = {
                "allow_origin": allow_origin,
                "allow_credentials": allow_credentials,
                "status_code": cors_response["status_code"],
            }
            if allow_origin == origin and allow_credentials.lower() == "true":
                result.findings.append(
                    FindingDraft(
                        title="CORS reflects arbitrary origins with credentials",
                        description="The API reflects the supplied hostile origin and allows credentials, enabling cross-origin data theft from authenticated browsers.",
                        severity="high",
                        cvss_score=8.1,
                        evidence=cors,
                        remediation="Allowlist trusted origins and never combine reflected origins with credentials.",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        technique_ids=["T1190", "T1539"],
                    )
                )
            elif allow_origin == "*" and allow_credentials.lower() == "true":
                result.findings.append(
                    FindingDraft(
                        title="Wildcard CORS response with credentials enabled",
                        description="The API advertises a wildcard origin alongside credential support.",
                        severity="high",
                        cvss_score=7.5,
                        evidence=cors,
                        remediation="Use an explicit origin allowlist and separate public/authenticated origins.",
                        technique_ids=["T1190"],
                    )
                )
            elif allow_origin == "*":
                result.findings.append(
                    FindingDraft(
                        title="Wildcard CORS origin advertised",
                        description="Public APIs may intentionally allow wildcard CORS; authenticated APIs should not.",
                        severity="low",
                        cvss_score=3.1,
                        evidence=cors,
                        remediation="Restrict CORS to trusted origins for authenticated routes.",
                        technique_ids=["T1190"],
                    )
                )
        except Exception as exc:
            cors = {"error": type(exc).__name__}

    rate_limit: dict = {"tested": False}
    if config.get("include_rate_limit_check", False):
        statuses = []
        for _ in range(6):
            try:
                response = await safe_fetch(
                    urljoin(base_url, endpoints[0].lstrip("/")),
                    context,
                    timeout=timeout,
                    max_bytes=32_000,
                )
                statuses.append(response["status_code"])
            except Exception:
                statuses.append(None)
            await asyncio.sleep(0.35)
        rate_limit = {
            "tested": True,
            "requests": len(statuses),
            "statuses": statuses,
            "observed_429": 429 in statuses,
        }
        if 429 not in statuses:
            result.findings.append(
                FindingDraft(
                    title="No rate limiting observed in a limited API probe",
                    description="Six spaced requests did not produce HTTP 429. This is not conclusive and does not attempt to exhaust limits.",
                    severity="low",
                    cvss_score=3.7,
                    evidence=rate_limit,
                    remediation="Enforce per-identity and per-IP rate limits with structured 429 responses and monitoring.",
                    technique_ids=["T1110", "T1190"],
                )
            )

    if not result.findings:
        result.findings.append(
            FindingDraft(
                title="API baseline checks completed without notable findings",
                description="No missing headers, anonymous sensitive endpoints or CORS misconfiguration met the reporting threshold.",
                severity="info",
                evidence={"endpoints": len(inventory)},
                remediation="Add authenticated authorization tests and schema validation in a lab environment.",
            )
        )

    result.summary = {
        "base_url": base_url,
        "reachable": True,
        "endpoints": inventory,
        "endpoint_count": len(inventory),
        "unauthenticated_responses": unauthenticated,
        "cors": cors,
        "rate_limit": rate_limit,
        "header_checks": headers_checked,
        "notice": "Only safe GET/OPTIONS probes with a small request budget. No authorization bypass or exploit payload is used.",
    }
    return result.finalize("api_security")
