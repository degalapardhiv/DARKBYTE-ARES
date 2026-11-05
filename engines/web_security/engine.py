from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from engines.base import EngineResult, FindingDraft, RunContext
from engines.common import SafeFetchError, safe_fetch
from engines.reconnaissance.engine import tls_inventory

OWASP_REF = "https://owasp.org/www-project-top-ten/"
HEADERS_REF = "https://owasp.org/www-project-secure-headers/"


def analyze_security_headers(headers: dict[str, str], *, is_https: bool) -> tuple[list[FindingDraft], dict]:
    findings: list[FindingDraft] = []
    lower = {key.lower(): value for key, value in headers.items()}
    checks: dict[str, dict] = {}

    def add(
        name: str,
        present: bool,
        description: str,
        remediation: str,
        severity: str = "medium",
        cvss: float | None = None,
        value: str | None = None,
    ):
        checks[name] = {"present": present, "value": value}
        if not present:
            findings.append(
                FindingDraft(
                    title=description,
                    description=f"Security header check failed: {name}.",
                    severity=severity,
                    cvss_score=cvss,
                    evidence={"header": name, "value": value, "check": "missing-security-header"},
                    remediation=remediation,
                    references=[HEADERS_REF, OWASP_REF],
                    technique_ids=["T1190"],
                )
            )

    csp = lower.get("content-security-policy")
    add(
        "Content-Security-Policy",
        bool(csp),
        "Content-Security-Policy header is missing",
        "Define a restrictive CSP without unsafe-inline/unsafe-eval and deploy it in report-only mode first.",
        "medium",
        5.3,
        csp,
    )
    hsts = lower.get("strict-transport-security")
    if is_https:
        add(
            "Strict-Transport-Security",
            bool(hsts),
            "HSTS is not enforced",
            "Send Strict-Transport-Security with max-age of at least six months, includeSubDomains, and preload after validation.",
            "medium",
            4.9,
            hsts,
        )
    xfo = lower.get("x-frame-options")
    frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    add(
        "X-Frame-Options",
        bool(xfo) or frame_ancestors,
        "Clickjacking protection is not configured",
        "Set X-Frame-Options: DENY (or SAMEORIGIN) and use CSP frame-ancestors.",
        "medium",
        5.4,
        xfo,
    )
    xcto = lower.get("x-content-type-options")
    add(
        "X-Content-Type-Options",
        (xcto or "").lower() == "nosniff",
        "MIME sniffing protection is missing",
        "Add X-Content-Type-Options: nosniff to all responses.",
        "low",
        3.1,
        xcto,
    )
    referrer = lower.get("referrer-policy")
    add(
        "Referrer-Policy",
        bool(referrer),
        "Referrer-Policy header is missing",
        "Use a strict referrer policy such as strict-origin-when-cross-origin or no-referrer.",
        "low",
        3.1,
        referrer,
    )
    permissions = lower.get("permissions-policy")
    add(
        "Permissions-Policy",
        bool(permissions),
        "Permissions-Policy header is missing",
        "Restrict powerful browser features (camera, microphone, geolocation) with Permissions-Policy.",
        "info",
        0.0,
        permissions,
    )

    acao = lower.get("access-control-allow-origin")
    acac = lower.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(
            FindingDraft(
                title="Wildcard CORS origin with credentials enabled",
                description="The application reflects wildcard origins while permitting credentials, enabling cross-site data theft if browsers honor the combination.",
                severity="high",
                cvss_score=7.5,
                evidence={"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
                remediation="Return an explicit allowlist of trusted origins and never pair wildcard CORS with credentials.",
                references=[OWASP_REF],
                technique_ids=["T1190"],
            )
        )
        checks["CORS"] = {"present": False, "value": f"{acao} / credentials={acac}"}
    elif acao == "*":
        checks["CORS"] = {"present": True, "value": acao}

    cookie_issues: list[str] = []
    for cookie in lower.get("set-cookie", "").split(","):
        if not cookie:
            continue
        cookie_lower = cookie.lower()
        name = cookie.split("=", 1)[0].strip()[:80]
        if "secure" not in cookie_lower and is_https:
            cookie_issues.append(f"{name}: missing Secure")
        if "httponly" not in cookie_lower and any(token in name.lower() for token in ("session", "auth", "token")):
            cookie_issues.append(f"{name}: missing HttpOnly")
        if "samesite" not in cookie_lower:
            cookie_issues.append(f"{name}: missing SameSite")
    checks["Cookies"] = {"present": not cookie_issues, "value": cookie_issues[:10]}
    if cookie_issues:
        findings.append(
            FindingDraft(
                title="Cookie security attributes are incomplete",
                description="Session cookies lack defense-in-depth attributes, increasing exposure to script access and cross-site requests.",
                severity="medium",
                cvss_score=5.3,
                evidence={"issues": cookie_issues[:10]},
                remediation="Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies and scope the domain narrowly.",
                references=[OWASP_REF],
                technique_ids=["T1190", "T1539"],
            )
        )

    server = lower.get("server")
    powered = lower.get("x-powered-by")
    if server or powered:
        findings.append(
            FindingDraft(
                title="Technology version disclosure in response headers",
                description="Server/framework headers expose implementation details that help attackers select known exploits.",
                severity="low",
                cvss_score=3.7,
                evidence={"server": server, "x-powered-by": powered},
                remediation="Remove unnecessary version tokens and keep exposed components patched.",
                references=[OWASP_REF],
            )
        )
        checks["ServerDisclosure"] = {"present": False, "value": server or powered}
    return findings, checks


async def inspect_tls(host: str, timeout: float) -> dict:
    info = await tls_inventory(host, timeout)
    if not info.get("available"):
        return info
    protocol = info.get("protocol", "")
    info["weak_protocol"] = protocol in {"TLSv1", "TLSv1.1"}
    return info


async def run(context: RunContext, config: dict) -> EngineResult:
    target = context.target
    raw = str(target["value"])
    parsed = urlparse(raw)
    if target.get("target_type") == "domain":
        base_url = f"https://{raw.strip('/')}/"
        host = raw
    elif parsed.scheme in {"http", "https"}:
        base_url = raw if raw.endswith("/") else raw + "/"
        host = parsed.hostname or ""
    else:
        raise ValueError("Web assessment requires a URL or domain target.")

    result = EngineResult()
    timeout = float(config.get("timeout", 8.0))
    checks: dict = {}
    try:
        response = await safe_fetch(
            base_url,
            context,
            timeout=timeout,
            max_bytes=750_000,
            allow_redirects=True,
        )
    except SafeFetchError as exc:
        result.findings.append(
            FindingDraft(
                title="Web endpoint could not be assessed",
                description="The scoped HTTP request failed before security checks could complete.",
                severity="info",
                evidence={"target": base_url, "error": str(exc)},
                remediation="Confirm the endpoint is online, the hostname resolves from the assessment node, and scope is accurate.",
            )
        )
        result.summary = {
            "url": base_url,
            "reachable": False,
            "error": str(exc),
            "headers": {},
            "checks": {},
            "notice": "No findings inferred from an unreachable endpoint.",
        }
        return result.finalize("web")

    headers = response["headers"]
    is_https = response["final_url"].startswith("https://")
    if config.get("include_headers", True):
        header_findings, checks = analyze_security_headers(headers, is_https=is_https)
        result.findings.extend(header_findings)
    if not is_https:
        result.findings.append(
            FindingDraft(
                title="Web endpoint served over cleartext HTTP",
                description="Traffic to this endpoint is not protected by TLS, exposing credentials, tokens and content in transit.",
                severity="high",
                cvss_score=7.4,
                evidence={"final_url": response["final_url"]},
                remediation="Redirect all HTTP traffic to HTTPS and enable HSTS after validation.",
                references=[OWASP_REF],
                technique_ids=["T1040", "T1190"],
            )
        )

    tls_info: dict = {}
    if config.get("include_tls", True) and is_https:
        tls_info = await inspect_tls(host, timeout)
        if tls_info.get("weak_protocol"):
            result.findings.append(
                FindingDraft(
                    title="Deprecated TLS protocol negotiated",
                    description="The endpoint negotiated TLS 1.0/1.1, which is deprecated and lacks modern cipher guarantees.",
                    severity="high",
                    cvss_score=7.4,
                    evidence={"protocol": tls_info.get("protocol"), "cipher": tls_info.get("cipher")},
                    remediation="Disable TLS 1.0/1.1; require TLS 1.2+ with modern AEAD cipher suites.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    technique_ids=["T1040"],
                )
            )
        if not tls_info.get("available"):
            result.findings.append(
                FindingDraft(
                    title="TLS configuration could not be validated",
                    description="The TLS handshake failed during the assessment. The certificate or protocol configuration may be invalid.",
                    severity="medium",
                    cvss_score=4.8,
                    evidence={"error": tls_info.get("error", "unknown"), "host": host},
                    remediation="Verify certificate chain, hostname coverage, expiry and supported protocols.",
                    technique_ids=["T1590"],
                )
            )

    misconfig: dict = {}
    if config.get("include_misconfig", True):
        for path, label in (("/.git/HEAD", "git metadata"), ("/.env", "environment file")):
            url = base_url.rstrip("/") + path
            try:
                probe = await safe_fetch(url, context, timeout=min(timeout, 6.0), max_bytes=32_000)
                exposed = False
                if path == "/.git/HEAD" and probe["status_code"] == 200 and probe["body"].startswith("ref:"):
                    exposed = True
                elif path == "/.env" and probe["status_code"] == 200 and re.search(
                    r"(?im)^(DB_|DATABASE_|AWS_|SECRET_|API_)[A-Z0-9_]*=", probe["body"]
                ):
                    exposed = True
                misconfig[path] = {"status": probe["status_code"], "exposed": exposed}
                if exposed:
                    result.findings.append(
                        FindingDraft(
                            title=f"Sensitive {label} exposed",
                            description=f"The scoped probe returned recognizable {label} content at {path}.",
                            severity="high",
                            cvss_score=7.5,
                            evidence={"url": url, "status": probe["status_code"], "bytes": probe["body_bytes"]},
                            remediation="Block dotfiles at the web server, remove them from the document root, rotate exposed secrets, and redeploy from a clean artifact.",
                            references=[OWASP_REF],
                            technique_ids=["T1552", "T1190"],
                        )
                    )
            except Exception as exc:
                misconfig[path] = {"status": None, "error": type(exc).__name__}

    lab_probes: dict = {"executed": False}
    if config.get("reflection_probe") or config.get("sqli_probe"):
        if not context.is_lab:
            result.findings.append(
                FindingDraft(
                    title="Lab-only probes were not executed",
                    description="Reflection and SQL error probes require a verified lab target and were skipped for this environment.",
                    severity="info",
                    evidence={"environment": context.environment},
                    remediation="Use a dedicated lab target with explicit authorization for destructive-capable testing.",
                )
            )
        else:
            lab_probes = await safe_lab_probes(
                base_url,
                response["final_url"],
                context,
                timeout,
                bool(config.get("reflection_probe")),
                bool(config.get("sqli_probe")),
            )
            result.findings.extend(lab_probes["findings"])

    passed = sum(1 for item in checks.values() if item.get("present"))
    result.summary = {
        "url": base_url,
        "final_url": response["final_url"],
        "status_code": response["status_code"],
        "reachable": True,
        "headers": response["headers"],
        "header_checks": checks,
        "header_checks_passed": passed,
        "header_checks_total": len(checks),
        "tls": tls_info,
        "misconfiguration_probes": misconfig,
        "lab_probes": lab_probes.get("evidence", {"executed": False}),
        "owasp": {
            "mapping": "A05:2021 Security Misconfiguration, A02:2021 Cryptographic Failures, A03:2021 Injection",
            "reference": OWASP_REF,
        },
        "notice": "Non-destructive checks only. Injection probes are disabled unless a verified lab target explicitly enables them.",
    }
    return result.finalize("web")


async def safe_lab_probes(
    base_url: str,
    final_url: str,
    context: RunContext,
    timeout: float,
    reflection: bool,
    sqli: bool,
) -> dict:
    findings: list[FindingDraft] = []
    evidence: dict = {"executed": True, "mode": "lab-only", "checks": []}
    parsed = urlparse(final_url)
    query = dict(parse_qsl(parsed.query))
    if reflection:
        token = "ares" + secrets.token_hex(6)
        query["ares_probe"] = token
        test_url = urlunparse(parsed._replace(query=urlencode(query)))
        try:
            response = await safe_fetch(test_url, context, timeout=timeout, max_bytes=500_000)
            reflected = token in response["body"]
            evidence["checks"].append({"name": "reflection", "reflected": reflected})
            if reflected:
                findings.append(
                    FindingDraft(
                        title="User input reflected in HTML response",
                        description=(
                            "A unique benign marker was returned in the HTML body. Reflection alone does not prove "
                            "cross-site scripting; context encoding must be verified manually in the lab."
                        ),
                        severity="low",
                        cvss_score=3.7,
                        evidence={"marker": "unique lab marker", "url_path": parsed.path, "lab_only": True},
                        remediation="Apply context-aware output encoding and a strict CSP. Validate with a browser-based test in the lab.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                        technique_ids=["T1059.007"],
                    )
                )
        except Exception as exc:
            evidence["checks"].append({"name": "reflection", "error": type(exc).__name__})
    if sqli:
        error_signatures = [
            "you have an error in your sql syntax",
            "unterminated quoted string",
            "ora-00933",
            "microsoft ole db provider for sql server",
            "postgresql query failed",
            "sqlite error",
            "syntax error at or near",
        ]
        probe_query = dict(parse_qsl(parsed.query))
        key = next(iter(probe_query), "id")
        original = probe_query.get(key, "1")
        probe_query[key] = str(original) + "'"
        test_url = urlunparse(parsed._replace(query=urlencode(probe_query)))
        try:
            response = await safe_fetch(test_url, context, timeout=timeout, max_bytes=500_000)
            haystack = response["body"].lower()
            matched = next((sig for sig in error_signatures if sig in haystack), None)
            evidence["checks"].append({"name": "sql_error_signal", "matched": bool(matched)})
            if matched:
                findings.append(
                    FindingDraft(
                        title="Database error signature observed after quote probe",
                        description=(
                            "A single benign quote marker produced a generic database error signature. "
                            "This is a lab-only signal of unsafe query construction, not proof of exploitability."
                        ),
                        severity="high",
                        cvss_score=8.1,
                        evidence={"parameter": key, "signature": matched, "lab_only": True},
                        remediation="Use parameterized queries, suppress database errors, and validate with a controlled lab exploit exercise.",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        technique_ids=["T1190"],
                    )
                )
        except Exception as exc:
            evidence["checks"].append({"name": "sql_error_signal", "error": type(exc).__name__})
    return {"findings": findings, "evidence": evidence}
