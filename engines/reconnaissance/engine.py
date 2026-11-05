from __future__ import annotations

import asyncio
import json
import random
import ssl
import string
from datetime import UTC, datetime
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from engines.base import EngineResult, FindingDraft, RunContext
from engines.common import SafeFetchError, safe_fetch

SUBDOMAIN_WORDLIST = [
    "www", "api", "app", "admin", "portal", "mail", "webmail", "vpn", "dev",
    "staging", "test", "uat", "qa", "docs", "status", "support", "blog", "shop",
    "cdn", "static", "assets", "auth", "sso", "git", "gitlab", "jenkins", "ci",
    "grafana", "monitor", "intranet", "remote", "files", "ftp",
]
EXPOSED_LABELS = {
    "admin", "dev", "staging", "test", "uat", "qa", "git", "gitlab", "jenkins",
    "ci", "grafana", "intranet", "remote", "files", "ftp",
}


async def dns_inventory(domain: str, timeout: float = 5.0) -> dict[str, Any]:
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answer = await resolver.resolve(domain, rtype, lifetime=timeout)
            values: list[str] = []
            for item in answer:
                if rtype == "MX":
                    values.append(f"{item.preference} {item.exchange}".strip())
                elif rtype == "TXT":
                    values.append("".join(part.decode() if isinstance(part, bytes) else str(part) for part in item.strings)[:500])
                elif rtype == "SOA":
                    values.append(str(item))
                else:
                    values.append(str(item).rstrip("."))
            records[rtype] = sorted(set(values))[:50]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[rtype] = []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            records[rtype] = []
            errors[rtype] = type(exc).__name__
        except Exception as exc:  # resolver backends vary by platform
            records[rtype] = []
            errors[rtype] = type(exc).__name__
    try:
        soa = await resolver.resolve(domain, "SOA", lifetime=timeout)
        records["SOA"] = [str(soa[0])]
    except Exception:
        records.setdefault("SOA", [])
    return {"records": records, "errors": errors}


def analyze_email_security(records: dict[str, list[str]]) -> list[FindingDraft]:
    txt = " ".join(records.get("TXT", [])).lower()
    findings: list[FindingDraft] = []
    if "v=spf1" not in txt:
        findings.append(
            FindingDraft(
                title="SPF policy not published",
                description=(
                    "No SPF record was found for the primary domain. Without SPF, "
                    "receivers cannot reliably distinguish authorized mail senders, "
                    "increasing spoofing and phishing risk."
                ),
                severity="medium",
                cvss_score=5.3,
                evidence={"record": "TXT", "observed": records.get("TXT", [])[:10], "control": "SPF"},
                remediation="Publish a narrow SPF policy (for example v=spf1 include:_spf.provider.example -all) and review senders quarterly.",
                references=["https://owasp.org/www-project-top-ten/", "https://www.rfc-editor.org/rfc/rfc7208"],
                technique_ids=["T1590"],
            )
        )
    dmarc_checked = records.get("_DMARC_TXT")
    if dmarc_checked is not None:
        dmarc = " ".join(dmarc_checked).lower()
        if not dmarc:
            findings.append(
                FindingDraft(
                    title="DMARC policy not published",
                    description="The _dmarc record is absent; domain owners receive no alignment or reporting signal for spoofed email.",
                    severity="medium",
                    cvss_score=5.3,
                    evidence={"record": "_dmarc TXT", "observed": []},
                    remediation="Publish a DMARC record, beginning with p=none monitoring, then move to p=quarantine or p=reject.",
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                    technique_ids=["T1590"],
                )
            )
        elif "p=none" in dmarc:
            findings.append(
                FindingDraft(
                    title="DMARC monitoring-only policy",
                    description="DMARC is present but set to p=none. Spoofed messages are not actively blocked.",
                    severity="low",
                    cvss_score=3.1,
                    evidence={"record": "_dmarc TXT", "observed": dmarc_checked[:3]},
                    remediation="Move DMARC enforcement to p=quarantine after validating reporting, then p=reject.",
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                    technique_ids=["T1590"],
                )
            )
    return findings


async def whois_lookup(domain: str, timeout: float = 8.0) -> dict[str, Any]:
    try:
        import whois as whois_lib

        data = await asyncio.wait_for(
            asyncio.to_thread(whois_lib.whois, domain),
            timeout=timeout,
        )
    except Exception as exc:
        return {"available": False, "error": type(exc).__name__}
    if not data or not data.get("domain_name"):
        return {"available": False, "error": "no_whois_record"}

    def norm(value):
        if isinstance(value, list):
            return [str(v) for v in value[:10]]
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)[:500] if value is not None else None

    friendly = {
        "domain_name": data.get("domain_name"),
        "registrar": data.get("registrar"),
        "creation_date": data.get("creation_date"),
        "expiration_date": data.get("expiration_date"),
        "updated_date": data.get("updated_date"),
        "name_servers": data.get("name_servers"),
        "status": data.get("status"),
        "emails": data.get("emails"),
        "org": data.get("org"),
        "country": data.get("country"),
    }
    return {"available": True, **{k: norm(v) for k, v in friendly.items() if v not in (None, [], "")}}


async def tls_inventory(domain: str, timeout: float = 6.0) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=context, server_hostname=domain),
            timeout=timeout,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert() or {}
        cipher = ssl_object.cipher()
        info = {
            "available": True,
            "protocol": ssl_object.version(),
            "cipher": cipher[0] if cipher else None,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"][:50],
        }
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return info
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: TLS handshake failed"}


async def _resolve_subdomain(name: str, resolver) -> list[str]:
    result: set[str] = set()
    for rtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(name, rtype)
            for item in answer:
                result.add(str(item))
        except Exception:
            continue
    return sorted(result)


async def subdomain_inventory(
    domain: str,
    extra: list[str],
    max_subdomains: int,
    timeout: float,
) -> dict[str, Any]:
    if max_subdomains <= 0:
        return {"subdomains": [], "wildcard": False, "tested": 0}
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = min(3.0, timeout)
    resolver.lifetime = min(3.0, timeout)
    random_label = "ares-wildcard-" + "".join(random.choices(string.ascii_lowercase, k=10))
    wildcard = bool(await _resolve_subdomain(f"{random_label}.{domain}", resolver))
    labels = sorted({*SUBDOMAIN_WORDLIST, *[item.lower() for item in extra]})[:max_subdomains]
    semaphore = asyncio.Semaphore(5)

    async def worker(label: str):
        async with semaphore:
            records = await _resolve_subdomain(f"{label}.{domain}", resolver)
            await asyncio.sleep(0.03)
            return label, records

    results = await asyncio.gather(*(worker(label) for label in labels), return_exceptions=True)
    found = []
    for item in results:
        if isinstance(item, Exception):
            continue
        label, addresses = item
        if addresses:
            found.append({"label": label, "hostname": f"{label}.{domain}", "addresses": addresses})
    return {"subdomains": found, "wildcard": wildcard, "tested": len(labels)}


def fingerprint_from_http(response: dict[str, Any]) -> dict[str, Any]:
    headers = response.get("headers", {})
    body = response.get("body", "")[:100_000].lower()
    technologies: set[str] = set()
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    if server:
        technologies.add(server.split("/")[0][:60])
    if powered:
        technologies.add(powered[:80])
    signatures = {
        "wordpress": "WordPress",
        "wp-content": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "react": "React",
        "next.js": "Next.js",
        "nginx": "nginx",
        "cloudflare": "Cloudflare",
        "shopify": "Shopify",
        "laravel": "Laravel",
        "django": "Django",
        "grafana": "Grafana",
        "jenkins": "Jenkins",
    }
    haystack = body + " " + json.dumps(headers).lower()
    for signature, label in signatures.items():
        if signature in haystack:
            technologies.add(label)
    return {"technologies": sorted(technologies), "server": server, "powered_by": powered}


async def run(context: RunContext, config: dict[str, Any]) -> EngineResult:
    target = context.target
    domain = str(target["value"]).lower().rstrip(".")
    timeout = float(config.get("timeout", 6.0))
    result = EngineResult()
    assets: list[dict[str, Any]] = [
        {"id": "root", "label": domain, "type": "domain", "value": domain, "risk": "info"}
    ]

    dns_task = dns_inventory(domain, timeout)
    whois_task = whois_lookup(domain, timeout) if config.get("include_whois", True) else asyncio.sleep(0)
    tls_task = tls_inventory(domain, timeout) if config.get("include_tls", True) else asyncio.sleep(0)
    dns_result, whois_result, tls_result = await asyncio.gather(dns_task, whois_task, tls_task)
    records = dns_result["records"]

    try:
        resolver = dns.asyncresolver.Resolver(configure=True)
        dmarc = await resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=timeout)
        records["_DMARC_TXT"] = ["".join(str(part) for part in item.strings) for item in dmarc]
    except Exception:
        records["_DMARC_TXT"] = []

    result.findings.extend(analyze_email_security(records))
    if records.get("A"):
        for address in records["A"][:10]:
            assets.append({"id": f"ip-{address}", "label": address, "type": "ip", "value": address, "risk": "info"})
    for mx in records.get("MX", [])[:10]:
        assets.append({"id": f"mx-{mx}", "label": mx, "type": "mx", "value": mx, "risk": "info"})
    for ns in records.get("NS", [])[:10]:
        assets.append({"id": f"ns-{ns}", "label": ns, "type": "nameserver", "value": ns, "risk": "info"})

    subdomains: dict[str, Any] = {"subdomains": [], "wildcard": False, "tested": 0}
    if config.get("include_subdomains", True):
        subdomains = await subdomain_inventory(
            domain,
            config.get("extra_subdomains", []),
            int(config.get("max_subdomains", 30)),
            timeout,
        )
        for item in subdomains["subdomains"]:
            risky = item["label"] in EXPOSED_LABELS
            assets.append(
                {
                    "id": f"sub-{item['label']}",
                    "label": item["hostname"],
                    "type": "subdomain",
                    "value": ", ".join(item["addresses"][:3]),
                    "risk": "medium" if risky else "info",
                }
            )
            if risky:
                result.findings.append(
                    FindingDraft(
                        title=f"Potentially sensitive subdomain exposed: {item['label']}",
                        description=(
                            f"{item['hostname']} resolves publicly. Administrative, development or "
                            "file-transfer names expand the attack surface and should be protected by "
                            "access controls or removed from public DNS."
                        ),
                        severity="medium",
                        cvss_score=5.3,
                        evidence={"hostname": item["hostname"], "addresses": item["addresses"][:5]},
                        remediation="Require SSO/VPN access, remove stale records, and monitor certificate transparency for shadow assets.",
                        technique_ids=["T1595", "T1590"],
                        references=["https://attack.mitre.org/techniques/T1595/"],
                    )
                )
        if subdomains["wildcard"]:
            result.findings.append(
                FindingDraft(
                    title="Wildcard DNS record observed",
                    description="Random subdomains resolve for this zone. Inventory results may include wildcard false positives.",
                    severity="info",
                    evidence={"control": "wildcard-dns"},
                    remediation="Document intentional wildcard records; tighten DNS where not required.",
                    technique_ids=["T1590"],
                )
            )

    technologies: dict[str, Any] = {"technologies": [], "server": None, "powered_by": None}
    if config.get("include_http", True):
        for scheme in ("https", "http"):
            try:
                response = await safe_fetch(
                    f"{scheme}://{domain}/",
                    context,
                    timeout=timeout,
                    max_bytes=160_000,
                    allow_redirects=True,
                )
                technologies = fingerprint_from_http(response)
                if technologies["technologies"]:
                    assets.append(
                        {
                            "id": "tech-stack",
                            "label": ", ".join(technologies["technologies"][:5]),
                            "type": "technology",
                            "value": scheme,
                            "risk": "info",
                        }
                    )
                if response["headers"].get("server"):
                    result.findings.append(
                        FindingDraft(
                            title="Server banner discloses technology details",
                            description="The HTTP response advertises server software. Version banners reduce the effort required to target known vulnerabilities.",
                            severity="low",
                            cvss_score=3.7,
                            evidence={"server": response["headers"].get("server"), "url": response["final_url"]},
                            remediation="Suppress product/version tokens at the edge and keep the server patched.",
                            technique_ids=["T1592"],
                            references=["https://owasp.org/www-project-secure-headers/"],
                        )
                    )
                break
            except (SafeFetchError, Exception):
                continue

    if tls_result.get("available"):
        from datetime import datetime as dt

        assets.append(
            {
                "id": "tls",
                "label": f"TLS · {tls_result.get('issuer', {}).get('organizationName', 'certificate')}",
                "type": "certificate",
                "value": tls_result.get("protocol", "TLS"),
                "risk": "info",
            }
        )
        try:
            expiry = dt.strptime(tls_result["not_after"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            days = (expiry - datetime.now(UTC)).days
            tls_result["days_until_expiry"] = days
            if days < 0:
                result.findings.append(
                    FindingDraft(
                        title="TLS certificate has expired",
                        description="The public TLS certificate is expired, breaking trust and integrity guarantees for users.",
                        severity="high",
                        cvss_score=7.4,
                        evidence={"not_after": tls_result.get("not_after"), "domain": domain},
                        remediation="Renew and deploy the certificate; automate renewal monitoring.",
                        technique_ids=["T1590"],
                    )
                )
            elif days < 21:
                result.findings.append(
                    FindingDraft(
                        title="TLS certificate expires soon",
                        description=f"The TLS certificate expires in {days} day(s).",
                        severity="low",
                        cvss_score=3.1,
                        evidence={"not_after": tls_result.get("not_after"), "days_remaining": days},
                        remediation="Confirm automated certificate renewal and alerting.",
                        technique_ids=["T1590"],
                    )
                )
        except Exception:
            pass
    elif config.get("include_tls", True):
        result.findings.append(
            FindingDraft(
                title="HTTPS endpoint unavailable or TLS handshake failed",
                description="A TLS inventory could not be completed. This may indicate a filtered port, invalid certificate, or unsupported protocol.",
                severity="info",
                evidence={"error": tls_result.get("error", "unknown")},
                remediation="Verify TLS availability and certificate chain on port 443.",
            )
        )

    record_counts = {key: len(value) for key, value in records.items()}
    result.summary = {
        "domain": domain,
        "dns": records,
        "dns_record_counts": record_counts,
        "whois": whois_result,
        "tls": tls_result,
        "technologies": technologies,
        "subdomains": subdomains["subdomains"][:80],
        "wildcard_dns": subdomains["wildcard"],
        "assets": assets[:250],
        "asset_count": len(assets),
        "notice": "Passive/public sources and scoped DNS queries only.",
    }
    if not records.get("A") and not records.get("AAAA"):
        result.findings.append(
            FindingDraft(
                title="Primary domain did not resolve",
                description="No A or AAAA records were returned. The domain may be inactive or DNS may be filtered.",
                severity="info",
                evidence={"domain": domain, "errors": dns_result["errors"]},
                remediation="Confirm the authorized scope and DNS availability before retesting.",
            )
        )
    return result.finalize("recon")
