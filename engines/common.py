from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from backend.core.exceptions import ScopeViolation
from engines.base import RunContext

USER_AGENT = "DARKBYTE-ARES/1.0 (+authorized-security-assessment)"
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


class SafeFetchError(Exception):
    pass


def _forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, context: RunContext) -> str | None:
    if ip in METADATA_IPS:
        return "cloud metadata endpoints are never in scope"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "reserved/multicast address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_loopback and not context.allow_loopback:
        return "loopback is only allowed for verified lab targets"
    if ip.is_private and not context.allow_private:
        return "private ranges are only allowed for verified lab/staging targets"
    return None


async def resolve_host(host: str, context: RunContext) -> list[str]:
    if not HOSTNAME_RE.match(host):
        raise ScopeViolation("Invalid hostname.")
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, family=socket.AF_UNSPEC),
            timeout=5,
        )
    except (socket.gaierror, TimeoutError, OSError) as exc:
        raise SafeFetchError(f"DNS resolution failed for {host}.") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise SafeFetchError(f"No DNS records returned for {host}.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        reason = _forbidden_ip(ip, context)
        if reason:
            raise ScopeViolation(f"Refusing to connect to {host} ({address}): {reason}.")
    return addresses


def _host_in_target(host: str, target: dict[str, Any]) -> bool:
    target_type = target.get("target_type") or target.get("target_type", "")
    value = str(target.get("value", "")).strip().lower()
    host = host.lower().rstrip(".")
    if target_type == "domain":
        value = value.rstrip(".")
        return host == value or host.endswith("." + value)
    if target_type in {"url", "api"}:
        parsed = urlparse(value)
        allowed = (parsed.hostname or "").lower()
        return host == allowed
    if target_type == "ip":
        return host == value
    if target_type == "local":
        return host in {"localhost", "127.0.0.1", "::1"} and bool(target.get("environment") == "lab")
    return False


def validate_url(url: str, target: dict[str, Any]) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ScopeViolation("Only http(s) URLs can be requested.")
    if parsed.username or parsed.password:
        raise ScopeViolation("URLs containing credentials are forbidden.")
    host = parsed.hostname or ""
    if not _host_in_target(host, target):
        raise ScopeViolation(f"Host {host!r} is outside the authorized target scope.")
    if parsed.port and parsed.port not in {80, 443, 8080, 8443, 8000, 3000, 5000, 9000}:
        if target.get("environment") != "lab":
            raise ScopeViolation("Non-standard ports require a lab-scoped target.")


async def safe_fetch(
    url: str,
    context: RunContext,
    *,
    timeout: float = 8.0,
    max_bytes: int = 512_000,
    allow_redirects: bool = False,
    verify: bool | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Scope-validated HTTP fetch with manual redirects and a response cap."""
    validate_url(url, context.target)
    host = urlparse(url).hostname or ""
    await resolve_host(host, context)
    if verify is None:
        verify = not context.is_lab
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        request_headers.update(headers)
    chain: list[str] = []
    current = url
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        headers=request_headers,
        verify=verify,
    ) as client:
        for _ in range(4):
            chain.append(current)
            try:
                async with client.stream(method, current) as response:
                    status = response.status_code
                    if allow_redirects and status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            break
                        current = urljoin(current, location)
                        validate_url(current, context.target)
                        await resolve_host(urlparse(current).hostname or "", context)
                        continue
                    body = b""
                    truncated = False
                    async for chunk in response.aiter_bytes():
                        remaining = max_bytes - len(body)
                        if remaining <= 0:
                            truncated = True
                            break
                        body += chunk[:remaining]
                        if len(chunk) > remaining:
                            truncated = True
                            break
                    text = body.decode(response.encoding or "utf-8", errors="replace")
                    return {
                        "url": current,
                        "final_url": str(response.url),
                        "status_code": status,
                        "headers": {k.lower(): v for k, v in response.headers.items()},
                        "body": text,
                        "body_bytes": len(body),
                        "truncated": truncated,
                        "redirect_chain": chain,
                        "elapsed_ms": round(response.elapsed.total_seconds() * 1000, 1)
                        if response.elapsed
                        else None,
                    }
            except httpx.SSLError:
                if context.is_lab and verify is not False:
                    verify = False
                    continue
                raise SafeFetchError("TLS certificate validation failed.")
            except httpx.TimeoutException as exc:
                raise SafeFetchError("Request timed out.") from exc
            except httpx.HTTPError as exc:
                raise SafeFetchError(f"HTTP request failed: {type(exc).__name__}") from exc
        raise SafeFetchError("Redirect limit exceeded or redirect escaped scope.")


async def read_bytes(url: str, context: RunContext, *, max_bytes=5_000_000, timeout=12.0) -> tuple[bytes, dict]:
    validate_url(url, context.target)
    host = urlparse(url).hostname or ""
    await resolve_host(host, context)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
        verify=not context.is_lab,
    ) as client:
        async with client.stream("GET", url) as response:
            if response.status_code >= 400:
                raise SafeFetchError(f"Remote server returned HTTP {response.status_code}.")
            content_type = response.headers.get("content-type", "")
            body = b""
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > max_bytes:
                    raise SafeFetchError(f"File exceeds the {max_bytes // 1_000_000} MB evidence limit.")
                body += chunk
            return body, {"status_code": response.status_code, "content_type": content_type}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2375: "docker",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5672: "amqp",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

RISKY_PORTS = {
    21: ("High", "FTP is often cleartext and may permit anonymous access.", "Disable FTP or require FTPS; restrict source ranges."),
    23: ("High", "Telnet sends credentials and session data in cleartext.", "Disable Telnet and replace it with SSH."),
    445: ("Medium", "SMB exposure can enable credential relay and lateral movement.", "Block SMB at the perimeter and enforce signing."),
    1433: ("High", "Database services should not be reachable from untrusted networks.", "Restrict to application subnets; require TLS and strong auth."),
    2375: ("Critical", "An exposed Docker API can permit host takeover.", "Never expose the Docker socket externally; require mTLS."),
    3306: ("High", "Database services should not be reachable from untrusted networks.", "Restrict to application subnets; require TLS and strong auth."),
    3389: ("High", "RDP is a frequent initial-access and ransomware target.", "Place behind VPN/Zero Trust, enable NLA and MFA."),
    5432: ("High", "Database services should not be reachable from untrusted networks.", "Restrict to application subnets; require TLS and strong auth."),
    6379: ("Critical", "Unauthenticated Redis commonly enables remote compromise.", "Bind to private interfaces, require ACLs, disable dangerous commands."),
    9200: ("High", "Elasticsearch frequently lacks authentication by default.", "Enable security features, TLS and least-privilege roles."),
    27017: ("Critical", "Public MongoDB instances are routinely mass-compromised.", "Bind privately, enforce SCRAM auth, enable TLS and auditing."),
}


@dataclass
class CvssBase:
    score: float
    severity: str
    vector: str


def parse_cvss_v3(vector: str) -> CvssBase:
    """Compute a CVSS v3.0/3.1 base score from a vector string."""
    metrics: dict[str, str] = {}
    parts = vector.strip().split("/")
    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value.upper()
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac = {"L": 0.77, "H": 0.44}
    ui = {"N": 0.85, "R": 0.62}
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(metric in metrics for metric in required):
        raise ValueError("CVSS vector is missing required base metrics.")
    if metrics["AV"] not in av or metrics["AC"] not in ac or metrics["UI"] not in ui:
        raise ValueError("CVSS vector contains an invalid metric value.")
    if any(metrics[metric] not in cia for metric in ("C", "I", "A")):
        raise ValueError("CVSS vector contains an invalid impact value.")
    scope_changed = metrics["S"] == "C"
    pr_map = {
        "N": 0.85,
        "L": 0.68 if scope_changed else 0.62,
        "H": 0.50 if scope_changed else 0.27,
    }
    if metrics["PR"] not in pr_map:
        raise ValueError("CVSS vector contains an invalid privilege requirement.")
    isc = 1 - ((1 - cia[metrics["C"]]) * (1 - cia[metrics["I"]]) * (1 - cia[metrics["A"]]))
    if scope_changed:
        impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    else:
        impact = 6.42 * isc
    exploitability = 8.22 * av[metrics["AV"]] * ac[metrics["AC"]] * pr_map[metrics["PR"]] * ui[metrics["UI"]]
    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = min(10.0, math_ceil1(min(1.08 * (impact + exploitability), 10.0)))
    else:
        base = math_ceil1(min(impact + exploitability, 10.0))
    from engines.base import severity_for_cvss

    return CvssBase(score=round(base, 1), severity=severity_for_cvss(round(base, 1)), vector=vector)


def math_ceil1(value: float) -> float:
    import math

    return math.ceil(value * 10) / 10
