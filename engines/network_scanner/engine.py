from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from engines.base import EngineResult, FindingDraft, RunContext
from engines.common import RISKY_PORTS, SERVICE_NAMES
from integrations.external_tools.nmap import is_available, run_nmap


def expand_target_scope(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if "/" in value:
        return ipaddress.ip_network(value, strict=False)
    ip = ipaddress.ip_address(value)
    return ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)


def _host_allowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, context: RunContext) -> str | None:
    metadata = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}
    if ip in metadata:
        return "cloud metadata address is never permitted"
    if ip.is_multicast or ip.is_unspecified:
        return "multicast/unspecified address"
    if ip.is_loopback and not context.allow_loopback:
        return "loopback scanning requires a verified lab target"
    if ip.is_private and not context.allow_private:
        return "private-range scanning requires a verified lab/staging target"
    return None


async def _probe_port(host: str, port: int, timeout: float, grab_banner: bool) -> dict[str, Any] | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError, asyncio.TimeoutError):
        return None
    banner = ""
    if grab_banner and port in {21, 22, 23, 25, 110, 143, 3306, 5432, 6379}:
        try:
            raw = await asyncio.wait_for(reader.read(256), timeout=0.7)
            banner = raw.decode(errors="replace").strip().splitlines()[0][:180] if raw else ""
        except Exception:
            banner = ""
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return {
        "port": port,
        "protocol": "tcp",
        "service": SERVICE_NAMES.get(port, "unknown"),
        "banner": banner,
    }


async def tcp_scan(
    hosts: list[str],
    ports: list[int],
    *,
    timeout: float,
    concurrency: int,
    grab_banner: bool,
) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results: dict[str, list[dict[str, Any]]] = {host: [] for host in hosts}

    async def worker(host: str, port: int):
        async with semaphore:
            open_port = await _probe_port(host, port, timeout, grab_banner)
            if open_port:
                results[host].append(open_port)

    tasks = [worker(host, port) for host in hosts for port in ports]
    await asyncio.gather(*tasks)
    output = []
    for host in hosts:
        output.append(
            {
                "address": host,
                "hostnames": [],
                "services": sorted(results[host], key=lambda item: item["port"]),
                "open_port_count": len(results[host]),
            }
        )
    return output


def build_topology(hosts: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [{"id": "assessment", "label": "Authorized scope", "type": "root", "risk": "info"}]
    edges: list[dict[str, Any]] = []
    for index, host in enumerate(hosts):
        host_id = f"host-{index}"
        risk = "medium" if host.get("open_port_count", 0) > 3 else "info"
        for service in host.get("services", []):
            if service["port"] in RISKY_PORTS:
                risk = RISKY_PORTS[service["port"]][0].lower()
        nodes.append(
            {
                "id": host_id,
                "label": host.get("address", "host"),
                "type": "host",
                "risk": risk,
                "open_ports": host.get("open_port_count", 0),
            }
        )
        edges.append({"source": "assessment", "target": host_id})
        for service in host.get("services", [])[:16]:
            service_id = f"{host_id}-{service['port']}"
            level = "critical" if service["port"] in (2375, 6379, 27017) else (
                "high" if service["port"] in RISKY_PORTS else "info"
            )
            nodes.append(
                {
                    "id": service_id,
                    "label": f"{service['port']}/{service.get('service', 'tcp')}",
                    "type": "service",
                    "risk": level,
                }
            )
            edges.append({"source": host_id, "target": service_id})
    return {"nodes": nodes[:220], "edges": edges[:260]}


async def run(context: RunContext, config: dict[str, Any]) -> EngineResult:
    settings = context.settings
    target = context.target
    network = expand_target_scope(str(target["value"]))
    max_hosts = min(int(config.get("max_hosts", 16)), settings.max_scan_hosts)
    ports = [int(port) for port in config.get("ports", [])]
    if not ports:
        raise ValueError("No ports selected.")
    if len(ports) > settings.max_ports_per_scan:
        raise ValueError("Port list exceeds the configured safety limit.")
    network_hosts = list(network.hosts())[: max_hosts + 1]
    if len(network_hosts) > max_hosts:
        network_hosts = network_hosts[:max_hosts]
    if not network_hosts:
        network_hosts = [str(network.network_address)]
    hosts: list[str] = []
    for ip in network_hosts:
        reason = _host_allowed(ip, context)
        if reason:
            raise ValueError(f"Refusing host {ip}: {reason}.")
        hosts.append(str(ip))

    result = EngineResult()
    scan_meta: dict[str, Any] = {"requested_engine": config.get("engine", "tcp")}
    if config.get("engine") == "nmap" and is_available():
        try:
            nmap_result = await run_nmap(hosts, ports, timeout=min(75.0, settings.scan_timeout_seconds * 15 + 20))
            host_results = nmap_result["hosts"]
            scan_meta["engine"] = "nmap"
        except Exception as exc:
            scan_meta["nmap_error"] = type(exc).__name__
            scan_meta["engine"] = "tcp-fallback"
            host_results = await tcp_scan(
                hosts,
                ports,
                timeout=float(config.get("timeout", 2.0)),
                concurrency=int(config.get("concurrency", 100)),
                grab_banner=bool(config.get("service_banners", True)),
            )
    else:
        if config.get("engine") == "nmap":
            scan_meta["nmap_error"] = "nmap_unavailable"
        scan_meta["engine"] = "tcp"
        host_results = await tcp_scan(
            hosts,
            ports,
            timeout=float(config.get("timeout", 2.0)),
            concurrency=int(config.get("concurrency", 100)),
            grab_banner=bool(config.get("service_banners", True)),
        )

    for host in host_results:
        for service in host["services"]:
            if service["port"] in RISKY_PORTS:
                severity, description, remediation = RISKY_PORTS[service["port"]]
                result.findings.append(
                    FindingDraft(
                        title=f"Risky service exposed: {service['port']}/{service.get('service', 'tcp')}",
                        description=description,
                        severity=severity.lower(),
                        evidence={
                            "host": host["address"],
                            "port": service["port"],
                            "service": service.get("service"),
                            "banner": service.get("banner", "")[:180],
                        },
                        remediation=remediation,
                        technique_ids=["T1046", "T1133"],
                        references=[
                            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            "https://attack.mitre.org/techniques/T1046/",
                        ],
                    )
                )
    total_ports = sum(host["open_port_count"] for host in host_results)
    result.findings.append(
        FindingDraft(
            title=f"Network inventory: {total_ports} open TCP service(s) across {len(host_results)} host(s)",
            description=(
                "A scoped TCP connect inventory was completed. Open services enlarge the attack "
                "surface and should be mapped to an explicit business owner."
            ),
            severity="info",
            evidence={"ports_tested": ports, "hosts_scanned": len(hosts), "open_services": total_ports},
            remediation="Maintain an approved service catalogue, close unused ports, and review exposure quarterly.",
            technique_ids=["T1046"],
        )
    )
    topology = build_topology(host_results)
    result.summary = {
        "network": str(network),
        "hosts_scanned": len(hosts),
        "ports_tested": len(ports),
        "open_services": total_ports,
        "hosts": host_results,
        "topology": topology,
        "scan": scan_meta,
        "notice": "TCP connect scan only. No exploit, denial-of-service or stealth capability is used.",
    }
    return result.finalize("network")
