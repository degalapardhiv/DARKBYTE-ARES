from __future__ import annotations

import asyncio
import shutil
import xml.etree.ElementTree as ET
from typing import Any


def is_available() -> bool:
    return shutil.which("nmap") is not None


async def run_nmap(
    hosts: list[str],
    ports: list[int],
    *,
    timeout: float = 75.0,
) -> dict[str, Any]:
    """Run a conservative TCP connect scan and return parsed service data.

    Arguments are passed as an array (never a shell string). The scan is
    intentionally limited to authorized targets by the calling engine.
    """
    binary = shutil.which("nmap")
    if not binary:
        raise RuntimeError("nmap is not installed")
    if not hosts or len(hosts) > 64:
        raise ValueError("nmap host limit exceeded")
    if not ports or len(ports) > 512:
        raise ValueError("nmap port limit exceeded")
    port_arg = ",".join(str(port) for port in sorted(set(ports)))
    command = [
        binary,
        "-sT",
        "-Pn",
        "-sV",
        "--version-light",
        "--max-retries",
        "1",
        "--host-timeout",
        "45s",
        "-p",
        port_arg,
        *hosts,
        "-oX",
        "-",
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError("nmap scan timed out")
    if process.returncode not in (0, 1):
        raise RuntimeError(f"nmap failed: {stderr.decode(errors='replace')[:300]}")
    return parse_nmap_xml(stdout.decode(errors="replace"))


def parse_nmap_xml(xml_data: str) -> dict[str, Any]:
    root = ET.fromstring(xml_data)
    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addresses = [node.get("addr") for node in host.findall("address") if node.get("addr")]
        hostnames = [node.get("name") for node in host.findall("./hostnames/hostname") if node.get("name")]
        services = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            services.append(
                {
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "service": (service.get("name") if service is not None else "unknown") or "unknown",
                    "product": (service.get("product") if service is not None else "") or "",
                    "version": (service.get("version") if service is not None else "") or "",
                }
            )
        hosts.append(
            {
                "address": addresses[0] if addresses else "",
                "hostnames": hostnames,
                "services": services,
                "open_port_count": len(services),
            }
        )
    return {"hosts": hosts, "tool": "nmap", "host_count": len(hosts)}
