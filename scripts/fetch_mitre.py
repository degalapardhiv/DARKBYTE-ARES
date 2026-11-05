#!/usr/bin/env python3
"""Refresh the bundled MITRE ATT&CK Enterprise catalogue from official STIX."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "integrations" / "mitre_attack" / "data" / "techniques.json"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def main() -> None:
    print(f"Downloading ATT&CK STIX from {URL}")
    response = httpx.get(URL, timeout=120, follow_redirects=True, headers={"User-Agent": "DARKBYTE-ARES"})
    response.raise_for_status()
    bundle = response.json()
    tactics = []
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external = obj.get("external_references", [])
        attack_ref = next((ref for ref in external if ref.get("source_name") == "mitre-attack"), None)
        if not attack_ref:
            continue
        ext_id = attack_ref.get("external_id")
        url = attack_ref.get("url")
        if obj.get("type") == "x-mitre-tactic" and ext_id:
            tactics.append(
                {
                    "id": ext_id,
                    "name": obj.get("name"),
                    "shortname": obj.get("x_mitre_shortname"),
                    "description": (obj.get("description") or "")[:1200],
                    "url": url,
                }
            )
        elif obj.get("type") == "attack-pattern" and ext_id:
            phases = [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            techniques.append(
                {
                    "id": ext_id,
                    "name": obj.get("name"),
                    "description": (obj.get("description") or "")[:1600],
                    "tactics": phases,
                    "platforms": obj.get("x_mitre_platforms", []),
                    "detection": (obj.get("x_mitre_detection") or "")[:1200],
                    "url": url,
                    "subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                }
            )
    tactics.sort(key=lambda item: item["id"])
    techniques.sort(key=lambda item: item["id"])
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": {
            "source": "MITRE ATT&CK Enterprise",
            "url": "https://attack.mitre.org/",
            "license": "See https://attack.mitre.org/resources/legal-and-branding/",
            "retrieved_at": datetime.now(UTC).isoformat(),
            "tactic_count": len(tactics),
            "technique_count": len(techniques),
        },
        "tactics": tactics,
        "techniques": techniques,
    }
    TARGET.write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(tactics)} tactics, {len(techniques)} techniques to {TARGET}")


if __name__ == "__main__":
    main()
