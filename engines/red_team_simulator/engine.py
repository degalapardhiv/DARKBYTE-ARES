from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from engines.base import EngineResult, FindingDraft, RunContext

SCENARIOS: dict[str, dict[str, Any]] = {
    "initial_access": {
        "name": "Initial access detection exercise",
        "techniques": [
            ("T1566.001", "Spearphishing attachment", "Mail security alerts on attachment detonation, unusual sender reputation and macro execution."),
            ("T1204.002", "Malicious file execution", "EDR telemetry for office child processes, unsigned binaries and LOLBin ancestry."),
            ("T1190", "Exploit public-facing application", "WAF and application logs correlated with unusual process or outbound behavior."),
            ("T1078", "Valid accounts", "Impossible-travel, new device and anomalous session alerts."),
        ],
    },
    "discovery": {
        "name": "Internal discovery detection exercise",
        "techniques": [
            ("T1046", "Network service discovery", "New port sweep patterns from a single asset; IDS aggregation alerts."),
            ("T1087", "Account discovery", "Sensitive directory enumeration thresholds and helpdesk verification."),
            ("T1082", "System information discovery", "Unusual command ancestry and host reconnaissance detections."),
            ("T1018", "Remote system discovery", "Bursts of SMB/RPC name queries from an unmanaged host."),
        ],
    },
    "credential_access": {
        "name": "Credential access detection exercise",
        "techniques": [
            ("T1110", "Brute force / password spray", "Distributed failure patterns, lockout anomalies and risky sign-in alerts."),
            ("T1003", "OS credential dumping", "LSASS access, credential-store access and suspicious memory reads."),
            ("T1558", "Steal or forge Kerberos tickets", "Anomalous TGS requests, ticket lifetimes and service account behavior."),
            ("T1621", "MFA request generation", "MFA fatigue patterns and repeated denied push notifications."),
        ],
    },
    "lateral_movement": {
        "name": "Lateral movement detection exercise",
        "techniques": [
            ("T1021.001", "Remote Desktop Protocol", "New RDP source/destination pairs and privileged session anomalies."),
            ("T1021.002", "SMB/Windows Admin Shares", "Admin-share access from non-jump hosts and service creation telemetry."),
            ("T1550", "Use alternate authentication material", "Token/session use from impossible locations or mismatched device identity."),
            ("T1570", "Lateral tool transfer", "File transfer from management hosts to servers outside normal baselines."),
        ],
    },
    "defense_evasion": {
        "name": "Defense evasion detection exercise",
        "techniques": [
            ("T1562", "Impair defenses", "Tamper-protection alerts, security service stop attempts and policy changes."),
            ("T1070", "Indicator removal", "Log clearing, event log gaps and audit policy changes."),
            ("T1036", "Masquerading", "Binary name/path mismatches and unsigned binaries in system directories."),
            ("T1027", "Obfuscated files or information", "Encoded command lines and suspicious script block logging."),
        ],
    },
    "impact_readiness": {
        "name": "Impact readiness tabletop",
        "techniques": [
            ("T1486", "Data encrypted for impact", "Mass file entropy changes, backup access and ransomware canaries."),
            ("T1490", "Inhibit system recovery", "Shadow copy deletion and backup service manipulation alerts."),
            ("T1489", "Service stop", "Critical service stop bursts and recovery plan activation."),
            ("T1657", "Financial theft", "Out-of-band payment change verification and finance workflow anomalies."),
        ],
    },
}


def build_plan(scenario: str, custom_techniques: list[str], objective: str) -> dict[str, Any]:
    spec = SCENARIOS.get(scenario, SCENARIOS["discovery"])
    steps = [
        {
            "step": index + 1,
            "technique_id": technique,
            "technique": name,
            "detection_exercise": detection,
            "simulation_mode": "tabletop-only",
            "executed_against_target": False,
        }
        for index, (technique, name, detection) in enumerate(spec["techniques"])
    ]
    existing = {step["technique_id"] for step in steps}
    for technique in custom_techniques:
        if technique not in existing:
            steps.append(
                {
                    "step": len(steps) + 1,
                    "technique_id": technique,
                    "technique": "Operator-selected ATT&CK technique",
                    "detection_exercise": "Define a hypothesis, telemetry source and expected alert for this technique before lab validation.",
                    "simulation_mode": "tabletop-only",
                    "executed_against_target": False,
                }
            )
    return {
        "scenario": scenario,
        "scenario_name": spec["name"],
        "objective": objective,
        "mode": "controlled-tabletop",
        "steps": steps,
        "detections_required": [step["detection_exercise"] for step in steps],
    }


async def run(context: RunContext, config: dict[str, Any]) -> EngineResult:
    scenario = config.get("scenario", "discovery")
    plan = build_plan(scenario, config.get("technique_ids", []), config.get("objective", ""))
    result = EngineResult()
    technique_ids = [step["technique_id"] for step in plan["steps"]]
    evidence_timestamp = datetime.now(UTC).isoformat()

    for step in plan["steps"]:
        result.findings.append(
            FindingDraft(
                title=f"Detection exercise required for {step['technique_id']} — {step['technique']}",
                description=(
                    "Tabletop simulation step generated for detection engineering. No technique was executed "
                    "against the target. Validate that the listed telemetry produces an actionable alert and "
                    "document the expected versus observed outcome."
                ),
                severity="low",
                cvss_score=3.1,
                evidence={
                    "simulation": True,
                    "simulated_evidence": {
                        "timestamp": evidence_timestamp,
                        "mode": "tabletop-only",
                        "step": step["step"],
                        "target_identifier": context.target.get("id"),
                        "action_executed": False,
                    },
                    "detection_hypothesis": step["detection_exercise"],
                },
                remediation=(
                    "Create or tune the detection described, map it to the technique, and run a separate "
                    "authorized lab validation before claiming coverage."
                ),
                references=[f"https://attack.mitre.org/techniques/{step['technique_id'].split('.')[0]}/"],
                technique_ids=[step["technique_id"]],
            )
        )

    result.summary = {
        **plan,
        "evidence": [
            {
                "type": "simulation_plan",
                "mode": "tabletop-only",
                "created_at": evidence_timestamp,
                "target_identifier": context.target.get("id"),
                "techniques": technique_ids,
                "executed": False,
            }
        ],
        "coverage_claim": "Planning and detection requirements only; no technique execution.",
        "notice": "No malware, credential theft, exploitation, lateral movement or network traffic is generated by this module.",
    }
    return result.finalize("red_team")
