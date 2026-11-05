from __future__ import annotations

from typing import Any

from engines.base import EngineResult, FindingDraft, RunContext


def _get(mapping: dict, *keys: str, default=None):
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.lower() in {"true", "yes", "enabled", "public", "allow"}
    return bool(value)


def analyze_snapshot(snapshot: dict[str, Any], provider: str) -> tuple[list[FindingDraft], dict[str, Any]]:
    findings: list[FindingDraft] = []
    passed: list[str] = []
    failed: list[str] = []

    identity = snapshot.get("identity") or snapshot.get("identity_security") or {}
    storage = snapshot.get("storage") or snapshot.get("buckets") or snapshot.get("containers") or []
    iam = snapshot.get("iam") or snapshot.get("iam_policies") or []
    logging = snapshot.get("logging") or snapshot.get("monitoring") or {}
    network = snapshot.get("network") or {}

    root_keys = _bool(_get(identity, "root_access_keys", "rootAccessKeys", default=False))
    root_mfa = _bool(_get(identity, "root_mfa", "rootMfa", "mfa_enabled_for_root", default=True))
    guest_access = _bool(_get(identity, "guest_access", "guestAccess", default=False))
    mfa_enforced = _bool(_get(identity, "mfa_enforced", "mfaEnforced", default=True))
    password_policy = identity.get("password_policy") or identity.get("passwordPolicy") or {}
    min_length = int(_get(password_policy, "minimum_length", "min_length", "minLength", default=12) or 12)

    if root_keys:
        failed.append("Root access keys present")
        findings.append(
            FindingDraft(
                title="Cloud root/global administrator access keys exist",
                description="Long-lived keys on the highest-privilege identity create an unacceptable takeover risk if leaked.",
                severity="critical",
                cvss_score=9.3,
                evidence={"control": "root_access_keys", "provider": provider},
                remediation="Delete root access keys, use federation/role assumption, enable hardware MFA, and review CloudTrail/Activity Log for prior use.",
                technique_ids=["T1078.004", "T1552.001"],
                references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html"],
            )
        )
    else:
        passed.append("No root access keys reported")
    if not root_mfa:
        failed.append("Root MFA missing")
        findings.append(
            FindingDraft(
                title="Root account does not enforce MFA",
                description="The highest-privilege account can be accessed with a password alone.",
                severity="high",
                cvss_score=8.1,
                evidence={"control": "root_mfa"},
                remediation="Enable hardware-backed MFA on the root/global administrator account and store recovery material offline.",
                technique_ids=["T1078.004"],
            )
        )
    else:
        passed.append("Root MFA enabled")
    if password_policy and min_length < 12:
        failed.append("Password policy below baseline")
        findings.append(
            FindingDraft(
                title="Cloud identity password policy is shorter than 12 characters",
                description="A weak password policy increases susceptibility to spraying and credential stuffing for cloud identities.",
                severity="medium",
                cvss_score=5.3,
                evidence={"minimum_length": min_length},
                remediation="Require 12+ character passwords or passphrases, block breached passwords, and enforce phishing-resistant MFA.",
                technique_ids=["T1110.003", "T1078.004"],
            )
        )
    if guest_access:
        findings.append(
            FindingDraft(
                title="Guest access is enabled in the tenant",
                description="Guest identities expand the trust boundary and require strict lifecycle and access reviews.",
                severity="medium",
                cvss_score=5.5,
                evidence={"control": "guest_access"},
                remediation="Restrict guest invitations, require MFA, and review guest access quarterly.",
                technique_ids=["T1078.004"],
            )
        )
    if not mfa_enforced:
        findings.append(
            FindingDraft(
                title="MFA is not enforced for cloud identities",
                description="Password-only cloud identities are susceptible to phishing and credential stuffing.",
                severity="high",
                cvss_score=7.5,
                evidence={"control": "mfa_enforced"},
                remediation="Enforce MFA with conditional access, then move administrators to phishing-resistant authentication.",
                technique_ids=["T1078.004", "T1621"],
            )
        )

    for bucket in storage if isinstance(storage, list) else []:
        if not isinstance(bucket, dict):
            continue
        name = str(_get(bucket, "name", "id", default="storage-object"))[:120]
        public = _bool(_get(bucket, "public", "public_access", "publicAccess", default=False))
        encrypted = _bool(_get(bucket, "encrypted", "encryption", default=True))
        https_only = _bool(_get(bucket, "https_only", "httpsOnly", default=True))
        if public:
            failed.append(f"Public storage: {name}")
            findings.append(
                FindingDraft(
                    title=f"Storage resource permits public access: {name}",
                    description="Public storage is a leading cause of cloud data exposure. Public access should be intentional, documented and restricted to non-sensitive content.",
                    severity="high",
                    cvss_score=7.5,
                    evidence={"resource": name, "provider": provider, "control": "public_storage"},
                    remediation="Enable account-level public access blocks; use signed URLs or CDN controls; classify and monitor any intentional public data.",
                    technique_ids=["T1530"],
                    references=["https://owasp.org/www-project-top-ten/"],
                )
            )
        if not encrypted:
            findings.append(
                FindingDraft(
                    title=f"Storage encryption is not reported for {name}",
                    description="Data at rest lacks an explicit encryption control in the supplied snapshot.",
                    severity="medium",
                    cvss_score=5.3,
                    evidence={"resource": name},
                    remediation="Enable default encryption with customer-managed keys where required, and verify key rotation.",
                    technique_ids=["T1530"],
                )
            )
        if not https_only:
            findings.append(
                FindingDraft(
                    title=f"Storage endpoint permits non-TLS access: {name}",
                    description="Cleartext object access enables interception and cache poisoning.",
                    severity="medium",
                    cvss_score=5.3,
                    evidence={"resource": name},
                    remediation="Require secure transport and redirect HTTP to HTTPS.",
                    technique_ids=["T1530"],
                )
            )
        if not public and encrypted and https_only:
            passed.append(f"Storage controls OK: {name}")

    for policy in iam if isinstance(iam, list) else []:
        if not isinstance(policy, dict):
            continue
        name = str(_get(policy, "name", "policy", "id", default="iam-policy"))[:120]
        wildcard_action = _bool(_get(policy, "wildcard_action", "wildcardAction", default=False)) or "*" in str(_get(policy, "actions", default=""))
        wildcard_resource = _bool(_get(policy, "wildcard_resource", "wildcardResource", default=False)) or "*" in str(_get(policy, "resources", default=""))
        if wildcard_action and wildcard_resource:
            failed.append(f"Wildcard IAM: {name}")
            findings.append(
                FindingDraft(
                    title=f"IAM policy grants wildcard action and resource: {name}",
                    description="A principal with Action:* and Resource:* effectively has administrative control and no meaningful blast-radius boundary.",
                    severity="high",
                    cvss_score=8.8,
                    evidence={"policy": name, "provider": provider, "wildcard_action": True, "wildcard_resource": True},
                    remediation="Replace wildcard statements with least-privilege actions and resource ARNs; add permission boundaries and access reviews.",
                    technique_ids=["T1098", "T1078.004"],
                )
            )
        elif wildcard_action:
            findings.append(
                FindingDraft(
                    title=f"IAM policy grants wildcard actions: {name}",
                    description="Wildcard actions allow broader capabilities than required for most workloads.",
                    severity="medium",
                    cvss_score=6.5,
                    evidence={"policy": name, "wildcard_action": True},
                    remediation="Scope actions to the minimum required services and review with IAM Access Analyzer.",
                    technique_ids=["T1098"],
                )
            )

    trail = _bool(_get(logging, "cloudtrail", "cloudtrail_enabled", "cloudTrail", default=False))
    guardduty = _bool(_get(logging, "guardduty", "guardduty_enabled", "defender", "sentinel", default=False))
    activity_log = _bool(_get(logging, "activity_log", "activityLog", "audit_log", default=False))
    if provider == "aws" and not trail:
        failed.append("CloudTrail disabled")
        findings.append(
            FindingDraft(
                title="Cloud audit logging (CloudTrail) is not enabled",
                description="Without central audit logs, unauthorized changes and credential abuse may go undetected.",
                severity="high",
                cvss_score=7.5,
                evidence={"control": "cloudtrail"},
                remediation="Enable organization-wide CloudTrail with immutable log archive, validation and alerting.",
                technique_ids=["T1562.008", "T1078.004"],
            )
        )
    elif provider in {"azure", "gcp"} and not (activity_log or trail):
        findings.append(
            FindingDraft(
                title="Cloud audit logging is not reported as enabled",
                description="A central activity/audit log is required for investigation and detection of cloud control-plane abuse.",
                severity="medium",
                cvss_score=6.5,
                evidence={"provider": provider},
                remediation="Enable tenant-wide audit logging, export logs to an immutable sink, and alert on high-risk operations.",
                technique_ids=["T1562.008"],
            )
        )
    if not guardduty:
        failed.append("Threat detection not enabled")
        findings.append(
            FindingDraft(
                title="Cloud threat detection service not reported as enabled",
                description="GuardDuty/Defender/Security Command Center coverage adds behavior-based detection for compromised identities and workloads.",
                severity="low",
                cvss_score=3.1,
                evidence={"provider": provider},
                remediation="Enable the native cloud threat detection service in all regions/subscriptions and route findings to the SOC.",
                technique_ids=["T1562.008"],
            )
        )
    if trail or guardduty or activity_log:
        passed.append("Cloud monitoring controls present")

    sg_list = network.get("security_groups") or network.get("securityGroups") or network.get("firewall_rules") or []
    for rule in sg_list if isinstance(sg_list, list) else []:
        if not isinstance(rule, dict):
            continue
        cidr = str(_get(rule, "cidr", "source", "source_ranges", default=""))
        port = _get(rule, "port", "from_port", "fromPort")
        name = str(_get(rule, "name", "nsg", "rule", default="network-rule"))[:120]
        try:
            port_int = int(port) if port is not None else None
        except (TypeError, ValueError):
            port_int = None
        if "0.0.0.0/0" in cidr and port_int in {22, 3389, 1433, 3306, 5432, 6379, 27017}:
            failed.append(f"Admin port exposed: {name}")
            findings.append(
                FindingDraft(
                    title=f"Management/database port open to the internet: {name}",
                    description=f"Port {port_int} allows 0.0.0.0/0 ingress. Internet-exposed management services are routinely targeted.",
                    severity="high",
                    cvss_score=8.6,
                    evidence={"rule": name, "port": port_int, "cidr": cidr},
                    remediation="Restrict ingress to approved bastions/VPN/Zero Trust, require MFA, and log all administrative connections.",
                    technique_ids=["T1133", "T1078.004"],
                )
            )
        elif "0.0.0.0/0" in cidr and port_int in {80, 443}:
            passed.append(f"Expected web ingress: {name}")
        elif "0.0.0.0/0" in cidr:
            findings.append(
                FindingDraft(
                    title=f"Broad internet ingress rule reported: {name}",
                    description="The rule permits 0.0.0.0/0 on a non-standard service. Validate business necessity.",
                    severity="low",
                    cvss_score=3.7,
                    evidence={"rule": name, "port": port_int, "cidr": cidr},
                    remediation="Document required ingress and restrict to known source ranges.",
                    technique_ids=["T1133"],
                )
            )

    if not findings:
        findings.append(
            FindingDraft(
                title="Cloud configuration snapshot passed the baseline",
                description="No issues were detected across identity, storage, IAM, logging and network controls in the supplied snapshot.",
                severity="info",
                evidence={"provider": provider, "controls_passed": len(passed)},
                remediation="Maintain continuous posture scanning and quarterly access reviews.",
            )
        )
    summary = {
        "provider": provider,
        "controls_passed": passed,
        "controls_failed": failed,
        "resources": {
            "storage": len(storage) if isinstance(storage, list) else 0,
            "iam_policies": len(iam) if isinstance(iam, list) else 0,
            "network_rules": len(sg_list) if isinstance(sg_list, list) else 0,
        },
        "notice": "Read-only configuration snapshot analysis. No cloud credentials were used and no changes were made.",
    }
    return findings, summary


async def run(context: RunContext, config: dict[str, Any]) -> EngineResult:
    provider = config.get("provider", "aws")
    findings, summary = analyze_snapshot(config.get("snapshot", {}), provider)
    result = EngineResult()
    result.findings = findings
    result.summary = {**summary, "source": "operator-supplied read-only snapshot"}
    return result.finalize("cloud")
