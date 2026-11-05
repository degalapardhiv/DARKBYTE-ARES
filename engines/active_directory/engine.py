from __future__ import annotations

from typing import Any

from engines.base import EngineResult, FindingDraft, RunContext


def _dict(snapshot: dict, *keys: str) -> dict:
    for key in keys:
        value = snapshot.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _list(snapshot: dict, *keys: str) -> list:
    for key in keys:
        value = snapshot.get(key)
        if isinstance(value, list):
            return value
    return []


def _int(mapping: dict, keys: tuple[str, ...], default: int = 0) -> int:
    for key in keys:
        if key in mapping:
            try:
                return int(mapping[key])
            except (TypeError, ValueError):
                return default
    return default


def _bool(mapping: dict, keys: tuple[str, ...], default: bool = False) -> bool:
    for key in keys:
        if key in mapping:
            return bool(mapping[key])
    return default


def analyze_snapshot(snapshot: dict[str, Any]) -> tuple[list[FindingDraft], dict[str, Any]]:
    findings: list[FindingDraft] = []
    passed: list[str] = []
    failed: list[str] = []

    policy = _dict(snapshot, "password_policy", "passwordPolicy")
    min_length = _int(policy, ("minimum_length", "min_length", "minLength"), 8)
    lockout = _int(policy, ("lockout_threshold", "lockoutThreshold", "lockout_after"), 0)
    lockout_duration = _int(policy, ("lockout_duration_minutes", "lockoutDurationMinutes"), 0)
    history = _int(policy, ("history_count", "password_history", "passwordHistoryCount"), 0)
    max_age = _int(policy, ("max_age_days", "maxPasswordAgeDays"), 0)
    complexity = _bool(policy, ("complexity_enabled", "complexityEnabled"), False)
    reversible = _bool(policy, ("reversible_encryption", "reversibleEncryption"), False)

    if not policy:
        failed.append("Password policy not supplied")
        findings.append(
            FindingDraft(
                title="Active Directory password policy was not present in the snapshot",
                description="The exported configuration did not include a password policy object, so strength and lockout controls could not be evaluated.",
                severity="medium",
                cvss_score=5.0,
                evidence={"expected_key": "password_policy"},
                remediation="Export the domain password policy and rerun the assessment.",
                technique_ids=["T1110.003"],
            )
        )
    else:
        if min_length < 14:
            failed.append("Minimum password length < 14")
            findings.append(
                FindingDraft(
                    title="Domain password minimum length is below 14 characters",
                    description="Short minimum lengths increase the feasibility of offline and online guessing, especially for privileged accounts.",
                    severity="medium",
                    cvss_score=5.3,
                    evidence={"minimum_length": min_length},
                    remediation="Require at least 14 characters (consider 16+ for privileged tiers) and screen against breached-password lists.",
                    references=["https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/password-policy"],
                    technique_ids=["T1110.003", "T1078.002"],
                )
            )
        else:
            passed.append("Minimum password length >= 14")
        if lockout == 0:
            failed.append("No lockout threshold")
            findings.append(
                FindingDraft(
                    title="No account lockout threshold is configured",
                    description="Without lockout or throttling, password spraying against the domain can continue indefinitely.",
                    severity="high",
                    cvss_score=7.5,
                    evidence={"lockout_threshold": lockout, "lockout_duration_minutes": lockout_duration},
                    remediation="Set a risk-based lockout threshold (for example 5–10) with observation windows and alerting.",
                    technique_ids=["T1110.003"],
                )
            )
        else:
            passed.append("Account lockout threshold configured")
        if 0 < history < 10:
            failed.append("Password history < 10")
            findings.append(
                FindingDraft(
                    title="Password history permits rapid reuse",
                    description="A short password history allows users to return to recently used or breached credentials.",
                    severity="low",
                    cvss_score=3.1,
                    evidence={"history_count": history},
                    remediation="Remember at least 24 passwords and enforce breached-credential screening.",
                    technique_ids=["T1110"],
                )
            )
        elif history >= 10:
            passed.append("Password history >= 10")
        if max_age == 0:
            passed.append("Password expiry disabled (supported by longer minimum length)")
        elif max_age < 60:
            failed.append("Password maximum age too short")
            findings.append(
                FindingDraft(
                    title="Aggressive password expiration policy may drive weak patterns",
                    description="Very short maximum password ages encourage predictable increments and reduce passphrase quality.",
                    severity="low",
                    cvss_score=2.6,
                    evidence={"max_age_days": max_age},
                    remediation="Prefer long passphrases, breached-password screening and MFA over frequent forced rotation.",
                    technique_ids=["T1110"],
                )
            )
        if not complexity:
            failed.append("Complexity disabled")
            findings.append(
                FindingDraft(
                    title="Password complexity is not enabled",
                    description="The domain does not enforce the configured character-class policy, which may be acceptable only when a long minimum length and breached-password screening are enforced.",
                    severity="low",
                    cvss_score=3.1,
                    evidence={"complexity_enabled": complexity, "minimum_length": min_length},
                    remediation="Use a long minimum length plus breached-password screening; if complexity is required by policy, enable it and monitor helpdesk impact.",
                    technique_ids=["T1110"],
                )
            )
        else:
            passed.append("Password complexity enabled")
        if reversible:
            failed.append("Reversible encryption enabled")
            findings.append(
                FindingDraft(
                    title="Reversible password encryption is enabled",
                    description="Reversible encryption exposes credentials to anyone who can read the relevant policy and directory data.",
                    severity="critical",
                    cvss_score=9.1,
                    evidence={"reversible_encryption": True},
                    remediation="Disable Store passwords using reversible encryption and rotate affected credentials.",
                    technique_ids=["T1555", "T1078.002"],
                )
            )

    kerberos = _dict(snapshot, "kerberos")
    krbtgt_age = _int(kerberos, ("krbtgt_password_age_days", "krbtgtPasswordAgeDays"), 0)
    if krbtgt_age > 180:
        failed.append("krbtgt password older than 180 days")
        findings.append(
            FindingDraft(
                title="krbtgt account password exceeds 180 days",
                description="A stale krbtgt key extends the usefulness of stolen Kerberos material and golden-ticket persistence.",
                severity="medium",
                cvss_score=5.9,
                evidence={"krbtgt_password_age_days": krbtgt_age},
                remediation="Execute the documented two-stage krbtgt password rotation with replication validation.",
                references=["https://learn.microsoft.com/windows-server/identity/ad-ds/manage/ad-forest-recovery-reset-the-krbtgt-password"],
                technique_ids=["T1558.001"],
            )
        )
    elif kerberos:
        passed.append("krbtgt key age within threshold")

    encryption_types = kerberos.get("supported_encryption_types") or kerberos.get("encryption_types") or []
    if isinstance(encryption_types, str):
        encryption_types = [item.strip() for item in encryption_types.split(",")]
    if any(str(item).upper() in {"RC4", "RC4_HMAC_MD5", "23", "0x17"} for item in encryption_types):
        failed.append("RC4 Kerberos enabled")
        findings.append(
            FindingDraft(
                title="RC4 is enabled for Kerberos",
                description="RC4 is cryptographically weak and increases Kerberoasting risk.",
                severity="medium",
                cvss_score=5.9,
                evidence={"supported_encryption_types": [str(item) for item in encryption_types][:10]},
                remediation="Require AES128/AES256, validate service account compatibility, then disable RC4.",
                technique_ids=["T1558.003"],
            )
        )
    elif encryption_types:
        passed.append("Modern Kerberos encryption present")

    unconstrained = snapshot.get("unconstrained_delegation") or snapshot.get("unconstrainedDelegation") or []
    if isinstance(unconstrained, int):
        unconstrained_count = unconstrained
    elif isinstance(unconstrained, list):
        unconstrained_count = len(unconstrained)
    else:
        unconstrained_count = 0
    if unconstrained_count:
        failed.append("Unconstrained delegation principals")
        findings.append(
            FindingDraft(
                title=f"{unconstrained_count} principal(s) use unconstrained delegation",
                description="Unconstrained Kerberos delegation can be abused to capture reusable credentials for any service.",
                severity="high",
                cvss_score=8.0,
                evidence={"principal_count": unconstrained_count},
                remediation="Replace unconstrained delegation with resource-based constrained delegation and protect Tier-0 accounts.",
                technique_ids=["T1558.001", "T1078.002"],
            )
        )
    else:
        passed.append("No unconstrained delegation reported")

    privileged = _list(snapshot, "privileged_groups", "privilegedGroups")
    excessive_groups = []
    for group in privileged:
        if not isinstance(group, dict):
            continue
        count = group.get("member_count") or group.get("memberCount") or len(group.get("members", []) or [])
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 0
        if count > 5:
            excessive_groups.append({"name": str(group.get("name", "privileged-group"))[:100], "members": count})
    if excessive_groups:
        findings.append(
            FindingDraft(
                title="Privileged groups exceed the least-privilege baseline",
                description="Several privileged groups have more than five members. Excess standing privilege increases blast radius.",
                severity="medium",
                cvss_score=5.9,
                evidence={"groups": excessive_groups[:10]},
                remediation="Adopt tiered administration, remove standing privilege, and use just-in-time elevation.",
                technique_ids=["T1078.002", "T1098"],
            )
        )
    elif privileged:
        passed.append("Privileged group sizes within baseline")

    accounts = _dict(snapshot, "accounts")
    stale = _int(accounts, ("stale_accounts", "staleAccounts", "inactive_accounts"), 0)
    never_expires = _int(accounts, ("password_never_expires", "passwordNeverExpires"), 0)
    if stale > 0:
        findings.append(
            FindingDraft(
                title=f"{stale} stale account(s) reported",
                description="Inactive accounts retain access paths and are often overlooked in joiner/mover/leaver processes.",
                severity="low",
                cvss_score=3.1,
                evidence={"stale_accounts": stale},
                remediation="Disable or delete inactive accounts after an approved review and alert on future stale accounts.",
                technique_ids=["T1078.002"],
            )
        )
    if never_expires > 0:
        findings.append(
            FindingDraft(
                title=f"{never_expires} account(s) configured with non-expiring passwords",
                description="Non-expiring passwords should be limited to documented break-glass accounts with compensating controls.",
                severity="low",
                cvss_score=3.1,
                evidence={"password_never_expires": never_expires},
                remediation="Review each non-expiring account; require long passphrases and MFA, and document exceptions.",
                technique_ids=["T1078.002"],
            )
        )

    trusts = _list(snapshot, "trusts")
    if any(bool(trust.get("sid_filtering_disabled")) for trust in trusts if isinstance(trust, dict)):
        failed.append("SID filtering disabled")
        findings.append(
            FindingDraft(
                title="A domain trust has SID filtering disabled",
                description="Disabling SID filtering can allow privilege escalation through injected SIDs from a trusted domain.",
                severity="high",
                cvss_score=8.1,
                evidence={"trusts_affected": [str(t.get("name", "trust")) for t in trusts if isinstance(t, dict) and t.get("sid_filtering_disabled")][:10]},
                remediation="Re-enable SID filtering and review the trust design with the identity team.",
                technique_ids=["T1134.005"],
            )
        )

    if not findings:
        findings.append(
            FindingDraft(
                title="Active Directory snapshot passed the configured baseline",
                description="The supplied read-only configuration snapshot did not trigger any baseline checks.",
                severity="info",
                evidence={"checks_passed": len(passed)},
                remediation="Retain the evidence, validate coverage against current benchmarks, and repeat the audit after changes.",
            )
        )

    summary = {
        "domain_name": str(snapshot.get("domain_name", ""))[:253],
        "controls_passed": passed,
        "controls_failed": failed,
        "privileged_group_count": len(privileged),
        "trust_count": len(trusts),
        "checks": {
            "password_policy": bool(policy),
            "kerberos": bool(kerberos),
            "privileged_groups": bool(privileged),
            "trusts": bool(trusts),
            "accounts": bool(accounts),
        },
        "notice": "This is a read-only configuration analysis. No LDAP connection, authentication attempt or password attack is performed.",
    }
    return findings, summary


async def run(context: RunContext, config: dict[str, Any]) -> EngineResult:
    snapshot = config.get("snapshot", {})
    findings, summary = analyze_snapshot(snapshot)
    result = EngineResult()
    result.findings = findings
    result.summary = {
        **summary,
        "domain_name": config.get("domain_name") or summary["domain_name"],
        "source": "operator-supplied read-only snapshot",
    }
    return result.finalize("active_directory")
