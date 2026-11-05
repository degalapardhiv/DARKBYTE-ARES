from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from engines.base import EngineResult, FindingDraft, RunContext

# Tiny local audit dictionary. It is not a cracking wordlist service and never
# leaves the assessment process; matched plaintext is never returned.
COMMON_PASSWORDS = [
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "letmein", "welcome", "admin", "admin123", "root",
    "sunshine", "iloveyou", "princess", "dragon", "monkey", "football",
    "baseball", "abc123", "master", "shadow", "superman", "batman", "trustno1",
    "passw0rd", "p@ssw0rd", "p@ssword", "qazwsx", "1q2w3e4r", "changeme",
    "secret", "summer2024", "winter2024", "spring2024", "autumn2024",
    "password!", "admin@123", "welcome1", "welcome123", "letmein123",
    "companyname", "company123", "testing123", "test1234", "default",
    "changeme123", "Password123!", "Ares!Admin2026", "P@ssw0rd!2024",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "zaq12wsx",
    "mypassword", "newpassword", "temporary", "temp1234", "guest",
    "guest123", "user1234", "administrator", "oracle", "cisco", "hunter2",
    "starwars", "whatever", "freedom", "ninja", "azerty", "loveme",
]
SEQUENCES = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
HASH_VARIANTS = {
    "md5": (32, hashlib.md5),
    "sha1": (40, hashlib.sha1),
    "sha256": (64, hashlib.sha256),
}


def _human_crack_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        (60, "seconds"), (60, "minutes"), (24, "hours"), (30, "days"),
        (12, "months"), (100, "years"),
    ]
    value = seconds
    unit = "seconds"
    for factor, name in units:
        if value < factor:
            break
        value /= factor
        unit = name
    if unit == "years" and value > 1000:
        return f"{value:,.0f} years"
    return f"{value:.1f} {unit}"


def score_password(password: str) -> dict[str, Any]:
    """Local strength estimate. The input is never logged or persisted."""
    length = len(password)
    classes = sum(
        [
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"\d", password)),
            bool(re.search(r"[^A-Za-z0-9]", password)),
        ]
    )
    unique = len(set(password)) or 1
    entropy = min(length * math.log2(unique + 1), 220.0)
    score = 0.0
    score += min(45, length * 3.2)
    score += classes * 10
    score += min(15, math.log2(unique + 1) * 3)
    feedback: list[str] = []
    lowered = password.lower()
    if any(common.lower() == lowered for common in COMMON_PASSWORDS):
        score = min(score, 12)
        feedback.append("Found in the local common-password list.")
    if any(common in lowered for common in COMMON_PASSWORDS if len(common) >= 6):
        score = min(score, max(18, score - 22))
        feedback.append("Contains a common password fragment.")
    if any(password[i : i + 4].lower() in SEQUENCES_STRING for i in range(max(0, length - 3))):
        score -= 15
        feedback.append("Contains a keyboard or alphabetical sequence.")
    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Contains repeated characters.")
    if length < 12:
        score -= 15
        feedback.append("Shorter than the 12-character baseline.")
    if classes < 3:
        feedback.append("Use a wider mix of character classes.")
    score = round(max(0.0, min(100.0, score)), 1)
    if score >= 80:
        label = "strong"
    elif score >= 60:
        label = "good"
    elif score >= 40:
        label = "weak"
    else:
        label = "critical"
    guesses = 2 ** min(entropy, 100)
    crack_seconds = guesses / 1e10
    return {
        "score": score,
        "label": label,
        "length": length,
        "character_classes": classes,
        "entropy_bits": round(entropy, 1),
        "estimated_offline_time": _human_crack_time(crack_seconds),
        "feedback": feedback[:6] or ["No obvious weakness detected; validate against your organisation policy."],
        "exposed": False,
    }


SEQUENCES_STRING = " ".join(SEQUENCES)


def detect_hash_format(value: str) -> str:
    value = value.strip()
    if value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
        return "bcrypt"
    if value.startswith("$argon2"):
        return "argon2"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "sha256"
    return "unknown"


def audit_hashes(
    hashes: list[str],
    *,
    algorithm: str = "auto",
    wordlist: list[str] | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Dictionary-check unsalted local hashes. Plaintext matches are redacted."""
    wordlist = wordlist or []
    candidates = sorted({*COMMON_PASSWORDS, *wordlist})[:2200]
    hashes = hashes[:limit]
    selected = algorithm if algorithm != "auto" else None
    supported = 0
    matched: list[dict[str, Any]] = []
    format_counts: dict[str, int] = {}
    unsupported: list[int] = []
    for index, raw in enumerate(hashes):
        detected = detect_hash_format(raw)
        format_counts[detected] = format_counts.get(detected, 0) + 1
        use = selected or detected
        if use not in HASH_VARIANTS:
            unsupported.append(index)
            continue
        supported += 1
        expected_len, digest_fn = HASH_VARIANTS[use]
        if len(raw) != expected_len:
            unsupported.append(index)
            continue
        target = raw.lower()
        for candidate in candidates:
            if digest_fn(candidate.encode()).hexdigest() == target:
                matched.append({"index": index, "algorithm": use, "dictionary_match": True})
                break
    score = 0 if not hashes else round(100 - (len(matched) / len(hashes)) * 100, 1)
    return {
        "hashes_audited": len(hashes),
        "supported_hashes": supported,
        "unsupported_indices": unsupported[:50],
        "matched_hashes": matched[:100],
        "match_count": len(matched),
        "formats": format_counts,
        "dictionary_size": len(candidates),
        "hash_score": score,
        "plaintext_returned": False,
        "notice": "Local dictionary audit only. bcrypt/argon2 hashes are identified but require an authorised external review.",
    }


def evaluate_policy(policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def add(key: str, severity: str, title: str, description: str, remediation: str, cvss: float, evidence: dict):
        findings.append(
            {
                "key": key,
                "severity": severity,
                "title": title,
                "description": description,
                "remediation": remediation,
                "cvss_score": cvss,
                "evidence": evidence,
            }
        )

    if int(policy.get("min_length", 12)) < 12:
        add(
            "min_length", "medium", "Password minimum length is below baseline",
            "The minimum password length is shorter than the 12-character baseline and increases guessing success.",
            "Require at least 12 characters (16 for privileged accounts) and permit long passphrases.",
            5.3, {"min_length": policy.get("min_length")},
        )
    if not policy.get("require_uppercase", True) or not policy.get("require_lowercase", True) or not policy.get("require_digit", True) or not policy.get("require_symbol", True):
        add(
            "complexity", "low", "Password composition policy is incomplete",
            "One or more character-class requirements are disabled. Length is primary, but composition still helps against simple guesses.",
            "Adopt a risk-based policy: long minimum length, breached-password screening, and composition where appropriate.",
            3.1, {"policy": {key: policy.get(key) for key in ("require_uppercase", "require_lowercase", "require_digit", "require_symbol")}},
        )
    if int(policy.get("max_reuse", 5)) < 5:
        add(
            "reuse", "medium", "Password history limit is too low",
            "Allowing rapid password reuse lets users cycle back to compromised credentials.",
            "Prevent reuse of at least the previous 5–24 passwords; screen against known-breached credentials.",
            4.0, {"max_reuse": policy.get("max_reuse")},
        )
    if int(policy.get("lockout_after", 5)) == 0:
        add(
            "lockout", "high", "No account lockout or throttling threshold",
            "Without lockout or adaptive throttling, online guessing and password spraying remain unchecked.",
            "Implement progressive throttling, risk-based lockout and alerting; avoid lockouts that enable denial of service.",
            7.5, {"lockout_after": policy.get("lockout_after")},
        )
    if not policy.get("mfa_required", False):
        add(
            "mfa", "medium", "MFA is not required for the audited scope",
            "Single-factor authentication leaves stolen or guessed passwords sufficient for access.",
            "Require phishing-resistant MFA for administrators and risk-based MFA for all users.",
            6.5, {"mfa_required": policy.get("mfa_required")},
        )
    return findings


async def run(context: RunContext, config: dict[str, Any]) -> EngineResult:
    result = EngineResult()
    passwords = config.get("test_passwords", [])
    hashes = config.get("hashes", [])
    policy = config.get("policy", {})

    strength_results = []
    for index, password in enumerate(passwords, start=1):
        scored = score_password(password)
        scored["index"] = index
        scored["label_name"] = f"Test password #{index}"
        strength_results.append(scored)

    hash_audit = audit_hashes(
        hashes,
        algorithm=config.get("hash_algorithm", "auto"),
        wordlist=config.get("wordlist", []),
    )

    policy_details = evaluate_policy(policy)
    for item in policy_details:
        result.findings.append(
            FindingDraft(
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                cvss_score=item["cvss_score"],
                evidence=item["evidence"],
                remediation=item["remediation"],
                references=["https://pages.nist.gov/800-63-4/", "https://owasp.org/www-project-top-ten/"],
                technique_ids=["T1110"],
            )
        )

    if strength_results:
        weak = [item for item in strength_results if item["score"] < 60]
        if weak:
            result.findings.append(
                FindingDraft(
                    title=f"{len(weak)} of {len(strength_results)} test password(s) are weak",
                    description=(
                        "Local offline strength testing identified passwords that are short, predictable or present "
                        "in the built-in common-password set. Plaintext inputs are not stored or returned."
                    ),
                    severity="high" if any(item["score"] < 40 for item in weak) else "medium",
                    cvss_score=8.1 if any(item["score"] < 40 for item in weak) else 5.3,
                    evidence={
                        "tested": len(strength_results),
                        "weak": len(weak),
                        "score_range": [
                            min(item["score"] for item in strength_results),
                            max(item["score"] for item in strength_results),
                        ],
                    },
                    remediation="Block breached and common passwords, increase minimum length, and require MFA. Re-test using representative test accounts only.",
                    technique_ids=["T1110"],
                    references=["https://pages.nist.gov/800-63-4/"],
                )
            )
        else:
            result.findings.append(
                FindingDraft(
                    title="Local password strength sample passed baseline checks",
                    description="All submitted test passwords scored 60 or higher in the local strength model.",
                    severity="info",
                    evidence={"tested": len(strength_results)},
                    remediation="Continue breached-password screening and periodic policy review.",
                )
            )
    if hash_audit["match_count"]:
        result.findings.append(
            FindingDraft(
                title=f"{hash_audit['match_count']} offline hash(es) matched common-password candidates",
                description=(
                    "The local dictionary audit identified weak hashes in the supplied sample. The matching plaintext "
                    "is deliberately not returned. This operation was offline and did not contact any credential store."
                ),
                severity="high",
                cvss_score=8.1,
                evidence={
                    "match_count": hash_audit["match_count"],
                    "hashes_audited": hash_audit["hashes_audited"],
                    "formats": hash_audit["formats"],
                    "indices": hash_audit["matched_hashes"][:20],
                },
                remediation="Force a reset for affected accounts, migrate to Argon2id or bcrypt, add per-user salts and pepper, and enforce MFA.",
                technique_ids=["T1110", "T1552.002"],
                references=["https://owasp.org/www-project-top-ten/"],
            )
        )
    elif hashes:
        result.findings.append(
            FindingDraft(
                title="No dictionary matches found in offline hash sample",
                description=(
                    "No supplied hash matched the limited local dictionary. This does not indicate strong passwords: "
                    "unsalted and fast hashes remain risky."
                ),
                severity="info",
                evidence={"hashes_audited": hash_audit["hashes_audited"], "format_counts": hash_audit["formats"]},
                remediation="Use memory-hard password hashing (Argon2id) and screen passwords against a breached-password corpus.",
                technique_ids=["T1110"],
            )
        )

    result.summary = {
        "strength": strength_results,
        "hash_audit": hash_audit,
        "policy_findings": policy_details,
        "policy": policy,
        "plaintext_persisted": False,
        "notice": "All password and hash inputs were processed in memory and omitted from the persisted assessment configuration.",
    }
    return result.finalize("password")
