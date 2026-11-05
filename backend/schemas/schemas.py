from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import Enum
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

# ─────────────────────────────────────────────────────────────────────────────
# Auth and users
# ─────────────────────────────────────────────────────────────────────────────
PASSWORD_POLICY = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,128}$")


class Role(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        if not PASSWORD_POLICY.match(value):
            raise ValueError(
                "Password must be 12+ characters and include uppercase, lowercase, a number and a symbol."
            )
        if value.lower() in {"password123!", "aresadmin2026!", "darkbyteares!"}:
            raise ValueError("This password is too common.")
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    preferences: dict[str, Any] = {}
    last_login_at: datetime | None = None
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    preferences: dict[str, Any] = Field(default_factory=dict)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        if not PASSWORD_POLICY.match(value):
            raise ValueError(
                "Password must be 12+ characters and include uppercase, lowercase, a number and a symbol."
            )
        return value


# ─────────────────────────────────────────────────────────────────────────────
# Targets / authorization
# ─────────────────────────────────────────────────────────────────────────────
TARGET_ACTIONS = {
    "recon",
    "network_scan",
    "web_scan",
    "vulnerability_lookup",
    "osint",
    "password_audit",
    "config_audit",
    "cloud_audit",
    "api_scan",
    "simulation",
}
TARGET_TYPES = {
    "domain",
    "ip",
    "cidr",
    "url",
    "api",
    "cloud_account",
    "ad_config",
    "password_policy",
    "local",
}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
HOST_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    target_type: Literal[
        "domain", "ip", "cidr", "url", "api", "cloud_account", "ad_config", "password_policy", "local"
    ]
    value: str = Field(min_length=1, max_length=1024)
    environment: Literal["production", "staging", "lab"] = "lab"
    authorization_ref: str = Field(
        min_length=6,
        max_length=320,
        description="Ticket, contract, or written authorization reference held by the operator.",
    )
    authorized_by: str = Field(min_length=2, max_length=160)
    authorization_expires: datetime | None = None
    allowed_actions: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=4000)

    @field_validator("allowed_actions")
    @classmethod
    def valid_actions(cls, actions: list[str]) -> list[str]:
        clean = sorted({a.strip() for a in actions if a.strip()})
        invalid = set(clean) - TARGET_ACTIONS
        if invalid:
            raise ValueError(f"Unknown actions: {', '.join(sorted(invalid))}")
        if not clean:
            raise ValueError("At least one allowed action is required.")
        return clean

    @model_validator(mode="after")
    def validate_target_value(self):
        value = self.value.strip()
        if self.target_type == "domain":
            value = value.lower().rstrip(".")
            if not DOMAIN_RE.match(value):
                raise ValueError("Enter a fully-qualified public domain (for example app.example.com).")
        elif self.target_type == "ip":
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise ValueError("Enter a valid IPv4 or IPv6 address.") from exc
        elif self.target_type == "cidr":
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError("Enter a valid IPv4 or IPv6 CIDR range.") from exc
            if network.prefixlen == 0:
                raise ValueError("A /0 scope is never permitted.")
            value = str(network)
        elif self.target_type in {"url", "api"}:
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Enter an absolute http(s) URL.")
            if parsed.username or parsed.password:
                raise ValueError("Credentials must never be embedded in target URLs.")
            value = value.rstrip("/")
        else:
            if not HOST_RE.match(value) or len(value) < 2:
                raise ValueError("Use a stable identifier without spaces or secrets.")
        self.value = value
        return self


class TargetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=2, max_length=160)
    environment: Literal["production", "staging", "lab"] | None = None
    authorization_ref: str | None = Field(default=None, min_length=6, max_length=320)
    authorized_by: str | None = Field(default=None, min_length=2, max_length=160)
    authorization_expires: datetime | None = None
    allowed_actions: list[str] | None = None
    notes: str | None = Field(default=None, max_length=4000)

    @field_validator("allowed_actions")
    @classmethod
    def valid_actions(cls, actions: list[str] | None) -> list[str] | None:
        if actions is None:
            return None
        clean = sorted({a.strip() for a in actions if a.strip()})
        invalid = set(clean) - TARGET_ACTIONS
        if invalid:
            raise ValueError(f"Unknown actions: {', '.join(sorted(invalid))}")
        if not clean:
            raise ValueError("At least one allowed action is required.")
        return clean


class TargetVerify(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_actions: list[str]
    authorization_expires: datetime | None = None
    note: str = Field(default="", max_length=2000)

    @field_validator("allowed_actions")
    @classmethod
    def valid_actions(cls, actions: list[str]) -> list[str]:
        clean = sorted({a.strip() for a in actions if a.strip()})
        invalid = set(clean) - TARGET_ACTIONS
        if invalid:
            raise ValueError(f"Unknown actions: {', '.join(sorted(invalid))}")
        if not clean:
            raise ValueError("At least one allowed action is required.")
        return clean


class TargetReject(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=1000)


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    target_type: str
    value: str
    environment: str
    authorization_ref: str
    authorized_by: str
    authorization_expires: datetime | None
    allowed_actions: list[str]
    status: str
    verified_by: str | None
    verified_at: datetime | None
    notes: str
    is_demo: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


# ─────────────────────────────────────────────────────────────────────────────
# Module configurations (validated before a job can enter the queue)
# ─────────────────────────────────────────────────────────────────────────────
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReconConfig(StrictModel):
    include_subdomains: bool = True
    include_whois: bool = True
    include_tls: bool = True
    include_http: bool = True
    max_subdomains: int = Field(default=30, ge=0, le=80)
    extra_subdomains: list[str] = Field(default_factory=list, max_length=50)
    timeout: float = Field(default=6.0, ge=2.0, le=15.0)

    @field_validator("extra_subdomains")
    @classmethod
    def valid_labels(cls, values: list[str]) -> list[str]:
        out: list[str] = []
        for item in values:
            label = item.strip().lower()
            if not re.match(r"^[a-z0-9][a-z0-9-]{1,61}$", label):
                raise ValueError(f"Invalid subdomain label: {item[:40]}")
            out.append(label)
        return sorted(set(out))


class NetworkConfig(StrictModel):
    ports: list[int] = Field(
        default_factory=lambda: [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
            3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017,
        ]
    )
    engine: Literal["tcp", "nmap"] = "tcp"
    timeout: float = Field(default=2.0, ge=0.4, le=10.0)
    max_hosts: int = Field(default=16, ge=1, le=256)
    concurrency: int = Field(default=100, ge=1, le=300)
    service_banners: bool = True

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values: list[int]) -> list[int]:
        clean = sorted({int(port) for port in values})
        if not clean:
            raise ValueError("Provide at least one port.")
        if len(clean) > 512:
            raise ValueError("A single scan is limited to 512 ports.")
        if any(port < 1 or port > 65535 for port in clean):
            raise ValueError("Ports must be between 1 and 65535.")
        return clean


class WebConfig(StrictModel):
    include_tls: bool = True
    include_headers: bool = True
    include_misconfig: bool = True
    reflection_probe: bool = False
    sqli_probe: bool = False
    timeout: float = Field(default=8.0, ge=2.0, le=20.0)


class VulnerabilityConfig(StrictModel):
    keywords: list[str] = Field(default_factory=list, max_length=5)
    cve_ids: list[str] = Field(default_factory=list, max_length=10)
    min_cvss: float = Field(default=0.0, ge=0.0, le=10.0)
    max_results: int = Field(default=20, ge=1, le=50)
    include_live_nvd: bool = True
    include_bundled_snapshot: bool = True

    @model_validator(mode="after")
    def query_required(self):
        if not self.keywords and not self.cve_ids:
            raise ValueError("Provide at least one product keyword or CVE identifier.")
        return self

    @field_validator("cve_ids")
    @classmethod
    def valid_cve_ids(cls, values: list[str]) -> list[str]:
        clean = [value.strip().upper() for value in values if value.strip()]
        for cve in clean:
            if not re.match(r"^CVE-\d{4}-\d{4,8}$", cve):
                raise ValueError(f"Invalid CVE identifier: {cve[:32]}")
        return sorted(set(clean))

    @field_validator("keywords")
    @classmethod
    def valid_keywords(cls, values: list[str]) -> list[str]:
        return [value.strip()[:80] for value in values if value.strip()]


class OsintConfig(StrictModel):
    include_crtsh: bool = True
    include_whois: bool = True
    include_dns: bool = True
    document_url: str | None = None
    timeout: float = Field(default=10.0, ge=3.0, le=25.0)

    @field_validator("document_url")
    @classmethod
    def valid_url(cls, value: str | None) -> str | None:
        if not value:
            return None
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Document URL must be an absolute http(s) URL.")
        if parsed.username or parsed.password:
            raise ValueError("Credentials are not allowed in a document URL.")
        return value


class PasswordPolicy(StrictModel):
    min_length: int = Field(default=12, ge=1, le=128)
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    max_reuse: int = Field(default=5, ge=0, le=50)
    lockout_after: int = Field(default=5, ge=0, le=100)
    lockout_minutes: int = Field(default=15, ge=1, le=1440)
    mfa_required: bool = False


class PasswordAuditRequest(StrictModel):
    target_id: str = Field(min_length=8, max_length=64)
    policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    test_passwords: list[str] = Field(default_factory=list, max_length=20)
    hashes: list[str] = Field(default_factory=list, max_length=100)
    hash_algorithm: Literal["auto", "md5", "sha1", "sha256", "bcrypt", "argon2"] = "auto"
    wordlist: list[str] = Field(default_factory=list, max_length=2000)

    @field_validator("test_passwords")
    @classmethod
    def password_sizes(cls, values: list[str]) -> list[str]:
        if any(len(value) > 256 for value in values):
            raise ValueError("Test passwords are limited to 256 characters.")
        return values

    @field_validator("hashes")
    @classmethod
    def hash_sizes(cls, values: list[str]) -> list[str]:
        clean = [value.strip() for value in values if value.strip()]
        if any(len(value) > 256 for value in clean):
            raise ValueError("Hash strings are limited to 256 characters.")
        return clean

    @field_validator("wordlist")
    @classmethod
    def word_sizes(cls, values: list[str]) -> list[str]:
        clean = [value for value in values if value]
        if any(len(value) > 128 for value in clean):
            raise ValueError("Wordlist entries are limited to 128 characters.")
        return clean


class ActiveDirectoryConfig(StrictModel):
    snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Read-only export of AD password/Kerberos/privilege configuration.",
    )
    domain_name: str = Field(default="", max_length=253)

    @model_validator(mode="after")
    def limited_snapshot(self):
        if len(str(self.snapshot)) > 400_000:
            raise ValueError("Configuration snapshot exceeds the 400 KB limit.")
        if not self.snapshot:
            raise ValueError("An exported AD configuration snapshot is required.")
        return self


class CloudConfig(StrictModel):
    provider: Literal["aws", "azure", "gcp"] = "aws"
    snapshot: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def limited_snapshot(self):
        if len(str(self.snapshot)) > 400_000:
            raise ValueError("Cloud snapshot exceeds the 400 KB limit.")
        if not self.snapshot:
            raise ValueError("A read-only cloud configuration snapshot is required.")
        return self


class ApiSecurityConfig(StrictModel):
    endpoints: list[str] = Field(default_factory=list, max_length=25)
    include_auth_checks: bool = True
    include_cors_check: bool = True
    include_rate_limit_check: bool = False
    timeout: float = Field(default=7.0, ge=2.0, le=20.0)

    @field_validator("endpoints")
    @classmethod
    def valid_paths(cls, paths: list[str]) -> list[str]:
        clean: list[str] = []
        for path in paths:
            p = path.strip()
            if not p:
                continue
            if not p.startswith("/") or len(p) > 300 or ".." in p or "://" in p:
                raise ValueError(f"Endpoint paths must start with '/' and stay on the authorized origin: {p[:80]}")
            if any(ch in p for ch in "\r\n"):
                raise ValueError("Invalid endpoint path.")
            clean.append(p)
        return sorted(set(clean))


class RedTeamConfig(StrictModel):
    scenario: Literal[
        "initial_access",
        "discovery",
        "credential_access",
        "lateral_movement",
        "defense_evasion",
        "impact_readiness",
    ] = "discovery"
    technique_ids: list[str] = Field(default_factory=list, max_length=20)
    objective: str = Field(default="Validate detection coverage for a controlled tabletop exercise.", max_length=500)

    @field_validator("technique_ids")
    @classmethod
    def valid_techniques(cls, values: list[str]) -> list[str]:
        clean: list[str] = []
        for value in values:
            if not re.match(r"^T\d{4}(?:\.\d{3})?$", value.strip().upper()):
                raise ValueError(f"Invalid ATT&CK technique ID: {value[:32]}")
            clean.append(value.strip().upper())
        return sorted(set(clean))


MODULE_CONFIG_SCHEMAS: dict[str, type[BaseModel]] = {
    "recon": ReconConfig,
    "network": NetworkConfig,
    "web": WebConfig,
    "vulnerability": VulnerabilityConfig,
    "osint": OsintConfig,
    "active_directory": ActiveDirectoryConfig,
    "cloud": CloudConfig,
    "api_security": ApiSecurityConfig,
    "red_team": RedTeamConfig,
}

ModuleName = Literal[
    "recon",
    "network",
    "web",
    "vulnerability",
    "osint",
    "password",
    "active_directory",
    "cloud",
    "api_security",
    "red_team",
]

ALL_MODULES: tuple[str, ...] = (
    "recon",
    "network",
    "web",
    "vulnerability",
    "osint",
    "password",
    "active_directory",
    "cloud",
    "api_security",
    "red_team",
)


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, max_length=200)
    module: ModuleName
    target_id: str = Field(min_length=8, max_length=64)
    config: dict[str, Any] = Field(default_factory=dict)
    start: bool = True

    @model_validator(mode="after")
    def validate_module_config(self):
        if self.module == "password":
            return self
        schema = MODULE_CONFIG_SCHEMAS[self.module]
        try:
            validated = schema.model_validate(self.config)
        except Exception as exc:
            raise ValueError(f"Invalid {self.module} configuration: {exc}") from exc
        self.config = validated.model_dump(mode="json")
        return self


class AssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    module: str
    target_id: str
    target_name: str | None = None
    target_value: str | None = None
    config: dict[str, Any]
    status: str
    progress: int
    summary: dict[str, Any]
    risk_score: float
    error: str | None
    is_demo: bool
    created_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class FindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "accepted", "remediated", "false_positive"]


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    assessment_id: str
    target_id: str
    module: str
    title: str
    description: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    cve_id: str | None
    evidence: dict[str, Any]
    remediation: str
    references: list[str]
    technique_ids: list[str]
    status: str
    is_demo: bool
    created_at: datetime


# ─────────────────────────────────────────────────────────────────────────────
# Reports, notifications, platform
# ─────────────────────────────────────────────────────────────────────────────
class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: str = Field(min_length=8, max_length=64)
    format: Literal["pdf", "html", "json"] = "pdf"
    title: str | None = Field(default=None, max_length=300)


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    assessment_id: str
    title: str
    format: str
    size_bytes: int
    status: str
    executive_summary: str
    meta: dict[str, Any]
    is_demo: bool
    created_by: str
    created_at: datetime


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    title: str
    message: str
    level: str
    read: bool
    link: str | None
    created_at: datetime


class PluginRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: str = Field(min_length=8, max_length=64)


class UserAdminUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preferences: dict[str, Any] = Field(default_factory=dict)

    @field_validator("preferences")
    @classmethod
    def bounded_preferences(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(str(value)) > 8000:
            raise ValueError("Preferences exceed the 8 KB limit.")
        allowed = {
            "notifications", "compactMode", "defaultEnvironment", "theme",
            "timezone", "emailDigest", "criticalAlerts",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"Unknown preference keys: {', '.join(sorted(unknown))}")
        return value


class CvssRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vector: str = Field(min_length=20, max_length=256)


class PasswordAuditResponse(BaseModel):
    assessment: AssessmentOut
    strength: list[dict[str, Any]]
    hash_audit: dict[str, Any]
    policy_findings: list[dict[str, Any]]


class HealthOut(BaseModel):
    status: str
    version: str
    environment: str
    demo_mode: bool
    database: str
    redis: str
    queue_workers: int
