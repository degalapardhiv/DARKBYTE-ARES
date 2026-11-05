# Modules and configuration

DARKBYTE ARES exposes ten modules. Nine run through the persistent assessment
queue; **Password Audit** is a synchronous tool so plaintext and hashes never
enter durable job storage.

Every module is bound to a target record. Before an assessment is queued and
again immediately before execution, the platform checks:

1. target status (`verified` unless verification is disabled);
2. demo/production separation;
3. authorization expiry;
4. the module's action against `allowed_actions`;
5. the module's accepted target types.

Module configuration is validated with Pydantic models that forbid unknown
fields. Array sizes, timeouts, ports and snapshots are capped server-side.

## Module matrix

| Module ID | Action | Target types | Execution |
| --- | --- | --- | --- |
| `recon` | `recon` | `domain` | Queued |
| `network` | `network_scan` | `ip`, `cidr` | Queued |
| `web` | `web_scan` | `url`, `domain` | Queued |
| `vulnerability` | `vulnerability_lookup` | `domain`, `url`, `local` | Queued |
| `osint` | `osint` | `domain` | Queued |
| `password` | `password_audit` | `local`, `password_policy` | Synchronous tool |
| `active_directory` | `config_audit` | `local`, `ad_config` | Queued |
| `cloud` | `cloud_audit` | `local`, `cloud_account` | Queued |
| `api_security` | `api_scan` | `api`, `url` | Queued |
| `red_team` | `simulation` | Any verified target type | Queued |

The module catalog returned by `GET /api/v1/modules` includes each module's
description, capabilities, target types, ATT&CK mapping and JSON schema.

---

## 01 · Reconnaissance (`recon`)

Passive-first external asset discovery and attack-surface mapping.

**What it collects**

- A/AAAA, MX, NS, TXT and CNAME records using the system resolver.
- Bounded subdomain labels (wordlist plus operator-supplied labels).
- WHOIS registration metadata via the optional `python-whois` integration.
- TLS certificate metadata and safe HTTP fingerprinting.
- Email-security posture from SPF/DMARC/DKIM-related TXT records.

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `include_subdomains` | `true` | bool | Enables bounded subdomain resolution. |
| `include_whois` | `true` | bool | WHOIS may be unavailable for some TLDs. |
| `include_tls` | `true` | bool | Certificate issuer, validity and subject metadata. |
| `include_http` | `true` | bool | Safe HTTP response metadata. |
| `max_subdomains` | `30` | 0–80 | Hard cap on labels resolved. |
| `extra_subdomains` | `[]` | max 50 labels | Validated single labels. |
| `timeout` | `6.0` | 2–15 s | Per-operation timeout. |

**Safety boundary:** no zone transfers, brute-force DNS, exploitation or
credential attacks. Domain targets must be fully qualified public domains.

---

## 02 · Network Scanner (`network`)

Bounded TCP service inventory for an authorized IP or CIDR.

**What it does**

- Expands the CIDR, caps hosts with `max_hosts` and the global
  `MAX_SCAN_HOSTS` setting.
- Opens TCP connections to the selected ports with bounded concurrency.
- Identifies common services from port mappings and optional first-line banners.
- Prioritizes risky exposed services (for example SMB, Redis, MongoDB, Docker,
  Elasticsearch) as findings.
- Builds a topology summary for the console.

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `ports` | 21 common ports | 1–512 unique, 1–65535 | Server cap also applies. |
| `engine` | `"tcp"` | `tcp` or `nmap` | Nmap is optional and local. |
| `timeout` | `2.0` | 0.4–10 s | Per-connection timeout. |
| `max_hosts` | `16` | 1–256 | Also capped by `MAX_SCAN_HOSTS`. |
| `concurrency` | `100` | 1–300 | Async connection semaphore. |
| `service_banners` | `true` | bool | Reads a short first line on selected ports. |

**Safety boundary:** cloud metadata addresses (`169.254.169.254`,
`fd00:ec2::254`) are always rejected. Loopback and private ranges require the
corresponding lab/staging flags. `/0` scope is never accepted. Nmap is used only
when available and configured; failures fall back to TCP connect with an
explanatory error in evidence.

---

## 03 · Web Security (`web`)

OWASP-aligned, non-destructive baseline for a URL or domain.

**What it checks**

- Security headers (HSTS, CSP, frame options, content type options, referrer
  policy, permissions policy).
- TLS certificate validity and basic transport metadata.
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`).
- Common sensitive files with bounded requests.
- Optional, lab-gated reflection and SQL-injection probes, disabled by default.

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `include_tls` | `true` | bool | Certificate and HTTPS checks. |
| `include_headers` | `true` | bool | Header baseline. |
| `include_misconfig` | `true` | bool | Sensitive-file and cookie review. |
| `reflection_probe` | `false` | bool | Lab-gated; requires lab context. |
| `sqli_probe` | `false` | bool | Lab-gated; disabled by default. |
| `timeout` | `8.0` | 2–20 s | Per-request timeout. |

**Safety boundary:** no exploit payload delivery, authentication bypass,
destructive requests or uncontrolled fuzzing. Probes remain off unless
explicitly enabled in a lab-scoped environment.

---

## 04 · Vulnerability Intelligence (`vulnerability`)

CVE correlation and CVSS v3 scoring for a query or authorized context.

**What it does**

- Queries the NVD API with optional `NVD_API_KEY`.
- Falls back to a bundled, dated real-data snapshot when offline or rate-limited.
- Accepts product keywords and/or explicit CVE IDs.
- Applies `min_cvss` and `max_results` filtering.
- Maps results to CVSS base score/vector, CWE references and ATT&CK context.

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `keywords` | `[]` | max 5 | Product/vendor search terms. |
| `cve_ids` | `[]` | max 10 | Must match `CVE-YYYY-NNNN...`. |
| `min_cvss` | `0.0` | 0–10 | Score filter. |
| `max_results` | `20` | 1–50 | Result cap. |
| `include_live_nvd` | `true` | bool | Live NVD lookup. |
| `include_bundled_snapshot` | `true` | bool | Offline resilience. |

At least one keyword or CVE ID is required. A CVE match describes a vulnerability
record; it does not assert that the target is exploitable. Findings should be
validated before remediation claims.

---

## 05 · OSINT (`osint`)

Passive public-source intelligence for a domain.

**What it collects**

- DNS and WHOIS metadata.
- Certificate transparency entries from crt.sh.
- Optional authorized public-document metadata via `document_url`.
- SHA-256 hashes of fetched document content for provenance.

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `include_crtsh` | `true` | bool | Certificate transparency query. |
| `include_whois` | `true` | bool | Registration metadata. |
| `include_dns` | `true` | bool | DNS inventory. |
| `document_url` | `null` | absolute http(s) | No embedded credentials. |
| `timeout` | `10.0` | 3–25 s | Per-operation timeout. |

**Safety boundary:** document bytes are never persisted. Only hashes, metadata
and derived observations are stored. Do not submit documents you are not
authorized to process.

---

## 06 · Password Audit (`password`)

Local strength and offline hash hygiene review. This module is **not queued**.

**Endpoint**

`POST /api/v1/tools/password-audit`

**Request**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `target_id` | required | — | Verified target allowing `password_audit`. |
| `policy` | see below | — | Policy posture to compare. |
| `test_passwords` | `[]` | max 20, 256 chars each | In-memory only. |
| `hashes` | `[]` | max 100, 256 chars each | In-memory only. |
| `hash_algorithm` | `"auto"` | auto/md5/sha1/sha256/bcrypt/argon2 | Offline audit. |
| `wordlist` | `[]` | max 2000, 128 chars each | In-memory only. |

Policy fields: `min_length` (1–128), `require_uppercase`, `require_lowercase`,
`require_digit`, `require_symbol`, `max_reuse` (0–50), `lockout_after` (0–100),
`lockout_minutes` (1–1440), `mfa_required`.

**Response:** `assessment`, `strength`, `hash_audit`, `policy_findings`. It never
contains the submitted plaintext, hashes or wordlist. The audit log stores only
aggregate counts (`test_password_count`, `hash_count`) and policy details.

**Safety boundary:** no credential store, domain controller, authentication
endpoint or external cracking service is contacted. No plaintext or hash is
persisted or returned. Do not paste production credentials into any shared
system.

---

## 07 · Active Directory Audit (`active_directory`)

Read-only analysis of an operator-supplied AD configuration export.

**Accepted snapshot themes**

- Password and lockout policy.
- Kerberos settings: krbtgt age, ticket lifetime, delegation, AES support.
- Privileged groups and service accounts.
- Audit policy and log retention.
- Account flags such as password-never-expires and admin count.

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `snapshot` | `{}` | required, ≤400 KB string form | Read-only JSON export. |
| `domain_name` | `""` | ≤253 chars | Optional display context. |

**Safety boundary:** no LDAP connection, bind attempt, credential use or write
operation. Findings describe configuration posture, not proof of compromise.

---

## 08 · Cloud Audit (`cloud`)

Read-only posture review of an exported AWS, Azure or GCP configuration snapshot.

**What it reviews**

- Root/administrator access keys, MFA and guest access.
- Public/encrypted storage and HTTPS-only settings.
- Wildcard IAM actions/resources and risky principals.
- Audit logging, flow logs and retention.
- Default VPC usage and publicly open SSH/RDP ranges.

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `provider` | `"aws"` | aws/azure/gcp | Display and interpretation context. |
| `snapshot` | `{}` | required, ≤400 KB string form | Read-only JSON export. |

**Safety boundary:** no cloud credentials are requested, stored or used. ARES
does not call cloud APIs for this module. Snapshot shape is operator-managed;
unknown fields are ignored or surfaced conservatively.

---

## 09 · API Security (`api_security`)

Safe API exposure and policy baseline for an authorized origin.

**What it checks**

- Anonymous GET/OPTIONS access to selected endpoint paths.
- Security headers and CORS policy.
- Authentication hints in responses (without attempting bypass).
- Optional bounded rate-limit evidence.
- Endpoint inventory and response metadata.

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `endpoints` | `[]` | max 25 | Paths must start with `/`; no absolute URLs or `..`. |
| `include_auth_checks` | `true` | bool | Anonymous exposure observations. |
| `include_cors_check` | `true` | bool | CORS policy review. |
| `include_rate_limit_check` | `false` | bool | Limited request-rate evidence. |
| `timeout` | `7.0` | 2–20 s | Per-request timeout. |

**Safety boundary:** no authorization bypass, credential stuffing, destructive
method or large-volume test. Endpoint paths stay on the authorized origin.

---

## 10 · Red Team Simulator (`red_team`)

ATT&CK-mapped tabletop planning and detection-engineering exercise.

**Scenarios**

- `initial_access`
- `discovery`
- `credential_access`
- `lateral_movement`
- `defense_evasion`
- `impact_readiness`

**Configuration**

| Field | Default | Bounds | Notes |
| --- | --- | --- | --- |
| `scenario` | `"discovery"` | one of the six scenarios | Prebuilt detection exercise. |
| `technique_ids` | `[]` | max 20, `T####`/`T####.###` | Additional ATT&CK IDs. |
| `objective` | default text | ≤500 chars | Exercise objective. |

**Output:** a step-by-step tabletop plan with detection hypotheses. Findings
contain `simulation: true`, `mode: "tabletop-only"` and
`executed_against_target: false`.

**Safety boundary:** ARES executes no technique, deploys no malware or payload,
steals no credentials and generates no adversary traffic. The module is a
planning aid, not an attack engine. Any live validation must happen separately
in a properly authorized lab.

---

## Report generation

Any completed assessment can produce a report:

- `pdf` — branded PDF with executive summary, scope, methodology and findings.
- `html` — standalone HTML with the same data.
- `json` — structured payload for integrations.

Reports embed the target's authorization reference and authorizer, and mark demo
data. Downloads require authentication and are audited.

## Config validation quick reference

| Module | Unknown fields | Array caps | Timeout |
| --- | --- | --- | --- |
| recon | rejected | 50 labels | 2–15 s |
| network | rejected | 512 ports, 256 hosts | 0.4–10 s |
| web | rejected | — | 2–20 s |
| vulnerability | rejected | 5 keywords, 10 CVEs | NVD client timeout |
| osint | rejected | — | 3–25 s |
| password | rejected | 20/100/2000 items | in-memory |
| active_directory | rejected | 400 KB snapshot | queue timeout |
| cloud | rejected | 400 KB snapshot | queue timeout |
| api_security | rejected | 25 endpoints | 2–20 s |
| red_team | rejected | 20 technique IDs | queue timeout |

Global queue limits still apply: `MAX_SCAN_HOSTS`, `MAX_PORTS_PER_SCAN`,
`MAX_CONCURRENT_ASSESSMENTS` and `ASSESSMENT_TIMEOUT_SECONDS`.

## ATT&CK mapping

The module catalog exposes a curated technique mapping used by the dashboard and
MITRE page. Findings also carry technique IDs where the engine provides them.
Coverage counts unique observed IDs against the bundled 706-technique dataset.
Coverage is a planning signal, not a certification of detection maturity.
