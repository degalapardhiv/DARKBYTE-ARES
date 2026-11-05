# API reference

DARKBYTE ARES exposes a versioned JSON API at:

```text
http://localhost:8000/api/v1
```

Interactive documentation is generated from the live schema:

- Swagger UI: `/docs`
- ReDoc: `/redoc`
- OpenAPI document: `/openapi.json`
- Liveness/readiness probe: `/api/v1/health` and `/health`

All endpoints except `/health`, `/api/v1/health`, login and (when enabled)
registration require an `Authorization: Bearer <token>` header.

## Authentication

### Register

`POST /api/v1/auth/register` — public while `ALLOW_REGISTRATION=true`

```json
{
  "email": "analyst@example.com",
  "name": "Analyst Name",
  "password": "A-Strong-Passphrase-2026!"
}
```

Passwords must be 12–128 characters and include uppercase, lowercase, a digit
and a symbol. Self-service accounts are created with the `analyst` role. The
endpoint returns the same token envelope as login.

### Login

`POST /api/v1/auth/login`

```json
{
  "email": "analyst@example.com",
  "password": "A-Strong-Passphrase-2026!"
}
```

Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 28800,
  "user": {
    "id": "usr_...",
    "email": "analyst@example.com",
    "name": "Analyst Name",
    "role": "analyst",
    "is_active": true,
    "preferences": {},
    "last_login_at": "2026-11-05T12:00:00Z",
    "created_at": "2026-11-01T09:00:00Z"
  }
}
```

Failed logins are audited. Six failures for the same email/IP pair within ten
minutes return `429 login_throttled` with `Retry-After`.

### Session and profile

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `GET` | `/auth/me` | Any authenticated | Current user. |
| `PATCH` | `/auth/profile` | Any authenticated | Update name and bounded preferences. |
| `POST` | `/auth/change-password` | Any authenticated | Change password (current password required). |
| `POST` | `/auth/logout` | Any authenticated | Audit logout; the client discards its token. |

The API uses stateless JWTs. Logout does not maintain a server-side denylist, so
the client must discard the token. Tokens expire after
`ACCESS_TOKEN_EXPIRE_MINUTES` (default 480 minutes).

## Roles

| Role | Capabilities |
| --- | --- |
| `viewer` | Read dashboards, targets, assessments, findings, reports, MITRE data, notifications and modules. |
| `analyst` | Viewer capabilities plus create targets, create/run/cancel owned assessments, triage findings, generate/delete owned reports, run password audits and execute enabled plugins. |
| `admin` | All capabilities plus verify/reject/delete targets, manage users, view/verify the audit chain, enable/disable plugins and delete any assessment. |

Scope-changing target updates by a non-admin are limited to targets they created
and cannot modify verified scope. Any change to scope fields on a verified target
resets it to `pending` for re-verification.

## Error contract

Every HTTP error is normalized:

```json
{
  "error": {
    "code": "target_not_authorized",
    "message": "The scope allowlist does not permit 'recon' for target 'Example'.",
    "details": {}
  }
}
```

Validation errors return `422` with `code: "validation_error"` and a list of
location/type/message objects. Submitted values are not echoed, which avoids
leaking plaintext password-audit payloads.

Common codes include `authentication_required`, `insufficient_role`,
`invalid_credentials`, `login_throttled`, `not_found`, `target_not_authorized`,
`scope_violation`, `assessment_in_progress`, `active_rate_limited`,
`validation_error`, `rate_limited` and `conflict`.

## Rate limits and headers

| Scope | Default | Setting |
| --- | --- | --- |
| Per-IP API requests | 120/minute | `RATE_LIMIT_PER_MINUTE` |
| Per-user active assessment starts | 30/minute | `ACTIVE_SCAN_RATE_LIMIT` |
| Login failures | 6 per email/IP / 10 minutes | Fixed |

Responses include:

```text
X-Request-ID: <id>
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 117
Retry-After: 60            # only on 429
```

The API also sets `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy`, a restrictive `Content-Security-Policy`
for API responses, and HSTS in production.

## Pagination and filtering

List endpoints generally accept `limit` (1–100, sometimes 1–200/500) and
`offset` (≥0), and return:

```json
{
  "items": [],
  "total": 0,
  "limit": 50,
  "offset": 0
}
```

Notifications additionally return `unread`. MITRE endpoints return a `source`
object describing the bundled dataset and retrieval date.

## Endpoint reference

### Targets and authorization

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/targets` | Any authenticated | Filters: `q`, `status`, `target_type`, `limit`, `offset`. |
| `POST` | `/targets` | Admin, analyst | Creates a `pending` target. |
| `GET` | `/targets/{id}` | Any authenticated | Target detail. |
| `PATCH` | `/targets/{id}` | Owner or admin | Scope changes on a verified target reset it to `pending`. |
| `POST` | `/targets/{id}/verify` | Admin | Verifies scope and replaces the allowlist/expiry. |
| `POST` | `/targets/{id}/reject` | Admin | Records a rejection reason. |
| `DELETE` | `/targets/{id}` | Admin | Rejected with `409` if assessments reference the target. |

Create request:

```json
{
  "name": "Customer portal",
  "target_type": "url",
  "value": "https://portal.example.com",
  "environment": "staging",
  "authorization_ref": "AUTH-2026-0042",
  "authorized_by": "Example Security Team",
  "authorization_expires": "2026-12-31T23:59:59Z",
  "allowed_actions": ["web_scan", "vulnerability_lookup", "api_scan"],
  "notes": "Scope agreed under the Q4 engagement."
}
```

Verification request:

```json
{
  "allowed_actions": ["web_scan", "vulnerability_lookup"],
  "authorization_expires": "2026-12-31T23:59:59Z",
  "note": "Verified against signed authorization AUTH-2026-0042."
}
```

Target types: `domain`, `ip`, `cidr`, `url`, `api`, `cloud_account`,
`ad_config`, `password_policy`, `local`.

Target actions: `recon`, `network_scan`, `web_scan`, `vulnerability_lookup`,
`osint`, `password_audit`, `config_audit`, `cloud_audit`, `api_scan`,
`simulation`.

### Assessments

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/assessments` | Any authenticated | Filters: `q`, `status`, `module`, `target_id`, `limit`, `offset`. |
| `POST` | `/assessments` | Admin, analyst | Validates module config and scope; queues by default. |
| `GET` | `/assessments/{id}` | Any authenticated | Detail, summary and error state. |
| `POST` | `/assessments/{id}/run` | Owner or admin | Re-queues a draft/completed/failed assessment. |
| `POST` | `/assessments/{id}/cancel` | Owner or admin | Only queued jobs. |
| `DELETE` | `/assessments/{id}` | Admin | Removes findings, jobs and reports; refuses active work. |
| `GET` | `/assessments/{id}/findings` | Any authenticated | Findings for one assessment. |

Create request:

```json
{
  "name": "Customer portal · OWASP baseline",
  "module": "web",
  "target_id": "tgt_...",
  "config": {
    "include_tls": true,
    "include_headers": true,
    "include_misconfig": true,
    "reflection_probe": false,
    "sqli_probe": false,
    "timeout": 8
  },
  "start": true
}
```

Password audits must **not** be created as queued assessments:

```json
{
  "module": "password",
  "target_id": "tgt_...",
  "config": {}
}
```

returns `400 password_endpoint_required`. Use
`POST /api/v1/tools/password-audit`.

### Findings

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/findings` | Any authenticated | Filters: `q`, `severity`, `status`, `module`, `assessment_id`, `target_id`, `limit` (≤200), `offset`. |
| `GET` | `/findings/{id}` | Any authenticated | Full evidence and remediation. |
| `PATCH` | `/findings/{id}` | Admin, analyst | Status: `open`, `accepted`, `remediated`, `false_positive`. |

Findings are ordered by severity rank and recency. Updating status appends an
audit event.

### Modules and tools

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/modules` | Any authenticated | Catalog, ATT&CK mapping and JSON config schema. |
| `GET` | `/modules/{id}` | Any authenticated | One module. |
| `POST` | `/tools/cvss` | Any authenticated | Parse a CVSS v3 vector and return score/severity. |
| `POST` | `/tools/password-audit` | Admin, analyst | Synchronous, in-memory password audit. |

CVSS request:

```json
{ "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
```

Password audit request:

```json
{
  "target_id": "tgt_...",
  "policy": {
    "min_length": 12,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digit": true,
    "require_symbol": true,
    "max_reuse": 5,
    "lockout_after": 5,
    "lockout_minutes": 15,
    "mfa_required": false
  },
  "test_passwords": ["example-only"],
  "hashes": [],
  "hash_algorithm": "auto",
  "wordlist": []
}
```

The target must be verified, allow `password_audit` and have type `local` or
`password_policy`. Plaintext, hashes and wordlists are never persisted or
returned. The response contains `assessment`, `strength`, `hash_audit` and
`policy_findings` with aggregate/strength results only.

### Dashboard

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/dashboard` | Any authenticated | Stats, severity distribution, 14-day risk/assessment trend, module activity, recent assessments, top findings, activity and ATT&CK coverage. |
| `GET` | `/dashboard/activity?limit=25` | Any authenticated | Recent audit-backed activity (limit 1–100). |

The overview is cached for 20 seconds in Redis/memory. Unread notification count
is always calculated per user.

### Reports

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/reports` | Any authenticated | Filters: `assessment_id`, `fmt`, `limit`, `offset`. |
| `POST` | `/reports` | Admin, analyst | Generates `pdf`, `html` or `json`. |
| `GET` | `/reports/{id}` | Any authenticated | Metadata and executive summary. |
| `GET` | `/reports/{id}/download` | Any authenticated | Streams the file; requires bearer auth. |
| `DELETE` | `/reports/{id}` | Owner or admin | Removes metadata and file. |

Create request:

```json
{
  "assessment_id": "asm_...",
  "format": "pdf",
  "title": "Customer portal assessment"
}
```

Use a blob/authenticated fetch for downloads; a plain browser link without the
`Authorization` header will receive `401`. The response includes a
`Content-Disposition` filename.

### MITRE ATT&CK

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/mitre/tactics` | Any authenticated | 15 tactics plus dataset metadata. |
| `GET` | `/mitre/techniques` | Any authenticated | Filters: `query`, `tactic`, `include_subtechniques`, `limit` (≤250), `offset`. |
| `GET` | `/mitre/techniques/{id}` | Any authenticated | Technique detail and source. |
| `GET` | `/mitre/coverage?assessment_id=...` | Any authenticated | Coverage across observed finding technique IDs, optionally scoped to one assessment. |

The bundled dataset contains 706 techniques and 15 tactics, retrieved
2026-11-05. Attribution metadata is returned with responses.

### Plugins

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/plugins` | Any authenticated | Lists trusted local plugins and their policy. |
| `POST` | `/plugins/{id}/enable` | Admin | Enables a plugin and audits the change. |
| `POST` | `/plugins/{id}/disable` | Admin | Disables a plugin and audits the change. |
| `POST` | `/plugins/{id}/run` | Admin, analyst | Runs an enabled plugin against an assessment. |

Plugins are trusted local code, not a sandbox. Keep the plugin directory
write-protected in production and review code before enabling it.

### Notifications

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/notifications` | Any authenticated | Filters: `unread_only`, `limit`, `offset`; returns `unread`. |
| `POST` | `/notifications/read-all` | Any authenticated | Marks all current user notifications read. |
| `POST` | `/notifications/{id}/read` | Owner | Marks one notification read. |
| `DELETE` | `/notifications/{id}` | Owner | Deletes one notification. |

### Platform and audit

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| `GET` | `/health` | Public | Database, Redis, queue workers and timestamp. |
| `GET` | `/platform/info` | Any authenticated | Version, environment, safety limits and policy strings. |
| `GET` | `/settings` | Any authenticated | User preferences and platform view. |
| `PATCH` | `/settings` | Any authenticated | Bounded preference update. |
| `GET` | `/audit` | Admin | Filters: `action`, `resource_type`, `outcome`, `limit` (≤200), `offset`. |
| `GET` | `/audit/verify` | Admin | Recomputes the SHA-256 chain and returns `valid`, `checked`, `broken_at`, `head`. |
| `GET` | `/users` | Admin | List users. |
| `PATCH` | `/users/{id}` | Admin | Change role or active state; self-lockout is refused. |

## Minimal API walkthrough

```bash
BASE=http://localhost:8000/api/v1

TOKEN=$(curl -s "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@ares.example.com","password":"Ares!Admin2026"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

# Inspect verified scope
curl -s "$BASE/targets?status=verified" \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool

# List module configuration schemas
curl -s "$BASE/modules" \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool

# Verify the audit chain
curl -s "$BASE/audit/verify" \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

## Versioning

The current release is `1.0.0` and the API prefix is `/api/v1`. Additive fields
may appear within v1. Breaking changes will use a new prefix. Health and root
metadata endpoints are intentionally outside the versioned prefix.
