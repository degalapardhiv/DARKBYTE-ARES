# Deployment and operations

This guide covers local Docker, production hardening, configuration, backups,
upgrades and troubleshooting for DARKBYTE ARES.

> DARKBYTE ARES performs real network activity when an assessment is run. Deploy
> it only on networks and against targets you are explicitly authorized to
> assess. Review [SECURITY.md](../SECURITY.md) before deployment.

## Prerequisites

| Deployment | Requirements |
| --- | --- |
| Local Docker | Docker Engine 24+ with Compose v2, 2 CPU / 4 GB RAM recommended. |
| Production | A hardened Linux host, Docker Engine, TLS termination, private network access to PostgreSQL/Redis, and a backup destination. |
| Local source | Python 3.12+, Node.js 20+, npm 10+. |

The default development stack uses PostgreSQL 16 and Redis 7 containers. Local
source development can run on SQLite with an in-memory cache.

## Development stack

```bash
cp .env.example .env
# Change SECRET_KEY, and keep DEMO_MODE=true only for local evaluation.
docker compose up --build
```

| Service | Published port | Notes |
| --- | --- | --- |
| `frontend` | `8080` | nginx serves the SPA and proxies `/api/` to the API. |
| `backend` | `8000` | Direct API access for Swagger/automation. |
| `postgres` | none | Internal bridge network only. |
| `redis` | none | Internal bridge network only. |

Health checks:

```bash
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8080/healthz
docker compose ps
```

Logs are JSON on stdout:

```bash
docker compose logs -f backend
docker compose logs -f frontend
```

Stop without deleting data:

```bash
docker compose down
```

Delete the database, cache and reports (destructive):

```bash
docker compose down -v
```

## Production deployment

Use the hardening overlay. It disables demo mode and registration, requires
explicit secrets and origins, hides PostgreSQL/Redis and the direct API port,
and sets conservative target defaults.

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export POSTGRES_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
export ADMIN_EMAIL="admin@your-domain.example"
export ADMIN_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
export ALLOWED_ORIGINS="https://ares.your-domain.example"

docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

The console is published on `${FRONTEND_PORT:-8080}`. Put a TLS reverse proxy in
front of it; do not expose port 8080 directly to the internet.

### Caddy example

```caddyfile
ares.your-domain.example {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
```

Caddy obtains and renews certificates automatically. If you use nginx, terminate
TLS in your edge proxy and set:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

The bundled frontend nginx already forwards `/api/` to the API service and sets
security headers. Keep the API’s `ALLOWED_ORIGINS` equal to the exact public
console origin, including scheme and port.

### First administrator

In production with an empty database, startup creates the administrator from
`ADMIN_EMAIL` and `ADMIN_PASSWORD` when the password is not the demo default and
is at least 12 characters. For explicit provisioning instead:

```bash
# On the host, from the repository root and with the same DATABASE_URL:
.venv/bin/python scripts/create_admin.py --email admin@your-domain.example
```

The script is interactive by default and never echoes the password. It refuses
to modify an existing account.

If neither path creates a user, sign-in will fail. Check the backend logs for the
seed warning and verify the database URL.

### Production boot checks

The API refuses to start when `APP_ENV=production` and any of the following is
true:

- `DEMO_MODE=true`;
- `SECRET_KEY` is a known placeholder or shorter than 32 characters;
- `ALLOWED_ORIGINS` contains `*`.

Validate the merged Compose model before starting:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml config
```

## Configuration reference

Environment variables are read from `.env` (development) or the process
environment (production). Names are case-insensitive.

### Application

| Variable | Default | Description |
| --- | --- | --- |
| `APP_NAME` | `DARKBYTE ARES` | Display name. |
| `APP_ENV` | `development` | `development`, `test`, `staging`, `production`. |
| `DEBUG` | `false` | Enables verbose framework logging. Keep off in production. |
| `DEMO_MODE` | `true` | Seeds demo users/data. Must be `false` in production. |
| `ALLOW_REGISTRATION` | `true` | Self-service analyst registration. |
| `SECRET_KEY` | placeholder | JWT signing key. 32+ random characters in production. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | Token lifetime (5–1440). |
| `ALLOWED_ORIGINS` | localhost origins | Comma-separated exact CORS origins. |

### Data and cache

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/ares.db` | Async SQLAlchemy URL. Compose uses PostgreSQL. |
| `REDIS_URL` | `redis://localhost:6379/0` | Empty value disables Redis and uses memory. |
| `CACHE_TTL_SECONDS` | `900` | Default cache TTL (30–86400). |
| `REPORTS_DIR` | `./data/reports` | Report storage; mounted as `ares-data` in Compose. |

### Safety limits

| Variable | Default | Valid range / effect |
| --- | --- | --- |
| `MAX_SCAN_HOSTS` | `64` | 1–256. Hard host ceiling. |
| `MAX_PORTS_PER_SCAN` | `512` | 1–2048. Hard port ceiling. |
| `SCAN_TIMEOUT_SECONDS` | `4.0` | 0.5–30. Used by network/Nmap paths. |
| `MAX_CONCURRENT_ASSESSMENTS` | `2` | 1–8 worker pool size. |
| `ASSESSMENT_TIMEOUT_SECONDS` | `180` | 15–900. Hard per-engine timeout. |
| `RATE_LIMIT_PER_MINUTE` | `120` | 10–10000 per-IP API limit. |
| `ACTIVE_SCAN_RATE_LIMIT` | `30` | 2–1000 active starts per user/minute. |
| `REQUIRE_VERIFIED_TARGETS` | `true` | Keep enabled; rejects unverified scope. |
| `ALLOW_PRIVATE_TARGETS` | `true` | Allow private ranges for lab/staging scope. |
| `ALLOW_LOOPBACK_LAB` | `true` | Allow loopback only for lab scope. |
| `LAB_MODE` | `true` | Lab-mode flag exposed in platform info. |

### Initial administrator

| Variable | Default | Description |
| --- | --- | --- |
| `ADMIN_EMAIL` | `admin@ares.example.com` | Initial administrator email. |
| `ADMIN_PASSWORD` | demo value | Initial administrator password. Set a strong value. |
| `ANALYST_EMAIL` | `analyst@ares.example.com` | Demo analyst email. |
| `ANALYST_PASSWORD` | demo value | Demo analyst password. |

### Intelligence sources

| Variable | Default | Description |
| --- | --- | --- |
| `NVD_API_KEY` | empty | Optional NVD API key. |
| `NVD_API_URL` | NIST NVD CVE API | Override for a mirror/proxy. |
| `MITRE_ATTACK_URL` | MITRE enterprise ATT&CK STIX URL | Used only by the refresh script. |
| `CRTSH_URL` | `https://crt.sh/` | Certificate transparency source. |

### Compose-only

| Variable | Default | Description |
| --- | --- | --- |
| `POSTGRES_DB` | `ares` | Database name. |
| `POSTGRES_USER` | `ares` | Database user. |
| `POSTGRES_PASSWORD` | local placeholder | Required for production. |
| `API_PORT` | `8000` | Development API port. The prod overlay hides it. |
| `FRONTEND_PORT` | `8080` | Console port. |

## Security hardening checklist

- [ ] `APP_ENV=production`, `DEMO_MODE=false`, `ALLOW_REGISTRATION=false`.
- [ ] Unique `SECRET_KEY` (48+ random bytes), stored in a secret manager.
- [ ] Strong, unique `POSTGRES_PASSWORD`; PostgreSQL not published.
- [ ] Redis private and password-protected if it leaves the host.
- [ ] TLS terminated at the edge; HTTP redirects to HTTPS.
- [ ] `ALLOWED_ORIGINS` is the exact console HTTPS origin, no wildcard.
- [ ] `ALLOW_PRIVATE_TARGETS=false` and `ALLOW_LOOPBACK_LAB=false` unless a
      documented lab requirement exists.
- [ ] Demo data absent; production boot rejects it regardless.
- [ ] Host firewall restricts management access; egress is monitored.
- [ ] Container runtime uses `no-new-privileges`; the API runs as non-root.
- [ ] Audit chain verified after deployment and on a schedule.
- [ ] Backups tested; report directory included.
- [ ] Dependency updates reviewed; images rebuilt regularly.

## Backups and restore

### PostgreSQL

```bash
# Back up
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  exec -T postgres pg_dump -U ares -d ares -Fc > "ares-$(date +%F).dump"

# Restore into an empty database
cat ares-2026-11-05.dump | \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  exec -T postgres pg_restore -U ares -d ares --clean --if-exists
```

### Reports

```bash
docker run --rm \
  -v darkbyte-ares_ares-data:/data:ro \
  -v "$PWD/backups:/backup" \
  alpine tar czf /backup/ares-reports-$(date +%F).tar.gz -C /data reports
```

Keep database and report backups together so evidence and metadata remain
consistent. Encrypt backups at rest and restrict access.

## Upgrades

1. Read the changelog and back up the database and reports.
2. Pull the new source or image tag.
3. Rebuild and recreate:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```
4. Check `/api/v1/health`, `/healthz` and recent logs.
5. Verify the audit chain and a report download.

**Schema changes:** this release creates tables with
`Base.metadata.create_all()` and does not ship migrations. If a future release
changes model columns, use an explicit migration (Alembic recommended) before
starting the new containers. Do not assume `create_all()` alters existing tables.

## Scaling and high availability

- PostgreSQL and Redis should be managed services or dedicated, backed-up
  instances for serious deployments.
- The assessment queue is **in-process**. Run exactly one API process with the
  worker pool, or split the queue into a dedicated worker service before scaling
  the API horizontally. Multiple API processes with the same worker loop can
  race for jobs.
- Rate limits use Redis for shared state; without Redis, each process has its own
  window.
- Report files require shared storage if multiple API processes can serve
  downloads.
- The frontend is stateless and can be replicated behind a load balancer.

## Observability

- JSON logs include request IDs, method, path, status, duration and safe event
  fields. `X-Request-ID` is returned to clients and accepted from trusted
  upstreams.
- `GET /api/v1/health` reports database availability, cache mode and queue
  worker count.
- `GET /health` is a lightweight liveness response.
- The dashboard exposes posture metrics; the audit page exposes the verification
  result for administrators.
- Recommended production alerts: health failures, repeated assessment failures,
  audit-chain verification failure, queue depth, login throttling spikes and
  report storage exhaustion.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Backend exits in production | `DEMO_MODE`, `SECRET_KEY` length/placeholder, wildcard origins, required Compose variables. |
| Console loads but API calls fail | Frontend nginx `/api/` proxy, API container health, `ALLOWED_ORIGINS`. |
| Login fails after production deploy | Initial admin was not created; check seed logs and `ADMIN_EMAIL`/`ADMIN_PASSWORD`, or run `scripts/create_admin.py`. |
| `redis: memory-fallback` | Redis unavailable; check container health and `REDIS_URL`. Rate limits are per-process until fixed. |
| Target cannot be assessed | Target must be verified, unexpired, allow the module action and have a compatible type. See the error `code`. |
| Assessment stuck queued | Check worker count in health, queue logs and `scan_jobs`; restart recovers interrupted jobs. |
| NVD results missing | Check egress, NVD rate limits and `NVD_API_KEY`; bundled snapshot may be used. |
| Report download 401 | Downloads require a bearer token; use the console or an authenticated request. |
| Report file missing | `REPORTS_DIR` changed or volume lost; metadata alone cannot reconstruct the file. |
| Docker build fails on fonts | ReportLab falls back to Helvetica/Courier; DejaVu is optional. |

For security issues, follow [SECURITY.md](../SECURITY.md) and do not open a
public issue.
