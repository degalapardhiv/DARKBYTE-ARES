# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability. Report it privately
to the maintainer through GitHub Security Advisories on the repository or by
contacting **DarkByteHunter** through the profile linked from this project.

Include:

- the affected component and version;
- reproduction steps or a minimal proof of concept;
- impact and required preconditions;
- any suggested remediation;
- whether the report involves the safety controls described below.

You will receive an acknowledgement as soon as possible. Please allow time for
triage and a coordinated fix before public disclosure.

## Authorized-use boundary

DARKBYTE ARES is a defensive and authorized-testing platform. It is **not** a
tool for unauthorized access, malware deployment, credential theft, persistence,
or denial of service. The project will not accept contributions that:

- bypass target authorization or scope enforcement;
- execute exploits, payloads or adversary infrastructure;
- capture, persist or exfiltrate credentials or plaintext secrets;
- add uncontrolled high-volume scanning or denial-of-service features;
- weaken the append-only audit trail or rate limits;
- hide activity from the operator or the audit log.

## Security model summary

- Every assessment requires a verified target record with a written
  authorization reference, an expiry and an explicit action allowlist.
- Scope and target-type checks run before an assessment can be queued.
- Assessment inputs are validated server-side; concurrency, host, port and
  timeout ceilings cannot be raised from the client.
- Passwords, hashes and wordlists are processed in memory. Only aggregate
  counts and findings are persisted.
- OSINT documents are hashed for provenance; document bytes are not stored.
- The red-team simulator is a tabletop planning module. It executes no
  techniques and generates no target traffic.
- Audit entries are append-only and linked with a SHA-256 hash chain. The chain
  can be verified from the administrator console.
- Demo records are marked `is_demo=true` and are rejected when
  `APP_ENV=production`.
- Production boot fails with demo mode enabled, a weak `SECRET_KEY`, or wildcard
  CORS origins.

## Deployment hardening checklist

- Run with `APP_ENV=production` and `DEMO_MODE=false`.
- Set a unique, random `SECRET_KEY` of at least 32 characters.
- Set a strong initial `ADMIN_PASSWORD` or provision the first administrator
  with `scripts/create_admin.py`.
- Disable self-service registration unless it is explicitly required.
- Terminate TLS at the reverse proxy and set `ALLOWED_ORIGINS` to the exact
  console origin.
- Keep PostgreSQL and Redis on a private network; never publish them publicly.
- Restrict egress and run the platform from a controlled, monitored network.
- Back up the database and the report directory; test restoration regularly.
- Rotate credentials, review the audit chain and patch dependencies regularly.

## Scope of this policy

This policy covers the DARKBYTE ARES codebase and its deployment guidance. It
does not grant permission to test any third-party system. Operators are solely
responsible for obtaining and retaining written authorization for every target
they assess.
