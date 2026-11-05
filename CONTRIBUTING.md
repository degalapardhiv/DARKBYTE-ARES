# Contributing to DARKBYTE ARES

Thank you for helping improve an authorized-use security platform. Contributions
are welcome when they strengthen defensive value, safety and code quality.

## Ground rules

1. **Authorization first.** Every feature must remain bound to a verified target
   record and the explicit action allowlist. Never add a bypass.
2. **No offensive capability creep.** Do not add exploitation, payload delivery,
   malware, credential theft, persistence, evasion or denial-of-service logic.
   The red-team module is a tabletop planner and stays that way.
3. **Secrets stay ephemeral.** Never log, persist or return plaintext passwords,
   hashes or wordlist entries.
4. **Audit everything material.** New state-changing operations must append to
   the audit chain.
5. **Be respectful.** Assume good intent, discuss designs in the open and avoid
   personal attacks.

## Development setup

Requirements: Python 3.12+, Node.js 20+, npm 10+.

```bash
git clone <repository-url>
cd darkbyte-ares

python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

cd frontend
npm ci
cd ..

cp .env.example .env
# Edit SECRET_KEY and other local values.
```

Run locally in two terminals:

```bash
.venv/bin/uvicorn backend.main:app --reload --port 8000
```

```bash
cd frontend && npm run dev
```

Open `http://localhost:5173`. Demo mode seeds a labelled dataset and two demo
accounts when `DEMO_MODE=true`.

## Before opening a pull request

```bash
# Backend
.venv/bin/ruff check backend engines integrations scripts tests
.venv/bin/python -m pytest tests -q

# Frontend
cd frontend
npm run lint
npm run test
npm run build
```

Keep changes focused. Add or update tests for behaviour you change. Update the
docs and `.env.example` when a setting or API contract changes.

## Style

- Python: Ruff defaults, type hints on public functions, 4-space indentation.
- TypeScript: strict mode, functional components, keep `any` out of shared
  contracts, and reuse the existing design primitives.
- Commit messages: imperative mood, concise scope, for example
  `api: validate assessment timeouts`.
- UI copy: precise, calm and safety-aware. Avoid implying that an intelligence
  match is a validated exploit.

## Security reports

Do not disclose vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the MIT
License in [LICENSE](LICENSE).
