# SENTINAL X — Autonomous Cyber-Defense Platform

An AI-assisted platform that runs the whole security lifecycle over one shared
attacker-state graph, instead of as a bag of separate scanners:

> **Discover → Validate → Correlate → Prioritize → Remediate → Retest → Report**

It discovers the real application surface, *proves* which findings are actually
exploitable with harmless non-destructive checks and a replayable evidence
bundle, turns that evidence into an attack graph, computes the probability an
attacker reaches your crown jewels and the cheapest set of fixes that severs
every path, generates AI remediation guidance grounded in the evidence, and then
re-runs the same validation to confirm the fix. It also scores suspicious URLs,
emails, domains and IPs and checks an address against public breach data.

Everything runs in containers — **the only host requirement is Docker.**

---

## Requirements

- **Docker Engine 24+** with the Compose v2 plugin
  (Docker Desktop on Windows/macOS, or Docker Engine on Linux).
- **~4 GB free RAM** and **~8 GB disk** — the backend image bundles Chromium and
  the security tooling (nuclei, katana, nmap, …).
- `bash` and either `python3` or `openssl` on the host, only to generate secrets
  during setup. Nothing else is installed on the host.

## Quick start (three commands)

```bash
git clone <repo-url> sentinal-x && cd sentinal-x

./setup.sh                 # one-time: writes backend/.env with fresh random
                           # secrets; prints the console password

docker compose up -d       # builds images, runs DB migrations, starts the platform
```

The first build downloads base images and compiles the security tools, so it
takes a few minutes. After it finishes:

| Service | URL | Notes |
|---|---|---|
| **Operator console** | <http://localhost:3001> | log in with the password `setup.sh` printed |
| API + OpenAPI docs | <http://localhost:8000/docs> | |

> Database migrations run automatically when the API container starts
> (`alembic upgrade head`), so there is no separate migration step.

> Need intentionally-vulnerable targets to try it against? They live separately
> in [`labs/`](labs/README.md) and are not part of the product.

## Run your first scan

Add a target **you are authorised to test** to the scope allow-list in
`backend/.env` (`SCOPE_ALLOWLIST`, comma-separated: exact `host:port`,
`*.wildcard`, or CIDR) and recreate the app services:

```bash
# edit backend/.env: SCOPE_ALLOWLIST=target.example.com
docker compose up -d --force-recreate api worker validation-worker
```

**From the console:** open <http://localhost:3001>, go to **New Scan**, enter the
target URL, choose the **deep** profile, and start it. Watch it discover →
validate, then open the **Attack Graph** view. Mark the asset as a *crown jewel*
(Asset Criticality panel) to see compromise probability, chokepoints and the
min-cut plan.

**From the CLI** (equivalent):

```bash
cd backend
./scan_target.sh https://target.example.com/ deep
```

### Authenticated targets

For a login-gated target, use the New Scan form's **Form login** or **API/JSON
login** option. The scanner logs itself in against the (scope-checked) target,
**verifies** the session reached an authenticated page, and crawls the
authenticated surface — no one pastes a cookie. Only the derived session is
stored (encrypted, auto-expiring); the credentials are used transiently. The
*Manual cookie / headers* option remains for API keys or short investigations.

## Stop, reset, logs

```bash
docker compose down            # stop everything
docker compose down -v         # also wipe the database (full clean reset)
docker compose logs -f worker  # follow a service's logs
```

Remote/internet targets are reached directly over the workers' network egress;
local Docker targets should sit on the same Compose network and be scanned by
container name.

## Running the tests

The container image ships runtime dependencies only, so the test suites run with
the project's Python environment (managed by [uv](https://docs.astral.sh/uv/)):

```bash
cd backend && uv sync          # once: creates backend/.venv with all dev deps
../backend/.venv/bin/python -m pytest      # the whole suite (run from backend/)
```

There are 680+ tests across discovery, the validation oracles, the attack-graph
engine, remediation/retest and the intelligence package.

## Repository layout

| Path | Contents |
|---|---|
| `backend/` | FastAPI service: `app/` package, `migrations/`, `Dockerfile`, `docker-compose.yml`, `pyproject.toml`, `tests/` |
| `backend/app/core/` | config, db, scope allow-list, kill-switch, credentials, runtime settings, authenticator |
| `backend/app/schemas/`, `models/` | Pydantic contracts and SQLAlchemy tables (the data model) |
| `backend/app/graph/` | Attack-graph engine: Monte-Carlo, dominators, min-cut, scoring, break-the-chain |
| `backend/app/llm/` | Shared LLM provider client + prompts |
| `backend/app/api/`, `tasks/` | FastAPI routers; background workers + job queues |
| `backend/app/engines/discovery/` | Discovery pipeline (S0–S7) |
| `backend/app/engines/validation/` | Validation oracles + transport/service |
| `backend/app/engines/remediation/` | AI remediation + verified retest |
| `backend/app/engines/intel/` | URL / email / domain / IP intelligence + email-exposure scanner |
| `frontend/` | Operator console (Next.js + Cytoscape) |
| `labs/` | Optional, separately-run practice targets (not part of the product) |
| `docs/adr/` | Architecture Decision Records |

## Configuration reference

All runtime configuration lives in `backend/.env` (generated by `setup.sh` from
`backend/.env.example`, which documents every option). The values you may want
to change:

- `SCOPE_ALLOWLIST` — the fail-closed authorisation list (empty ⇒ nothing is in
  scope).
- `NVD_API_KEY` — optional, raises the CVE-enrichment rate limit.
- `VT_API_KEY` — optional, enables live VirusTotal reputation in the intelligence
  module (skipped gracefully without it).
- `OFFLINE_MODE=true` — skip all outbound enrichment/model downloads for a
  fully air-gapped demo.

## Safety

The platform actively probes systems, so its limits are enforced in code:
every outbound request is checked against `SCOPE_ALLOWLIST` first; validation
uses only harmless `GET`/`HEAD` checks and never destructive payloads; a global
kill switch is honoured by every worker; and anything that cannot be confirmed
safely is reported as `unverifiable_safely` rather than guessed. Only scan
systems you own or are explicitly authorised to test.
