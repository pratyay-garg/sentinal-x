# Discovery Engine (Module 1) — README

This directory contains the integrated Discovery implementation. Pre-change
evidence and verified defects are recorded in `AUDIT_BASELINE.md`.

The integrated SENTINAL X operator console lives in `../frontend` and is served
by Compose at `http://localhost:3001`. Before starting it, set strong independent
values for `CONSOLE_PASSWORD` and `CONSOLE_SESSION_SECRET` in `.env`. Discovery
and administrator API keys stay in the Next.js server process and are never
included in browser JavaScript or local storage. See `../UI_INTEGRATION_MAP.md`
for the audited feature-to-endpoint map and intentionally omitted capabilities.

## 0. The one thing to do before anything else

Discovery imports the executable shared contract shipped in this repository:

```
GRAPH_CONTRACT_MODULE=app.graph.contract
GRAPH_MODEL_MODULE=app.graph.model
```

From the repository root, run:

```bash
PYTHONPATH=backend python -c "from app.contract_adapter import assert_vocabulary_matches_graph; assert_vocabulary_matches_graph()"
```

If this raises, the shared contract and graph semantics have drifted. The
contract test exercises the real `Slice_6` files and proves a NULL-confidence
database row can be consumed by Graph without importing Discovery runtime code.

## 1. Running it

```bash
cp .env.example .env        # then fill in both API keys, SCOPE_ALLOWLIST, and NVD_API_KEY
docker compose up --build
```

For a one-command authorized target test, pass the target URL to
`scan_target.sh`. Use `PROFILE=deep` for the broadest crawl and medium-aggression
bounded DAST pass. For an authenticated target, set `AUTH_HEADERS_JSON` to the
session header shown in the example in that file, then run:

```bash
./scan_target.sh https://target.example.com/ deep
```

The script temporarily restricts `SCOPE_ALLOWLIST` to that exact URL, waits for
completion, prints events/results, verifies PostgreSQL rows, and deletes its
temporary environment file. It never changes the checked-in `.env`.

To present or audit the Discovery database, run:

```bash
./inspect_database.sh
```

Set `EXPORT_CSV=true` near the top of that script to export every public table,
or override it for one run with `./inspect_database.sh --export-csv true`.
Exports are written under `db_exports/` with private file permissions. Because
raw observations and evidence may contain sensitive target data, do not commit
or publicly share that directory.

For the quickest judge-facing integrity check, open
`_verification_summary.csv`. A verdict count of zero means no tested candidate
produced that outcome; it does not mean the verdict is unsupported. In
particular, `unvalidated` appearing in `_schema_columns.csv` is the intentional
default for newly discovered findings. The important backlog metric is
`stranded_unvalidated` in `_verification_summary.csv`, which must be zero after
all Validation jobs complete. `_schema_constraints.csv` proves all allowed
verdict states are enforced by PostgreSQL.

This starts four containers: `db` (Postgres), `api` (FastAPI, runs migrations),
`worker` (Discovery), and `validation-worker` (safe active confirmation).
Discovery automatically queues every mapped finding for Validation. Kick off a
scan:

```bash
curl -X POST http://localhost:8000/api/v1/discovery/scans \
  -H "X-API-Key: $DISCOVERY_API_KEY" -H "Content-Type: application/json" \
  -d '{"target": "example.com", "profile": "fast"}'
```

All non-health HTTP endpoints require `X-API-Key`. Watch it live:
`GET /api/v1/discovery/scans/{job_id}/events?after=0` (poll
this — it's the resilient primary path, not a fallback) or connect a
WebSocket to `/ws/{job_id}?api_key=...` for lower-latency push. Inspect durable
results and coverage at `GET /api/v1/discovery/scans/{job_id}/results`.

The Discovery event ledger emits `validation:queued` with the durable
Validation job IDs. Inspect each job and its evidence with:

```bash
curl -H "X-API-Key: $DISCOVERY_API_KEY" \
  "http://localhost:8000/api/v1/validation/jobs/$VALIDATION_JOB_ID"
curl -H "X-API-Key: $DISCOVERY_API_KEY" \
  "http://localhost:8000/api/v1/validation/jobs/$VALIDATION_JOB_ID/events?after=0"
curl -H "X-API-Key: $DISCOVERY_API_KEY" \
  "http://localhost:8000/api/v1/validation/findings/$FINDING_ID"
```

Validation reuses Discovery's exact scope allow-list and checks the global kill
switch before every outbound request. It does not follow redirects, accepts only
GET/HEAD in unattended mode, caps response bodies, redacts secret headers, and
persists the ordered request/response manifest in Postgres. SQL injection and
SSTI candidates use Slice 5's controlled differential/statistical oracles.
Parameterized GET endpoints no longer depend on a Nuclei hit: route/parameter
semantics create low-confidence SQLi, reflected-XSS, and SSTI hypotheses which
the deterministic Validation oracles confirm or disprove. Reflected XSS uses
two unique inert HTML elements and never executes JavaScript. Missing-security-header findings are repeated three times against the precise
matcher names preserved by Discovery. Classes needing accounts, a browser,
state changes, target files, or callback infrastructure are recorded as
`unverifiable_safely` until those prerequisites are explicitly configured.

## Attack graph (Discovery → Validation → graph)

Migration `0004_attack_graph` adds durable asset roles, directed routes, facts,
and immutable analysis snapshots. Migration `0005_graph_patch_groups` assigns
an independent `finding::<uuid>` action only when no evidence-derived CVE or
component group exists; this avoids falsely claiming one patch fixes unrelated
findings while keeping the label-cut problem complete.

Directly scanned assets become observed entry points automatically. Crown-jewel
status is deliberately never guessed from a hostname or scanner severity: list
assets, then make the explicit business decision with the admin key.

```bash
curl -H "X-API-Key: $DISCOVERY_API_KEY" \
  http://localhost:8000/api/v1/graph/assets

curl -X PATCH -H "X-API-Key: $DISCOVERY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"is_crown_jewel":true,"criticality":5,"zone":"data"}' \
  http://localhost:8000/api/v1/graph/assets/ASSET_ID

curl -H "X-API-Key: $DISCOVERY_API_KEY" \
  'http://localhost:8000/api/v1/graph/analyze?trials=10000&seed=1337&budget_hours=8'
curl -H "X-API-Key: $DISCOVERY_API_KEY" \
  http://localhost:8000/api/v1/graph/cytoscape
curl -H "X-API-Key: $DISCOVERY_API_KEY" \
  http://localhost:8000/api/v1/graph/priority
```

Generate the minimal, self-contained visualization and open the saved file:

```bash
curl -H "X-API-Key: $DISCOVERY_API_KEY" \
  http://localhost:8000/api/v1/graph/view -o attack-graph.html
```

The HTML has no third-party runtime dependency, contains one immutable snapshot,
and does not contain the API key.

`/analyze` always reads the current PostgreSQL assets/findings/evidence/routes;
identical input and parameters reuse the same durable snapshot. CPU-bound graph
work runs off the async event loop, and request parameters are bounded. A
`jewels_unreachable` result is a successful isolation finding—not an error—and
still returns the full frontier graph with passing invariants. Add observed or
explicitly labelled routes using `POST /api/v1/graph/routes`; add non-patchable
AND preconditions using `POST /api/v1/graph/facts`.

Retest can preview exact node deletion without altering findings:

```bash
curl -X POST -H "X-API-Key: $DISCOVERY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"patched":["FINDING_ID"],"trials":10000,"seed":1337}' \
  http://localhost:8000/api/v1/graph/recompute
```

For a target published on a host port, authorize and address the stable Compose
host gateway (the API hostname remains `localhost`):

```dotenv
SCOPE_ALLOWLIST=http://host.docker.internal:3000/
```

After changing `.env`, rebuild/recreate the Discovery containers so they load
the new configuration:

```bash
docker compose up -d --build api worker
export DISCOVERY_API_KEY='replace-with-the-value-from-your-.env'
export AUTHORIZED_TARGET='http://host.docker.internal:3000/'

RESPONSE=$(curl --fail-with-body --silent --show-error \
  -X POST http://localhost:8000/api/v1/discovery/scans \
  -H "X-API-Key: ${DISCOVERY_API_KEY}" \
  -H 'Content-Type: application/json' \
  --data "{\"target\":\"${AUTHORIZED_TARGET}\",\"profile\":\"fast\"}")
JOB_ID=$(printf '%s' "$RESPONSE" | sed -n 's/.*"job_id":"\([^"]*\)".*/\1/p')
printf 'job_id=%s\n' "$JOB_ID"

curl --fail-with-body --silent --show-error \
  -H "X-API-Key: ${DISCOVERY_API_KEY}" \
  "http://localhost:8000/api/v1/discovery/scans/${JOB_ID}/events?after=0"
curl --fail-with-body --silent --show-error \
  -H "X-API-Key: ${DISCOVERY_API_KEY}" \
  "http://localhost:8000/api/v1/discovery/scans/${JOB_ID}/results"
```

Do not paste Markdown links such as `[http://...](http://...)` into the shell,
and use the same `JOB_ID` variable in both follow-up requests.

Authenticated headers are accepted only when
`DISCOVERY_CREDENTIAL_ENCRYPTION_KEY` is configured. They are AES-256-GCM
encrypted in the expiring `scan_credentials` table, bound to the job as
authenticated data, redacted from events/evidence, and reused by Discovery and
Validation. `custom_headers` supplies one `authenticated` context; advanced API
clients can submit up to eight named `auth_contexts` for role-specific crawling.

S4 combines Katana with an independent bounded HTML/form/JavaScript crawler,
expands OpenAPI operations into concrete request shapes, probes common OpenAPI
and GraphQL paths, and merges parameters across sources. S5 runs both normal
Nuclei signatures and explicit low/medium-aggression DAST while continuing to
exclude DoS, brute-force and intrusive templates and disabling external OAST.
Every external scanner pass exposes return code, timeout, redacted stderr and
parsed counts in `scan_runs.coverage`; a failed tool can no longer masquerade as
a clean scan.

## 2. What each file is, in the order you'll actually touch them

| File | What it does | Read this if... |
|---|---|---|
| `app/config.py` | Every tunable value, loaded from `.env`. Nothing else reads `os.environ` directly. | you need to change a timeout/threshold |
| `app/models.py` | The full Postgres schema (spec §6) as SQLAlchemy ORM classes. | you're adding a column |
| `migrations/versions/0001_initial.py` | The Alembic migration that actually creates those tables, including the `findings`↔`evidence` circular-FK handling. | you're changing the schema — add a new migration, don't hand-edit this one |
| `app/scope.py` | S0. The single highest-consequence file in the module (spec §10). Fail-closed CIDR/wildcard/exact-host logic. | you're touching anything scope-related — read `tests/test_scope.py` first, every case there is load-bearing |
| `app/identity.py` | Stable `asset_id` (`SHA256(hostname)`) and the never-merge-across-registrable-domains rule. | assets are duplicating or wrongly merging |
| `app/dedup.py` | The vuln-class-aware `dedup_key` formula (spec §6, the fix for risk #10). | findings are duplicating, or two different vulns are collapsing into one |
| `app/killswitch.py` | Global killswitch + `StageGuard`, the async poller that can kill a running subprocess's whole process group mid-stage. | a kill/cancel isn't taking effect fast enough |
| `app/subprocess_utils.py` | The ONLY place `asyncio.create_subprocess_exec` is called. Process-group kill on timeout — every pipeline stage depends on this. | you're adding a new external tool call |
| `app/queue.py` | Postgres-only orchestration: `SKIP LOCKED` job claiming, heartbeat, the self-testing `LISTEN/NOTIFY` layer with polling as the always-on default. | jobs aren't being picked up, or real-time events aren't arriving |
| `app/contract_adapter.py` | Loads the real vocabulary and patch rules, validates canonical DB columns, and quarantines unknown types. | you're touching anything that ends up in a `Finding` row |
| `app/enrichment.py` | S6 — EPSS/NVD calls, all best-effort, all skippable under `OFFLINE_MODE`. | enrichment is hanging or failing the pipeline (it shouldn't — that's a bug if it does) |
| `app/pipeline/s1_recon.py` … `s7_persist.py` | One file per pipeline stage, matching spec §5 exactly. | you're changing what a specific stage does |
| `app/pipeline/runner.py` | Orchestrates S0→S7 for one claimed job, re-checking scope/killswitch before every stage. | you're changing the overall pipeline order or adding a stage |
| `app/worker.py` | The process entrypoint (`python -m app.worker`) — claim loop, runs the pipeline, marks complete/failed. | the worker won't start or keeps crashing |
| `app/validation/` | Live scope-gated transport and routing into Slice 5's deterministic oracles. | changing validation safety or oracle routing |
| `app/validation_queue.py` | Durable Validation claiming, heartbeats, and events. | Validation jobs are stuck or duplicated |
| `app/validation_worker.py` | Independent Validation process; checks kill switch before every request and persists evidence/verdicts. | live confirmation is not completing |
| `app/main.py` | FastAPI app — routes only, no scan logic. | you're adding an API endpoint |
| `app/schemas.py` | Pydantic request/response models for the API. | you're changing the API's request/response shape |
| `tests/test_scope.py` | Every scope-engine edge case that must never regress, including the non-obvious "zero CIDR entries" rule. | **run this before every commit that touches `scope.py`** |
| `tests/test_dedup.py` | Proves the vuln-class-aware dedup fix actually works. | **run this before every commit that touches `dedup.py`** |
| `tests/test_contract_adapter.py` | Tests against the actual supplied contract/model and DB-only Graph loader. | **run this before every commit that touches `contract_adapter.py`** |
| `Dockerfile` | Builds pinned subfinder/dnsx/naabu/httpx/katana/nuclei versions, installs `nmap`, pre-seeds pinned Nuclei templates, and installs Python dependencies from `backend/uv.lock`. | a tool binary is missing or the wrong version |
| `docker-compose.yml` | Wires `db`+`api`+Discovery worker+Validation worker. Grants `NET_RAW`/`NET_ADMIN` only to Discovery for naabu's SYN scan. | a worker is not starting |
| `.env.example` | Every environment variable, with inline comments on what each one controls. | first-time setup, or you're not sure what a setting does |

## 3. Running the tests

```bash
source backend/.venv/bin/activate
cd backend && uv sync --active && cd ..
(cd backend && ../backend/.venv/bin/python -m pytest -q)
ruff check backend/app backend/tests Slice_6/loader.py
mypy --ignore-missing-imports backend/app
MYPYPATH=backend mypy --ignore-missing-imports -p Slice_6.loader
```

No Postgres or Docker required for the unit tests above — `test_scope.py`,
`test_dedup.py`, and `test_contract_adapter.py` are pure-Python and run in
under a second. They are also the three files spec §10/§13 singles out as
needing "disproportionate test coverage" — if you only have time to keep one
part of this repo green, keep these three files green.

## 4. Why the process layout looks the way it does

`api` and `worker` are deliberately separate processes/containers sharing
one Postgres instance, with **no Celery, no Redis** — see
`IMPLEMENTATION_SPEC_v4.md` §8 for the full argument. In one sentence: a job
row surviving in Postgres, plus a heartbeat and `SKIP LOCKED` reclaiming, get
you the same crash-recoverability a task-queue framework would, without a
second stateful service to run and explain during a demo. Real-time push
(`LISTEN/NOTIFY`) is opportunistic and self-disables automatically if
anything (most commonly a connection pooler) breaks it — polling is always
running underneath regardless, at 1–2 second latency, which is invisible on
a live demo.

## 5. Known gaps, stated honestly (see spec §11/§13 for the full list)

- Mapping aliases are versioned in `app/vuln_mapping.json`; unknown types are
  persisted as explicit review items and excluded from graph semantics.
- Endpoint ownership is derived from observed services and preserves scheme,
  host, and non-standard port. Redirect-time DNS pinning remains unfinished.
- **GraphQL field-suggestion enumeration (for introspection-disabled
  targets) and Kiterunner's fallback path are stubbed narrowly or omitted**
  — `s4_crawl.py`'s `{__typename}` check is a liveness probe only, exactly as
  documented; it does not enumerate a disabled schema. Treat as a stretch
  goal per spec §11.
- **`registrable_domain()` in `identity.py` falls back to a naive
  last-two-labels heuristic because `tldextract` is not yet in the canonical
  backend lock** — wrong for multi-level public suffixes (`co.uk`, `github.io`).
  Add it to `backend/pyproject.toml` and refresh `backend/uv.lock` when that
  identity slice is implemented.

Remaining advanced work is explicit workflow ownership metadata for reliable
BOLA adjudication, refreshable OAuth/login recipes, a project-controlled OAST
service, browser DOM data-flow analysis, redirect-time DNS pinning, robust
soft-404 statistics, metrics, and vulnerability scanning of the built image.
Those capabilities are not guessed or simulated because doing so would create
false positives or violate the non-destructive/scope guarantees.
