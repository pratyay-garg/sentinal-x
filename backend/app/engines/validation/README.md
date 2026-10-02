# Module 2 — Autonomous Pentest Validation Engine

> Read this before touching any file in `app/validation/`. It is the full,
> authoritative context for the validation engine: what every file is, why it
> exists, what it must and must not do, and which behaviours *look* like bugs but
> are deliberate. If something here conflicts with a guess, **this document
> wins** — do not invent, stub, or "fix" a file to match an assumption.

---

## 0. TL;DR for an assistant picking this up cold

- This is **Module 2** of a two-module platform. Module 3 (the attack-graph
  engine) is separate and complete. Module 2 **validates** scanner findings and
  writes rows Module 3 consumes.
- **`writer.py` is NOT a database/serialization layer.** It is the **output
  adapter**: it turns an oracle `Verdict` into a contract-valid finding row. It
  defines `Candidate`, `OracleOutcome`, `Verdict`, `FAILURE_FAMILY`,
  `SELF_CORROBORATING`, `fingerprint`, `observations`, `corroboration_warnings`,
  `to_finding_row`, `to_route_rows`, `write`. **Every oracle imports from it.**
  If it is "missing", the whole module fails to import. Do **not** stub it — use
  the real file (shipped alongside this README).
- Everything is **deterministic and seeded** (default seed 1337). Same input →
  byte-identical output, across processes and `PYTHONHASHSEED`. If a change
  breaks that, the change is wrong.
- Every oracle is tested against an **in-process mock target** — no network is
  needed to run the suite.
- Full suite: **307 tests** (168 in `tests/validation/`, the rest Module 3).
  All green. Never mark work done with a red suite.

---

## 1. What the module does and why

A scanner (Nuclei) produces **hypotheses** — many findings, mostly false, none
aware of each other. Module 2 **adjudicates** each hypothesis with a controlled,
non-destructive, *replayable* experiment, and emits a verdict with calibrated
confidence and reproducible evidence.

**Thesis:** *a security finding is a hypothesis; value lies in adjudicating it
with reproducible evidence, not in generating more hypotheses.*

Worth **15 of 60 solution marks** outright, and it feeds Retest (10),
Attack-Path (15, via the rows), Phishing/Email (6, via the shared scorecard),
and Integration (4).

### The seven non-negotiable laws
1. **Determinism over autonomy.** No LLM in the analysis loop. Everything seeded
   and replayable.
2. **Soundness over impressiveness.** Never call a result "minimum/optimal/
   calibrated" unless it provably is.
3. **AI at the edges, never in the core.** AI may map a `vuln_class` or write a
   remediation note; its output is constrained to an enum or verified. It never
   decides a verdict or a score.
4. **Modules never call each other.** Module 2 reads candidates, writes rows.
   The only shared code is `app/graph/contract.py`.
5. **Safe by construction.** Deny-by-default scope; non-destructive probes;
   prove capability then stop; refusal (`unverifiable_safely`) is a feature.
6. **Evidence is replayable or it is not evidence.** Every validated finding
   carries a seeded manifest; retest replays it.
7. **Honesty is graded.** Distinguish a proof from a measurement; ship
   `inconclusive`/`unverifiable_safely` rather than force a decision.

---

## 2. Architecture at a glance

```
 Nuclei JSON (cached)                         [scanner.py]
        │  parse + enum-constrained class map
        ▼
   Candidate  ──────────────────────────────  [writer.py: Candidate]
        │
        ▼   pick applicable oracle(s)
 ┌───────────────────────────────────────────────────────────────┐
 │ CONTROL ENGINE (shared substrate)                              │
 │   scope gate · k-baseline + learned volatility · sanity canary │
 │   per-target timing mutex + rate limit + kill switch           │
 │   [scope.py, control.py, sanity.py, limiter.py]                │
 └───────────────────────────────────────────────────────────────┘
        │
        ▼   each oracle -> OracleOutcome -> Verdict
 ┌───────────────────────────────────────────────────────────────┐
 │ ORACLES  [oracles/*.py]                                        │
 │   authorization · differential · timing · execution · oob      │
 └───────────────────────────────────────────────────────────────┘
        │  one candidate's verdicts
        ▼
   ADJUDICATOR  [adjudicate.py]  ── calibrated confidence ──  [calibration.py, corpus.py]
        │  status + calibrated posterior + contribution breakdown
        ▼
   WRITER  [writer.py]  ── contract-valid rows ──  [app/graph/contract.py]
        │
        ├── EVIDENCE  [evidence.py] manifest + replay + retest ── GET /evidence/{id} [api.py]
        │
        ▼
   Postgres rows ─────────────────────────────►  MODULE 3 (attack graph)

 SCANNER-INDEPENDENCE  [independence.py, scenario.py]  → the "N flagged, D
 disproved, X found" scoreboard.
```

**Golden rule of data flow:** `oracle → Verdict → writer → rows → Module 3`.
Module 3 never imports anything in `app/validation/`.

---

## 3. File-by-file manifest

Directory: `backend/app/validation/`. (Module 3 lives in `backend/app/graph/`.)

### Core value types & output adapter
| File | Role | Key exports | Never do |
|---|---|---|---|
| **`writer.py`** | **Output adapter.** Verdict → contract-valid row. The type home for the whole module. | `Candidate`, `OracleOutcome`, `Verdict`, `WriteResult`, `FAILURE_FAMILY`, `SELF_CORROBORATING`, `fingerprint`, `observations`, `corroboration_warnings`, `to_finding_row`, `to_route_rows`, `write` | Do **not** treat as a DB layer or stub it. Every oracle imports these types. |
| `http.py` | Transport-agnostic `Request`/`Response`/`Fetcher`. Lets everything run offline. | `Request`, `Response`, `Fetcher` | Don't add a live HTTP client here; the real one is a `Fetcher` adapter (see §12). |
| `fixtures.py` | Hand-authored `Verdict` objects — lets the writer be tested before any oracle exists. | `verdicts()`, `assets()`, `scanner_routes()`, `entries()` | — |

### Control engine (Phase 1 — shared substrate)
| File | Role | Key exports |
|---|---|---|
| `scope.py` | **The one safety chokepoint.** Deny-by-default CIDR + hostname; refuses non-http schemes and embedded creds. | `Scope`, `assert_in_scope`, `in_scope`, `OutOfScopeError` |
| `control.py` | k-baseline sampler + **learned volatility threshold** (shingle Jaccard); timing median/MAD. | `sample_baseline`, `Baseline`, `similarity`, `shingles`, `jaccard` |
| `sanity.py` | **Server-sanity canary** — detects catch-all/WAF servers so probes aren't trusted blindly. | `sanity_canary`, `SanityResult` |
| `limiter.py` | Per-target **timing mutex**, rate limit, kill switch (the one async piece). | `TargetLimiter`, `KillSwitchError` |
| `mock_target.py` | **All mock targets in one file** (grew each phase; keep the latest — it contains every earlier target). | `MockTarget`, `MockAuthzTarget`, `MockSqliTarget`, `MockSstiTarget`, `MockTimingTarget`, `MockXssTarget`, `MockOOBTarget`, `CanaryListener` |

### Oracles (`app/validation/oracles/`)
| File | Oracle(s) | What it proves | Family | Self-corroborating? | Observed grant |
|---|---|---|---|---|---|
| `authz.py` | authorization (2×2 matrix) | broken object-level auth (IDOR) | identity | **yes** | `data_read` |
| `differential.py` | differential (boolean + expression) | injection (SQLi, SSTI, LFI, auth-bypass) | content | **no** | none (injection ≠ extraction) |
| `timing.py` | timing (MAD-z + SLEEP scaling) | blind time-based injection | time | no | none |
| `execution.py` | execution (nonce runs in a `Renderer`) | XSS by execution, not reflection | browser | **yes** | `user_session` |
| `oob.py` | oob_ssrf / oob_rce / oob_xxe (canary) | server reached attacker infra | out_of_band | **yes** | `network_reach`/`code_exec`/`data_read` |
| `combine.py` | corroboration combiner (Phase 4) | merges outcomes; **placeholder confidence** | — | — | — |
| `__init__.py` | package marker | — | — | — | — |

> `combine.py` is superseded by `adjudicate.py` for confidence. It stays because
> its merge/decision logic is the seed of the adjudicator and some tests use it.
> Prefer `adjudicate.adjudicate()` for real verdicts.

### Adjudicator & calibration (Phase 5)
| File | Role | Key exports |
|---|---|---|
| `calibration.py` | Naive-Bayes LLR fitting (Laplace-smoothed, clamped ±4), `score`, reliability + ECE, separation + AUC. **Neutral prior 0.5.** | `Calibration`, `fit_calibration`, `score`, `reliability`, `separation`, `DEFAULT_PRIOR`, `SCANNER_BASE_RATE` |
| `corpus.py` | Labeled corpus built by running the **real oracles** against known mocks (a practice-target analogue). | `fitting_corpus`, `evaluation_corpus` |
| `adjudicate.py` | The calibrated adjudicator (replaces `combine`'s number). status + calibrated posterior + contribution breakdown. | `adjudicate`, `Adjudication`, `default_calibration` |

### Evidence & retest (Phase 6)
| File | Role | Key exports |
|---|---|---|
| `evidence.py` | `RecordingFetcher` (captures the transaction array), `EvidenceManifest`, `EvidenceStore`, `record_run`, `replay`, `retest`, `ORACLE_REGISTRY`. | as listed |
| `api.py` | `GET /evidence/{id}` — resolves a finding to its proof (the "click the edge → see the proof" surface). | `build_evidence_router` |

### Scanner & independence (Phase 7)
| File | Role | Key exports |
|---|---|---|
| `scanner.py` | Nuclei JSONL → `Candidate`; `HeuristicMapper` (enum-constrained), `LLMMapper` (proposes, deterministic check ratifies). | `parse_nuclei`, `candidates_from_nuclei`, `to_candidate`, `HeuristicMapper`, `LLMMapper` |
| `independence.py` | The `Scoreboard` (raw/confirmed/disproved/inconclusive/discovered) + pitch. | `Scoreboard`, `build_scoreboard` |
| `scenario.py` | End-to-end scenario driving real oracles against ground-truth mocks → the scoreboard. | `run_scenario` |
| `fixtures/nuclei_scan.jsonl` | Cached Nuclei output (never live in the demo). | — |

### Report scripts (`backend/scripts/`)
| File | Produces |
|---|---|
| `reliability_diagram.py` | `reliability.png` — calibration reliability + AUC/ECE |
| `scoreboard_chart.py` | `scoreboard.png` — scanner-independence bar chart |

### Tests (`backend/tests/validation/`)
`test_control.py` (32) · `test_writer.py` (34) · `test_authz.py` (15) ·
`test_differential.py` (15) · `test_phase4_oracles.py` (22) ·
`test_calibration.py` (19) · `test_evidence.py` (14) · `test_scanner.py` (17).

### Shared with Module 3 (do NOT duplicate)
| File (in `app/graph/`) | Why Module 2 imports it |
|---|---|
| `contract.py` | The frozen vocabulary + write-time validation. `VULN_CLASSES`, `VERDICTS`, `ORACLE_PROVES`, `patch_group_for`, `patch_hours_for`, `validate_batch`, `normalise_finding_row`. |
| `model.py` | Privilege constants (`DATA_READ`, `USER_SESSION`, …) used by `writer.py`. |
| `build.py`, `loader.py`, `pipeline.py` | Only in round-trip tests (verify rows produce a valid graph; retest → `recompute`). |

---

## 4. The candidate → verdict → row lifecycle

1. **Candidate** arrives (from `scanner.py`, or hand-built in assist mode).
2. **Control engine** establishes a trustworthy baseline (or returns
   `inconclusive` if the endpoint is out of scope / a catch-all / too volatile).
3. **Oracle(s)** run against the (scope-guarded) `Fetcher`, each producing an
   `OracleOutcome` and a per-oracle `Verdict`.
4. **Adjudicator** (`adjudicate`) merges a candidate's outcomes → one `Verdict`
   with a **calibrated** confidence and a contribution breakdown.
5. **Writer** (`to_finding_row` / `write`) turns the `Verdict` into a
   contract-valid row (with `patch_group`, `observed_grants`, stable
   `finding_id`, `generated_by='tool'`), validated against `contract.py`.
6. **Evidence** (`record_run`) captures the transaction array into a manifest;
   `retest` replays it after a fix.
7. Rows go to Postgres → Module 3.

---

## 5. Verdict states (there are FOUR, not two)

| Status | Meaning | Enters the graph? |
|---|---|---|
| `validated` | oracle(s) fired, corroborated, controls clean | yes |
| `false_positive` | the oracle **actively disproved** the scanner | **no** (dropped) |
| `inconclusive` | environment prevented clean measurement (WAF, instability, no OOB callback) | yes, low weight |
| `unverifiable_safely` | a real class with **no non-destructive oracle** (e.g. a deserialization gadget we refuse to fire) | yes, weighted above `unvalidated` |

Shipping the last two is deliberate. A validator that always decides is a
validator that lies.

---

## 6. Behaviours that LOOK like bugs but are CORRECT (anti-hallucination)

Do not "fix" any of these. Each is intentional and tested.

1. **A validated differential-only SQLi carries a corroboration warning.**
   `differential` and `timing` are single-family (`content`/`time`) and *not*
   self-corroborating; a lone one is flagged until a disjoint family agrees. The
   warning is the honest signal, not a defect.
2. **The differential oracle emits `observed_grants = ()` (empty).** It proves
   *injection*, not *extraction*, so it claims no privilege; the grant comes
   from the CVSS vector instead. Only authz/execution/oob observe a grant.
3. **OOB with no callback → `inconclusive`, never `false_positive`.** A blind
   channel's silence cannot disprove (the target may be egress-filtered). Only a
   callback is conclusive.
4. **A confirmed finding's confidence is not 1.0.** It's a calibrated posterior
   (e.g. corroborated SQLi ≈ 0.97, single-channel ≈ 0.93). Calibration never
   emits 1.0.
5. **The calibration prior is 0.5 (neutral), not the scanner's 0.12.** An
   independent instrument does not inherit the scanner's bias, and in assist
   mode there is no scanner. `SCANNER_BASE_RATE = 0.12` remains documented as an
   alternative.
6. **Reliability ECE ≈ 0.13 and points sit above the diagonal.** The mock corpus
   is perfectly *separable* (AUC 1.0), so the model is conservative on single-
   channel truths — the safe direction. Mid-range calibration needs graded real
   targets (known-vulnerable practice targets). This is disclosed, not hidden.
7. **`combine.py` and `adjudicate.py` both exist.** `adjudicate` is the real
   confidence engine; `combine` is the Phase-4 placeholder kept for its
   decision logic and a few tests.
8. **`tech-detect-nginx` in the Nuclei fixture is "unmappable".** An info-level
   template has no `vuln_class`; we return `None` and surface the diagnostic
   rather than force a wrong label. Counted in the scoreboard as `unmappable`.
9. **The scenario reports the RCE as `inconclusive`.** Its OOB canary is
   egress-filtered in the mock — correct per rule #3.

---

## 7. The contract (the M2 ↔ M3 seam)

`app/graph/contract.py` is imported by both modules and is the single source of
truth for:
- `VULN_CLASSES` — the allowed `vuln_class` enum (derived from Module 3's
  `SEMANTICS`, so it can never drift).
- `VERDICTS` — the four states + `unvalidated`/`remediated`.
- `ORACLE_PROVES` — oracle → (observed_requires, observed_grant). This is
  exactly `SELF_CORROBORATING` in `writer.py`.
- `patch_group_for(cve/component/root_cause)` — the grouping rule the ILP needs;
  returns `None` rather than inventing a group.
- `patch_hours_for(vuln_class)` — remediation-effort lookup.
- `validate_batch(rows)` / `normalise_finding_row(row)` — write-time validation.

**Adding a new vuln class:** add it to Module 3's `SEMANTICS` (so it enters
`VULN_CLASSES`) **and** to `contract.M2_EMITTED_CLASSES`. A CI test fails if
Module 2 emits a class outside the enum.

---

## 8. The row Module 2 writes (the output schema)

```
finding_id, asset_id, vuln_class, status, confidence,
cvss_vector, epss, epss_snapshot_date, patch_hours, patch_group,
evidence_id, endpoint, param, target_asset_id,
observed_requires, observed_grants, generated_by='tool'
```
Plus, for SSRF, an **observed Route row** (`src, dst, provenance='observed',
reason`). `observed_grants` is the highest-value field: it flips the graph edge
to `provenance='evidence'`, raising Module 3's published derived-fraction.

---

## 9. How to run

```bash
cd backend
pip install -r requirements.txt      # networkx, pulp, fastapi, pytest, matplotlib, httpx
PYTHONPATH=. pytest tests -q                 # 307 tests
PYTHONPATH=. pytest tests/validation -q      # 168 validation tests
PYTHONPATH=. python scripts/reliability_diagram.py reliability.png
PYTHONPATH=. python scripts/scoreboard_chart.py scoreboard.png
PYTHONPATH=. python -c "from app.validation.scenario import run_scenario; sb,_=run_scenario(); print(sb.pitch())"
```
Determinism check (must be identical every time):
```bash
for h in 0 1 42; do PYTHONHASHSEED=$h PYTHONPATH=. python -c \
 "from app.validation.scenario import run_scenario; print(run_scenario()[0].as_dict())"; done
```

---

## 10. Package layout & import notes

```
backend/app/validation/
  __init__.py
  http.py  scope.py  control.py  sanity.py  limiter.py  mock_target.py
  writer.py  fixtures.py
  calibration.py  corpus.py  adjudicate.py
  evidence.py  api.py
  scanner.py  independence.py  scenario.py
  fixtures/nuclei_scan.jsonl
  oracles/
    __init__.py  authz.py  differential.py  timing.py  execution.py  oob.py  combine.py
backend/app/graph/            # Module 3 — contract.py, model.py, etc. (do not edit for M2)
backend/tests/validation/     # 8 test files
backend/scripts/              # reliability_diagram.py, scoreboard_chart.py
```
- Every subpackage needs an `__init__.py` (`app/`, `app/validation/`,
  `app/validation/oracles/`, `tests/`, `tests/validation/`). A missing one is
  the usual cause of import errors — **not** a missing source file.
- `writer.py` imports from `app.graph.contract` and `app.graph.model`. Those are
  Module 3 files and must be on the path.

---

## 11. Two files Module 2 does NOT own (don't confuse them)

`app/graph/diagnostics.py` and `app/graph/_pulp_compat.py` belong to Module 3.
If your Module 3 bundle is missing them, get them from the Module 3 delivery —
do not reconstruct stubs, which is what produces wrong test results.

---

## 12. What is intentionally NOT built (do not invent it)

- **A live HTTP client.** Oracles take a `Fetcher` (`Request → Response`). In
  production it is a thin **httpx adapter** that calls `assert_in_scope` and the
  `TargetLimiter`, then does the real request. In tests it is the mock target.
  Wiring it is deployment work, not a missing module.
- **A real Playwright renderer.** `execution.py` takes a `Renderer` protocol;
  `MockBrowser` stands in. Playwright drops in unchanged.
- **A live Nuclei run.** We cache JSON (`nuclei_scan.jsonl`) so the demo never
  waits on a scan.
- **Persistent storage.** `EvidenceStore` is in-memory; production swaps in
  Postgres/object storage using `manifest.to_dict()`.
- **A dashboard.** Frontend consumes `GET /evidence/{id}` and Module 3's graph
  endpoints.

None of these being absent is a bug. Building them is the remaining integration
work; the interfaces they plug into are already tested.

---

## 13. One-paragraph pitch (for the report / demo)

> Module 2 treats every scanner finding as a hypothesis and adjudicates it with a
> controlled, non-destructive experiment. Vulnerability classes reduce to a
> handful of observation channels — content differential, timing, out-of-band,
> in-browser execution, and the authorization matrix — and a finding is
> `validated` only when the evidence is direct (a nonce that ran, a canary that
> called back, a matrix that proved its own control) or two channels with
> disjoint failure modes agree. Confidence is a calibrated naive-Bayes posterior,
> not a vibe; every finding is a seeded, replayable manifest, so retest proves a
> fix by re-running the identical experiment and requiring the verdict to flip.
> Against a cached scan we disproved the hallucinations, confirmed the real
> vulnerabilities, and — in assist mode — found one the scanner missed. We
> verify; we do not repeat.
