# ADR-0007: Generic target authentication, saved scan configurations, and operator-controlled runtime settings

- Status: proposed
- Date: 2026-10-02
- Amends: ADR-0003 (adds an operator-controlled, warned opt-in to relax the scanner's destructive-template exclusion; the shipped default stays non-destructive)

## Context

The platform was hardened around two practice labs. This leaves three problems
for a product that authorised organisations run against their own targets.

### 1. Target-specific coupling

Scan creation accepts `preset: "dvwa" | "bwapp"`. The authenticator embeds those
labs' default credentials, their database-install/reset URLs (`setup_url`), and a
direct `set_cookies` write for a lab difficulty toggle. The crawler hard-codes
`setup.php` and `security.php` in its exclusion pattern. Two lab services ship in
the product compose file, and helper scripts print a session cookie for each lab.
The product reads as a tool for two sites rather than a general assessment engine.

### 2. Correctness defects in the generic login path

A generic `form_login` recipe already exists, but:

- **Login success is inferred from the cookie jar.** `_cookie_header` returns
  whatever cookies the server set. A failed login still issues a session cookie,
  so an "authenticated" scan can crawl a login page and report it as clean
  coverage.
- **The login flow is not scope-checked.** The client follows redirects and never
  re-checks `login_url`, `setup_url`, `post_login_url`, or any redirect hop
  against the allow-list. architecture.md §5.2 states that it restricts recipe
  URLs to the target origin and checks unsuccessful statuses; the code does
  neither, so the technical report currently describes a control that does not
  exist.
- **Only cookie sessions are produced.** `resolve_auth_headers` always returns a
  `Cookie` header. Token-based applications — log in with a JSON body, receive a
  token, send it as `Authorization: Bearer` — cannot be authenticated at all.
- **CSRF handling reads a single named field.** A generic login should carry
  every hidden input the login form contains.

### 3. Sessions expire before retest, producing false "fixed" verdicts

Credentials are used transiently and discarded; only the derived session is
stored, encrypted, for `scan_credential_ttl_seconds` (7200 s). When a retest
runs after that window the session is dead. An auth-only endpoint then answers
with a login page or a 403, the replay sees the vulnerability is no longer
reproducible, and the retest records it as fixed. A false "remediated" result is
the most damaging error this stage can make: it closes a live issue.

### 4. Behaviour is frozen in code and `.env`

Roughly eighty values govern scan behaviour — subprocess timeouts, crawl depth
and page caps, Nuclei rate/concurrency and template timeouts, validation
request bounds and retry counts, orchestration heartbeat/stale thresholds, the
credential TTL, Monte-Carlo trial counts, LLM timeouts, and the oracle
confidence/statistical thresholds. Some live in `config.Settings`; many are
literals inside the pipeline stages. Changing any of them means editing Python
or recreating containers. That is incompatible with shipping the platform as a
single Docker image that an operator runs and tunes from the web console.

## Decision

### D1 — No target-specific behaviour

Remove `preset` and the embedded DVWA/bWAPP recipes, `setup_url`, `set_cookies`,
the `scripts/*_session.sh` helpers, the lab services from the product compose
file, and the lab filenames from the crawl exclusion pattern. Provisioning a
target — installing it, creating its database, selecting a difficulty — is the
operator's responsibility. Once an instance exists, the discovery and validation
engines do everything they can against it (crawl, authenticate where possible,
SQLi/XSS/authz validation) with no per-site knowledge.

### D2 — Two generic authentication methods

`ScanAuthLogin` offers exactly one of:

- **`form`** — GET the login page, parse the login form, and submit every hidden
  input it contains together with the operator's supplied field values. The
  result is a cookie session.
- **`json`** — POST an operator-defined JSON body to a login endpoint, read the
  token from an operator-given response JSON path (or a named response header),
  and inject it into subsequent requests through a header template such as
  `Authorization: Bearer {token}`.

Both methods yield one or more named auth contexts, preserving the existing
public-versus-authenticated differential coverage and the multi-context slot
already in the schema.

### D3 — Verified login, not an assumed one

A login configuration must carry a **success check**: a URL to request after
login plus a logged-in marker (expected content, or an expected status) and/or a
logged-out marker (a redirect to the login URL, a password field, a known
"please log in" string). Login is treated as successful only when the check
passes. A failed check raises the existing `AuthLoginError`; it never degrades
silently to an unauthenticated scan.

### D4 — Scope enforced across the whole login flow

Every URL the login flow touches — the login endpoint, the success-check URL,
and each redirect hop — is re-checked against `app/core` scope before the
request is made. This brings the code in line with the architecture document
rather than the reverse.

### D5 — Session lifetime and refresh

Encrypted credentials are retained for the lifetime of their scan configuration
(see D7) so a session can be re-established. During discovery, validation, and
retest the session's health is checked with the D3 success check:

- Between pipeline stages, a dead session is refreshed within a bounded retry
  budget.
- If refresh fails, the affected context's coverage is marked **incomplete**;
  the stage is not reported as a clean result.
- **Retest returns an explicit `inconclusive` / session-invalid outcome when a
  working session cannot be established.** It never reports an auth-only finding
  as fixed on the strength of a login-page response. This adds a status value to
  `retest_results`.

### D6 — Operator-controlled runtime settings (expose everything, with guardrails)

A single-row `runtime_settings` table holds JSON overrides. Effective value =
operator override → `.env` → code default, read through the existing `Settings`
object so no module reads overrides directly. A **System → Settings** console
panel edits them live; changes take effect on the next job with no container
recreate and are written to the audit log.

Per the product owner's decision, operational knobs **and** safety/method knobs
are exposed, including the Nuclei destructive-template exclusion
(`dos`, `brute`, `intrusive`) and the oracle confidence and statistical
thresholds. These sit in an **Advanced (expert)** section:

- Enabling destructive/brute/intrusive templates shows a prominent warning that
  it departs from the non-destructive posture of ADR-0003 and may violate
  the rules of engagement for a given target; the action is audit-logged.
- Loosening an oracle threshold warns that it raises the false-positive rate.

The **shipped defaults remain non-destructive**: the exclusion stays on and the
thresholds keep their validated values unless an operator deliberately changes
them. The one mandatory guardrail — the scope allow-list — is never relaxable to
"scan anything"; it remains fail-closed.

### D7 — Saved scan configurations, operator-clearable

A `scan_configs` table stores a reusable scan definition: target, profile, auth
configuration, and any per-scan setting overrides. Secrets (passwords, cookies,
tokens) are encrypted with the existing AES-GCM store and kept until the
operator deletes the configuration. The UI never re-displays a stored secret;
it shows a masked placeholder that can be replaced. Every stored item is
deletable from the operator end — a saved configuration, a scan, and a global
reset — so the system can be returned to a clean state.

### D8 — Scope editing is admin-gated

The scope allow-list becomes editable from System under the separate admin key
(the key already used for kill-switch reset), seeded from `.env` on first boot,
and every change is audit-logged. Console-password holders can view it but not
change it.

## Consequences

- The API contract and UI lose `preset`; `custom_headers` and the generic
  recipe remain. A migration adds `runtime_settings` and `scan_configs`, extends
  `scan_credentials` for lifetime-based retention, and adds the retest
  `inconclusive` status.
- architecture.md §5.2 is rewritten to describe the generic `form`/`json`
  methods, the verified-login and scope checks, and session refresh — matching
  the code.
- The product no longer bundles intentionally-vulnerable services; operators
  bring their own authorised targets. README and `setup.sh` scope defaults are
  de-labbed.
- Exposing the destructive-template toggle is a deliberate departure from
  ADR-0003's blanket exclusion. It is mitigated by non-destructive defaults, an
  explicit warning, and an audit entry, and bounded by the scope allow-list,
  which is never relaxed.
- This ADR is delivered as separate vertical slices (generic auth + retest
  correctness; runtime settings; saved configurations; admin scope; de-lab),
  each shipped and tested before the next.
