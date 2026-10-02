# Module 3 — Attack-Path Intelligence & Break-the-Chain

Worth 15 of the 60 solution marks (Attack-Path Intelligence & Risk Prioritization),
and it feeds Remediation (10), Retest, Phishing (3), Email Exposure (3), and
Integration/Engineering Quality (4).

Everything here is **deterministic and seeded**. Run it twice, get identical
numbers. That property is worth more than any feature.

The implementation lives in `backend/app/graph/`. Dependencies are pinned in
`backend/pyproject.toml`/`backend/uv.lock`; do not install them with bare pip.

```bash
source ../backend/.venv/bin/activate
PYTHONPATH=../backend:.. pytest -q # run from Slice_6; 139 tests
PYTHONPATH=../backend:.. python demo.py
```

The shared seam is `contract.py` (not `contact.py`). Discovery and Validation
write contract-compatible PostgreSQL rows; the graph reads those rows without
calling either engine.

---

## The design decision everything rests on

Almost every team will build an **asset graph**: nodes are hosts, edges mean
"there's a vuln here." It renders fine and it is analytically worthless, because
you cannot ask it *what does the attacker actually hold after this step?*

This is a **typed attacker-state graph** (simplified MulVAL, Ou et al. 2005).

| Node | Meaning | Example |
|---|---|---|
| `State(asset, privilege)` | what the attacker holds | `("state","db-01","data_read")` |
| `Vuln(finding_id)` | a specific patchable finding | `("vuln","F4")` |
| `Fact(kind, ref)` | a non-patchable enabler | `("fact","shared_credential","global")` |

| Edge | Meaning |
|---|---|
| `State → Vuln` | precondition |
| `Fact → Vuln` | non-patchable precondition |
| `Vuln → State` | postcondition — **the only probabilistic edge** |
| `State → State` | privilege implication (same asset, downward) or network route |

**Why it matters:** a vulnerability is its own node, so *patch this finding* is
exactly *delete this node*. Remediation maps one-to-one onto graph operations.
In an asset graph you'd need a mapping from cut edges back to patches, and that
mapping is ambiguous. Here it's the identity function, and `recompute()` is one
line.

**Cut composition tells a story no asset graph can.** Because elements are typed,
we report *"the cut is 3 vulnerabilities and 1 Fact — but the Fact is a trust
relationship we can't patch, so this is 3 patches plus one architectural
recommendation."*

### The privilege lattice is a partial order, not a chain

```
code_exec → admin_session → user_session → network_reach → none
info_disclosure → network_reach
data_read       → network_reach          ← incomparable to code_exec
```

`code_exec` does **not** imply `data_read`. Owning the web server is not owning
the database — that's the whole point of the SQLi step you're modelling. Making
this a chain invents lateral movement, which is the most likely source of
"wait, how did you get from there to there?" during judging.

### `State → State` is constrained to exactly two forms

1. **Privilege implication**, same asset, downward only — generated mechanically
   from the lattice.
2. **Network route**, cross-asset, `network_reach` only.

Nothing else crosses assets for free. Every cross-asset privilege gain must pass
through a `Vuln` or a `Fact`. This single rule is what keeps the graph honest.

---

## The pipeline

| Stage | Algorithm | Complexity | Answers |
|---|---|---|---|
| A0 | AND/OR least-fixpoint reachability | O(V+E) | can they get there at all |
| A1 | AND-aware bidirectional prune | O(V+E) | what's even relevant |
| A2 | node-split min cut (Dinic) + AND reduction | O(E√E) | cheapest full isolation |
| A3 | ILP label cut (CBC) | ms at this scale | cheapest when patches group |
| A4 | dominator tree (Cooper–Harvey–Kennedy) | O(E log V) eff. | unbypassable chokepoints |
| A5 | CVE-correlated Monte Carlo | O(k(V+E)) | probability across all paths |
| A6 | Yen k-shortest + greedy coverage | O(KV(E+V log V)) | best fix set for N hours |
| A7 | topological DP on −ln(p) | O(V+E) | fallback display path |

Measured on the 30-node fixture: whole pipeline **≈900 ms**, of which Monte Carlo
is ~110 ms and the cut ~25 ms.

### A0 — why there is no AND-retry sweep

An AND node fires when its **last** precondition is reached. Every precondition
is a direct predecessor and every reached node is eventually popped, so the last
one popped fires it. A periodic re-sweep over the reached set is redundant *and*
O(V·E) per fixpoint — it made 10k trials take minutes instead of a second.

### A1 — pruning must be AND-aware (a bug this codebase actually had)

Naive `descendants(source) ∩ ancestors(sink)` drops preconditions that lead
nowhere useful. An AND node that loses a precondition **silently degrades into
an OR node** and invents a path to the crown jewel. Pruning therefore runs the
AND-aware fixpoint for its forward set. Pinned by
`test_prune_preserves_and_preconditions`.

### A5 — an asset's probability is a UNION (a bug this codebase also had)

An asset can have several terminal privileges (`data_read`, `code_exec`,
`admin_session`). Its compromise probability is P(the attacker obtains **any**
of them). Keying a dict by asset while iterating a *set* of states silently kept
whichever the set happened to yield last — hash-order dependent, so the numbers
changed between processes while the README claimed reproducibility. Now grouped,
sorted, and counted as a union; the modal path is canonicalised the same way
(shortest witness, then lexicographic). Pinned by
`test_reproducible_across_processes_under_hash_randomisation`, which re-runs the
simulation in subprocesses under two different `PYTHONHASHSEED` values.

Verified: identical output across `PYTHONHASHSEED` ∈ {0, 1, 42, 999}.

### A2 — node splitting, and what we honestly claim

Split every node into `v_in → v_out`. Internal edge capacity = `patch_hours` for
`Vuln` nodes, `+inf` for everything else; all structural edges `+inf`. A minimum
cut can never contain an infinite edge, so **every returned edge is a
vulnerability's internal edge**. The cut *is* the patch list, by construction.

Minimum cut is exact only on OR-graphs; on AND/OR graphs it is NP-hard. So:

1. compute on the OR-relaxation;
2. every AND-path is also an OR-path → the cut is **guaranteed sufficient**;
3. reduce it: put each element back and keep it only if the jewel becomes
   reachable again under full AND semantics.

Result: **sound and irreducible**. Not claimed to be the global minimum, and we
say so. That distinction is the difference between a true claim and a false one.

**Ties are not an implementation detail.** Many cuts share a value and NetworkX
returns whichever falls out of residual traversal order. "The library picked it"
is a bad answer to *why these two?* We take the canonical **source-minimal** cut
(forward residual reachability from `s`), then break remaining ties by total
patch hours, then node id — and state the rule out loud.

### Why we do NOT condense cycles first

Tarjan/SCC condensation is the standard suggestion. It is unnecessary — max-flow
has no acyclicity requirement, dominators are defined on arbitrary flowgraphs,
and non-negative `−ln(p)` weights mean Dijkstra never traverses a cycle. Worse,
contracting an SCC deletes its internal edges from the cuttable set, so
`mincut(condensed) ≥ mincut(original)`: you compute a feasible but possibly
**non-minimal** patch set while claiming minimality. We detect cycles for display
(*"these hosts form a mutual-compromise cluster"* is a real finding) and never
condense.

### A3 — the ILP, and why min-cut alone would be a false claim

Max-flow assumes edges are cut **independently**. One base-image upgrade kills
the same CVE on twelve hosts; one WAF rule closes eight edges. Once actions
group, this is **minimum label cut**, which is NP-hard.

```
min  Σ_l cost_l · x_l
s.t. d_s = 0, d_t = 1
     d_v − d_u ≤ x_{label(u,v)}   ∀ edges
     d, x ∈ {0,1}
```

If the edge crosses from source side (`d_u=0`) to sink side (`d_v=1`) the left
side is 1, forcing `x_l = 1`. Polynomial in size, exact, milliseconds under CBC.
Degenerates to the min-cut answer when every label is unique, so it's a strict
generalisation. Falls back to Dinic if PuLP is missing — **never crash a demo on
a solver**.

`test_4_same_patch_group_makes_the_ilp_beat_the_min_cut` pins the divergence:
min-cut says 4.0 hours, ILP says 2.0. That gap is the proof the ILP does real work.

### A4 — dominators, cited correctly

NetworkX does **not** implement Lengauer–Tarjan. `nx.immediate_dominators` is
**Cooper–Harvey–Kennedy**: reverse postorder, each node's idom set to the
pairwise intersection of its processed predecessors' idoms, intersection walking
both pointers up the tree until they meet. O(V²) worst case, converges in 2–3
passes in practice. Get this right in the report — a judge who knows compilers
will notice.

**Betweenness centrality is not the fix-first metric.** It's an all-pairs
shortest-path heuristic answering a different question and can rank a fully
bypassable node above a true dominator. Kept only as a tertiary tie-break.

### A5 — correlated Monte Carlo

The single most-likely path is not the risk. Forty paths at p=0.3 give the
attacker near-certain success while a shortest-path metric reports 0.3. The
correct quantity is s-t network reliability (#P-hard). Sampling is unbiased and
gives error bars.

**The correction nobody else makes:** naive Monte Carlo samples each edge
independently, but the same CVE on twenty hosts does *not* succeed or fail twenty
independent times. We draw **one uniform per patch group** and apply it to every
edge in that group (comonotonic coupling).

**Which way does that move the number? It depends on the topology, and saying so
is the point.** Positive dependence lowers the probability of a *union* and
raises the probability of an *intersection*:

| Shape | Independent | Correlated | Naive sampling therefore |
|---|---|---|---|
| Redundant **parallel** paths sharing one CVE | `1−(1−p)² = 2p−p²` | `p` | **overstates** risk |
| A **chain** reusing the same CVE twice | `p·p` | `min(p,p) = p` | **understates** risk |

Both directions are pinned:
`test_correlated_sampling_lowers_union_risk_vs_independent` and
`test_correlated_sampling_raises_series_risk_vs_independent`.

Real attack graphs are mostly union-shaped, so in practice the coupling makes our
headline compromise probability **lower** than a naive engine would report. That
is the honest direction and the stronger claim: *we refused to inflate the number
by pretending one exploit was twenty coin flips.*

Note the symmetry worth saying out loud: *the same grouping that makes patches
cheaper in the ILP makes exploit outcomes correlated here.*

**Two edge metrics, and the pitch must name which is on screen:**

- `witness` — the edge is in that world's witness tree. Discounts redundancy
  (one route credited per world) and produces the modal path. **Drives the heat map.**
- `participation` — edge live *and* tail compromised. Intuitive, but a redundant
  edge whose target is reachable forty other ways still lights up hot even
  though patching it changes nothing. Secondary "exposure" toggle.

**Never call it "flow."** Flow is conserved (in = out); edge participation is not
— a node with one in-edge at 0.9 and four out-edges at 0.9 has 0.9 in and 3.6
out. The honest word is *pressure*, *participation*, or *marginal edge
probability*. Say "flow" and one networks-literate judge undercuts everything
true you said before it.

**Adaptive stopping.** Sample until the widest CI half-width among jewel
probabilities drops below 0.01. Reports the N it actually needed, turning
simulation depth from an arbitrary round number into a stated precision
requirement.

### A6 — the budget objective

Min-cut answers *what fully isolates the jewels*. Full isolation is usually
unaffordable; the real question is *we have 8 hours, what do we fix*. Yen's
enumerates the top-K paths, then greedy coverage picks the vuln killing the most
uncovered paths per hour.

Because this is coverage over an **explicit finite collection** under a budget,
greedy carries the standard **(1 − 1/e) ≈ 0.632** guarantee, and we state it.
We deliberately do **not** claim submodularity for the Monte Carlo objective —
that one is presented as an empirical ordering. *"Here we have a proof / here we
have a measurement"* is exactly what the 20% explainability component grades.

### A7 — the display path

`w = −ln(p)`; minimising the sum maximises the product. Topological DP on the
acyclic part: O(V+E), simpler than Dijkstra, and it does not silently return a
wrong answer if a score ever exceeds 1 and a weight goes negative (Dijkstra
would fail quietly — the worst kind of bug to find on stage).

**This is a visualisation, not a risk metric.** In practice the dashboard draws
the **modal path from A5** instead: the single most frequently observed chain
across the simulated worlds. Path and heat map then come from one engine, which
is a strictly better claim than running two algorithms and hoping they agree.

---

## Removing the hardcoding

### CVSS vectors are already a precondition/postcondition spec

Nobody uses them this way. The exploitability metrics *are* preconditions and
the impact metrics *are* postconditions:

| Metric | Reads as |
|---|---|
| `AV:N` / `AV:L` | precondition `network_reach` / `user_session` |
| `PR:L` / `PR:H` | precondition `user_session` / `admin_session` |
| `UI:R` | add `Fact(user_interaction)` — **this is where phishing attaches** |
| `C:H` / `I:H` | grants `data_read` / `code_exec` |
| `S:C` | **the grant lands on a different asset** — CVSS formally declaring lateral movement |

`S:C` is the single most valuable bit in the vector and most teams will never
notice it's there.

Exploitability subscore = `8.22 · AV · AC · PR · UI`, max 3.887. We use the
*Exploitability* subscore, not Base, because an edge asks "can they take this
step", not "how bad is the outcome".

**Precedence: observed evidence > CVSS vector > class table.** The hand-written
`SEMANTICS` table is now the *fallback* for app-layer findings with no CVE, not
the model.

### The assumption budget is a published number

Every node and edge carries `derived_from ∈ {evidence, cvss_vector, observed,
class_table, assumed}`. The pipeline reports:

```
provenance: 86% of edges are evidence/standard-derived, 14% modelled
```

This is the direct answer to *"how much of this did you hardcode?"* — measured
before anyone asks. Teams that hardcode everything cannot produce this number.

### Edge probability: EPSS is a prior, never a multiplier

```
logit(P) = b + w₁·cvss_exploitability + w₂·logit(EPSS) + w₃·evidence + w₄·status
```

`P_edge = EPSS × (CVSS_Exploitability / 3.9)` is tempting and wrong, four ways:

1. **It zeroes the graph.** EPSS is heavily right-skewed (median ~1e-3).
   Multiply and nearly every edge lands near zero; 10k trials over near-zero
   edges reach nothing and the heat map is uniformly cold on stage.
2. **Different quantities.** EPSS = "is this CVE exploited *somewhere in the
   world* in the next 30 days". An edge needs "does this step work *here*".
3. **Double counting.** EPSS's model already consumes CVSS components — the
   product is the same evidence squared, biased downward.
4. **Coverage collapses.** EPSS keys on CVE ids; XSS, IDOR, broken access
   control and misconfigs have none. You'd have inconsistent edge semantics
   inside one graph.

Additive log-odds fixes all four: validated findings dominate (`w₃` largest),
missing EPSS contributes exactly zero, and the per-signal contribution table
renders straight into the UI as the explainability artifact.

**Unvalidated findings still produce edges**, at reduced weight. The graph is
complete and demoable on Day 4 *before* the validation module exists, and
improves automatically as your teammate ships. Render the two edge classes
differently and you have a live demo of *validation reducing uncertainty in the
attack graph*.

**Pin an EPSS snapshot.** It is republished daily; live calls mean your midterm
and endterm numbers won't match, and reproducibility was your strongest claim.

### Calibration we can't do → sensitivity we can

We have no labelled corpus, so we don't claim calibrated weights. Instead we
perturb them ±30% over N draws and measure ranking survival:

```
top-3 chokepoint ranking is unchanged in 100% of ±30% weight perturbations
top-3 ranking is unchanged when unvalidated findings are excluded
```

A measured property beats a fabricated calibration, and it's checkable live.

### The engine verifies its own answers

Seven metamorphic invariants, asserted every run, milliseconds:

```
[ok] prune_invariance                compares the reached JEWEL SET, not a boolean
[ok] cut_soundness                   jewels actually unreachable after patching
[ok] cut_irreducibility              restoring any element restores reachability
[ok] cut_dominator_consistency       A2 and A4 must agree
[ok] monotonicity                    patching never grows the reach set
[ok] mc_probability_bounds
[ok] mc_reachability_consistency     nothing sampled that's deterministically unreachable
```

When a judge asks *"how do you know your cut is right?"* the answer is **"we
verify it every run — here's the assertion,"** not "we trust NetworkX."

---

## Integration contracts

**Module 3 never calls another module.** It reads rows and writes rows. A
teammate's broken code cannot break this.

### From Discovery
```
Asset: asset_id (STABLE across re-scans), zone, is_crown_jewel, criticality 1-5
Route: src, dst, provenance, reason
```
`asset_id` stability is the one thing to push hard on — that's what their
Union-Find identity resolution is for. Fresh UUIDs per scan make retest
meaningless.

Route provenance should come from observations: open ports, DNS/CNAME, redirect
targets, CORS headers, a successful SSRF probe (strongest — a *proven* route),
Docker Compose membership. What you can't observe, mark `assumed` and let it show
up in the percentage. A graph missing real connectivity is worse than one with
labelled guesses.

### From Validation — deliberately boring, and pinned by `contract.py`
```
Finding: finding_id, asset_id, vuln_class, status, confidence,
         cvss_vector, patch_hours, patch_group, evidence_id, endpoint, param
```
**No graph semantics requested.** They'd get it wrong under time pressure and
you'd be debugging their model. This module owns `SEMANTICS` + `cvss.py`; their
job stays "classify the vuln", which they were doing anyway.

`contract.py` is the seam both modules import. It exists because the failure
mode here is not a crash — it is **silent semantic drift**: Module 2 writes a
`vuln_class` this module has never heard of, the graph still builds, still
renders, still reports a number, and that number is just quietly worse
(`DEFAULT_SEMANTICS` grants `info_disclosure` at `ASSUMED` provenance, so the
path dies *and* the published `derived_fraction` drops). `diagnostics.py`
catches it at analysis time; `contract.py` catches it at **write** time.

- `VULN_CLASSES` is derived from `SEMANTICS`, so it cannot fall out of date.
- `M2_EMITTED_CLASSES` is what Module 2's oracles produce.
  `test_every_class_module_2_emits_has_semantics` asserts the subset relation, so
  **adding an oracle without adding its semantics is a red build**, not a quiet
  downgrade.
- `patch_group_for(cve=/component=/root_cause=)` is the grouping rule **A3
  depends on** — without it every finding is its own group and the ILP silently
  degenerates to min-cut on live data even though it beats it on the fixture. It
  returns `None` rather than inventing a group, because over-grouping would make
  the ILP claim one action fixes work that really needs two: a *false*
  minimality claim, which is exactly what `breakchain.py` is careful never to
  make.
- `DEFAULT_PATCH_HOURS` keeps A6's budget plan from being uniformly 1.0.
- `POST /graph/load` runs `validate_batch` and returns the problems in the
  response; `GET /graph/contract` serves the vocabulary so Module 2 can assert
  against it in CI instead of duplicating the lists.

**`observed_grants` / `observed_requires` are the highest-value fields Module 2
can emit.** `cvss.semantics_from_finding` gives them top precedence and stamps
`Provenance.EVIDENCE` — the strongest tier — so they *raise the
`derived_fraction` this module already prints on screen*. Module 2's proofs are
what make this graph evidence-derived. `contract.ORACLE_PROVES` maps each oracle
to the transition it establishes:

| Oracle | observed_requires | observed_grants |
|---|---|---|
| authorization (the 2×2 matrix) | `user_session` | `data_read` |
| execution (marker ran in the DOM) | `network_reach` | `user_session` |
| oob_rce (canary command executed) | `network_reach` | `code_exec` |
| oob_ssrf (server fetched our URL) | `network_reach` | `network_reach` |
| oob_xxe (external entity resolved) | `network_reach` | `data_read` |
| priv_esc (low-priv hit an admin route) | `user_session` | `admin_session` |

Differential and timing oracles are deliberately **absent** from that table:
they prove *injection*, not *extraction*, so they return `((), None)` and let the
CVSS vector decide. Claiming an observed `data_read` from a two-sided boolean
test would be over-claiming, and over-claiming is what loses trust.

An SSRF canary callback should also be written as an **observed `Route` row** —
a route *proven by experiment*, which no scanner can produce. Note that SSRF
grants only `network_reach`; a second finding still has to convert reach into
read, or you would have SSRF magically granting `data_read`.

### The fourth verdict state

Module 2 ships four terminal verdicts, not two. `unverifiable_safely` is a real
vulnerability class with no non-destructive oracle — a deserialization gadget we
**refused to fire**. It is *not* `unvalidated`: we have a strong prior it is real
and simply declined to prove it, so `scoring.py` gives it its own weight
(`+0.60`) sitting above an untested candidate and below a proven one. It stays in
the graph as a patchable node carrying an honest uncertainty label.

> *"The graph carries the RCE we refused to exploit as a high-uncertainty edge
> with an architectural recommendation. We neither hid it nor faked proof of it."*

### To Remediation — `GET /graph/priority`
```json
{"vuln_id","rank","priority","impact","patch_hours","dominated_assets",
 "dominated_jewels","in_min_cut","in_budget_set","mitre_ids","evidence_id"}
```
Back from them: `patch_group` and `patch_hours`. No hours yet? Default 1 and the
ILP degrades gracefully to min-cut.

### To Retest — `POST /graph/recompute {"patched":[...]}`
```json
{"jewel_delta":{"db-01":{"before":0.949,"after":0.000,"reduction_pct":100}},
 "paths_before":6,"paths_after":0,"paths_eliminated":6,
 "jewels_still_reachable":[],"seed":1337,"reproducible":true}
```
This is the demo climax, and it exists only because A5 produces a number that
*moves*.

### To Frontend — `GET /graph/cytoscape`
Stable node ids (`nid()`) so layout doesn't jump on every poll. Overlays ride as
node/edge data so the frontend toggles views without a new payload:
`compromise_prob`, `prob_ci`, `witness`, `participation`, `in_min_cut`,
`dominated_jewels`, `provenance`, `on_modal_path`, `mitre`, **`evidence_id`**.

Every edge carries its `evidence_id`. Clicking an edge opens the screenshot or
request/response diff that proves it. **An attack graph where every edge is
backed by a reproducible artifact is a fundamentally different object from one
where edges are asserted** — that is the single strongest thing to show a judge.

### From Phishing (M5) and Email Exposure (M6)
`POST /graph/entry/phishing`, `POST /graph/entry/breach`

The PS says modules "should contribute data to a common security/attack graph"
and rewards "integration and intelligent correlation". So a high-risk phishing
finding inserts `Fact(phished_credential) → Vuln → State(asset, user_session)`
wired to the super-source, at `p = phishing_risk_score`.

Now the 3-mark module measurably moves the 15-mark graph: *"this phishing email
scores 0.82; adding it as an entry point raises database compromise probability
from 0.31 to 0.79."* Forty lines, and the highest-scoring forty lines in the
project. The breach endpoint rejects anything containing `@` — it takes an HMAC
digest, never an address.

---

## Failure modes, pre-decided

| Situation | What we show |
|---|---|
| No jewel reachable | Frontier + **nearest miss** — "one credential reuse from compromise" |
| `recompute()` on an already-isolated graph | No-op delta with a `note`, not an `AttributeError` |
| Module 2 writes an unknown `vuln_class` | Error at write time (`/graph/load`) *and* at analysis time |
| Cut value 0 | Already isolated. A valid finding, not a bug |
| Cut value ∞ | Every path routes through non-patchable Facts → "architectural change, not a patch" |
| Dinic `NetworkXUnbounded` | Caught → reported as the ∞ case |
| PuLP/CBC missing | Silent Dinic fallback, logged |
| ILP infeasible | Reported as uncuttable |
| All probabilities 1.0 | Monte Carlo degenerates to deterministic reachability; detected |
| Multiple entries | Super-source handles it; per-entry attribution |

Every one ends in a sentence you'd be happy to say out loud. That's the test.

---

## Files

```
backend/app/graph/
  contract.py     THE MODULE 2 SEAM -- shared vocabulary, patch grouping,
                  oracle->observation map, write-time validation
  model.py        node/edge types, privilege lattice, SEMANTICS fallback, provenance
  cvss.py         CVSS v3.1 parsing → exploitability subscore + derived semantics
  scoring.py      additive log-odds edge probability (shared with M2 and M5)
  build.py        construction, or_relaxation, remove_patched, M5/M6 entry hooks
  fixpoint.py     A0 AND/OR least fixpoint + witness trees + nearest_miss
  prune.py        A1 AND-aware bidirectional prune
  breakchain.py   A2 node-split Dinic + reduction, A3 ILP label cut, cycle detection
  dominators.py   A4 Cooper–Harvey–Kennedy + chokepoint ranking
  montecarlo.py   A5 correlated sampling, witness/participation, modal path, deltas
  ranking.py      A6 Yen + greedy budget, A7 topological DP, priority ranking
  invariants.py   7 runtime metamorphic checks
  sensitivity.py  weight perturbation stability + validation ablation
  export.py       Cytoscape JSON with stable ids
  pipeline.py     orchestrator + recompute() retest hook
  api.py          FastAPI router — the whole integration surface
  loader.py       JSON fixture + Postgres row adapters
  _pulp_compat.py PuLP 3.x/4.x shim (add_variable, COIN_CMD) -- keeps the ILP
                  off both deprecated APIs so a PuLP upgrade cannot break us
  fixtures/attack_graph_30.json
backend/tests/graph/     139 tests (100 engine + 39 contract)
backend/demo.py
```

---

## Build order

**Days 1–2** — Freeze the schema. Write the fixture. Nothing else.
**Days 3–4** — All of A0–A7 against the fixture, fully tested. Zero dependency on
Discovery, Validation, or the authorised target. **This is your Day-7 midterm PoC**
and it's the safest possible one because nothing external can break it.
**Days 5–6** — Swap the fixture loader for the Postgres loader. One file.
**Days 8–11** — Phishing/exposure entry points, retest delta, sensitivity endpoint.

Run this track in parallel with Validation from Day 3; they meet only at the
schema, frozen on Day 2.

---

## The ninety-second defence

> Attacker-state graph rather than an asset graph, so patches map one-to-one onto
> nodes. AND semantics so we never invent a path, with an explicitly
> sound-but-possibly-non-minimal cut that we then reduce to irreducible. An ILP
> for the true cost when patches group — one base-image patch collapses eleven
> edges across seven hosts and we prove it's the cheapest such set. Dominators
> for unbypassable chokepoints. Seeded Monte Carlo with error bars for
> probability across all paths at once, correlated per CVE — which makes our
> number *lower* than a naive engine's, because we refused to pretend one exploit
> was twenty independent coin flips. Eighty-six percent of our edges are
> evidence- or standard-derived and we publish the number. Eight invariants
> verify the engine's own answers every run. And every edge is clickable through
> to the artifact that proves it.
