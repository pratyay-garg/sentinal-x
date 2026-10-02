#!/usr/bin/env python3
"""Module 3 demo: runs the whole A0-A7 pipeline against the fixture and prints
the numbers you would say out loud. Deterministic -- re-run it and the output is
byte-identical."""
import time
from app.graph.loader import load_fixture
from app.graph.pipeline import recompute, run
from app.graph.sensitivity import validation_ablation, weight_stability

def line(c="-"): print(c * 78)

gi = load_fixture()
t0 = time.perf_counter()
res = run(gi, trials=10_000, seed=1337, budget_hours=6.0, priority_trials=2000)
elapsed = time.perf_counter() - t0

line("=")
print("MODULE 3 - ATTACK-PATH INTELLIGENCE & BREAK-THE-CHAIN")
line("=")
print(f"pipeline: {elapsed*1000:.0f} ms total   seed=1337 (reproducible)")
print(f"A1 prune: {res.prune['nodes_before']} -> {res.prune['nodes_after']} nodes "
      f"({res.prune['reduction']:.0%} removed)")
print(f"A0 crown jewels reachable: {', '.join(res.reachable_jewels) or 'none'}")
if res.diagnosis.get("status") != "ok":
    print(f"!! {res.diagnosis['headline']}")
    for pr in res.diagnosis["problems"]:
        print(f"   [{pr['severity']}] {pr['code']}: {pr['message']}")
        print(f"        fix -> {pr['fix']}")

line()
print("A5  COMPROMISE PROBABILITY (correlated Monte Carlo, all paths)")
for a, p in sorted(res.monte_carlo.jewel_prob.items()):
    print(f"   {a:<12} {p:.3f} +/- {res.monte_carlo.jewel_ci[a]:.3f}   "
          f"({res.monte_carlo.trials} trials, adaptive stop)")

line()
print("A2/A3  MINIMUM PATCH SET")
c = res.cut
print(f"   method    : {c['method']}")
print(f"   patches   : {', '.join(c['vulns'])}   ({c['cost']} hours)")
print(f"   actions   : {', '.join(c['patch_groups'])}")
print(f"   guarantee : sound={c['sound']}  irreducible={c['irreducible']}  exact={c['exact']}")
print(f"   tie-break : {c['tie_break']}")
for n in c["notes"]:
    print(f"   note      : {n}")

line()
print("A4  DOMINATORS (unbypassable chokepoints)")
for ch in res.chokepoints[:5]:
    print(f"   {ch['vuln_id']:<5} {ch['label'][:28]:<28} gates {ch['dominated_jewels']} "
          f"(impact {ch['weighted_impact']}, {ch['patch_hours']}h)")

line()
print("A6  BUDGET PLAN (6 hours)")
b = res.budget_plan
for p in b["picks"]:
    print(f"   {p['vuln_id']:<5} {p['patch_hours']}h -> kills {p['paths_killed']} paths "
          f"({p['paths_killed_per_hour']}/h)")
print(f"   coverage {b['paths_covered']}/{b['paths_total']} enumerated paths "
      f"({b['coverage']:.0%}); {b['guarantee']}")

line()
print("A5  MODAL ATTACK PATH (most frequently observed, not a separate algorithm)")
for a, m in sorted(res.modal_paths.items()):
    print(f"   {a}: seen in {m['count']}/{res.monte_carlo.trials} worlds ({m['share']:.0%})")
    for step in m["path"]:
        if step.startswith(("vuln|", "state|", "fact|")):
            print(f"        -> {step}")

line()
print("ASSURANCE")
print(f"   provenance: {res.provenance['derived_fraction']:.0%} of edges are "
      f"evidence/standard-derived, {res.provenance['assumed_fraction']:.0%} modelled")
print(f"   invariants: {'ALL PASS' if res.invariants['all_passed'] else 'FAILURE'}")
for ck in res.invariants["checks"]:
    print(f"      [{'ok' if ck['passed'] else 'XX'}] {ck['check']}: {ck['detail']}")
st = weight_stability(gi, trials=50, top_k=3)
print(f"   sensitivity: {st.as_dict()['claim']}")
ab = validation_ablation(gi)
print(f"   ablation   : {ab['claim']}")
print(f"   cycles     : mutual-compromise clusters {res.cycles} (detected, NOT condensed)")

line()
print("RETEST DELTA (apply the minimum patch set)")
d = recompute(gi, set(c["vulns"]), trials=10_000)
for a, m in sorted(d["jewel_delta"].items()):
    print(f"   {a:<12} {m['before']:.3f} -> {m['after']:.3f}  "
          f"({m['reduction_pct']:.0f}% reduction)")
print(f"   attack paths {d['paths_before']} -> {d['paths_after']} "
      f"({d['paths_eliminated']} eliminated)")
print(f"   jewels still reachable: {d['jewels_still_reachable'] or 'none'}")
line("=")
