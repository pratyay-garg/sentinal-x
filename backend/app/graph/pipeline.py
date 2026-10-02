"""
The orchestrator. Deterministic stages, run in order, producing one result
object. No agent autonomy, no LLM in the loop -- everything here is reproducible
and re-runnable by a judge.

    A0  reachability fixpoint (AND/OR)          O(V+E)
    A1  bidirectional prune                     O(V+E)
    A2  node-split min cut (Dinic) + reduction  O(E*sqrt(E))
    A3  ILP label cut (exact, grouped patches)  ms at this scale
    A4  dominator tree -> chokepoint ranking    O(E log V) effective
    A5  correlated Monte Carlo + modal path     O(k(V+E))
    A6  Yen k-shortest + greedy budget plan     O(KV(E + V log V))
    A7  topological DP on -ln(p) (display only) O(V+E)
        + runtime invariants, provenance report
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import networkx as nx

from . import breakchain, diagnostics, dominators, montecarlo, ranking
from .build import build_graph, provenance_report, remove_patched
from .export import to_cytoscape
from .fixpoint import jewels_reached, nearest_miss, reachable
from .invariants import verify
from .model import GraphInput
from .prune import prune, prune_stats


@dataclass
class GraphResult:
    graph: nx.DiGraph
    reachable_jewels: list[str] = field(default_factory=list)
    nearest_miss: list[dict] = field(default_factory=list)
    prune: dict = field(default_factory=dict)
    cut: dict = field(default_factory=dict)
    chokepoints: list[dict] = field(default_factory=list)
    monte_carlo=None
    modal_paths: dict = field(default_factory=dict)
    display_path: dict | None = None
    budget_plan: dict = field(default_factory=dict)
    priority: list[dict] = field(default_factory=list)
    invariants: dict = field(default_factory=dict)
    diagnosis: dict = field(default_factory=dict)
    provenance: dict = field(default_factory=dict)
    cycles: list = field(default_factory=list)
    timings_ms: dict = field(default_factory=dict)

    def summary(self) -> dict:
        d = {
            # FIRST key, deliberately: an empty analysis caused by a missing
            # is_crown_jewel flag must not read as a clean successful run.
            "diagnosis": self.diagnosis,
            "reachable_jewels": self.reachable_jewels,
            "prune": self.prune,
            "cut": self.cut,
            "top_chokepoints": self.chokepoints[:5],
            "jewel_probability": {
                a: {"p": round(p, 4),
                    "ci": round(self.monte_carlo.jewel_ci.get(a, 0.0), 4)}
                for a, p in sorted(self.monte_carlo.jewel_prob.items())
            } if self.monte_carlo else {},
            "mc_trials": self.monte_carlo.trials if self.monte_carlo else 0,
            "modal_paths": self.modal_paths,
            "budget_plan": self.budget_plan,
            "priority_top5": self.priority[:5],
            "invariants": self.invariants,
            "provenance": self.provenance,
            "mutual_compromise_clusters": self.cycles,
            "timings_ms": self.timings_ms,
        }
        if not self.reachable_jewels:
            d["nearest_miss"] = self.nearest_miss[:5]
        return d

    def cytoscape(self) -> dict:
        modal = next(iter(self.modal_paths.values()), None) if self.modal_paths else None
        return to_cytoscape(
            self.graph, mc=self.monte_carlo,
            cut=breakchain.Cut(vulns=self.cut.get("vulns", [])),
            chokes=[dominators.Chokepoint(
                vuln_id=c["vuln_id"], dominated_assets=c["dominated_assets"],
                dominated_jewels=c["dominated_jewels"],
                weighted_impact=c["weighted_impact"], label=c["label"],
                patch_hours=c["patch_hours"]) for c in self.chokepoints],
            modal_path=modal,
        )


def run(gi: GraphInput, *, trials: int = 10_000, seed: int = 1337,
        budget_hours: float = 8.0, k_paths: int = 50,
        with_priority: bool = True, priority_trials: int = 2000) -> GraphResult:
    t: dict[str, float] = {}

    def _t(name, fn):
        s = time.perf_counter()
        out = fn()
        t[name] = round((time.perf_counter() - s) * 1000, 2)
        return out

    full = _t("build", lambda: build_graph(gi))
    g = _t("A1_prune", lambda: prune(full))

    r = _t("A0_reachability", lambda: reachable(g))
    jewels = sorted({g.nodes[n].get("asset") for n in jewels_reached(g, r)})

    res = GraphResult(graph=g)
    res.diagnosis = diagnostics.diagnose(gi, full).as_dict()
    res.prune = prune_stats(full, g)
    res.reachable_jewels = jewels
    res.provenance = provenance_report(g)
    # Computed on the FULL graph, deliberately. A pair of hosts that can
    # compromise each other is a finding in its own right, whether or not that
    # pair happens to sit on a path to a crown jewel -- running this on the
    # pruned graph silently discarded real mutual-compromise clusters.
    res.cycles = _t("cycles", lambda: breakchain.cycle_clusters(full))

    if not jewels:
        # Do not render an empty screen. "One credential reuse away" is a finding.
        # The path-pruned graph is empty by definition when the sink is
        # unreachable. Diagnose and render from the full graph so a valid
        # isolation result does not masquerade as a malformed input.
        full_reach = reachable(full)
        res.graph = full
        res.nearest_miss = nearest_miss(full, full_reach)
        res.provenance = provenance_report(full)
        res.timings_ms = t
        res.invariants = verify(full, breakchain.Cut()).as_dict()
        return res

    cut = _t("A2_A3_cut", lambda: breakchain.solve(g))
    res.cut = cut.as_dict()

    res.chokepoints = [c.as_dict() for c in _t("A4_dominators",
                                               lambda: dominators.chokepoints(g))]

    mc = _t("A5_montecarlo", lambda: montecarlo.simulate(
        g, trials=trials, seed=seed, correlated=True))
    res.monte_carlo = mc
    res.modal_paths = mc.modal_paths

    res.budget_plan = _t("A6_budget",
                         lambda: ranking.budget_plan(g, budget_hours, k_paths).as_dict())
    res.display_path = _t("A7_display", lambda: ranking.display_path(g))

    if with_priority:
        res.priority = _t("priority", lambda: ranking.priority_ranking(
            g, mc, trials=priority_trials, seed=seed))

    res.invariants = _t("invariants", lambda: verify(g, cut, mc).as_dict())
    res.timings_ms = t
    return res


# ---------------------------------------------------------------- retest hook

def recompute(gi: GraphInput, patched: set[str], *, trials: int = 10_000,
              seed: int = 1337) -> dict:
    """Module 9 (Automated Retesting) calls this after flipping findings to
    `remediated`. Patch == node deletion, exactly -- that one line is the entire
    integration.

    Returns the before/after delta that is the demo climax.
    """
    before = run(gi, trials=trials, seed=seed, with_priority=False)

    if before.monte_carlo is None:
        # run() returns early with monte_carlo=None when no crown jewel is
        # reachable, and delta() then dereferenced None. Retest can legitimately
        # be called on an already-isolated graph, so report the no-op honestly
        # instead of raising AttributeError mid-demo.
        return {
            "patched": sorted(patched),
            "jewel_delta": {},
            "paths_before": 0, "paths_after": 0, "paths_eliminated": 0,
            "cut_before": before.cut, "cut_after": before.cut,
            "jewels_still_reachable": [],
            "seed": seed, "reproducible": True,
            "note": "no crown jewel was reachable before patching; "
                    "nothing to compare",
            "diagnosis": before.diagnosis,
        }

    g_after = remove_patched(before.graph, patched)
    mc_after = montecarlo.simulate(g_after, trials=trials, seed=seed)
    cut_after = breakchain.solve(g_after)

    paths_before = len(ranking.k_shortest_paths(before.graph, 50))
    paths_after = len(ranking.k_shortest_paths(g_after, 50))

    return {
        "patched": sorted(patched),
        "jewel_delta": montecarlo.delta(before.monte_carlo, mc_after),
        "paths_before": paths_before,
        "paths_after": paths_after,
        "paths_eliminated": paths_before - paths_after,
        "cut_before": before.cut,
        "cut_after": cut_after.as_dict(),
        "jewels_still_reachable": sorted(
            {g_after.nodes[n].get("asset")
             for n in jewels_reached(g_after, reachable(g_after))}),
        "seed": seed,
        "reproducible": True,
    }
