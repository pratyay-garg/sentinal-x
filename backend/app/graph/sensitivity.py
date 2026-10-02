"""
Sensitivity analysis -- the honest alternative to claiming calibration.

We cannot fit the scorecard weights: there is no labelled corpus, and claiming
a calibration we did not perform is the one thing that could actually damage us
in the contention round.

The rigorous substitute is cheaper than fitting. Perturb the weights (+/-30%,
a few hundred draws) and measure how often the top-k fix-first ranking survives.
"Our top-3 recommendation is stable in 94% of weight perturbations" converts a
hard-coded constant into a MEASURED property, and it is checkable live.

The ablation does the complementary job: recompute with unvalidated findings
excluded entirely. If the top-3 is unchanged, our conclusions rest on evidence
rather than on priors -- which is the whole thesis of the project.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from .breakchain import solve as solve_cut
from .build import build_graph
from .dominators import chokepoints
from .model import GraphInput
from .prune import prune
from .scoring import WEIGHTS


@dataclass
class Stability:
    trials: int = 0
    top_k: int = 3
    ranking_stable: float = 0.0
    cut_stable: float = 0.0
    baseline_top: list[str] = field(default_factory=list)
    baseline_cut: list[str] = field(default_factory=list)
    perturbation: float = 0.3

    def as_dict(self) -> dict:
        return {
            "trials": self.trials, "top_k": self.top_k,
            "ranking_stability": round(self.ranking_stable, 4),
            "cut_stability": round(self.cut_stable, 4),
            "baseline_top": self.baseline_top, "baseline_cut": self.baseline_cut,
            "perturbation": self.perturbation,
            "claim": (f"top-{self.top_k} chokepoint ranking is unchanged in "
                      f"{self.ranking_stable:.0%} of +/-{self.perturbation:.0%} "
                      f"weight perturbations"),
        }


def weight_stability(gi: GraphInput, *, trials: int = 200, top_k: int = 3,
                     perturbation: float = 0.3, seed: int = 1337) -> Stability:
    rng = random.Random(seed)
    base_g = prune(build_graph(gi))
    base_top = [c.vuln_id for c in chokepoints(base_g)][:top_k]
    base_cut = sorted(solve_cut(base_g).vulns)

    rank_hits = cut_hits = 0
    for _ in range(trials):
        w = {k: v * (1 + rng.uniform(-perturbation, perturbation))
             for k, v in WEIGHTS.items()}
        g = prune(build_graph(gi, weights=w))
        if [c.vuln_id for c in chokepoints(g)][:top_k] == base_top:
            rank_hits += 1
        if sorted(solve_cut(g).vulns) == base_cut:
            cut_hits += 1

    return Stability(trials=trials, top_k=top_k,
                     ranking_stable=rank_hits / trials if trials else 0.0,
                     cut_stable=cut_hits / trials if trials else 0.0,
                     baseline_top=base_top, baseline_cut=base_cut,
                     perturbation=perturbation)


def validation_ablation(gi: GraphInput, top_k: int = 3) -> dict:
    """Recompute with unvalidated findings dropped. If the top-k is unchanged,
    the conclusions rest on evidence, not on priors."""
    full = prune(build_graph(gi))
    full_top = [c.vuln_id for c in chokepoints(full)][:top_k]

    validated_only = GraphInput(
        assets=gi.assets,
        findings=[f for f in gi.findings if f.status in ("validated", "remediated")],
        facts=gi.facts, routes=gi.routes, entries=gi.entries,
    )
    abl = prune(build_graph(validated_only))
    abl_top = [c.vuln_id for c in chokepoints(abl)][:top_k]

    return {
        "with_unvalidated": full_top,
        "validated_only": abl_top,
        "unchanged": full_top == abl_top,
        "findings_dropped": len(gi.findings) - len(validated_only.findings),
        "claim": ("top-%d ranking is unchanged when unvalidated findings are "
                  "excluded" % top_k) if full_top == abl_top else
                 ("top-%d ranking depends on unvalidated findings; flagged" % top_k),
    }
