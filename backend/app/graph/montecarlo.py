"""
A5 -- compromise probability across ALL paths at once, by sampling.

WHY NOT SHORTEST PATH
The single most-likely path is not the risk. Forty independent paths at p=0.3
each give the attacker near-certain success, while a shortest-path metric
reports 0.3. The correct quantity is s-t network reliability, which is #P-hard
exactly. Sampling is unbiased, cheap, and gives error bars.

CORRELATED SAMPLING (the part nobody else will do)
Naive Monte Carlo samples each edge independently. That is wrong in a specific,
correctable way: the same CVE on twenty hosts does NOT succeed or fail twenty
independent times. If the attacker's exploit works, it works everywhere that
CVE lives.

We therefore draw one uniform per PATCH GROUP (== per CVE / per base image) and
apply it to every edge in that group -- a comonotonic coupling, the standard way
to induce maximal positive dependence.

WHICH WAY DOES IT MOVE THE NUMBER? IT DEPENDS ON THE TOPOLOGY, AND SAYING SO IS
THE POINT. Positive dependence lowers the probability of a UNION and raises the
probability of an INTERSECTION:

  redundant PARALLEL paths sharing one CVE (a union) -- independent sampling
      gives the attacker N independent shots at what is really one exploit, so
      it OVERSTATES risk. Two paths at p: independent 1-(1-p)^2 = 2p-p^2, versus
      correlated p. Pinned by
      test_correlated_sampling_lowers_union_risk_vs_independent.

  a CHAIN that reuses the same CVE twice (an intersection) -- the steps succeed
      together, so independent sampling UNDERSTATES risk. Independent p*p versus
      correlated min(p,p) = p. Pinned by
      test_correlated_sampling_raises_series_risk_vs_independent.

Real attack graphs are mostly union-shaped, so in practice the coupling makes
our headline compromise probability LOWER than a naive engine would report. That
is the honest direction and it is the stronger pitch: we refused to inflate the
number by pretending one exploit was twenty coin flips.

Note the symmetry worth pointing out in the presentation: the same grouping that
makes patches cheaper in the ILP makes exploit outcomes correlated here.

WITNESS FREQUENCY vs PARTICIPATION
Two different quantities, and the pitch has to name which one is on screen:
  participation -- edge is live AND its tail is compromised. Intuitive, but a
      redundant edge whose target is reachable forty other ways still lights up
      hot even though patching it changes nothing.
  witness       -- edge appears in the actual witness tree of that trial. Free
      from the fixpoint, discounts redundancy (only one route is credited per
      world), and it is what produces the modal path.
We compute both; `witness` drives the heat map, `participation` is the secondary
"exposure" toggle. The contrast between "hot but redundant" and "hot and
load-bearing" is itself a good slide.

DO NOT call this "flow". Flow is conserved (in == out); edge participation is
not. The honest word is pressure, participation, or marginal edge probability.
"""
from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import networkx as nx

from .fixpoint import adjacency as fp_adjacency, reachable
from .model import SUPER_SINK, SUPER_SOURCE, nid

DEFAULT_SEED = 1337


@dataclass
class MCResult:
    trials: int
    seed: int
    node_prob: dict = field(default_factory=dict)
    node_ci: dict = field(default_factory=dict)
    edge_witness: dict = field(default_factory=dict)
    edge_participation: dict = field(default_factory=dict)
    jewel_prob: dict = field(default_factory=dict)
    jewel_ci: dict = field(default_factory=dict)
    modal_paths: dict = field(default_factory=dict)     # jewel asset -> (path, count)
    correlated: bool = True
    stopped_early: bool = False

    def ci_half_width(self, node) -> float:
        return self.node_ci.get(node, 0.0)


def _half_width(p: float, n: int, z: float = 1.96) -> float:
    """Wald half-width. sqrt(p(1-p)/n) <= 0.5/sqrt(n), so at n=10k it is at most
    0.005 -- reporting '0.87 +/- 0.01' costs one line and signals we know this
    is an estimate."""
    if n <= 0:
        return 1.0
    return z * math.sqrt(max(p * (1 - p), 1e-12) / n)


def simulate(g: nx.DiGraph, *, trials: int = 10_000, seed: int = DEFAULT_SEED,
             correlated: bool = True, target_ci: float | None = 0.01,
             check_every: int = 1000, min_trials: int = 1000,
             adj: dict | None = None) -> MCResult:
    """Sample possible worlds; report marginal probabilities with error bars.

    Adaptive stopping: keep sampling until the widest CI half-width among the
    crown-jewel probabilities drops below `target_ci`, capped at `trials`. This
    turns simulation depth from an arbitrary round number into a stated
    PRECISION REQUIREMENT -- "we sampled until the estimate was tight enough,
    which took 6,400 trials on this graph".

    Performance note: the adjacency structure is built once and edges are masked
    with a `live` predicate rather than rebuilding a subgraph per trial.
    """
    rng = random.Random(seed)
    a = adj if adj is not None else fp_adjacency(g)

    prob_edges, groups = [], {}
    for u, v, d in sorted(g.edges(data=True), key=lambda e: (str(e[0]), str(e[1]))):
        p = float(d.get("p", 1.0))
        if p < 1.0:
            grp = (g.nodes[u].get("patch_group", str(u))
                   if g.nodes[u].get("type") == "vuln" else str(u))
            prob_edges.append((u, v, p, grp))
            groups.setdefault(grp, None)
    group_list = sorted(groups)

    # An asset may have several terminal privileges (data_read, code_exec,
    # admin_session). Its compromise probability is P(the attacker obtains ANY
    # of them) -- the UNION, not one arbitrarily chosen marginal. Keying a dict
    # by asset from a set of states silently picked whichever the set iterated
    # last, which is hash-order dependent and therefore not reproducible across
    # processes. Grouped and sorted here so both the probability and the modal
    # path are deterministic.
    jewel_by_asset: dict[str, list] = defaultdict(list)
    for n, d in sorted(g.nodes(data=True), key=lambda x: str(x[0])):
        if d.get("jewel") and g.has_edge(n, SUPER_SINK):
            jewel_by_asset[d.get("asset", str(n))].append(n)
    jewel_by_asset = {a: sorted(v, key=str) for a, v in sorted(jewel_by_asset.items())}

    asset_hits: Counter = Counter()
    node_hits: Counter = Counter()
    edge_witness: Counter = Counter()
    edge_part: Counter = Counter()
    path_counts: dict[str, Counter] = defaultdict(Counter)
    n = 0
    stopped_early = False

    while n < trials:
        n += 1
        # ONE draw per patch group -> the same CVE succeeds or fails together.
        draws = {grp: rng.random() for grp in group_list} if correlated else None
        dead = set()
        for u, v, p, grp in prob_edges:
            u_ = draws[grp] if correlated else rng.random()
            if u_ >= p:
                dead.add((u, v))

        r = reachable(g, [SUPER_SOURCE] if SUPER_SOURCE in a["succ"] else [],
                      adj=a, live=(lambda x, y: (x, y) not in dead) if dead else None)
        reached = r.reached
        node_hits.update(reached)

        # participation: edge live AND its tail compromised
        for u, nbrs in a["succ"].items():
            if u not in reached:
                continue
            for v in nbrs:
                if (u, v) not in dead:
                    edge_part[(u, v)] += 1
        # witness: edge appears in this world's witness tree (discounts redundancy)
        for child, parent in r.witness.items():
            if parent is not None:
                edge_witness[(parent, child)] += 1

        for asset, states in jewel_by_asset.items():
            hit = [j for j in states if j in reached]
            if not hit:
                continue
            asset_hits[asset] += 1
            # canonical witness among the terminal privileges reached:
            # shortest first, then lexicographic. Deterministic by construction.
            paths = [tuple(r.path_to(j)) for j in hit if r.path_to(j)]
            if paths:
                path_counts[asset][min(paths, key=lambda pp: (len(pp), tuple(map(str, pp))))] += 1

        if target_ci and n >= min_trials and n % check_every == 0:
            widest = max((_half_width(asset_hits[a] / n, n) for a in jewel_by_asset),
                         default=0.0)
            if widest <= target_ci:
                stopped_early = True
                break

    node_prob = {k: node_hits[k] / n for k in g.nodes}
    node_ci = {k: _half_width(node_prob[k], n) for k in g.nodes}
    modal = {}
    for asset in sorted(path_counts):
        counter = path_counts[asset]
        # ties broken deterministically: highest count, then shortest, then lex
        best = max(counter, key=lambda pp: (counter[pp], -len(pp),
                                            tuple(-ord(c) for c in str(pp))))
        modal[asset] = {"path": [nid(x) for x in best], "count": counter[best],
                        "share": round(counter[best] / n, 4)}

    return MCResult(
        trials=n, seed=seed,
        node_prob=node_prob, node_ci=node_ci,
        edge_witness={k: v / n for k, v in edge_witness.items()},
        edge_participation={k: v / n for k, v in edge_part.items()},
        jewel_prob={a: asset_hits[a] / n for a in jewel_by_asset},
        jewel_ci={a: _half_width(asset_hits[a] / n, n) for a in jewel_by_asset},
        modal_paths=modal, correlated=correlated, stopped_early=stopped_early,
    )


def modal_path_for(res: MCResult, asset: str) -> dict | None:
    """The path we draw on the dashboard.

    It is NOT computed by a separate algorithm on averaged weights -- it is the
    single most frequently observed attack chain across the simulated worlds.
    The path and the heat map come from one engine, which is a strictly better
    claim than running Dijkstra alongside Monte Carlo and hoping they agree.
    """
    return res.modal_paths.get(asset)


def delta(before: MCResult, after: MCResult) -> dict:
    """Before/after for the retest loop. This is the demo climax, and it only
    exists because A5 produces a number that MOVES when you patch."""
    out = {}
    for asset, p0 in before.jewel_prob.items():
        p1 = after.jewel_prob.get(asset, 0.0)
        out[asset] = {
            "before": round(p0, 4), "after": round(p1, 4),
            "delta": round(p1 - p0, 4),
            "before_ci": round(before.jewel_ci.get(asset, _half_width(p0, before.trials)), 4),
            "after_ci": round(after.jewel_ci.get(asset, _half_width(p1, after.trials)), 4),
            "reduction_pct": round((1 - p1 / p0) * 100, 1) if p0 > 0 else 0.0,
        }
    return out
