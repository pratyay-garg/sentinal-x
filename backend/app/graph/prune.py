"""
A1 -- bidirectional pruning. Two BFS passes, O(V + E).

Keep only nodes that are both reachable from the entry set and co-reachable to
a crown jewel. Everything else is noise. This typically removes 60-90% of the
graph, speeds up every later stage, and -- more importantly for a five-minute
demo -- makes the Cytoscape render legible.

Pruning must not change any answer: test_invariants asserts that jewel
reachability on the pruned graph equals jewel reachability on the full graph.
"""
from __future__ import annotations

import networkx as nx

from .fixpoint import reachable
from .model import SUPER_SINK, SUPER_SOURCE


def prune(g: nx.DiGraph) -> nx.DiGraph:
    if SUPER_SOURCE not in g or SUPER_SINK not in g:
        return g.copy()

    # AND-AWARE forward set. Using plain nx.descendants here is a latent bug:
    # it keeps AND nodes whose preconditions are unreachable, and once the
    # unreachable precondition is pruned away the AND node degrades into an OR
    # node and invents an attack path. The fixpoint already answers this
    # correctly, so we use it.
    fwd = reachable(g).reached | {SUPER_SOURCE}
    rev = nx.ancestors(g, SUPER_SINK) | {SUPER_SINK}
    keep = fwd & rev
    keep = _close_over_and_preconditions(g, keep, fwd)

    h = g.subgraph(keep).copy()
    h.graph["pruned_from"] = g.number_of_nodes()
    h.graph["pruned_to"] = h.number_of_nodes()
    return h


def _close_over_and_preconditions(g: nx.DiGraph, keep: set, fwd: set) -> set:
    """An AND node needs EVERY precondition present to be evaluated correctly.

    A precondition may itself lead nowhere useful (state(db,user_session) has no
    path to the sink), so the naive fwd & rev intersection drops it -- and an
    AND node that has lost a precondition silently degrades into an OR node,
    inventing an attack path that does not exist. That is the exact bug this
    closure prevents, and test_prune_preserves_and_preconditions pins it.

    We therefore re-admit every predecessor of a kept AND node, plus that
    predecessor's own forward-reachable ancestry, to a fixpoint.
    """
    def is_and(n):
        d = g.nodes[n]
        return d.get("type") == "vuln" and d.get("join") == "AND"

    frontier = [n for n in keep if is_and(n)]
    seen: set = set()
    while frontier:
        n = frontier.pop()
        if n in seen:
            continue
        seen.add(n)
        for pred in g.predecessors(n):
            if pred in fwd and pred not in keep:
                anc = (nx.ancestors(g, pred) & fwd) | {pred}
                added = anc - keep
                keep |= anc
                frontier.extend(x for x in added if is_and(x))
    return keep


def prune_stats(g: nx.DiGraph, h: nx.DiGraph) -> dict:
    before, after = g.number_of_nodes(), h.number_of_nodes()
    return {
        "nodes_before": before,
        "nodes_after": after,
        "removed": before - after,
        "reduction": round(1 - after / before, 4) if before else 0.0,
    }
