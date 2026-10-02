"""
A0 -- reachability by least fixpoint, honouring AND semantics.

A plain BFS treats every incoming edge as sufficient (OR). Some exploits need
two things at once -- an IDOR needs both a session AND sequential object ids.
Treating that as OR silently invents attack paths that do not exist, and it is
the most common correctness bug in student attack graphs.

The iteration is monotone (the reached set only grows), so it terminates at the
UNIQUE least fixpoint regardless of processing order. We additionally process
successors in sorted order so the witness trees are byte-identical across runs
-- that determinism is what makes "re-run it and get the same numbers" true.

WHY THERE IS NO SEPARATE AND-RETRY SWEEP
An AND node fires when its LAST precondition is reached. Every precondition is a
direct predecessor, and every reached node is eventually popped from the
worklist; when the last one is popped, its successor scan finds the AND node
with all predecessors satisfied and fires it. A periodic re-sweep over the whole
reached set is therefore redundant -- and it is O(V*E) per fixpoint, which made
10k Monte Carlo trials take minutes instead of seconds.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import networkx as nx

from .model import SUPER_SINK, SUPER_SOURCE


@dataclass
class Reach:
    reached: set = field(default_factory=set)
    witness: dict = field(default_factory=dict)   # node -> parent node
    support: dict = field(default_factory=dict)   # AND vuln -> all preconditions
    fired: set = field(default_factory=set)       # vuln nodes that fired

    def path_to(self, target) -> list | None:
        """Canonical witness path target <- ... <- SUPER_SOURCE.

        For AND nodes this returns the primary spine; `support` carries the
        additional preconditions so the UI can render the full justification.
        """
        if target not in self.reached:
            return None
        out, seen, cur = [], set(), target
        while cur is not None and cur not in seen:
            out.append(cur)
            seen.add(cur)
            cur = self.witness.get(cur)
        return list(reversed(out))


def adjacency(g: nx.DiGraph) -> dict:
    """Precomputed, deterministically ordered structure the fixpoint runs on.

    Building this ONCE and reusing it across Monte Carlo trials is what keeps
    10,000 trials in the low seconds instead of the low minutes.
    """
    return {
        "succ": {n: sorted(g.successors(n), key=str) for n in g.nodes},
        "preds": {n: sorted(g.predecessors(n), key=str) for n in g.nodes},
        "kind": {n: d.get("type", "state") for n, d in g.nodes(data=True)},
        "join": {n: d.get("join", "OR") for n, d in g.nodes(data=True)},
    }


def reachable(g: nx.DiGraph, sources=None, *, respect_and: bool = True,
              adj: dict | None = None, live=None) -> Reach:
    """Least-fixpoint reachability. O(V + E) amortised.

    `live` is an optional predicate (u, v) -> bool used by the Monte Carlo
    sampler to mask edges without rebuilding the graph each trial.
    """
    a = adj if adj is not None else adjacency(g)
    succ, preds, kind, join = a["succ"], a["preds"], a["kind"], a["join"]

    if sources is None:
        sources = [SUPER_SOURCE] if SUPER_SOURCE in succ else []

    r = Reach()
    work: deque = deque()
    for s in sorted(sources, key=str):
        if s in succ and s not in r.reached:
            r.reached.add(s)
            r.witness[s] = None
            work.append(s)

    reached = r.reached
    while work:
        cur = work.popleft()
        for nxt in succ.get(cur, ()):
            if nxt in reached:
                continue
            if live is not None and not live(cur, nxt):
                continue
            if kind.get(nxt) == "vuln":
                p = preds.get(nxt, ())
                if respect_and and join.get(nxt) == "AND":
                    if not all(x in reached for x in p):
                        continue      # retried when the missing precondition arrives
                    r.support[nxt] = list(p)
                elif p and not any(x in reached for x in p):
                    continue
                r.fired.add(nxt)
            reached.add(nxt)
            r.witness[nxt] = cur
            work.append(nxt)
    return r


def jewels_reached(g: nx.DiGraph, r: Reach) -> set:
    """Crown-jewel states that the attacker can actually obtain."""
    return {n for n in r.reached
            if g.nodes.get(n, {}).get("jewel") and g.has_edge(n, SUPER_SINK)}


def sink_reachable(g: nx.DiGraph, sources=None) -> bool:
    return SUPER_SINK in reachable(g, sources).reached


def nearest_miss(g: nx.DiGraph, r: Reach) -> list[dict]:
    """When no jewel is reachable, do not render an empty screen.

    Report the single hypothetical edge that would connect the frontier --
    'one credential reuse away from compromise' is a finding, not a failure.
    """
    misses = []
    for n in g.nodes:
        if n in r.reached or g.nodes[n].get("type") != "vuln":
            continue
        preds = sorted(g.predecessors(n), key=str)
        missing = [p for p in preds if p not in r.reached]
        if len(missing) == 1:
            misses.append({
                "vuln": n,
                "missing_precondition": missing[0],
                "label": g.nodes[n].get("label", ""),
                "would_grant": next(iter(g.successors(n)), None),
            })
    return sorted(misses, key=lambda m: str(m["vuln"]))
