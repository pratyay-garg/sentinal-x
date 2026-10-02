"""
A2 / A3 -- break-the-chain. The minimum-cost set of patches that isolates the
crown jewels.

WHY NODE SPLITTING
    Max-flow cuts edges, but you patch nodes. Split every node v into
    v_in -> v_out. Give the internal edge capacity = patch_hours for vuln nodes
    and +inf for everything else; give every structural edge +inf. A minimum
    cut can never contain an infinite edge, so every edge it returns is a
    vulnerability's internal edge. The cut IS the patch list, by construction,
    with no interpretation step.

WHY WE DO NOT CONDENSE CYCLES FIRST
    Tarjan/SCC condensation is commonly proposed as a preprocessing step. It is
    unnecessary -- max-flow has no acyclicity requirement, dominators are
    defined on arbitrary flowgraphs, and non-negative -ln(p) weights mean
    Dijkstra never traverses a cycle. Worse, contracting an SCC deletes its
    internal edges from the cuttable set, so mincut(condensed) >= mincut(original):
    you would compute a feasible but possibly NON-minimal patch set while
    claiming minimality. We detect cycles for display (they are a real finding)
    and never condense.

AND SEMANTICS AND WHAT WE HONESTLY CLAIM
    Minimum cut is exact only on OR-graphs. On AND/OR graphs it is NP-hard.
    So:
      1. compute the cut on the OR-relaxation;
      2. every AND-path is also an OR-path, so the cut is GUARANTEED SUFFICIENT
         (sound) on the real graph;
      3. it may be larger than necessary, so we reduce it: put each element
         back one at a time and keep it only if the jewel becomes reachable
         again under full AND semantics.
    The result is sound and IRREDUCIBLE -- every element is necessary. It is
    not claimed to be the global minimum, and we say so. That distinction is
    the difference between a true claim and a false one.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx
from networkx.algorithms.flow import dinitz
from networkx.exception import NetworkXUnbounded

from .build import or_relaxation, remove_patched
from .fixpoint import sink_reachable
from .model import SUPER_SINK, SUPER_SOURCE, node_type

INF = float("inf")


@dataclass
class Cut:
    vulns: list[str] = field(default_factory=list)
    cost: float = 0.0
    method: str = "mincut"
    sound: bool = True
    irreducible: bool = False
    exact: bool = False
    tie_break: str = "source-minimal, then total patch hours, then node id"
    patch_groups: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "vulns": self.vulns, "cost": round(self.cost, 3), "method": self.method,
            "sound": self.sound, "irreducible": self.irreducible, "exact": self.exact,
            "tie_break": self.tie_break, "patch_groups": self.patch_groups,
            "notes": self.notes, "size": len(self.vulns),
        }


# ------------------------------------------------------------- node splitting

def node_split(g: nx.DiGraph, cost_key: str = "patch_hours") -> nx.DiGraph:
    """v -> (v,'in') -> (v,'out'). Only vuln internal edges are finite."""
    h = nx.DiGraph()
    for v, d in g.nodes(data=True):
        cap = float(d.get(cost_key, 1.0)) if d.get("type") == "vuln" else INF
        h.add_edge((v, "in"), (v, "out"), capacity=max(cap, 1e-6), internal=True,
                   origin=v)
    for u, v in g.edges():
        h.add_edge((u, "out"), (v, "in"), capacity=INF, internal=False)
    return h


def _residual_partitions(h: nx.DiGraph, s, t):
    """Return (source-minimal S, sink-minimal S).

    networkx hands back an arbitrary min cut determined by residual traversal
    order. There are usually many cuts of equal value, and 'the library picked
    it' is a bad answer to 'why these three vulnerabilities?'. The cut derived
    from forward residual reachability from s is the canonical SOURCE-MINIMAL
    cut (cut as early as possible); reverse reachability from t gives the
    sink-minimal one. We pick source-minimal and say so out loud.
    """
    R = dinitz(h, s, t)
    resid = nx.DiGraph()
    resid.add_nodes_from(R.nodes)
    for u, v, d in R.edges(data=True):
        if d["capacity"] - d["flow"] > 1e-9 or d["capacity"] == INF and d["flow"] < INF:
            resid.add_edge(u, v)
    s_side = nx.descendants(resid, s) | {s}
    t_can_reach = nx.ancestors(resid, t) | {t}
    sink_min_s_side = set(R.nodes) - t_can_reach
    return s_side, sink_min_s_side, R


def min_cut(g: nx.DiGraph, cost_key: str = "patch_hours",
            prefer: str = "source") -> Cut:
    """Minimum-cost vertex cut on the OR-relaxation. Dinic, O(E*sqrt(E)) on
    small integer capacities; sub-millisecond at hackathon scale."""
    ored = or_relaxation(g)
    if SUPER_SOURCE not in ored or SUPER_SINK not in ored:
        return Cut(method="mincut", notes=["no source/sink in graph"])
    if not sink_reachable(ored):
        return Cut(method="mincut", cost=0.0, sound=True, irreducible=True,
                   exact=True, notes=["crown jewels already isolated"])

    h = node_split(ored, cost_key)
    s, t = (SUPER_SOURCE, "out"), (SUPER_SINK, "in")
    try:
        s_side, sink_min_side, R = _residual_partitions(h, s, t)
    except NetworkXUnbounded:
        # An entirely infinite-capacity s-t path exists: every route to the
        # crown jewels goes through non-patchable States/Facts. That is a real
        # finding, not a crash.
        return Cut(method="mincut", cost=INF, sound=False,
                   notes=["every path to the crown jewels routes through "
                          "non-patchable elements; this requires an "
                          "architectural change, not a patch"])
    side = s_side if prefer == "source" else sink_min_side

    vulns, cost, groups = [], 0.0, set()
    for u, v, d in h.edges(data=True):
        if d.get("internal") and u in side and v not in side:
            origin = d["origin"]
            if node_type(origin) != "vuln":
                # Only reachable if a non-patchable node somehow got a finite
                # capacity; treat as an architectural blocker.
                continue
            vulns.append(origin[1])
            cost += float(ored.nodes[origin].get(cost_key, 1.0))
            groups.add(ored.nodes[origin].get("patch_group", origin[1]))

    if not vulns:
        return Cut(method="mincut", cost=INF, sound=False,
                   notes=["every path to the crown jewels routes through "
                          "non-patchable Facts; this requires an architectural "
                          "change, not a patch"])

    return Cut(vulns=sorted(vulns), cost=cost, method="mincut", sound=True,
               exact=True, patch_groups=sorted(groups))


# --------------------------------------------------------------- AND reduction

def reduce_cut(g: nx.DiGraph, cut: Cut, cost_key: str = "patch_hours") -> Cut:
    """Make a sound cut irreducible under full AND semantics.

    Cost: |cut| * O(V + E). Milliseconds. What it buys is the ability to say
    'provably sufficient and provably irredundant' and have it be true.
    """
    if not cut.vulns:
        return cut
    keep = list(cut.vulns)
    # Drop the most expensive first: a greedy pass in that order tends to leave
    # the cheapest irreducible set. Deterministic tie-break on id.
    order = sorted(keep, key=lambda v: (-_hours(g, v, cost_key), v))
    for candidate in order:
        trial = [v for v in keep if v != candidate]
        if not sink_reachable(remove_patched(g, set(trial))):
            keep = trial                       # still disconnects -> redundant
    removed = sorted(set(cut.vulns) - set(keep))
    return Cut(
        vulns=sorted(keep),
        cost=sum(_hours(g, v, cost_key) for v in keep),
        method=cut.method + "+reduced",
        sound=True,
        irreducible=True,
        exact=cut.exact and not removed,
        patch_groups=sorted({_group(g, v) for v in keep}),
        notes=(cut.notes + ([f"removed {len(removed)} redundant element(s) "
                             f"under AND semantics: {removed}"] if removed else [])),
    )


def _hours(g, vid: str, key="patch_hours") -> float:
    n = ("vuln", vid)
    return float(g.nodes[n].get(key, 1.0)) if n in g else 1.0


def _group(g, vid: str) -> str:
    n = ("vuln", vid)
    return g.nodes[n].get("patch_group", vid) if n in g else vid


# ------------------------------------------------------------------ A3: ILP

def label_cut(g: nx.DiGraph, cost_key: str = "patch_hours",
              group_cost: str = "max") -> Cut:
    """Exact minimum-cost cut when one remediation action removes several
    vulnerabilities (same CVE on 12 hosts, one base-image upgrade, one WAF rule).

    Max-flow assumes edges are cut INDEPENDENTLY. Once actions group, the
    problem is minimum LABEL cut, which is NP-hard -- so calling the min-cut
    answer 'minimum' would be false. The compact formulation below is exact and
    polynomial in SIZE (one constraint per edge, no path enumeration):

        min  sum_l cost_l * x_l
        s.t. d_s = 0, d_t = 1
             d_v - d_u <= x_{label(u,v)}      for every edge (u,v)
             d, x binary

    Read the constraint: if the edge crosses from the source side (d_u=0) to
    the sink side (d_v=1) then the left side is 1, forcing x_l = 1 and charging
    for that patch. If it does not cross, the constraint is slack.

    When every label is unique this returns exactly the min-cut answer, so it is
    a strict generalisation. Falls back to Dinic if PuLP/CBC is unavailable --
    never crash a demo on a solver.
    """
    try:
        import pulp
        from ._pulp_compat import make_binary, pick_solver
    except ImportError:
        c = min_cut(g, cost_key)
        c.notes.append("PuLP unavailable; fell back to Dinic min-cut")
        c.method = "mincut(fallback)"
        return c

    ored = or_relaxation(g)
    if not sink_reachable(ored):
        return Cut(cost=0.0, method="ilp", sound=True, irreducible=True,
                   exact=True, notes=["crown jewels already isolated"])

    h = node_split(ored, cost_key)
    s, t = (SUPER_SOURCE, "out"), (SUPER_SINK, "in")

    # label -> cost. One action, charged once.
    labels: dict[str, float] = {}
    edge_label: dict[tuple, str] = {}
    for u, v, d in h.edges(data=True):
        if not d.get("internal"):
            continue
        origin = d["origin"]
        if node_type(origin) != "vuln":
            continue
        lab = ored.nodes[origin].get("patch_group", origin[1])
        hrs = float(ored.nodes[origin].get(cost_key, 1.0))
        if lab in labels:
            labels[lab] = max(labels[lab], hrs) if group_cost == "max" else labels[lab] + hrs
        else:
            labels[lab] = hrs
        edge_label[(u, v)] = lab

    prob = pulp.LpProblem("label_cut", pulp.LpMinimize)
    # Deterministic sequential names. abs(hash(node)) would be hash-randomised
    # per process AND could collide between two distinct nodes, silently merging
    # two variables into one and yielding a wrong cut with no error.
    d_ = {n: make_binary(prob, f"d{i}")
          for i, n in enumerate(sorted(h.nodes, key=str))}
    x_ = {label: make_binary(prob, f"x{i}")
          for i, label in enumerate(sorted(labels))}
    prob += pulp.lpSum(labels[label] * x_[label] for label in labels)
    prob += d_[s] == 0
    prob += d_[t] == 1
    for u, v in h.edges():
        lab = edge_label.get((u, v))
        if lab is None:
            prob += d_[v] - d_[u] <= 0          # uncuttable: cannot cross
        else:
            prob += d_[v] - d_[u] <= x_[lab]

    try:
        status = prob.solve(pick_solver(pulp))
    except Exception:
        c = min_cut(g, cost_key)
        c.notes.append("solver error; fell back to Dinic min-cut")
        return c
    if pulp.LpStatus[status] != "Optimal":
        # Infeasible == no cut exists at any price: uncuttable by construction.
        if pulp.LpStatus[status] == "Infeasible":
            return Cut(method="ilp-label-cut", cost=INF, sound=False,
                       notes=["no cut exists: every path routes through "
                              "non-patchable elements"])
        c = min_cut(g, cost_key)
        c.notes.append("ILP not optimal; fell back to Dinic min-cut")
        return c

    chosen = {label for label in labels
              if x_[label].value() and x_[label].value() > 0.5}
    vulns = sorted(n[1] for n, dd in ored.nodes(data=True)
                   if dd.get("type") == "vuln"
                   and dd.get("patch_group", n[1]) in chosen)
    return Cut(vulns=vulns, cost=float(pulp.value(prob.objective) or 0.0),
               method="ilp-label-cut", sound=True, exact=True,
               patch_groups=sorted(chosen),
               notes=[f"{len(chosen)} patch action(s) remove {len(vulns)} finding(s)"])


# ------------------------------------------------------------------ cycles

def cycle_clusters(g: nx.DiGraph) -> list[list]:
    """Detect mutual-compromise clusters. FOR DISPLAY ONLY -- we never condense
    them, for the reason given in the module docstring. 'These 4 hosts form a
    mutual-compromise cluster' is a genuine finding worth a panel."""
    out = []
    for comp in nx.strongly_connected_components(g):
        if len(comp) > 1:
            assets = sorted({g.nodes[n].get("asset") for n in comp
                             if g.nodes[n].get("asset")})
            if len(assets) > 1:
                out.append(assets)
    return sorted(out, key=str)


def solve(g: nx.DiGraph, cost_key: str = "patch_hours") -> Cut:
    """The production entry point: ILP when patches group, Dinic otherwise,
    always reduced to irreducible under AND semantics."""
    groups = {g.nodes[n].get("patch_group", n[1])
              for n, d in g.nodes(data=True) if d.get("type") == "vuln"}
    n_vulns = sum(1 for _, d in g.nodes(data=True) if d.get("type") == "vuln")
    cut = label_cut(g, cost_key) if len(groups) < n_vulns else min_cut(g, cost_key)
    return reduce_cut(g, cut, cost_key)
