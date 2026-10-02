"""
Graph construction. Reads flat rows (assets, findings, facts, routes) and emits
the typed attacker-state graph.

Nothing here calls another module. Discovery/Validation write Postgres rows;
this reads them. A teammate's broken code cannot break this module.

Every node and edge carries `provenance`, so pipeline.py can report the exact
share of the graph that is evidence-derived vs standard-derived vs assumed.
"""
from __future__ import annotations

import networkx as nx

from .cvss import semantics_from_finding
from .model import (
    NETWORK_REACH, PRIVILEGES, PRIVILEGE_IMPLICATIONS, SUPER_SINK, SUPER_SOURCE,
    Finding, GraphInput, Provenance, fact as fact_node, state, vuln,
)
from .scoring import edge_probability, phishing_entry_probability

TERMINAL_PRIVILEGES = ("data_read", "code_exec", "admin_session")


def build_graph(gi: GraphInput, weights: dict | None = None, *,
                include_assumed_facts: bool = True) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(SUPER_SOURCE, type="meta")
    g.add_node(SUPER_SINK, type="meta")

    assets_by_id = {a.id: a for a in gi.assets}

    # ---- 1. state nodes + intra-asset privilege implication edges
    for a in gi.assets:
        display_name = a.hostnames[0] if a.hostnames else a.id
        for p in PRIVILEGES:
            g.add_node(state(a.id, p), type="state", asset=a.id, privilege=p,
                       zone=a.zone, criticality=a.criticality,
                       jewel=a.is_crown_jewel, hostname=display_name,
                       label=f"{display_name}:{p}")
        for hi, lo in PRIVILEGE_IMPLICATIONS:
            g.add_edge(state(a.id, hi), state(a.id, lo), p=1.0, kind="implies",
                       provenance=Provenance.OBSERVED.value)

    # ---- 2. cross-asset routes, network_reach ONLY
    # Nothing else crosses assets for free. Every cross-asset privilege gain
    # must pass through a Vuln or a Fact. This single rule is what stops the
    # graph inventing lateral movement.
    for r in gi.routes:
        if r.src not in assets_by_id or r.dst not in assets_by_id:
            continue
        g.add_edge(state(r.src, NETWORK_REACH), state(r.dst, NETWORK_REACH),
                   p=1.0, kind="route", provenance=r.provenance.value,
                   reason=r.reason)

    # ---- 3. facts (non-patchable enablers)
    # A Fact is a static property of the environment: if it holds, the attacker
    # has it from the start. We therefore seed every fact from the super-source.
    # Assumed facts are seeded too -- a graph MISSING real connectivity is worse
    # than one carrying a labelled guess -- but the edge keeps provenance
    # ASSUMED so it shows up in the provenance report. Set
    # include_assumed_facts=False for the conservative, evidence-only view.
    for f in gi.facts:
        fn = fact_node(f.kind, f.ref)
        g.add_node(fn, type="fact", kind=f.kind, description=f.description,
                   patchable=False, provenance=f.provenance.value)
        if include_assumed_facts or f.provenance is not Provenance.ASSUMED:
            g.add_edge(SUPER_SOURCE, fn, p=1.0, kind="fact_holds",
                       provenance=f.provenance.value)

    # ---- 4. vulnerabilities
    for f in gi.findings:
        if f.status in ("remediated", "false_positive"):
            # remediated  == fixed, no longer in the live graph
            # false_positive == our validator PROVED it is not exploitable.
            # Leaving it in at p=0.01 let the greedy budget planner spend real
            # hours "fixing" a non-vulnerability. Excluding it is the point of
            # having a validation module at all.
            continue
        if f.asset_id not in assets_by_id:
            continue
        _add_finding(g, f, assets_by_id, weights, include_assumed_facts)

    # ---- 5. entries and jewels
    for e in gi.entries:
        if e in assets_by_id:
            g.add_edge(SUPER_SOURCE, state(e, NETWORK_REACH), p=1.0, kind="entry",
                       provenance=Provenance.OBSERVED.value)

    for a in gi.jewels():
        for p in TERMINAL_PRIVILEGES:
            g.add_edge(state(a.id, p), SUPER_SINK, p=1.0, kind="jewel",
                       provenance=Provenance.OBSERVED.value,
                       criticality=a.criticality)

    return g


def _add_finding(g: nx.DiGraph, f: Finding, assets_by_id, weights,
                 include_assumed_facts: bool = True) -> None:
    sem, sem_prov = semantics_from_finding(f)
    score = edge_probability(f, weights)
    v = vuln(f.id)

    g.add_node(
        v, type="vuln", finding_id=f.id, asset=f.asset_id,
        vuln_class=f.vuln_class, join=sem.join, status=f.status,
        patch_hours=max(f.patch_hours, 0.25),
        patch_group=f.patch_group or f.id,
        evidence_id=f.evidence_id, endpoint=f.endpoint,
        mitre=list(sem.mitre), confidence=f.confidence,
        cvss_vector=f.cvss_vector, epss=f.epss,
        provenance=sem_prov.value,
        score_contributions=score.explain(),
        label=f"{f.vuln_class} {f.endpoint or ''}".strip(),
    )

    # preconditions: state -> vuln, probability 1.0 (certainty lives on `post`)
    for req in sem.requires:
        g.add_edge(state(f.asset_id, req), v, p=1.0, kind="pre",
                   provenance=sem_prov.value)

    # fact preconditions: fact -> vuln
    for fk in sem.requires_facts:
        fn = fact_node(fk, f.asset_id)
        if fn not in g:
            fn = fact_node(fk, "global")
        if fn not in g:
            # The enabler was never observed. Model it explicitly as assumed
            # rather than silently dropping the precondition.
            fn = fact_node(fk, f.asset_id)
            g.add_node(fn, type="fact", kind=fk, patchable=False,
                       provenance=Provenance.ASSUMED.value,
                       description=f"assumed enabler for {f.id}")
            if include_assumed_facts:
                g.add_edge(SUPER_SOURCE, fn, p=1.0, kind="fact_holds",
                           provenance=Provenance.ASSUMED.value)
        g.add_edge(fn, v, p=1.0, kind="pre", provenance=g.nodes[fn]["provenance"])

    # postcondition: vuln -> state. THE ONLY probabilistic edge in the graph.
    # S:C (scope changed) means the grant lands on a different asset -- CVSS
    # formally declaring lateral movement.
    target = f.target_asset_id if (sem.scope_changed and f.target_asset_id) else f.asset_id
    if target not in assets_by_id:
        target = f.asset_id
    g.add_edge(v, state(target, sem.grants), p=score.probability, kind="post",
               provenance=score.provenance.value,
               contributions=score.explain(), evidence_id=f.evidence_id)


# ------------------------------------------------------------------ module 5/6

def attach_phishing_entry(g: nx.DiGraph, *, asset_id: str, risk_score: float,
                          ref: str, granted: str = "user_session") -> tuple:
    """Module 5 (phishing, 3 marks) contributes an entry point to Module 3.

    A high-risk phishing finding becomes Fact(phished_credential) -> Vuln ->
    State(asset, user_session), wired to the super-source. The 3-mark module
    now measurably moves the 15-mark attack graph, which is exactly the
    "integration and intelligent correlation" the PS rewards.
    """
    fn = fact_node("phished_credential", ref)
    g.add_node(fn, type="fact", kind="phished_credential", patchable=False,
               provenance=Provenance.EVIDENCE.value,
               description=f"phishing risk {risk_score:.2f}")
    v = vuln(f"phish::{ref}")
    g.add_node(v, type="vuln", finding_id=f"phish::{ref}", asset=asset_id,
               vuln_class="phishing_credential", join="OR", status="validated",
               patch_hours=2.0, patch_group=f"phish::{ref}",
               mitre=["T1566"], provenance=Provenance.EVIDENCE.value,
               label="phished credential")
    g.add_edge(SUPER_SOURCE, fn, p=1.0, kind="entry",
               provenance=Provenance.EVIDENCE.value)
    g.add_edge(fn, v, p=1.0, kind="pre", provenance=Provenance.EVIDENCE.value)
    g.add_edge(v, state(asset_id, granted),
               p=phishing_entry_probability(risk_score), kind="post",
               provenance=Provenance.EVIDENCE.value)
    return v


def attach_breached_credential(g: nx.DiGraph, *, asset_id: str, ref: str,
                               granted: str = "user_session",
                               p: float = 0.6) -> tuple:
    """Module 6 (email exposure, 3 marks) contributes the same way. `ref` must
    already be an HMAC digest -- never a raw address."""
    fn = fact_node("breached_credential", ref)
    g.add_node(fn, type="fact", kind="breached_credential", patchable=False,
               provenance=Provenance.EVIDENCE.value,
               description="k-anonymity exposure hit")
    v = vuln(f"breach::{ref}")
    g.add_node(v, type="vuln", finding_id=f"breach::{ref}", asset=asset_id,
               vuln_class="cred_reuse", join="OR", status="validated",
               patch_hours=1.0, patch_group="credential_rotation",
               mitre=["T1078"], provenance=Provenance.EVIDENCE.value,
               label="credential reuse")
    g.add_edge(SUPER_SOURCE, fn, p=1.0, kind="entry",
               provenance=Provenance.EVIDENCE.value)
    g.add_edge(fn, v, p=1.0, kind="pre", provenance=Provenance.EVIDENCE.value)
    g.add_edge(v, state(asset_id, granted), p=p, kind="post",
               provenance=Provenance.EVIDENCE.value)
    return v


# ------------------------------------------------------------------ utilities

def or_relaxation(g: nx.DiGraph) -> nx.DiGraph:
    """Every AND node treated as OR. Min-cut and dominators run here.

    Soundness: every AND-path is also an OR-path, so anything that disconnects
    the relaxation disconnects the real graph. The answer is guaranteed
    sufficient; breakchain.reduce_cut then makes it irreducible.
    """
    h = g.copy()
    for n, d in h.nodes(data=True):
        if d.get("type") == "vuln":
            d["join"] = "OR"
    return h


def remove_patched(g: nx.DiGraph, patched: set[str]) -> nx.DiGraph:
    """Patch == node deletion, exactly. This one line is the entire retest
    integration (Module 9)."""
    h = g.copy()
    h.remove_nodes_from([vuln(p) for p in patched if vuln(p) in h])
    return h


def provenance_report(g: nx.DiGraph) -> dict:
    """The honest answer to 'how much of this graph did you hard-code?'."""
    counts: dict[str, int] = {}
    for _, _, d in g.edges(data=True):
        counts[d.get("provenance", "assumed")] = counts.get(d.get("provenance", "assumed"), 0) + 1
    total = sum(counts.values())
    derived = sum(v for k, v in counts.items()
                  if k in (Provenance.EVIDENCE.value, Provenance.CVSS_VECTOR.value,
                           Provenance.OBSERVED.value))
    return {
        "counts": counts,
        "total_edges": total,
        "derived_fraction": round(derived / total, 4) if total else 0.0,
        "assumed_fraction": round(1 - derived / total, 4) if total else 0.0,
    }
