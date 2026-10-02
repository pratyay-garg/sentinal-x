"""
Cytoscape.js export.

Two rules that matter for the frontend contract:

 1. NODE IDS MUST BE STABLE across re-renders. Otherwise the layout jumps on
    every poll and the dashboard looks broken. `nid()` is deterministic.
 2. EVERY EDGE CARRIES ITS evidence_id. Clicking an edge in the attack path
    opens the screenshot or request/response diff that proves it. An attack
    graph where every edge is backed by a reproducible artifact is a
    fundamentally different object from one where edges are asserted.

Overlays ride as node/edge data so the frontend can toggle views (heat map,
witness, min-cut, dominators, provenance) without asking the backend for a new
payload.
"""
from __future__ import annotations

import networkx as nx

from .model import nid


def to_cytoscape(g: nx.DiGraph, *, mc=None, cut=None, chokes=None,
                 modal_path=None) -> dict:
    cut_ids = set(cut.vulns) if cut else set()
    choke_map = {c.vuln_id: c for c in (chokes or [])}
    modal_edges = set()
    if modal_path:
        seq = modal_path.get("path", [])
        modal_edges = set(zip(seq, seq[1:]))

    nodes = []
    for n, d in g.nodes(data=True):
        i = nid(n)
        t = d.get("type", "state")
        entry = {
            "data": {
                "id": i,
                "type": t,
                "label": d.get("label") or _label(n, d),
                "asset": d.get("asset"),
                "hostname": d.get("hostname"),
                "privilege": d.get("privilege"),
                "zone": d.get("zone"),
                "jewel": bool(d.get("jewel")),
                "criticality": d.get("criticality"),
                "provenance": d.get("provenance", "assumed"),
                "status": d.get("status"),
                "mitre": d.get("mitre", []),
                "evidence_id": d.get("evidence_id"),
                "patch_hours": d.get("patch_hours"),
                "patch_group": d.get("patch_group"),
                "join": d.get("join"),
                "score_contributions": d.get("score_contributions", []),
            }
        }
        if mc is not None:
            p = mc.node_prob.get(n, 0.0)
            entry["data"]["compromise_prob"] = round(p, 4)
            entry["data"]["prob_ci"] = round(mc.node_ci.get(n, 0.0), 4)
        if t == "vuln":
            entry["data"]["in_min_cut"] = n[1] in cut_ids
            c = choke_map.get(n[1])
            entry["data"]["dominated_assets"] = len(c.dominated_assets) if c else 0
            entry["data"]["dominated_jewels"] = c.dominated_jewels if c else []
        nodes.append(entry)

    edges = []
    for u, v, d in g.edges(data=True):
        su, sv = nid(u), nid(v)
        e = {
            "data": {
                "id": f"{su}->{sv}",
                "source": su, "target": sv,
                "kind": d.get("kind", "pre"),
                "p": round(float(d.get("p", 1.0)), 4),
                "provenance": d.get("provenance", "assumed"),
                "evidence_id": d.get("evidence_id"),
                "contributions": d.get("contributions", []),
                "on_modal_path": (su, sv) in modal_edges,
            }
        }
        if mc is not None:
            # `witness` drives the heat map (discounts redundancy);
            # `participation` is the secondary "exposure" toggle.
            e["data"]["witness"] = round(mc.edge_witness.get((u, v), 0.0), 4)
            e["data"]["participation"] = round(mc.edge_participation.get((u, v), 0.0), 4)
        edges.append(e)

    return {"elements": {"nodes": nodes, "edges": edges},
            "legend": {
                "heat_metric": "witness frequency (marginal edge probability)",
                "not_flow": ("edge participation is NOT a conserved flow; the "
                             "correct word is pressure / marginal probability"),
            }}


def _label(n: tuple, d: dict) -> str:
    if n[0] == "state":
        return f"{n[1]}:{n[2]}"
    if n[0] == "fact":
        return f"fact:{n[1]}"
    if n[0] == "meta":
        return n[1]
    return str(n[-1])
