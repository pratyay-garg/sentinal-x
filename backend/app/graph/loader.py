"""
Input adapters. The graph engine is developed and tested entirely against the
JSON fixture, so it is complete and demoable on Day 4 with zero dependency on
Discovery, Validation, or the authorised target being live. Swapping the
fixture loader for the Postgres loader is one file.
"""
from __future__ import annotations

import json
from pathlib import Path

from .contract import normalise_finding_row
from .model import Asset, Fact, Finding, GraphInput, Provenance, Route

FIXTURE_DIR = Path(__file__).parent / "fixtures"


_ASSET_KEYS = {"id", "zone", "is_crown_jewel", "criticality", "hostnames", "ips"}
_FINDING_KEYS = {"id", "asset_id", "vuln_class", "status", "confidence",
                 "cvss_vector", "epss", "epss_snapshot_date", "patch_hours",
                 "patch_group", "evidence_id", "endpoint", "param",
                 "observed_grants", "observed_requires", "target_asset_id"}
_FINDING_KEYS.add("generated_by")
_FACT_KEYS = {"kind", "ref", "description", "provenance"}
_ROUTE_KEYS = {"src", "dst", "provenance", "reason"}


def _unknown(rows, known: set) -> list[str]:
    seen: set[str] = set()
    for r in rows or ():
        if isinstance(r, dict):
            seen |= set(r) - known
    return sorted(k for k in seen if not k.startswith("_"))


def from_dict(d: dict) -> GraphInput:
    gi = GraphInput(
        assets=[Asset(
            id=a["id"], zone=a.get("zone", "default"),
            is_crown_jewel=bool(a.get("is_crown_jewel")),
            criticality=int(a.get("criticality", 1)),
            hostnames=tuple(a.get("hostnames", [])),
            ips=tuple(a.get("ips", [])),
        ) for a in d.get("assets", [])],
        findings=[Finding(
            id=f["id"], asset_id=f["asset_id"], vuln_class=f["vuln_class"],
            status=f.get("status", "unvalidated"),
            confidence=float(f.get("confidence", 0.25)),
            cvss_vector=f.get("cvss_vector"),
            epss=f.get("epss"), epss_snapshot_date=f.get("epss_snapshot_date"),
            patch_hours=float(f.get("patch_hours", 1.0)),
            patch_group=f.get("patch_group"),
            evidence_id=f.get("evidence_id"), endpoint=f.get("endpoint"),
            param=f.get("param"),
            observed_grants=tuple(f.get("observed_grants", [])),
            observed_requires=tuple(f.get("observed_requires", [])),
            target_asset_id=f.get("target_asset_id"),
        ) for f in d.get("findings", [])],
        facts=[Fact(
            kind=x["kind"], ref=x["ref"], description=x.get("description", ""),
            provenance=Provenance(x.get("provenance", "assumed")),
        ) for x in d.get("facts", [])],
        routes=[Route(
            src=r["src"], dst=r["dst"],
            provenance=Provenance(r.get("provenance", "assumed")),
            reason=r.get("reason", ""),
        ) for r in d.get("routes", [])],
        entries=list(d.get("entries", [])),
    )
    gi.unknown_keys = {k: v for k, v in {
        "assets": _unknown(d.get("assets"), _ASSET_KEYS),
        "findings": _unknown(d.get("findings"), _FINDING_KEYS),
        "facts": _unknown(d.get("facts"), _FACT_KEYS),
        "routes": _unknown(d.get("routes"), _ROUTE_KEYS),
    }.items() if v}
    return gi


def load_fixture(name: str = "attack_graph_30.json") -> GraphInput:
    return from_dict(json.loads((FIXTURE_DIR / name).read_text()))


def from_rows(assets, findings, facts=(), routes=(), entries=()) -> GraphInput:
    """Postgres adapter. Accepts SQLAlchemy rows or plain dicts.

    The ONLY contract with Discovery/Validation is these column names. In
    particular `asset_id` must be STABLE across re-scans (that is what
    Discovery's Union-Find identity resolution is for) -- if it changes per
    scan, the retest comparison is meaningless.
    """
    def g(row, key, default=None):
        return row.get(key, default) if isinstance(row, dict) else getattr(row, key, default)

    finding_rows = [{
        "id": g(f, "finding_id") or g(f, "id"), "asset_id": g(f, "asset_id"),
        "vuln_class": g(f, "vuln_class"), "status": g(f, "status", "unvalidated"),
        "confidence": g(f, "confidence"),
        "cvss_vector": g(f, "cvss_vector"), "epss": g(f, "epss"),
        "epss_snapshot_date": g(f, "epss_snapshot_date"),
        "patch_hours": g(f, "patch_hours"),
        "patch_group": g(f, "patch_group"),
        "evidence_id": g(f, "evidence_id"), "endpoint": g(f, "endpoint"),
        "param": g(f, "param"),
        "observed_grants": list(g(f, "observed_grants", []) or []),
        "observed_requires": list(g(f, "observed_requires", []) or []),
        "target_asset_id": g(f, "target_asset_id"),
    } for f in findings if g(f, "vuln_class")]

    return from_dict({
        "assets": [{
            "id": g(a, "asset_id") or g(a, "id"), "zone": g(a, "zone", "default"),
            "is_crown_jewel": g(a, "is_crown_jewel", False),
            "criticality": g(a, "criticality", 1),
            "hostnames": list(g(a, "hostnames", []) or []),
            "ips": list(g(a, "ips", []) or []),
        } for a in assets],
        "findings": [normalise_finding_row(row) for row in finding_rows],
        "facts": [{"kind": g(x, "kind"), "ref": g(x, "ref"),
                   "description": g(x, "description", ""),
                   "provenance": g(x, "provenance", "assumed")} for x in facts],
        "routes": [{"src": g(r, "src"), "dst": g(r, "dst"),
                    "provenance": g(r, "provenance", "assumed"),
                    "reason": g(r, "reason", "")} for r in routes],
        "entries": list(entries),
    })
