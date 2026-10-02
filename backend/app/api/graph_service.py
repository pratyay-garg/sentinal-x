"""Database boundary and durable cache for the deterministic attack graph.

The algorithms never import Discovery or Validation. This module is the single
adapter that reads their persisted rows, invokes ``app.graph``, and writes an
immutable analysis snapshot for audit and frontend consumption.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import asdict
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.graph import contract
from app.graph.loader import from_rows
from app.graph.model import GraphInput
from app.graph.pipeline import GraphResult, recompute, run

from app.models import (
    Asset,
    AssetAlias,
    Finding,
    FindingObservation,
    GraphFact,
    GraphRoute,
    GraphSnapshot,
)


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"cannot serialize {type(value).__name__}")


@lru_cache(maxsize=1)
def engine_fingerprint() -> str:
    """Hash executable graph sources so code changes invalidate old cache keys."""
    graph_dir = Path(contract.__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(graph_dir.glob("*.py")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


async def load_graph_input(
    session: AsyncSession, scan_run_id: str | None = None
) -> tuple[GraphInput, dict]:
    # The scan is the unit of analysis: a graph for one target must never mix in
    # another target's findings. When scan_run_id is given we restrict the graph
    # to exactly the findings observed in that run and the assets/routes/facts
    # those findings reach; global mode (None) keeps the historical union.
    assets = list((await session.scalars(select(Asset).order_by(Asset.id))).all())
    aliases = list((await session.scalars(
        select(AssetAlias).order_by(AssetAlias.asset_id, AssetAlias.alias_value)
    )).all())
    finding_where = [
        Finding.mapping_status == "mapped", Finding.vuln_class.is_not(None)
    ]
    if scan_run_id is not None:
        finding_where.append(
            Finding.id.in_(
                select(FindingObservation.finding_id).where(
                    FindingObservation.scan_run_id == scan_run_id
                )
            )
        )
    findings = list((await session.scalars(
        select(Finding).where(*finding_where).order_by(Finding.id)
    )).all())
    route_rows = list((await session.scalars(
        select(GraphRoute).order_by(GraphRoute.src_asset_id, GraphRoute.dst_asset_id)
    )).all())
    facts = list((await session.scalars(
        select(GraphFact).order_by(GraphFact.kind, GraphFact.ref)
    )).all())

    if scan_run_id is not None:
        in_scope_assets = {f.asset_id for f in findings}
        in_scope_assets |= {f.target_asset_id for f in findings if f.target_asset_id}
        scoped_finding_ids = {f.id for f in findings}
        # Identify entities we are deliberately excluding so we can drop only the
        # routes/facts that explicitly reference them, while keeping global facts.
        all_finding_ids = set((await session.scalars(select(Finding.id))).all())
        out_of_scope = (
            ({a.id for a in assets} - in_scope_assets)
            | (all_finding_ids - scoped_finding_ids)
        )
        assets = [a for a in assets if a.id in in_scope_assets]
        aliases = [a for a in aliases if a.asset_id in in_scope_assets]
        route_rows = [
            r for r in route_rows
            if r.src_asset_id in in_scope_assets and r.dst_asset_id in in_scope_assets
        ]
        facts = [f for f in facts if f.ref not in out_of_scope]

    rows = [{
        "id": f.id,
        "asset_id": f.asset_id,
        "vuln_class": f.vuln_class,
        "status": f.status,
        "confidence": f.confidence,
        "cvss_vector": f.cvss_vector,
        "epss": f.epss,
        "epss_snapshot_date": f.epss_snapshot_date,
        "patch_hours": f.patch_hours,
        "patch_group": f.patch_group,
        "evidence_id": f.evidence_id,
        "endpoint": f.endpoint,
        "param": f.param,
        "observed_grants": f.observed_grants or [],
        "observed_requires": f.observed_requires or [],
        "target_asset_id": f.target_asset_id,
        "generated_by": f.generated_by,
    } for f in findings]
    validation = contract.validate_batch(rows)
    if not validation["ok"]:
        raise ValueError(
            "persisted findings violate the graph contract: "
            + json.dumps(validation["problems"], sort_keys=True)
        )

    routes = [{
        "src": row.src_asset_id,
        "dst": row.dst_asset_id,
        "provenance": row.provenance,
        "reason": row.reason,
    } for row in route_rows]
    ips_by_asset: dict[str, list[str]] = {}
    for alias in aliases:
        if alias.alias_type == "ip":
            ips_by_asset.setdefault(alias.asset_id, []).append(alias.alias_value)
    asset_rows = [{
        "id": asset.id,
        "zone": asset.zone,
        "is_crown_jewel": asset.is_crown_jewel,
        "criticality": asset.criticality,
        "hostnames": [asset.canonical_hostname],
        "ips": sorted(set(ips_by_asset.get(asset.id, []))),
    } for asset in assets]
    gi = from_rows(
        assets=asset_rows,
        findings=rows,
        facts=facts,
        routes=routes,
        entries=[a.id for a in assets if a.is_entry_point],
    )
    return gi, {
        "assets": len(assets),
        "aliases": len(aliases),
        "findings": len(findings),
        "facts": len(facts),
        "routes": len(routes),
        "entries": len(gi.entries),
        "crown_jewels": len(gi.jewels()),
        "contract": validation,
    }


def analysis_hash(gi: GraphInput, parameters: dict) -> str:
    canonical = json.dumps(
        {
            "engine": engine_fingerprint(),
            "input": asdict(gi),
            "parameters": parameters,
        },
        default=_json_default,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def priority_payload(result: GraphResult) -> list[dict]:
    by_id = {item["vuln_id"]: item for item in result.chokepoints}
    cut = set(result.cut.get("vulns", []))
    budget = {item["vuln_id"] for item in result.budget_plan.get("picks", [])}
    payload = []
    for item in result.priority:
        choke = by_id.get(item["vuln_id"], {})
        node = ("vuln", item["vuln_id"])
        attributes = result.graph.nodes.get(node, {})
        payload.append({
            **item,
            "dominated_assets": choke.get("dominated_assets", []),
            "dominated_jewels": choke.get("dominated_jewels", []),
            "in_min_cut": item["vuln_id"] in cut,
            "in_budget_set": item["vuln_id"] in budget,
            "mitre_ids": attributes.get("mitre", []),
            "evidence_id": attributes.get("evidence_id"),
        })
    return payload


def snapshot_payload(snapshot: GraphSnapshot, *, cached: bool) -> dict:
    return {
        "snapshot_id": snapshot.id,
        "input_hash": snapshot.input_hash,
        "cached": cached,
        "seed": snapshot.seed,
        "trials": snapshot.trials,
        "budget_hours": snapshot.budget_hours,
        "created_at": snapshot.created_at.isoformat(),
        "summary": snapshot.summary,
        "cytoscape": snapshot.cytoscape,
        "priority": snapshot.priority,
    }


async def analyze_and_persist(
    session: AsyncSession,
    *,
    trials: int,
    seed: int,
    budget_hours: float,
    k_paths: int,
    priority_trials: int,
    scan_run_id: str | None = None,
) -> tuple[GraphSnapshot, bool, dict]:
    gi, inventory = await load_graph_input(session, scan_run_id)
    parameters = {
        "trials": trials,
        "seed": seed,
        "budget_hours": budget_hours,
        "k_paths": k_paths,
        "priority_trials": priority_trials,
        "scan_run_id": scan_run_id,
    }
    digest = analysis_hash(gi, parameters)
    cached = await session.scalar(
        select(GraphSnapshot).where(GraphSnapshot.input_hash == digest)
    )
    if cached is not None:
        return cached, True, inventory

    result = await asyncio.to_thread(
        run,
        gi,
        trials=trials,
        seed=seed,
        budget_hours=budget_hours,
        k_paths=k_paths,
        priority_trials=priority_trials,
    )
    snapshot_id = str(uuid.uuid4())
    values = {
        "id": snapshot_id,
        "input_hash": digest,
        "seed": seed,
        "trials": trials,
        "budget_hours": budget_hours,
        "summary": result.summary(),
        "cytoscape": result.cytoscape(),
        "priority": priority_payload(result),
    }
    await session.execute(
        pg_insert(GraphSnapshot).values(**values).on_conflict_do_nothing(
            index_elements=[GraphSnapshot.input_hash]
        )
    )
    await session.commit()
    snapshot = await session.scalar(
        select(GraphSnapshot).where(GraphSnapshot.input_hash == digest)
    )
    if snapshot is None:  # defensive: the insert or concurrent winner must exist
        raise RuntimeError("attack-graph snapshot persistence failed")
    return snapshot, False, inventory


async def recompute_live(
    session: AsyncSession, *, patched: set[str], trials: int, seed: int,
    scan_run_id: str | None = None,
) -> dict:
    gi, inventory = await load_graph_input(session, scan_run_id)
    known = {finding.id for finding in gi.findings}
    unknown = sorted(patched - known)
    if unknown:
        raise LookupError(f"unknown finding ids: {unknown}")
    output = await asyncio.to_thread(
        recompute, gi, patched, trials=trials, seed=seed
    )
    output["inventory"] = inventory
    return output
