"""Authenticated FastAPI surface for live, database-backed attack analysis."""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.graph import contract

from app.core.db import get_session_dep
from .graph_service import analyze_and_persist, recompute_live, snapshot_payload
from .graph_view import GRAPH_VIEW_HTML
from app.models import Asset, GraphFact, GraphRoute, GraphSnapshot
from app.schemas import (
    GraphAssetUpdate,
    GraphFactCreate,
    GraphRecomputeRequest,
    GraphRouteCreate,
)


def build_graph_router(require_api_key, require_admin_api_key) -> APIRouter:
    router = APIRouter(prefix="/api/v1/graph", tags=["attack-graph"])

    @router.get("/view", response_class=HTMLResponse, include_in_schema=False)
    async def graph_view(
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> str:
        """Return a self-contained authenticated snapshot visualization."""
        snapshot, cached, inventory = await analyze_and_persist(
            session, trials=2_000, seed=1337, budget_hours=8.0,
            k_paths=50, priority_trials=500,
        )
        payload = {**snapshot_payload(snapshot, cached=cached), "inventory": inventory}
        encoded = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")
        return GRAPH_VIEW_HTML.replace("__GRAPH_PAYLOAD__", encoded)

    @router.get("/contract")
    async def vocabulary(_auth: None = Depends(require_api_key)) -> dict:
        return {
            "vuln_classes": sorted(contract.VULN_CLASSES),
            "m2_emitted_classes": sorted(contract.M2_EMITTED_CLASSES),
            "verdicts": sorted(contract.VERDICTS),
            "live_verdicts": sorted(contract.LIVE_VERDICTS),
            "oracle_proves": {
                key: {"observed_requires": list(value[0]), "observed_grants": [value[1]]}
                for key, value in sorted(contract.ORACLE_PROVES.items())
            },
            "default_patch_hours": contract.DEFAULT_PATCH_HOURS,
        }

    @router.get("/assets")
    async def graph_assets(
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        rows = list((await session.scalars(select(Asset).order_by(Asset.id))).all())
        return {"items": [{
            "id": row.id,
            "hostname": row.canonical_hostname,
            "zone": row.zone,
            "criticality": row.criticality,
            "is_entry_point": row.is_entry_point,
            "is_crown_jewel": row.is_crown_jewel,
        } for row in rows]}

    @router.patch("/assets/{asset_id}")
    async def update_graph_asset(
        asset_id: str,
        body: GraphAssetUpdate,
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_admin_api_key),
    ) -> dict:
        asset = await session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="asset not found")
        for key, value in body.model_dump(exclude_none=True).items():
            setattr(asset, key, value)
        await session.commit()
        return {
            "id": asset.id,
            "zone": asset.zone,
            "criticality": asset.criticality,
            "is_entry_point": asset.is_entry_point,
            "is_crown_jewel": asset.is_crown_jewel,
        }

    @router.post("/routes", status_code=201)
    async def create_route(
        body: GraphRouteCreate,
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_admin_api_key),
    ) -> dict:
        assets = set((await session.scalars(
            select(Asset.id).where(Asset.id.in_([body.src_asset_id, body.dst_asset_id]))
        )).all())
        missing = sorted({body.src_asset_id, body.dst_asset_id} - assets)
        if missing:
            raise HTTPException(status_code=404, detail={"missing_assets": missing})
        route_id = str(uuid.uuid4())
        stmt = pg_insert(GraphRoute).values(
            id=route_id,
            src_asset_id=body.src_asset_id,
            dst_asset_id=body.dst_asset_id,
            provenance=body.provenance,
            reason=body.reason,
        ).on_conflict_do_update(
            constraint="uq_graph_route",
            set_={"provenance": body.provenance, "reason": body.reason},
        ).returning(GraphRoute.id)
        resolved = (await session.execute(stmt)).scalar_one()
        await session.commit()
        return {"id": resolved, **body.model_dump()}

    @router.post("/facts", status_code=201)
    async def create_fact(
        body: GraphFactCreate,
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_admin_api_key),
    ) -> dict:
        fact_id = str(uuid.uuid4())
        stmt = pg_insert(GraphFact).values(
            id=fact_id, **body.model_dump()
        ).on_conflict_do_update(
            constraint="uq_graph_fact",
            set_={"description": body.description, "provenance": body.provenance},
        ).returning(GraphFact.id)
        resolved = (await session.execute(stmt)).scalar_one()
        await session.commit()
        return {"id": resolved, **body.model_dump()}

    async def analyze(
        session: AsyncSession,
        trials: int,
        seed: int,
        budget_hours: float,
        k_paths: int,
        priority_trials: int,
        scan_run_id: str | None = None,
    ) -> dict:
        try:
            snapshot, cached, inventory = await analyze_and_persist(
                session,
                trials=trials,
                seed=seed,
                budget_hours=budget_hours,
                k_paths=k_paths,
                priority_trials=priority_trials,
                scan_run_id=scan_run_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {**snapshot_payload(snapshot, cached=cached), "inventory": inventory}

    @router.get("/analyze")
    async def analyze_graph(
        trials: int = Query(default=10_000, ge=100, le=100_000),
        seed: int = Query(default=1337, ge=0, le=4_294_967_295),
        budget_hours: float = Query(default=8.0, gt=0, le=10_000),
        k_paths: int = Query(default=50, ge=1, le=500),
        priority_trials: int = Query(default=2_000, ge=100, le=20_000),
        scan_run_id: str | None = Query(default=None, max_length=64),
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        return await analyze(
            session, trials, seed, budget_hours, k_paths, priority_trials, scan_run_id
        )

    @router.get("/cytoscape")
    async def cytoscape(
        scan_run_id: str | None = Query(default=None, max_length=64),
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        payload = await analyze(session, 10_000, 1337, 8.0, 50, 2_000, scan_run_id)
        return {
            "snapshot_id": payload["snapshot_id"],
            "cached": payload["cached"],
            **payload["cytoscape"],
        }

    @router.get("/priority")
    async def priority(
        top: int = Query(default=20, ge=1, le=1_000),
        scan_run_id: str | None = Query(default=None, max_length=64),
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        payload = await analyze(session, 10_000, 1337, 8.0, 50, 2_000, scan_run_id)
        return {
            "snapshot_id": payload["snapshot_id"],
            "items": payload["priority"][:top],
            "cut": payload["summary"].get("cut", {}),
            "budget_plan": payload["summary"].get("budget_plan", {}),
        }

    @router.post("/recompute")
    async def graph_recompute(
        body: GraphRecomputeRequest,
        scan_run_id: str | None = Query(default=None, max_length=64),
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        try:
            return await recompute_live(
                session, patched=set(body.patched), trials=body.trials, seed=body.seed,
                scan_run_id=scan_run_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.get("/snapshots/latest")
    async def latest_snapshot(
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        snapshot = await session.scalar(
            select(GraphSnapshot).order_by(GraphSnapshot.created_at.desc()).limit(1)
        )
        if snapshot is None:
            raise HTTPException(status_code=404, detail="no graph snapshot exists")
        return snapshot_payload(snapshot, cached=True)

    @router.get("/snapshots/{snapshot_id}")
    async def get_snapshot(
        snapshot_id: uuid.UUID,
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        snapshot = await session.get(GraphSnapshot, str(snapshot_id))
        if snapshot is None:
            raise HTTPException(status_code=404, detail="graph snapshot not found")
        return snapshot_payload(snapshot, cached=True)

    return router
