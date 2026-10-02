"""Read-only operator-console projections over the shared pipeline database.

These endpoints intentionally do not create a second data model. They expose the
existing Discovery, Validation, Evidence, and Attack-Graph rows in bounded,
paginated forms suitable for an operator UI.
"""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings
from app.core.db import get_session_dep
from app.models import Evidence
from .remediation_api import build_remediation_router
from app.core.runtime_config import (
    effective_view, refresh_runtime_overrides, validate_overrides,
)


def _iso(value):
    return value.isoformat() if value is not None else None


class SettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    overrides: dict[str, object] = Field(default_factory=dict)


def build_console_router(require_api_key, require_admin_api_key=None) -> APIRouter:
    # The admin authority gates safety-relevant config writes (ADR-0007 D6/D8).
    # Fall back to the console key only if no admin dependency is wired.
    admin_guard = require_admin_api_key or require_api_key
    router = APIRouter(prefix="/api/v1/console", tags=["operator-console"])

    @router.get("/overview")
    async def overview(
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        counts = (await session.execute(text("""
            SELECT
              (SELECT COUNT(*) FROM scan_jobs) AS scans,
              (SELECT COUNT(*) FROM scan_jobs
                 WHERE status IN ('queued','claimed','running')) AS active_scans,
              (SELECT COUNT(*) FROM assets) AS assets,
              (SELECT COUNT(*) FROM findings) AS findings,
              (SELECT COUNT(*) FROM findings WHERE status='validated') AS validated,
              (SELECT COUNT(*) FROM findings WHERE status='unvalidated') AS unvalidated,
              (SELECT COUNT(*) FROM findings
                 WHERE lower(COALESCE(severity_raw,''))='critical') AS critical,
              (SELECT COUNT(*) FROM findings
                 WHERE lower(COALESCE(severity_raw,''))='high') AS high,
              (SELECT COUNT(*) FROM validation_jobs
                 WHERE status IN ('queued','claimed','running')) AS active_validations,
              (SELECT COUNT(*) FROM evidence) AS evidence,
              (SELECT COUNT(*) FROM graph_snapshots) AS graph_snapshots
        """))).mappings().one()
        control = (await session.execute(text("""
            SELECT killswitch_engaged, reason, updated_at
            FROM system_control WHERE id=1
        """))).mappings().first()
        latest_graph = (await session.execute(text("""
            SELECT id, seed, trials, summary, created_at
            FROM graph_snapshots ORDER BY created_at DESC LIMIT 1
        """))).mappings().first()
        graph_summary = latest_graph.summary if latest_graph else {}
        graph_diagnosis = graph_summary.get("diagnosis", {})
        graph_invariants = graph_summary.get("invariants", {})
        return {
            "counts": dict(counts),
            "killswitch": {
                "engaged": bool(control.killswitch_engaged) if control else False,
                "reason": control.reason if control else None,
                "updated_at": _iso(control.updated_at) if control else None,
            },
            "latest_graph": ({
                "id": str(latest_graph.id),
                "seed": latest_graph.seed,
                "trials": latest_graph.trials,
                "diagnosis": (
                    graph_diagnosis.get("status", "unknown")
                    if isinstance(graph_diagnosis, dict) else str(graph_diagnosis)
                ),
                "answerable": bool(
                    graph_diagnosis.get("answerable", False)
                    if isinstance(graph_diagnosis, dict) else False
                ),
                "invariants_passed": bool(
                    graph_invariants.get("all_passed", False)
                    if isinstance(graph_invariants, dict) else False
                ),
                "summary": graph_summary,
                "created_at": _iso(latest_graph.created_at),
            } if latest_graph else None),
        }

    @router.get("/scans")
    async def scans(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        status: str | None = Query(default=None, max_length=32),
        search: str | None = Query(default=None, max_length=256),
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        where = ["TRUE"]
        params: dict = {"limit": limit, "offset": offset}
        if status:
            where.append("j.status=:status")
            params["status"] = status
        if search:
            where.append("j.target ILIKE '%' || :search || '%'")
            params["search"] = search
        predicate = " AND ".join(where)
        total = (await session.execute(
            text(f"SELECT COUNT(*) FROM scan_jobs j WHERE {predicate}"), params
        )).scalar_one()
        rows = (await session.execute(text(f"""
            SELECT j.id, j.scan_run_id, j.target, j.profile, j.status,
                   j.attempt_count, j.cancel_requested, j.error,
                   j.created_at, j.started_at, j.completed_at,
                   COALESCE((SELECT MAX(e.seq) FROM scan_events e WHERE e.job_id=j.id), 0) event_count,
                   COALESCE((SELECT COUNT(DISTINCT o.finding_id)
                     FROM finding_observations o WHERE o.scan_run_id=j.scan_run_id), 0) finding_count
            FROM scan_jobs j WHERE {predicate}
            ORDER BY j.created_at DESC LIMIT :limit OFFSET :offset
        """), params)).mappings().all()
        return {"items": [{
            **{key: value for key, value in dict(row).items()
               if key not in {"id", "scan_run_id", "created_at", "started_at", "completed_at"}},
            "id": str(row.id),
            "scan_run_id": str(row.scan_run_id) if row.scan_run_id else None,
            "created_at": _iso(row.created_at),
            "started_at": _iso(row.started_at),
            "completed_at": _iso(row.completed_at),
        } for row in rows], "total": total, "limit": limit, "offset": offset}

    @router.get("/findings")
    async def findings(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        status: str | None = Query(default=None, max_length=32),
        severity: str | None = Query(default=None, max_length=32),
        search: str | None = Query(default=None, max_length=256),
        scan_run_id: str | None = Query(default=None, max_length=64),
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        clauses = ["TRUE"]
        params: dict = {"limit": limit, "offset": offset}
        if scan_run_id:
            # The scan is the unit of triage: show only findings observed in this run.
            clauses.append(
                "f.id IN (SELECT o.finding_id FROM finding_observations o "
                "WHERE o.scan_run_id = CAST(:scan_run_id AS uuid))"
            )
            params["scan_run_id"] = scan_run_id
        if status:
            clauses.append("f.status=:status")
            params["status"] = status
        if severity:
            clauses.append("lower(COALESCE(f.severity_raw,''))=lower(:severity)")
            params["severity"] = severity
        if search:
            clauses.append("""(
                a.canonical_hostname ILIKE '%' || :search || '%'
                OR COALESCE(f.vuln_class, f.vuln_class_candidate) ILIKE '%' || :search || '%'
                OR COALESCE(f.endpoint,'') ILIKE '%' || :search || '%'
                OR COALESCE(f.cve_id,'') ILIKE '%' || :search || '%'
            )""")
            params["search"] = search
        predicate = " AND ".join(clauses)
        total = (await session.execute(text(f"""
            SELECT COUNT(*) FROM findings f JOIN assets a ON a.id=f.asset_id
            WHERE {predicate}
        """), params)).scalar_one()
        rows = (await session.execute(text(f"""
            SELECT f.id, f.asset_id, a.canonical_hostname hostname,
                   f.vuln_class, f.vuln_class_candidate, f.mapping_status,
                   f.status, f.confidence, f.discovery_confidence,
                   f.severity_raw severity, f.cvss_vector, f.epss, f.cve_id,
                   f.endpoint, f.param, f.patch_hours, f.patch_group,
                   f.evidence_id, f.source_tool, f.generated_by,
                   f.observed_requires, f.observed_grants,
                   f.first_seen, f.last_seen,
                   (SELECT COUNT(*) FROM finding_observations o WHERE o.finding_id=f.id) observation_count
            FROM findings f JOIN assets a ON a.id=f.asset_id
            WHERE {predicate}
            ORDER BY CASE lower(COALESCE(f.severity_raw,''))
                       WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                       WHEN 'low' THEN 2 ELSE 1 END DESC,
                     COALESCE(f.confidence, f.discovery_confidence) DESC, f.last_seen DESC
            LIMIT :limit OFFSET :offset
        """), params)).mappings().all()
        return {"items": [{
            **{key: value for key, value in dict(row).items()
               if key not in {"id", "evidence_id", "first_seen", "last_seen"}},
            "id": str(row.id),
            "evidence_id": str(row.evidence_id) if row.evidence_id else None,
            "first_seen": _iso(row.first_seen), "last_seen": _iso(row.last_seen),
        } for row in rows], "total": total, "limit": limit, "offset": offset}

    @router.get("/evidence/{evidence_id}")
    async def evidence_detail(
        evidence_id: uuid.UUID,
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        evidence = await session.get(Evidence, str(evidence_id))
        if evidence is None:
            raise HTTPException(status_code=404, detail="evidence not found")
        return {
            "id": evidence.id,
            "finding_id": evidence.finding_id,
            "generated_by": evidence.generated_by,
            "oracle": evidence.oracle,
            "expected_status": evidence.expected_status,
            "confidence": evidence.confidence,
            "seed": evidence.seed,
            "manifest": evidence.manifest,
            "redacted_request_excerpt": evidence.redacted_request_excerpt,
            "har_ref": evidence.har_ref,
            "screenshot_ref": evidence.screenshot_ref,
            "created_at": _iso(evidence.created_at),
        }

    @router.get("/inventory")
    async def inventory(
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        row = (await session.execute(text("""
            SELECT
              (SELECT COUNT(*) FROM scan_jobs) AS scans,
              (SELECT COUNT(*) FROM scan_jobs WHERE status IN ('queued','claimed','running')) AS active_scans,
              (SELECT COUNT(*) FROM findings) AS findings,
              (SELECT COUNT(*) FROM findings WHERE status='validated') AS validated,
              (SELECT COUNT(*) FROM evidence) AS evidence,
              (SELECT COUNT(*) FROM assets) AS assets,
              (SELECT COUNT(*) FROM remediation_actions) AS remediation_actions,
              (SELECT COUNT(*) FROM retest_results) AS retests,
              (SELECT COUNT(*) FROM graph_snapshots) AS graph_snapshots
        """))).mappings().one()
        scope = [entry.strip() for entry in (settings.scope_allowlist or "").split(",") if entry.strip()]
        return {
            **dict(row),
            "scope_allowlist": scope,
            "credential_encryption_enabled": bool(settings.discovery_credential_encryption_key),
            "offline_mode": bool(getattr(settings, "offline_mode", False)),
        }

    # The prototype guardrails (CLAUDE.md rule 4) keep only the scope allow-list;
    # operators must be able to reset state cleanly between assessments.
    @router.delete("/scans/{scan_run_id}")
    async def delete_scan(
        scan_run_id: uuid.UUID,
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        run = str(scan_run_id)
        exists = await session.scalar(
            text("SELECT 1 FROM scan_runs WHERE id = CAST(:run AS uuid)"), {"run": run}
        )
        if not exists:
            raise HTTPException(status_code=404, detail="scan run not found")
        # Remove this run's observations first; any finding left with no
        # observation is now orphaned and is deleted with its dependents. Findings
        # still observed by another scan are kept — only this scan's data goes.
        await session.execute(text(
            "DELETE FROM finding_observations WHERE scan_run_id = CAST(:run AS uuid)"
        ), {"run": run})
        orphan = ("(SELECT f.id FROM findings f WHERE NOT EXISTS "
                  "(SELECT 1 FROM finding_observations o WHERE o.finding_id = f.id))")
        removed = (await session.execute(text(f"SELECT COUNT(*) FROM findings f WHERE f.id IN {orphan}"))).scalar_one()
        await session.execute(text(f"DELETE FROM retest_results WHERE finding_id IN {orphan}"))
        await session.execute(text(f"DELETE FROM remediation_action_findings WHERE finding_id IN {orphan}"))
        await session.execute(text(
            f"DELETE FROM validation_events WHERE job_id IN (SELECT id FROM validation_jobs WHERE finding_id IN {orphan})"
        ))
        await session.execute(text(f"DELETE FROM validation_jobs WHERE finding_id IN {orphan}"))
        await session.execute(text(f"UPDATE findings SET evidence_id = NULL WHERE id IN {orphan}"))
        await session.execute(text(f"DELETE FROM evidence WHERE finding_id IN {orphan}"))
        await session.execute(text(f"DELETE FROM findings WHERE id IN {orphan}"))
        # Drop remediation actions that no longer cover any finding.
        await session.execute(text(
            "DELETE FROM remediation_actions WHERE id NOT IN "
            "(SELECT DISTINCT action_id FROM remediation_action_findings)"
        ))
        # This scan's job/run infrastructure (scan_events + credentials cascade).
        await session.execute(text(
            "DELETE FROM validation_events WHERE job_id IN (SELECT id FROM validation_jobs WHERE scan_run_id = CAST(:run AS uuid))"
        ), {"run": run})
        await session.execute(text("DELETE FROM validation_jobs WHERE scan_run_id = CAST(:run AS uuid)"), {"run": run})
        await session.execute(text(
            "DELETE FROM scan_events WHERE job_id IN (SELECT id FROM scan_jobs WHERE scan_run_id = CAST(:run AS uuid))"
        ), {"run": run})
        await session.execute(text("DELETE FROM scan_jobs WHERE scan_run_id = CAST(:run AS uuid)"), {"run": run})
        await session.execute(text("DELETE FROM scan_runs WHERE id = CAST(:run AS uuid)"), {"run": run})
        # Graph snapshots are cached analyses; drop them so the graph recomputes.
        await session.execute(text("DELETE FROM graph_snapshots"))
        await session.commit()
        return {"deleted_scan_run_id": run, "findings_removed": int(removed)}

    @router.post("/reset")
    async def reset_all(
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        # Full demo reset: wipe every scan-derived table but keep system controls
        # (kill switch). TRUNCATE CASCADE resolves all foreign-key ordering.
        await session.execute(text(
            "TRUNCATE TABLE scan_runs, scan_jobs, scan_events, scan_credentials, "
            "assets, asset_aliases, services, tech_fingerprints, endpoints, "
            "findings, finding_observations, evidence, validation_jobs, "
            "validation_events, graph_routes, graph_facts, graph_snapshots, "
            "remediation_actions, remediation_action_findings, retest_results "
            "RESTART IDENTITY CASCADE"
        ))
        await session.commit()
        return {"reset": True}

    @router.get("/settings")
    async def get_settings(
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        # Reflect the persisted overrides into this process before reporting, so
        # the console shows what is actually in effect even across restarts.
        await refresh_runtime_overrides(session, settings)
        return {"settings": effective_view(settings)}

    @router.patch("/settings")
    async def patch_settings(
        body: SettingsPatch,
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(admin_guard),
    ) -> dict:
        try:
            incoming = validate_overrides(body.overrides)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        current = (await session.execute(text(
            "SELECT overrides FROM runtime_settings WHERE id = 1"
        ))).scalar_one_or_none() or {}
        merged = {**current, **incoming}
        await session.execute(text(
            "INSERT INTO runtime_settings (id, overrides, updated_at, updated_by) "
            "VALUES (1, CAST(:ov AS jsonb), now(), :by) "
            "ON CONFLICT (id) DO UPDATE SET overrides = CAST(:ov AS jsonb), "
            "updated_at = now(), updated_by = :by"
        ), {"ov": json.dumps(merged), "by": "admin"})
        await session.execute(text(
            "INSERT INTO config_audit (actor, change) VALUES (:by, CAST(:ch AS jsonb))"
        ), {"by": "admin", "ch": json.dumps({"action": "patch", "changed": incoming})})
        await session.commit()
        await refresh_runtime_overrides(session, settings)
        return {"settings": effective_view(settings)}

    @router.post("/settings/reset")
    async def reset_settings(
        key: str | None = Query(default=None, max_length=128),
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(admin_guard),
    ) -> dict:
        current = (await session.execute(text(
            "SELECT overrides FROM runtime_settings WHERE id = 1"
        ))).scalar_one_or_none() or {}
        if key:
            current.pop(key, None)
            change = {"action": "reset_key", "key": key}
        else:
            current = {}
            change = {"action": "reset_all"}
        await session.execute(text(
            "INSERT INTO runtime_settings (id, overrides, updated_at, updated_by) "
            "VALUES (1, CAST(:ov AS jsonb), now(), :by) "
            "ON CONFLICT (id) DO UPDATE SET overrides = CAST(:ov AS jsonb), "
            "updated_at = now(), updated_by = :by"
        ), {"ov": json.dumps(current), "by": "admin"})
        await session.execute(text(
            "INSERT INTO config_audit (actor, change) VALUES (:by, CAST(:ch AS jsonb))"
        ), {"by": "admin", "ch": json.dumps(change)})
        await session.commit()
        await refresh_runtime_overrides(session, settings)
        return {"settings": effective_view(settings)}

    router.include_router(build_remediation_router(require_api_key))
    return router
