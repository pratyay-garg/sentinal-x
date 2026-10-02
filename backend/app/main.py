"""
FastAPI application. Route handlers do ONLY: authenticate, scope-check,
persist a job row, notify, return 202. All scan logic lives in app/worker.py
+ app/pipeline/ — see IMPLEMENTATION_SPEC_v4.md §8/§9.

Run:
    uvicorn app.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import hmac
import json
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.authenticator import AuthLoginError, resolve_auth_headers
from app.core.config import settings
from app.core.credentials import CredentialConfigurationError, store_headers
from app.api.console_api import build_console_router
from app.core.db import get_session, get_session_dep
from app.api.graph_api import build_graph_router
from app.api.intel_api import build_intel_router
from .models import Evidence, Finding, ScanJob, ScanRun, SystemControl, ValidationJob
from app.tasks.queue import get_notify_bus, init_notify_bus, poll_events_since
from app.core.runtime_config import refresh_runtime_overrides
from .schemas import CancelResponse, ScanCreateRequest, ScanCreateResponse, ScanStatusResponse
from app.core.scope import is_in_scope, parse_allowlist
from app.tasks.validation_queue import enqueue_validation


@asynccontextmanager
async def lifespan(app: FastAPI):
    # The API process ALSO gets a NotifyBus instance so its WebSocket layer
    # can push events without polling the DB itself in a tight loop — see
    # queue.py. This is entirely optional; the /events polling endpoint below
    # never depends on it.
    await init_notify_bus(settings.database_url.replace("postgresql+asyncpg://", "postgresql://"))
    # Load operator setting overrides (ADR-0007 D6) into this process. Best-effort:
    # a cold/absent DB must not stop the API from coming up.
    try:
        async with get_session() as session:
            await refresh_runtime_overrides(session, settings)
    except Exception:  # noqa: BLE001
        pass
    yield


app = FastAPI(title="Discovery Engine (Module 1)", lifespan=lifespan)


@app.get("/health/live", include_in_schema=False)
async def liveness() -> dict:
    return {"status": "ok"}


@app.get("/health/ready", include_in_schema=False)
async def readiness(session: AsyncSession = Depends(get_session_dep)) -> dict:
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "ready"}


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_api_key, settings.discovery_api_key):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def require_admin_api_key(x_api_key: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_api_key, settings.discovery_admin_api_key):
        raise HTTPException(status_code=403, detail="administrative authorization required")


app.include_router(build_graph_router(require_api_key, require_admin_api_key))
app.include_router(build_intel_router(require_api_key))
app.include_router(build_console_router(require_api_key, require_admin_api_key))


@app.post("/api/v1/discovery/scans", response_model=ScanCreateResponse, status_code=202)
async def create_scan(
    body: ScanCreateRequest,
    session: AsyncSession = Depends(get_session_dep),
    _auth: None = Depends(require_api_key),
) -> ScanCreateResponse:
    # Any authenticated scan (supplied headers, auth contexts, or automatic
    # login) needs the encryption key to store its secret. Check that up front,
    # before touching the target, so we never lose a secret or log in pointlessly.
    if (body.custom_headers or body.auth_contexts or body.auth) and not settings.discovery_credential_encryption_key:
        raise HTTPException(
            status_code=422,
            detail="authenticated scanning requires DISCOVERY_CREDENTIAL_ENCRYPTION_KEY",
        )

    rules = parse_allowlist(settings.scope_allowlist)
    if not is_in_scope(rules, body.target):
        raise HTTPException(status_code=403, detail="target is not in the configured scope allowlist")

    # Automatic authentication: the scanner logs itself in against the (already
    # scope-checked) target and derives the session, so no operator pastes a
    # cookie. Only the resulting cookie is stored; credentials are transient.
    auto_headers: dict[str, str] | None = None
    if body.auth is not None:
        try:
            auto_headers = await resolve_auth_headers(
                body.target, body.auth, lambda url: is_in_scope(rules, url)
            )
        except AuthLoginError as exc:
            raise HTTPException(status_code=422, detail=f"automatic authentication failed: {exc}") from exc

    supplied_contexts = (
        {"authenticated": auto_headers} if auto_headers else
        {"authenticated": body.custom_headers} if body.custom_headers else
        {item.name: item.headers for item in (body.auth_contexts or [])}
    )

    run_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    header_names = sorted(
        f"{context}:{name}" for context, headers in supplied_contexts.items() for name in headers
    ) or None

    await session.execute(
        text("INSERT INTO scan_runs (id, target, profile, status, started_at) "
             "VALUES (:id, :target, :profile, 'running', now())"),
        {"id": run_id, "target": body.target, "profile": body.profile},
    )
    await session.execute(
        text("INSERT INTO scan_jobs (id, scan_run_id, target, profile, status, custom_header_names) "
             "VALUES (:id, :run_id, :target, :profile, 'queued', CAST(:headers AS jsonb))"),
        {"id": job_id, "run_id": run_id, "target": body.target, "profile": body.profile,
         # custom_header_names is JSONB; asyncpg does not serialise a Python list
         # for a raw text() bind, so hand it a JSON string and cast it.
         "headers": json.dumps(header_names) if header_names is not None else None},
    )
    if supplied_contexts:
        try:
            for context, headers in supplied_contexts.items():
                await store_headers(
                    session, job_id=job_id, scan_run_id=run_id,
                    context=context, headers=headers,
                )
        except CredentialConfigurationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    await session.commit()

    bus = get_notify_bus()
    if bus and bus.healthy:
        await bus.notify(json.dumps({"event": "job_created", "job_id": job_id}))

    return ScanCreateResponse(job_id=job_id, status="queued")


@app.get("/api/v1/discovery/scans/{job_id}", response_model=ScanStatusResponse)
async def get_scan(
    job_id: uuid.UUID, session: AsyncSession = Depends(get_session_dep),
    _auth: None = Depends(require_api_key),
) -> ScanStatusResponse:
    job = await session.get(ScanJob, str(job_id))
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return ScanStatusResponse(
        id=job.id, target=job.target, status=job.status,
        attempt_count=job.attempt_count, error=job.error,
    )


@app.get("/api/v1/discovery/scans/{job_id}/events")
async def get_scan_events(
    job_id: uuid.UUID, after: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session_dep), _auth: None = Depends(require_api_key),
) -> list[dict]:
    """The resilient PRIMARY path for clients — not a late-join fallback.
    See IMPLEMENTATION_SPEC_v4.md §8."""
    events = await poll_events_since(session, str(job_id), after)
    for e in events:
        e["created_at"] = e["created_at"].isoformat()
    return events


@app.patch("/api/v1/discovery/scans/{job_id}/cancel", response_model=CancelResponse)
async def cancel_scan(
    job_id: uuid.UUID, session: AsyncSession = Depends(get_session_dep),
    _auth: None = Depends(require_api_key),
) -> CancelResponse:
    job_id_value = str(job_id)
    job = await session.get(ScanJob, job_id_value)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    job.cancel_requested = True
    await session.commit()
    return CancelResponse(job_id=job_id_value, cancel_requested=True)


@app.post("/api/v1/discovery/killswitch")
async def engage_killswitch(
    reason: str = "manual", session: AsyncSession = Depends(get_session_dep), _auth: None = Depends(require_api_key)
) -> dict:
    row = await session.get(SystemControl, 1)
    if row is None:
        row = SystemControl(id=1, killswitch_engaged=True, reason=reason)
        session.add(row)
    else:
        row.killswitch_engaged = True
        row.reason = reason
    await session.commit()
    return {"killswitch_engaged": True, "reason": reason}


@app.post("/api/v1/discovery/killswitch/reset")
async def reset_killswitch(
    session: AsyncSession = Depends(get_session_dep), _auth: None = Depends(require_admin_api_key)
) -> dict:
    row = await session.get(SystemControl, 1)
    if row:
        row.killswitch_engaged = False
        row.reason = None
        await session.commit()
    return {"killswitch_engaged": False}


@app.get("/api/v1/discovery/scans/{job_id}/results")
async def get_scan_results(
    job_id: uuid.UUID, session: AsyncSession = Depends(get_session_dep),
    _auth: None = Depends(require_api_key),
) -> dict:
    """DB-only Discovery output, including quarantined rows and coverage gaps."""
    job_id_value = str(job_id)
    job = await session.get(ScanJob, job_id_value)
    if job is None or job.scan_run_id is None:
        raise HTTPException(status_code=404, detail="job not found")
    run = await session.get(ScanRun, job.scan_run_id)
    result = await session.execute(text("""
        SELECT f.id, f.asset_id, f.vuln_class, f.vuln_class_candidate,
               f.raw_finding_type, f.mapping_status, f.mapping_diagnostics,
               f.status, f.confidence, f.cvss_vector, f.epss,
               f.epss_snapshot_date, f.patch_hours, f.patch_group,
               f.evidence_id, f.endpoint, f.param, f.source_tool,
               f.template_id, f.generated_by,
               COUNT(o.id) AS observation_count,
               ARRAY_REMOVE(ARRAY_AGG(DISTINCT o.source_tool), NULL) AS source_set
        FROM findings f
        JOIN finding_observations o ON o.finding_id = f.id
        WHERE o.scan_run_id = :run_id
        GROUP BY f.id
        ORDER BY f.id
    """), {"run_id": job.scan_run_id})
    findings = []
    for row in result.mappings():
        item = dict(row)
        if item["epss_snapshot_date"]:
            item["epss_snapshot_date"] = item["epss_snapshot_date"].isoformat()
        item["id"] = str(item["id"])
        item["evidence_id"] = str(item["evidence_id"]) if item["evidence_id"] else None
        findings.append(item)
    return {
        "job_id": job_id_value, "scan_run_id": str(job.scan_run_id),
        "status": job.status, "coverage": run.coverage if run else None,
        "stats": run.stats if run else None, "findings": findings,
    }


@app.post("/api/v1/validation/findings/{finding_id}", status_code=202)
async def create_validation(
    finding_id: uuid.UUID,
    session: AsyncSession = Depends(get_session_dep),
    _auth: None = Depends(require_api_key),
) -> dict:
    """Queue or return the current durable Validation job for one finding."""
    finding = await session.get(Finding, str(finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if finding.mapping_status != "mapped" or not finding.vuln_class:
        raise HTTPException(status_code=409, detail="unmapped findings cannot be validated")
    job_id = await enqueue_validation(session, finding.id, finding.first_seen_scan_run_id)
    await session.commit()
    return {"job_id": job_id, "finding_id": finding.id, "status": "queued"}


@app.get("/api/v1/validation/jobs/{job_id}")
async def get_validation_job(
    job_id: uuid.UUID,
    session: AsyncSession = Depends(get_session_dep),
    _auth: None = Depends(require_api_key),
) -> dict:
    job = await session.get(ValidationJob, str(job_id))
    if job is None:
        raise HTTPException(status_code=404, detail="validation job not found")
    return {
        "id": job.id, "finding_id": job.finding_id, "scan_run_id": job.scan_run_id,
        "status": job.status, "attempt_count": job.attempt_count,
        "error": job.error, "result": job.result,
    }


@app.get("/api/v1/validation/jobs/{job_id}/events")
async def get_validation_events(
    job_id: uuid.UUID, after: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session_dep),
    _auth: None = Depends(require_api_key),
) -> list[dict]:
    exists = await session.get(ValidationJob, str(job_id))
    if exists is None:
        raise HTTPException(status_code=404, detail="validation job not found")
    rows = await session.execute(text("""
        SELECT seq, event, data, created_at FROM validation_events
        WHERE job_id=:job_id AND seq>:after ORDER BY seq
    """), {"job_id": str(job_id), "after": after})
    return [{**dict(row), "created_at": row.created_at.isoformat()}
            for row in rows.mappings()]


@app.get("/api/v1/validation/findings/{finding_id}")
async def get_validated_finding(
    finding_id: uuid.UUID,
    session: AsyncSession = Depends(get_session_dep),
    _auth: None = Depends(require_api_key),
) -> dict:
    finding = await session.get(Finding, str(finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    evidence = await session.get(Evidence, finding.evidence_id) if finding.evidence_id else None
    return {
        "id": finding.id, "asset_id": finding.asset_id,
        "vuln_class": finding.vuln_class, "status": finding.status,
        "confidence": finding.confidence, "endpoint": finding.endpoint,
        "param": finding.param, "patch_group": finding.patch_group,
        "evidence_id": finding.evidence_id,
        "observed_requires": finding.observed_requires or [],
        "observed_grants": finding.observed_grants or [],
        "target_asset_id": finding.target_asset_id,
        "evidence": ({
            "oracle": evidence.oracle, "expected_status": evidence.expected_status,
            "confidence": evidence.confidence, "seed": evidence.seed,
            "generated_by": evidence.generated_by, "manifest": evidence.manifest,
            "created_at": evidence.created_at.isoformat(),
        } if evidence else None),
    }


@app.websocket("/ws/{job_id}")
async def scan_events_ws(websocket: WebSocket, job_id: str, api_key: str = Query(default="")) -> None:
    """Best-effort convenience layer on top of the same polling loop —
    IMPLEMENTATION_SPEC_v4.md §8. If NotifyBus isn't healthy (e.g. behind a
    pooler), this still works, just at polling latency (1-2s) instead of
    near-instant.
    """
    if not hmac.compare_digest(api_key, settings.discovery_api_key):
        await websocket.close(code=4401, reason="authentication required")
        return
    await websocket.accept()
    bus = get_notify_bus()
    queue = bus.subscribe() if bus else None
    try:
        import asyncio
        last_seq = 0
        while True:
            if queue is not None:
                try:
                    await asyncio.wait_for(queue.get(), timeout=settings.poll_interval_seconds)
                except asyncio.TimeoutError:
                    pass
            else:
                await asyncio.sleep(settings.poll_interval_seconds)

            from app.core.db import get_session
            async with get_session() as session:
                events = await poll_events_since(session, job_id, last_seq)
            for e in events:
                last_seq = max(last_seq, e["seq"])
                e["created_at"] = e["created_at"].isoformat()
                await websocket.send_json(e)
    except WebSocketDisconnect:
        pass
    finally:
        if bus and queue is not None:
            bus.unsubscribe(queue)
