"""Independent worker for safe, restartable Validation jobs."""
from __future__ import annotations

import asyncio
import logging
import platform
import uuid
from typing import Any

import psycopg2
from sqlalchemy import text

from app.core.config import settings
from app.core.runtime_config import refresh_runtime_overrides
from app.core.credentials import load_for_run
from app.core.db import get_session
from app.models import Endpoint, Finding
from app.engines.validation.service import validate_finding
from .validation_queue import (
    claim_validation,
    emit_validation_event,
    fail_validation,
    validation_heartbeat,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)
WORKER_ID = f"validation:{platform.node()}:{uuid.uuid4().hex[:8]}"


class DatabaseStopCheck:
    """Thread-local synchronous kill/cancel check invoked before every request."""

    def __init__(self, job_id: str):
        dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
        self.connection = psycopg2.connect(dsn)
        self.connection.autocommit = True
        self.job_id = job_id

    def __call__(self) -> str | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT COALESCE((SELECT killswitch_engaged FROM system_control WHERE id=1), false), "
                "COALESCE((SELECT reason FROM system_control WHERE id=1), ''), "
                "COALESCE((SELECT status FROM validation_jobs WHERE id=%s), 'missing')",
                (self.job_id,),
            )
            engaged, reason, status = cursor.fetchone()
        if engaged:
            return reason or "global kill switch engaged"
        if status not in {"claimed", "running"}:
            return f"validation job is no longer active ({status})"
        return None

    def close(self) -> None:
        self.connection.close()


async def _load_candidate(job: dict) -> tuple[dict, list[str], dict[str, str] | None]:
    async with get_session() as session:
        finding = await session.get(Finding, str(job["finding_id"]))
        if finding is None:
            raise LookupError("finding no longer exists")
        row: dict[str, Any] = {
            "id": finding.id, "asset_id": finding.asset_id,
            "vuln_class": finding.vuln_class, "status": finding.status,
            "endpoint": finding.endpoint, "param": finding.param,
            "cvss_vector": finding.cvss_vector, "cve_id": finding.cve_id,
            "template_id": finding.template_id,
        }
        auth_context = "none"
        if finding.endpoint_id:
            endpoint = await session.get(Endpoint, finding.endpoint_id)
            if endpoint:
                auth_context = endpoint.auth_context
                # The other observed parameters on this endpoint. An oracle that
                # varies only the implicated parameter drops the siblings a form
                # requires (a form may run its query only when its Submit field is
                # also present), so validation must send them alongside the payload.
                row["endpoint_params"] = list(endpoint.param_names or [])
        row["auth_context"] = auth_context
        result = await session.execute(text("""
            SELECT DISTINCT raw_data->>'matcher-name' AS matcher
            FROM finding_observations
            WHERE finding_id=:finding_id AND raw_data->>'matcher-name' IS NOT NULL
            ORDER BY matcher
        """), {"finding_id": finding.id})
        contexts = await load_for_run(session, str(job.get("scan_run_id") or
                                                   finding.first_seen_scan_run_id))
        headers = contexts.get(auth_context)
        if auth_context != "none" and headers is None:
            row["auth_context_expired"] = True
        await session.commit()
        return row, [str(value) for value in result.scalars()], headers


def _run_in_thread(candidate: dict, matchers: list[str], job_id: str,
                   headers: dict[str, str] | None) -> dict:
    stop = DatabaseStopCheck(job_id)
    try:
        return validate_finding(candidate, matchers, should_stop=stop, headers=headers)
    finally:
        stop.close()


async def _heartbeat_loop(job_id: str) -> None:
    while True:
        async with get_session() as session:
            await validation_heartbeat(session, job_id)
        await asyncio.sleep(settings.heartbeat_interval_seconds)


async def _persist(job_id: str, result: dict) -> None:
    async with get_session() as session:
        finding = await session.get(Finding, result["finding_id"])
        if finding is None:
            raise LookupError("finding disappeared before validation persistence")
        await session.execute(text("""
            INSERT INTO evidence (
                id, finding_id, generated_by, oracle, expected_status,
                confidence, seed, manifest, redacted_request_excerpt
            ) VALUES (
                :id, :finding_id, 'tool', :oracle, :status,
                :confidence, 1337, CAST(:manifest AS jsonb), :excerpt
            )
        """), {
            "id": result["evidence_id"], "finding_id": finding.id,
            "oracle": result["oracle"], "status": result["status"],
            "confidence": result["confidence"],
            "manifest": __import__("json").dumps(result["manifest"]),
            "excerpt": result["reason"][:4096],
        })
        finding.status = result["status"]
        finding.confidence = result["confidence"]
        finding.evidence_id = result["evidence_id"]
        finding.observed_requires = result["observed_requires"]
        finding.observed_grants = result["observed_grants"]
        finding.target_asset_id = result["target_asset_id"]
        await session.execute(text("""
            UPDATE validation_jobs
            SET status='completed', result=CAST(:result AS jsonb), completed_at=now(),
                heartbeat_at=now(), error=NULL
            WHERE id=:id
        """), {"id": job_id, "result": __import__("json").dumps({
            k: v for k, v in result.items() if k != "manifest"
        })})
        await session.commit()
        await emit_validation_event(session, job_id, "validation:completed", {
            "finding_id": result["finding_id"], "status": result["status"],
            "confidence": result["confidence"], "oracle": result["oracle"],
            "evidence_id": result["evidence_id"],
        })


async def run_one(job: dict) -> None:
    job_id = str(job["id"])
    async with get_session() as session:
        await emit_validation_event(session, job_id, "validation:started", {
            "finding_id": str(job["finding_id"]), "worker": WORKER_ID,
        })
    candidate, matchers, headers = await _load_candidate(job)
    heartbeat_task = asyncio.create_task(_heartbeat_loop(job_id))
    try:
        result = await asyncio.to_thread(_run_in_thread, candidate, matchers, job_id, headers)
        await _persist(job_id, result)
    finally:
        heartbeat_task.cancel()


async def main() -> None:
    logger.info("validation worker starting, id=%s", WORKER_ID)
    while True:
        async with get_session() as session:
            job = await claim_validation(session, WORKER_ID)
            if job is not None:
                # Operator setting overrides (ADR-0007 D6); separate process.
                await refresh_runtime_overrides(session, settings)
        if job is None:
            await asyncio.sleep(settings.poll_interval_seconds)
            continue
        try:
            await run_one(job)
        except Exception as exc:  # worker must survive one malformed candidate
            logger.exception("validation job %s failed", job["id"])
            async with get_session() as session:
                await fail_validation(session, str(job["id"]), f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
