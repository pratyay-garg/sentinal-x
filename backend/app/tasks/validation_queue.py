"""Durable Postgres queue and event ledger for Validation jobs."""
from __future__ import annotations

import json
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings


async def enqueue_validation(
    session: AsyncSession, finding_id: str, scan_run_id: str | None = None,
) -> str:
    pending = await session.execute(text("""
        SELECT id FROM validation_jobs
        WHERE finding_id=:finding_id AND status IN ('queued','claimed','running')
        ORDER BY created_at DESC LIMIT 1
    """), {"finding_id": finding_id})
    existing = pending.scalar_one_or_none()
    if existing:
        return str(existing)
    job_id = str(uuid.uuid4())
    await session.execute(text("""
        INSERT INTO validation_jobs (id, finding_id, scan_run_id, status)
        VALUES (:id, :finding_id, :scan_run_id, 'queued')
    """), {"id": job_id, "finding_id": finding_id, "scan_run_id": scan_run_id})
    await emit_validation_event(session, job_id, "validation:queued", {"finding_id": finding_id})
    return job_id


async def claim_validation(session: AsyncSession, worker_id: str) -> dict | None:
    await session.execute(text("""
        UPDATE validation_jobs
        SET status='failed', completed_at=now(),
            error='retry budget exhausted after stale worker claims'
        WHERE status IN ('claimed','running')
          AND heartbeat_at < now() - (:stale * INTERVAL '1 second')
          AND attempt_count >= :attempts
    """), {"stale": settings.stale_job_threshold_seconds,
             "attempts": settings.validation_max_attempts})
    result = await session.execute(text("""
        UPDATE validation_jobs
        SET status='claimed', claimed_by=:worker, claimed_at=now(), heartbeat_at=now(),
            started_at=COALESCE(started_at, now()), attempt_count=attempt_count+1
        WHERE id = (
            SELECT id FROM validation_jobs
            WHERE status='queued'
               OR (status IN ('claimed','running')
                   AND heartbeat_at < now() - (:stale * INTERVAL '1 second')
                   AND attempt_count < :attempts)
            ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED
        )
        RETURNING id, finding_id, scan_run_id
    """), {"worker": worker_id, "stale": settings.stale_job_threshold_seconds,
             "attempts": settings.validation_max_attempts})
    await session.commit()
    row = result.mappings().first()
    return dict(row) if row else None


async def emit_validation_event(
    session: AsyncSession, job_id: str, event: str, data: dict,
) -> None:
    await session.execute(text("""
        INSERT INTO validation_events (job_id, seq, event, data)
        VALUES (:job_id,
                COALESCE((SELECT MAX(seq)+1 FROM validation_events WHERE job_id=:job_id), 1),
                :event, CAST(:data AS jsonb))
    """), {"job_id": job_id, "event": event, "data": json.dumps(data)})
    await session.commit()


async def validation_heartbeat(session: AsyncSession, job_id: str) -> None:
    await session.execute(
        text("UPDATE validation_jobs SET status='running', heartbeat_at=now() WHERE id=:id"),
        {"id": job_id},
    )
    await session.commit()


async def fail_validation(session: AsyncSession, job_id: str, error: str) -> None:
    await session.execute(text("""
        UPDATE validation_jobs SET status='failed', error=:error, completed_at=now()
        WHERE id=:id
    """), {"id": job_id, "error": error[:4000]})
    await session.commit()
    await emit_validation_event(session, job_id, "validation:failed", {"error": error[:500]})
