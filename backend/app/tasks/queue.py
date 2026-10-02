"""
IMPLEMENTATION_SPEC_v4.md §8: Postgres-only orchestration. No Celery, no
Redis. Job claiming via SKIP LOCKED (pooler-safe as-is); real-time push via
polling as the ALWAYS-ON DEFAULT, with LISTEN/NOTIFY layered on top only
after a runtime self-test passes (a transaction-mode pooler in front of
Postgres makes LISTEN silently stop receiving, with zero error anywhere —
see the spec for the primary-source citations).

Concrete numbers (do not "tune" these without re-reading spec §8 first):
    heartbeat_interval = 15s   (updated DURING long stages, not just between)
    stale_threshold     = 300s
    attempt_count      <= 3
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
import asyncpg
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

logger = logging.getLogger(__name__)

_CLAIM_SQL = text("""
UPDATE scan_jobs
SET status='claimed', claimed_by=:worker_id, claimed_at=now(), heartbeat_at=now(),
    attempt_count = attempt_count + 1
WHERE id = (
  SELECT id FROM scan_jobs
  WHERE status='queued'
     OR (status IN ('claimed','running')
         AND heartbeat_at < now() - (:stale_seconds * INTERVAL '1 second')
         AND attempt_count < :max_attempts)
  ORDER BY created_at
  LIMIT 1
  FOR UPDATE SKIP LOCKED
)
RETURNING id, target, profile, scan_run_id, custom_header_names;
""")


async def claim_next_job(session: AsyncSession, worker_id: str) -> dict | None:
    """Claim exactly one job, or reclaim one whose heartbeat has gone stale
    (crashed worker). MUST commit immediately in its own transaction — never
    share this transaction with the pipeline run that follows, or you hold a
    row lock for the whole scan and defeat SKIP LOCKED's purpose
    (IMPLEMENTATION_SPEC_v4.md §10 risk #15).
    """
    await session.execute(text("""
        UPDATE scan_jobs
        SET status='failed', completed_at=now(),
            error='retry budget exhausted after stale worker claims'
        WHERE status IN ('claimed','running')
          AND heartbeat_at < now() - (:stale_seconds * INTERVAL '1 second')
          AND attempt_count >= :max_attempts
    """), {
        "stale_seconds": settings.stale_job_threshold_seconds,
        "max_attempts": settings.max_job_attempts,
    })
    result = await session.execute(
        _CLAIM_SQL,
        {
            "worker_id": worker_id,
            "stale_seconds": settings.stale_job_threshold_seconds,
            "max_attempts": settings.max_job_attempts,
        },
    )
    await session.commit()  # commit HERE, before any pipeline work starts
    row = result.mappings().first()
    return dict(row) if row else None


async def heartbeat(session: AsyncSession, job_id: str) -> None:
    """Call this DURING long stages (not only between them) — a stage that
    legitimately runs 4 minutes must not look stale at the 5-minute mark.
    Commits immediately; callers should invoke this from a periodic task
    running alongside (not blocking) the stage's own work.
    """
    await session.execute(
        text("UPDATE scan_jobs SET heartbeat_at = now() WHERE id = :id"),
        {"id": job_id},
    )
    await session.commit()


async def mark_completed(session: AsyncSession, job_id: str) -> None:
    await session.execute(
        text("UPDATE scan_jobs SET status='completed', completed_at=now() WHERE id=:id"),
        {"id": job_id},
    )
    await session.commit()


async def mark_failed(session: AsyncSession, job_id: str, error: str) -> None:
    await session.execute(
        text("UPDATE scan_jobs SET status='failed', completed_at=now(), error=:err WHERE id=:id"),
        {"id": job_id, "err": error[:4000]},
    )
    await session.commit()


class HeartbeatLoop:
    """Runs alongside a long stage, updating heartbeat_at every
    HEARTBEAT_INTERVAL_SECONDS until cancelled. Use as an async context
    manager wrapping the stage's own work.
    """

    def __init__(self, session_factory, job_id: str):
        self._session_factory = session_factory
        self._job_id = job_id
        self._task: asyncio.Task | None = None

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(settings.heartbeat_interval_seconds)
            async with self._session_factory() as session:
                await heartbeat(session, self._job_id)

    async def __aenter__(self) -> "HeartbeatLoop":
        self._task = asyncio.create_task(self._loop())
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._task and not self._task.done():
            self._task.cancel()


# --------------------------------------------------------------------------
# Real-time events: durable table + polling default + self-testing NOTIFY
# --------------------------------------------------------------------------

async def emit_event(session: AsyncSession, job_id: str, event: str, data: dict) -> int:
    """Write a durable event row and best-effort NOTIFY. The payload sent via
    pg_notify is tiny (job_id + seq only) — it's a "go fetch" pointer, never
    the event body itself, which stays well under NOTIFY's 8000-byte limit
    even if a caller accidentally tries to shove something huge into `data`.
    """
    result = await session.execute(
        text("""
            INSERT INTO scan_events (job_id, seq, event, data)
            VALUES (:job_id,
                    COALESCE((SELECT MAX(seq) + 1 FROM scan_events WHERE job_id = :job_id), 1),
                    :event, :data)
            RETURNING seq
        """),
        {"job_id": job_id, "event": event, "data": json.dumps(data)},
    )
    seq = result.scalar_one()
    await session.commit()

    notify_bus = get_notify_bus()
    if notify_bus and notify_bus.healthy:
        try:
            await notify_bus.notify(json.dumps({"job_id": str(job_id), "seq": seq}))
        except Exception:
            logger.warning("NOTIFY failed post-hoc; polling clients are unaffected", exc_info=True)

    return seq


class NotifyBus:
    """Optional latency optimization layered on top of the polling default.
    Self-tests at startup: LISTEN a canary channel, NOTIFY itself, confirm
    receipt within LISTEN_NOTIFY_SELFTEST_TIMEOUT_SECONDS. If it doesn't
    arrive (most commonly: a transaction-mode connection pooler sits in
    front of this Postgres instance and silently ate the LISTEN
    registration), log loudly and disable — polling continues regardless and
    is the correctness backstop, not a fallback.

    IMPORTANT: this class needs its own dedicated asyncpg connection, NOT one
    borrowed from the SQLAlchemy pool. If DATABASE_URL points at a pooled
    connection string in your deployment, set a separate
    DATABASE_URL_DIRECT env var for this connection specifically.
    """

    CHANNEL = "scan_events_channel"
    _SELFTEST_CHANNEL = "discovery_selftest_channel"

    def __init__(self, dsn: str):
        self._dsn = dsn
        self._conn: asyncpg.Connection | None = None
        self.healthy = False
        self._subscribers: dict[str, list[asyncio.Queue]] = {}

    async def start(self) -> None:
        try:
            self._conn = await asyncpg.connect(self._dsn)
        except Exception:
            logger.warning("NotifyBus: could not open a dedicated connection; polling only", exc_info=True)
            self.healthy = False
            return

        received = asyncio.Event()

        def _on_selftest(*_args) -> None:
            received.set()

        await self._conn.add_listener(self._SELFTEST_CHANNEL, _on_selftest)
        token = str(uuid.uuid4())
        await self._conn.execute(f"NOTIFY {self._SELFTEST_CHANNEL}, '{token}'")

        try:
            await asyncio.wait_for(received.wait(), timeout=settings.listen_notify_selftest_timeout_seconds)
            self.healthy = True
            logger.info("NotifyBus self-test PASSED — LISTEN/NOTIFY is active on top of polling")
        except asyncio.TimeoutError:
            self.healthy = False
            logger.warning(
                "NotifyBus self-test FAILED (no NOTIFY received within %ss) — "
                "this almost always means a transaction-mode connection pooler "
                "(PgBouncer/RDS Proxy/Supabase pooler) sits in front of this "
                "Postgres instance. Falling back to polling-only for this "
                "process's lifetime. This is expected, safe behavior, not an error.",
                settings.listen_notify_selftest_timeout_seconds,
            )
        finally:
            await self._conn.remove_listener(self._SELFTEST_CHANNEL, _on_selftest)

        if self.healthy:
            await self._conn.add_listener(self.CHANNEL, self._dispatch)

    def _dispatch(self, connection, pid, channel, payload) -> None:
        for queue in self._subscribers.get("*", []):
            queue.put_nowait(payload)

    async def notify(self, payload: str) -> None:
        if not self._conn:
            return
        escaped = payload.replace("'", "''")
        await self._conn.execute(f"NOTIFY {self.CHANNEL}, '{escaped}'")

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault("*", []).append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.get("*", []).remove(q)

    async def stop(self) -> None:
        if self._conn:
            await self._conn.close()


_notify_bus: NotifyBus | None = None


def get_notify_bus() -> NotifyBus | None:
    return _notify_bus


async def init_notify_bus(dsn: str) -> None:
    global _notify_bus
    _notify_bus = NotifyBus(dsn)
    await _notify_bus.start()


async def poll_events_since(session: AsyncSession, job_id: str, after_seq: int) -> list[dict]:
    """The resilient PRIMARY path for clients, not a late-join fallback —
    see IMPLEMENTATION_SPEC_v4.md §8. WebSocket clients use NotifyBus (if
    healthy) purely as a latency optimization on top of this.
    """
    result = await session.execute(
        text("""
            SELECT seq, event, data, created_at FROM scan_events
            WHERE job_id = :job_id AND seq > :after_seq
            ORDER BY seq
        """),
        {"job_id": job_id, "after_seq": after_seq},
    )
    return [dict(r) for r in result.mappings().all()]
