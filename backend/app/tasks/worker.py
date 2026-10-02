"""
Worker process entrypoint. Run as its OWN container/process
(docker-compose.yml's `worker` service) — deliberately separate from the API
process so a crash or restart of one never kills a running scan owned by the
other. See IMPLEMENTATION_SPEC_v4.md §8.

    python -m app.tasks.worker
"""
from __future__ import annotations

import asyncio
import logging
import platform
import uuid

from app.core.config import settings
from app.core.db import get_session
from app.engines.discovery.runner import KillswitchTripped, ScopeViolation, run_pipeline
from .queue import claim_next_job, init_notify_bus, mark_completed, mark_failed
from app.core.runtime_config import refresh_runtime_overrides

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

WORKER_ID = f"{platform.node()}:{uuid.uuid4().hex[:8]}"


async def main() -> None:
    logger.info("discovery worker starting, id=%s", WORKER_ID)

    # NotifyBus is opportunistic — see queue.py. Failure to start it is not
    # fatal; polling is the correctness backstop regardless.
    await init_notify_bus(settings.database_url.replace("postgresql+asyncpg://", "postgresql://"))

    while True:
        job = None
        async with get_session() as session:
            job = await claim_next_job(session, WORKER_ID)
            if job is not None:
                # Pick up operator setting overrides (ADR-0007 D6) before the
                # pipeline reads them; this worker is a separate process.
                await refresh_runtime_overrides(session, settings)

        if job is None:
            await asyncio.sleep(settings.poll_interval_seconds)
            continue

        logger.info("claimed job %s target=%s", job["id"], job["target"])
        try:
            await run_pipeline(job)
            async with get_session() as session:
                await mark_completed(session, job["id"])
            logger.info("job %s completed", job["id"])
        except (ScopeViolation, KillswitchTripped) as exc:
            logger.warning("job %s halted: %s", job["id"], exc)
            async with get_session() as session:
                await mark_failed(session, job["id"], str(exc))
        except Exception as exc:  # noqa: BLE001 - top-level worker loop must never die
            logger.exception("job %s crashed", job["id"])
            async with get_session() as session:
                await mark_failed(session, job["id"], f"unhandled exception: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
