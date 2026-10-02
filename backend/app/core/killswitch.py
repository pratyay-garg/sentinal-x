"""
IMPLEMENTATION_SPEC_v4.md §8/§10 risk #14: a killswitch checked only between
pipeline stages will not stop a Nuclei run with 8 minutes left. This module
provides both the cheap between-stage check AND a background poller that can
kill an in-flight subprocess's whole process group the moment the switch
trips, for any stage expected to run more than ~30 seconds.
"""
from __future__ import annotations

import asyncio
import os
import signal
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from app.models import ScanJob, SystemControl


async def is_killswitch_engaged(session: AsyncSession) -> tuple[bool, str | None]:
    row = await session.get(SystemControl, 1)
    if row is None:
        return False, None  # no row yet == not engaged; migration seeds id=1 with False
    return row.killswitch_engaged, row.reason


async def is_job_cancelled(session: AsyncSession, job_id: str) -> bool:
    job = await session.get(ScanJob, job_id)
    return bool(job and job.cancel_requested)


class StageGuard:
    """Wrap a long-running subprocess call with a background poller that
    kills the process GROUP (not just the process) the instant the global
    killswitch trips or this specific job is cancelled.

    Usage:
        async with StageGuard(session_factory, job_id, proc) as guard:
            await asyncio.wait_for(proc.communicate(), timeout=stage_timeout)
        # guard's __aexit__ cancels the poller automatically either way.
    """

    def __init__(self, session_factory, job_id: str, proc: asyncio.subprocess.Process):
        self._session_factory = session_factory
        self._job_id = job_id
        self._proc = proc
        self._poller_task: asyncio.Task | None = None

    async def _poll_loop(self) -> None:
        while True:
            await asyncio.sleep(settings.killswitch_poll_interval_seconds)
            async with self._session_factory() as session:
                engaged, reason = await is_killswitch_engaged(session)
                cancelled = await is_job_cancelled(session, self._job_id)
            if engaged or cancelled:
                kill_process_group(self._proc)
                return

    async def __aenter__(self) -> "StageGuard":
        self._poller_task = asyncio.create_task(self._poll_loop())
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._poller_task and not self._poller_task.done():
            self._poller_task.cancel()


def kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """Kill the ENTIRE process group, not just proc.pid. See
    IMPLEMENTATION_SPEC_v4.md §5/§10 risk #9: Nuclei's headless mode spawns a
    Chromium child; proc.kill() alone orphans it. Every subprocess in this
    codebase is launched with start_new_session=True (app/subprocess_utils.py)
    specifically so this call is safe and effective.
    """
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # already dead — fine
