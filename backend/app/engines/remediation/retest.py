"""Explicit, scope-bound revalidation used after an operator applies a fix.

The validation engine remains the single implementation of live security probes.
This module only supplies concurrency control and a kill-switch callback.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from urllib.parse import urlsplit

import psycopg2

# The image copies backend/app to /srv/app, so the runtime package is `app`.
# Import through that canonical runtime name; source-tree tests put backend/ on
# the path so the same package resolves.
from app.core.config import settings
from app.engines.validation.service import validate_finding

_ORIGIN_LOCKS: dict[str, asyncio.Lock] = {}
_LOCKS_GUARD = asyncio.Lock()


async def _origin_lock(endpoint: str | None) -> asyncio.Lock:
    parsed = urlsplit((endpoint or "").split(" ", 1)[-1])
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else "unknown"
    async with _LOCKS_GUARD:
        return _ORIGIN_LOCKS.setdefault(origin, asyncio.Lock())


class KillSwitchCheck:
    """Synchronous callback used by LiveFetcher immediately before each request."""

    def __init__(self) -> None:
        dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
        self.connection = psycopg2.connect(dsn)
        self.connection.autocommit = True

    def __call__(self) -> str | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT killswitch_engaged, COALESCE(reason, '') "
                "FROM system_control WHERE id=1"
            )
            row = cursor.fetchone()
        return (row[1] or "global kill switch engaged") if row and row[0] else None

    def close(self) -> None:
        self.connection.close()


def _run(candidate: dict, matchers: list[str], headers: dict[str, str] | None) -> dict:
    stop = KillSwitchCheck()
    try:
        return validate_finding(candidate, matchers, should_stop=stop, headers=headers)
    finally:
        stop.close()


async def replay(
    candidate: dict, matchers: list[str], headers: dict[str, str] | None,
) -> dict:
    """Run one validation replay, serialized per target origin.

    This deliberately delegates all scope, redirect, body-size and method policy
    enforcement to the already hardened validation transport and service.
    """
    lock = await _origin_lock(candidate.get("endpoint"))
    async with lock:
        return await asyncio.to_thread(_run, candidate, matchers, headers)
