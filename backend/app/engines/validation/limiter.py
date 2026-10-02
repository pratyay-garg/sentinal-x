"""
Per-target concurrency + rate control, and the global kill switch.

Two safety jobs (LAW 5), one primitive:

  * TIMING MUTEX. If several timing probes hit one target concurrently they
    exhaust its connection pool; the whole server then slows, the timing oracle
    reads that self-inflicted delay as a hit, and you have both a false positive
    AND an accidental DoS. So timing probes against a given target are
    serialised: exactly one at a time, per target.

  * RATE LIMIT. A minimum interval between requests to a target, so validation
    stays polite and does not itself degrade the thing it is measuring.

  * KILL SWITCH. One flag stops all further outbound work immediately.

This is the one genuinely async piece of Phase 1. The production httpx Fetcher
wraps each call in `acquire`, and the timing oracle additionally holds
`timing_lock` for the duration of a timing measurement. Everything else in the
control engine is synchronous and pure.
"""
from __future__ import annotations

import asyncio


class KillSwitchError(Exception):
    """Raised by acquire() once the limiter has been killed."""


def _target_key(target: str) -> str:
    return target.lower().rstrip("/")


class TargetLimiter:
    def __init__(self, rate_per_sec: float = 10.0):
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0
        self._locks: dict[str, asyncio.Lock] = {}
        self._last: dict[str, float] = {}
        self._killed = False

    # -- kill switch ------------------------------------------------------
    def kill(self) -> None:
        self._killed = True

    def resume(self) -> None:
        self._killed = False

    @property
    def killed(self) -> bool:
        return self._killed

    # -- timing mutex -----------------------------------------------------
    def timing_lock(self, target: str) -> asyncio.Lock:
        """The per-target lock a timing measurement holds for its whole
        duration. `async with limiter.timing_lock(t):`"""
        key = _target_key(target)
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    # -- rate limit -------------------------------------------------------
    async def acquire(self, target: str) -> None:
        """Await until it is polite to send the next request to `target`.
        Raises KillSwitchError if the run has been stopped."""
        if self._killed:
            raise KillSwitchError("validation run has been stopped")
        if self.min_interval <= 0:
            return
        key = _target_key(target)
        loop = asyncio.get_event_loop()
        now = loop.time()
        last = self._last.get(key)
        if last is not None:
            wait = self.min_interval - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
        self._last[key] = asyncio.get_event_loop().time()
