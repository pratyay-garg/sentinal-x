"""
The server-sanity canary -- the "is this server telling the truth?" meta-control.

Some servers are configured, or fronted by a WAF, such that a request for a path
that does not exist still returns 200 with generic content (a catch-all handler
or an SPA that serves index.html for everything). Against such a server EVERY
probe looks like it "worked", and a naive validator fires a false positive on
every endpoint.

Before trusting any content oracle we prove the server discriminates at all:
a known-good path should look real, and a random nonsense path should NOT look
like it. When that fails we return `trustworthy=False` with a reason, and the
adjudicator maps it to `inconclusive` rather than emitting garbage.

This is also a demo beat: point the engine at a catch-all server and watch a
lesser tool fire while ours reports the server is lying.

Determinism: the nonsense path is derived from a fixed seed, so a re-run probes
the identical path and produces the identical verdict.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from .control import similarity
from .http import Fetcher, Request

CATCH_ALL_SIMILARITY = 0.90     # nonsense ~ homepage this closely => catch-all


@dataclass
class SanityResult:
    trustworthy: bool
    reason: str
    good_status: int = 0
    bad_status: int = 0
    good_bad_similarity: float = 0.0

    def as_dict(self) -> dict:
        return {"trustworthy": self.trustworthy, "reason": self.reason,
                "good_status": self.good_status, "bad_status": self.bad_status,
                "good_bad_similarity": round(self.good_bad_similarity, 4)}


def _nonsense_path(seed: int) -> str:
    rng = random.Random(seed)
    token = "".join(rng.choice("0123456789abcdef") for _ in range(16))
    return f"/{token}-does-not-exist-{token[:6]}"


def sanity_canary(fetch: Fetcher, good_path: str = "/", *,
                  seed: int = 1337) -> SanityResult:
    good = fetch(Request.get(good_path))
    bad = fetch(Request.get(_nonsense_path(seed)))
    sim = similarity(good.body, bad.body)

    # 1. The baseline endpoint must itself be answerable with real content.
    if good.status in (401, 403):
        return SanityResult(
            False, f"baseline path returned {good.status}: server is blocking "
                   f"us (WAF or auth wall); content oracle cannot be trusted",
            good.status, bad.status, sim)
    if not good.is_2xx:
        return SanityResult(
            False, f"baseline path returned {good.status}, not 2xx; cannot "
                   f"establish a control",
            good.status, bad.status, sim)

    # 2. A nonsense path returning 2xx that looks like the homepage is a
    #    catch-all handler -- the classic liar.
    if bad.is_2xx and sim >= CATCH_ALL_SIMILARITY:
        return SanityResult(
            False, f"catch-all handler detected: a nonsense path returned "
                   f"{bad.status} with content {sim:.0%} similar to the "
                   f"baseline; every probe would appear to succeed",
            good.status, bad.status, sim)

    # 3. Healthy server: nonsense path is rejected or clearly different.
    return SanityResult(
        True, f"server discriminates (nonsense path -> {bad.status}, "
              f"{sim:.0%} similar); content oracle is trustworthy",
        good.status, bad.status, sim)
