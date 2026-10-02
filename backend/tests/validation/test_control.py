"""Phase 1 -- the control engine and safety substrate.

Everything runs against the in-process MockTarget, so these tests need no
network and cannot flake. The async limiter is driven with asyncio.run() rather
than a plugin.
"""
from __future__ import annotations

import asyncio

import pytest

from app.engines.validation.control import (
    USABILITY_FLOOR, jaccard, sample_baseline, shingles, similarity,
)
from app.engines.validation.http import Request, Response
from app.engines.validation.limiter import KillSwitchError, TargetLimiter
from app.engines.validation.mock_target import MockTarget
from app.engines.validation.sanity import sanity_canary
from app.engines.validation.scope import OutOfScopeError, Scope, assert_in_scope, in_scope


# --------------------------------------------------------------- scope gate

class TestScopeGate:
    def _scope(self):
        return Scope(cidrs=("10.0.0.0/24",), hosts=("target.local",))

    def test_empty_scope_permits_nothing(self):
        assert not in_scope(Scope(), "https://target.local/")

    def test_allowed_host_and_subdomain(self):
        s = self._scope()
        assert in_scope(s, "https://target.local/search")
        assert in_scope(s, "https://api.target.local/v1")   # suffix match

    def test_unrelated_host_is_refused(self):
        assert not in_scope(self._scope(), "https://evil.example.com/")

    def test_ip_inside_and_outside_cidr(self):
        s = self._scope()
        assert in_scope(s, "http://10.0.0.15/")
        assert not in_scope(s, "http://10.0.1.15/")

    def test_non_http_schemes_are_refused(self):
        """SSRF-adjacent schemes must never be followed."""
        s = self._scope()
        for u in ("file:///etc/passwd", "gopher://target.local/",
                  "ftp://target.local/", "data:text/html,x"):
            assert not in_scope(s, u)

    def test_embedded_credentials_are_refused(self):
        assert not in_scope(self._scope(), "https://user:pass@target.local/")

    def test_assert_raises_out_of_scope(self):
        with pytest.raises(OutOfScopeError):
            assert_in_scope(self._scope(), "https://evil.example.com/")

    def test_assert_passes_in_scope(self):
        assert_in_scope(self._scope(), "https://target.local/")  # no raise

    def test_reason_is_always_populated(self):
        ok, reason = self._scope().permits("https://nope.example.com/")
        assert not ok and reason


# --------------------------------------------------------------- similarity math

class TestSimilarity:
    def test_identical_text_is_one(self):
        assert similarity("the quick brown fox jumps", "the quick brown fox jumps") == 1.0

    def test_disjoint_text_is_zero(self):
        assert similarity("alpha beta gamma delta", "one two three four") == 0.0

    def test_jaccard_of_two_empty_sets_is_one(self):
        assert jaccard(frozenset(), frozenset()) == 1.0

    def test_short_text_falls_back_to_token_set(self):
        assert shingles("hi there", w=3) == frozenset({"hi", "there"})

    def test_small_change_stays_highly_similar(self):
        """A one-token change in a realistically large body barely moves the
        score -- which is exactly why shingle Jaccard is a good volatility
        metric for whole HTML pages (a ticking clock is a tiny fraction of the
        shingles). On short strings the same change dominates, so the test uses
        a long body, as real pages are."""
        base = " ".join(f"word{i}" for i in range(200))
        a = base + " dog"
        b = base + " cat"
        assert 0.9 < similarity(a, b) < 1.0


# --------------------------------------------------------------- learned volatility

class TestLearnedVolatility:
    def test_stable_endpoint_is_usable_with_a_high_threshold(self):
        bl = sample_baseline(MockTarget("stable"), Request.get("/"), k=5)
        assert bl.content_usable
        assert bl.min_pair_similarity == 1.0          # identical baselines
        assert bl.content_threshold >= 0.9

    def test_a_real_change_is_flagged_different_on_a_stable_endpoint(self):
        bl = sample_baseline(MockTarget("stable"), Request.get("/"), k=5)
        injected = Response(200, "<html><body>totally different error page "
                                 "stack trace exception at line 42</body></html>")
        assert bl.is_different(injected)

    def test_the_same_page_is_not_flagged_different(self):
        target = MockTarget("stable")
        bl = sample_baseline(target, Request.get("/"), k=5)
        assert not bl.is_different(target(Request.get("/")))

    def test_dynamic_endpoint_learns_a_looser_threshold_but_stays_usable(self):
        """Per-request timestamp + CSRF token: baselines agree closely but not
        perfectly, so the threshold drops below 1.0 yet stays above the floor."""
        bl = sample_baseline(MockTarget("dynamic"), Request.get("/"), k=6)
        assert bl.content_usable
        assert bl.min_pair_similarity < 1.0
        assert bl.content_threshold >= USABILITY_FLOOR

    def test_dynamic_noise_alone_is_not_flagged_as_a_finding(self):
        """The natural per-request variation must fall INSIDE the learned
        threshold -- otherwise every probe on a dynamic page is a false positive."""
        target = MockTarget("dynamic")
        bl = sample_baseline(target, Request.get("/"), k=6)
        assert not bl.is_different(target(Request.get("/")))

    def test_one_sample_is_not_usable(self):
        bl = sample_baseline(MockTarget("stable"), Request.get("/"), k=1)
        assert not bl.content_usable and "at least 2" in bl.reason

    def test_unusable_baseline_refuses_to_classify(self):
        bl = sample_baseline(MockTarget("stable"), Request.get("/"), k=1)
        with pytest.raises(ValueError):
            bl.is_different(Response(200, "x"))

    def test_timing_stats_are_captured(self):
        bl = sample_baseline(MockTarget("stable"), Request.get("/"), k=5)
        assert bl.time_median_ms > 0 and bl.time_mad_ms >= 0

    def test_baseline_is_deterministic(self):
        a = sample_baseline(MockTarget("dynamic", seed=7), Request.get("/"), k=5)
        b = sample_baseline(MockTarget("dynamic", seed=7), Request.get("/"), k=5)
        assert a.content_threshold == b.content_threshold
        assert a.time_median_ms == b.time_median_ms


# --------------------------------------------------------------- sanity canary

class TestSanityCanary:
    def test_healthy_server_is_trustworthy(self):
        r = sanity_canary(MockTarget("stable"))
        assert r.trustworthy and r.bad_status == 404

    def test_catch_all_server_is_caught(self):
        r = sanity_canary(MockTarget("catch_all"))
        assert not r.trustworthy
        assert "catch-all" in r.reason
        assert r.bad_status == 200 and r.good_bad_similarity >= 0.9

    def test_blocking_server_is_caught(self):
        r = sanity_canary(MockTarget("blocking"))
        assert not r.trustworthy
        assert r.good_status == 403

    def test_nonsense_path_is_deterministic(self):
        a = sanity_canary(MockTarget("stable"), seed=99)
        b = sanity_canary(MockTarget("stable"), seed=99)
        assert a.as_dict() == b.as_dict()


# --------------------------------------------------------------- limiter

class TestTargetLimiter:
    def test_timing_lock_serialises_one_target(self):
        """Two coroutines contending for the same target's timing lock must not
        interleave -- that is what prevents a self-inflicted DoS poisoning the
        timing oracle."""
        lim = TargetLimiter(rate_per_sec=0)      # disable rate wait for this test
        events: list[str] = []

        async def worker(tag: str):
            async with lim.timing_lock("api.target.local"):
                events.append(f"{tag}-start")
                await asyncio.sleep(0.01)
                events.append(f"{tag}-end")

        async def main():
            await asyncio.gather(worker("A"), worker("B"))

        asyncio.run(main())
        # whichever ran first, its start and end are adjacent (no interleave)
        assert events[0].endswith("-start") and events[1].endswith("-end")
        assert events[0][0] == events[1][0]
        assert events[2][0] == events[3][0]

    def test_different_targets_get_different_locks(self):
        lim = TargetLimiter()
        assert lim.timing_lock("a.local") is not lim.timing_lock("b.local")
        assert lim.timing_lock("a.local") is lim.timing_lock("A.local/")  # normalised

    def test_kill_switch_stops_acquire(self):
        lim = TargetLimiter(rate_per_sec=100)
        lim.kill()

        async def main():
            await lim.acquire("target.local")

        with pytest.raises(KillSwitchError):
            asyncio.run(main())

    def test_resume_reenables_acquire(self):
        lim = TargetLimiter(rate_per_sec=1000)
        lim.kill()
        lim.resume()

        async def main():
            await lim.acquire("target.local")   # must not raise

        asyncio.run(main())

    def test_rate_limit_spaces_requests(self):
        lim = TargetLimiter(rate_per_sec=50)     # 20 ms apart

        async def main():
            loop = asyncio.get_event_loop()
            await lim.acquire("t.local")
            t0 = loop.time()
            await lim.acquire("t.local")
            return loop.time() - t0

        gap = asyncio.run(main())
        assert gap >= 0.018      # ~20 ms, allow scheduler slack
