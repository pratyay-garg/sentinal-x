"""Phase 4 -- timing, execution, OOB oracles, and the corroboration payoff."""
from __future__ import annotations

import pytest

from app.engines.validation.mock_target import (
    CanaryListener, MockOOBTarget, MockSqliTarget, MockTimingTarget, MockXssTarget,
)
from app.engines.validation.oracles.combine import combine
from app.engines.validation.oracles.differential import run_boolean_differential
from app.engines.validation.oracles.execution import run_execution
from app.engines.validation.oracles.oob import run_oob
from app.engines.validation.oracles.timing import run_timing_differential
from app.engines.validation.writer import (
    corroboration_warnings, observations, to_finding_row, write,
)

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"


def _timing(mode, **kw):
    return run_timing_differential(
        MockTimingTarget(mode), asset_id="api-01", endpoint="/search", param="q",
        base_value="book", cvss_vector=VEC, cve="CVE-2026-1", **kw)


def _exec(mode, **kw):
    return run_execution(MockXssTarget(mode), asset_id="web-01", endpoint="/echo",
                         param="msg", vuln_class="xss_reflected", **kw)


def _oob(mode, oracle="oob_ssrf", **kw):
    lis = CanaryListener()
    return run_oob(MockOOBTarget(lis, mode), lis, asset_id="api-01",
                   endpoint="/fetch", param="url", oracle=oracle, **kw)


# --------------------------------------------------------------- timing

class TestTimingOracle:
    def test_vulnerable_scales_and_is_validated(self):
        r = _timing("vulnerable")
        assert r.verdict.status == "validated"
        assert r.z > 3.5 and abs(r.scale_ratio - 2.0) < 0.4

    def test_secure_has_no_timing_signal(self):
        assert _timing("secure").verdict.status == "false_positive"

    def test_tarpit_is_caught_by_the_negative_control(self):
        """A WAF that delays on any SLEEP token trips the no-quote control first:
        the delay reproduces without breaking the query, so it is confounded."""
        r = _timing("tarpit")
        assert r.verdict.status == "inconclusive"
        assert "without breaking the query" in r.reason.lower()

    def test_constant_delay_on_break_is_caught_by_the_scaling_check(self):
        """A constant delay that fires ONLY on break-out passes the z-gate and
        the control, yet fails scaling -- z alone is never enough."""
        r = _timing("const_on_break")
        assert r.verdict.status == "inconclusive"
        assert "does not scale" in r.reason

    def test_timing_claims_no_grant_and_is_single_family(self):
        v = _timing("vulnerable").verdict
        assert observations(v) == ((), None)
        assert corroboration_warnings(v)          # single family 'time'

    def test_determinism(self):
        assert _timing("vulnerable").z == _timing("vulnerable").z


# --------------------------------------------------------------- execution

class TestExecutionOracle:
    def test_execution_is_validated_and_observes_user_session(self):
        r = _exec("vulnerable")
        assert r.verdict.status == "validated" and r.executed
        assert observations(r.verdict) == (("network_reach",), "user_session")

    def test_execution_is_self_corroborating_no_warning(self):
        assert corroboration_warnings(_exec("vulnerable").verdict) == []

    def test_reflection_without_execution_is_not_a_finding(self):
        """The whole point: a marker reflected into a non-executable context is
        NOT exploitability."""
        r = _exec("reflected_safe")
        assert r.reflected and not r.executed
        assert r.verdict.status == "false_positive"

    def test_escaped_output_is_disproved(self):
        assert _exec("secure").verdict.status == "false_positive"

    def test_plaintext_control_guards_the_detector(self):
        """If a plain-text nonce 'executes', the renderer is untrustworthy."""
        class BrokenBrowser:
            def execute(self, body, nonce):        # fires on anything
                return True
        r = _exec("vulnerable", renderer=BrokenBrowser())
        assert r.verdict.status == "inconclusive"


# --------------------------------------------------------------- oob

class TestOOBOracle:
    def test_callback_validates_and_observes_network_reach(self):
        r = _oob("vulnerable", target_asset_id="db-01")
        assert r.verdict.status == "validated" and r.callback_received
        assert observations(r.verdict) == (("network_reach",), "network_reach")

    def test_ssrf_callback_emits_a_proven_route(self):
        r = _oob("vulnerable", target_asset_id="db-01")
        assert r.verdict.proven_route == ("api-01", "db-01")
        assert to_finding_row(r.verdict)  # writer accepts it
        assert write([r.verdict]).routes[0]["provenance"] == "observed"

    def test_no_callback_is_inconclusive_never_false_positive(self):
        """The honest asymmetry: silence cannot disprove a blind channel."""
        for mode in ("secure", "egress_filtered"):
            r = _oob(mode, target_asset_id="db-01")
            assert r.verdict.status == "inconclusive"

    def test_rce_and_xxe_map_to_their_grants(self):
        rce = _oob("vulnerable", oracle="oob_rce")
        xxe = _oob("vulnerable", oracle="oob_xxe")
        assert observations(rce.verdict)[1] == "code_exec"
        assert observations(xxe.verdict)[1] == "data_read"

    def test_oob_is_self_corroborating(self):
        assert corroboration_warnings(_oob("vulnerable").verdict) == []

    def test_unique_token_per_probe(self):
        lis = CanaryListener()
        assert lis.issue() != lis.issue()


# --------------------------------------------------------------- corroboration

class TestCorroboration:
    def _diff(self):
        return run_boolean_differential(
            MockSqliTarget("vulnerable"), asset_id="api-01", endpoint="/search",
            param="q", base_value="book", cvss_vector=VEC, cve="CVE-2026-1").verdict

    def test_two_disjoint_families_clear_the_warning(self):
        """THE PAYOFF. Differential (content) alone warns; timing (time) alone
        warns; together they corroborate and the warning disappears."""
        d, t = self._diff(), _timing("vulnerable").verdict
        assert corroboration_warnings(d) and corroboration_warnings(t)
        c = combine([d, t])
        assert c.status == "validated"
        assert corroboration_warnings(c) == []
        assert len(c.outcomes) == 2

    def test_corroborated_confidence_exceeds_either_alone(self):
        d, t = self._diff(), _timing("vulnerable").verdict
        c = combine([d, t])
        assert c.confidence > d.confidence and c.confidence > t.confidence

    def test_disagreement_between_channels_abstains(self):
        """One channel validates, another disproves -> inconclusive, not a
        coin-flip."""
        d = self._diff()
        t = _timing("secure").verdict          # false_positive
        assert combine([d, t]).status == "inconclusive"

    def test_combine_refuses_mixed_candidates(self):
        d = self._diff()
        other = run_boolean_differential(
            MockSqliTarget("vulnerable"), asset_id="OTHER", endpoint="/x",
            param="q", base_value="book").verdict
        with pytest.raises(ValueError):
            combine([d, other])

    def test_combined_row_is_contract_valid(self):
        c = combine([self._diff(), _timing("vulnerable").verdict])
        assert write([c]).validation["ok"]
