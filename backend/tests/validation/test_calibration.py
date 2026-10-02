"""Phase 5 -- calibration + the adjudicator."""
from __future__ import annotations

import pytest

from app.engines.validation.adjudicate import adjudicate, default_calibration
from app.engines.validation.calibration import (
    fit_calibration, score, separation,
)
from app.engines.validation.corpus import evaluation_corpus, fitting_corpus
from app.engines.validation.mock_target import MockSqliTarget, MockTimingTarget
from app.engines.validation.oracles.differential import run_boolean_differential
from app.engines.validation.oracles.timing import run_timing_differential
from app.engines.validation.writer import corroboration_warnings, write

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"


def _diff(mode="vulnerable"):
    return run_boolean_differential(MockSqliTarget(mode), asset_id="api-01",
                                    endpoint="/search", param="q",
                                    base_value="book", cvss_vector=VEC,
                                    cve="CVE-1").verdict


def _timing(mode="vulnerable"):
    return run_timing_differential(MockTimingTarget(mode), asset_id="api-01",
                                   endpoint="/search", param="q",
                                   base_value="book", cvss_vector=VEC).verdict


# --------------------------------------------------------------- fitting

class TestFitting:
    def test_positive_llrs_are_positive_negative_are_negative(self):
        cal = default_calibration()
        assert all(v > 0 for v in cal.llr_pos.values())
        assert all(v < 0 for v in cal.llr_neg.values())

    def test_llrs_are_clamped(self):
        cal = default_calibration()
        assert all(abs(v) <= 4.0 for v in cal.llr_pos.values())
        assert all(abs(v) <= 4.0 for v in cal.llr_neg.values())

    def test_prior_is_neutral(self):
        """Neutral, not the scanner base rate: an independent instrument does not
        inherit the scanner's bias (and in assist mode there is no scanner)."""
        assert default_calibration().prior == 0.5

    def test_fit_is_deterministic(self):
        a = fit_calibration(fitting_corpus()).as_dict()
        b = fit_calibration(fitting_corpus()).as_dict()
        assert a == b

    def test_absent_family_contributes_zero(self):
        cal = default_calibration()
        assert cal.contribution("time", "absent") == 0.0


# --------------------------------------------------------------- scoring

class TestScoring:
    def test_corroborated_beats_single_channel_beats_prior(self):
        cal = default_calibration()
        _, p_none, _ = score(cal, {})
        _, p_one, _ = score(cal, {"content": "pos"})
        _, p_two, _ = score(cal, {"content": "pos", "time": "pos"})
        assert p_none < p_one < p_two

    def test_disproof_drives_confidence_below_the_prior(self):
        cal = default_calibration()
        _, p_prior, _ = score(cal, {})
        _, p_neg, _ = score(cal, {"content": "neg", "time": "neg"})
        assert p_neg < p_prior

    def test_contribution_breakdown_sums_to_the_logit(self):
        cal = default_calibration()
        logit, _, contribs = score(cal, {"content": "pos", "time": "pos"})
        assert sum(c["contribution"] for c in contribs) == pytest.approx(logit, abs=1e-3)


# --------------------------------------------------------------- adjudicator

class TestAdjudicator:
    def test_single_channel_is_validated_but_not_corroborated(self):
        a = adjudicate([_diff("vulnerable")])
        assert a.status == "validated" and not a.corroborated
        assert corroboration_warnings(a.verdict)

    def test_corroboration_clears_the_warning_and_raises_confidence(self):
        single = adjudicate([_diff("vulnerable")])
        both = adjudicate([_diff("vulnerable"), _timing("vulnerable")])
        assert both.corroborated and corroboration_warnings(both.verdict) == []
        assert both.confidence > single.confidence

    def test_secure_is_a_confident_false_positive(self):
        a = adjudicate([_diff("secure"), _timing("secure")])
        assert a.status == "false_positive" and a.confidence < 0.1

    def test_channel_disagreement_abstains(self):
        a = adjudicate([_diff("vulnerable"), _timing("secure")])
        assert a.status == "inconclusive"

    def test_confidence_is_calibrated_not_the_placeholder(self):
        """Phase 4's combiner returned ~0.985 by independent-OR; the calibrated
        posterior is traceable to measured LLRs and sits below the placeholder."""
        single = adjudicate([_diff("vulnerable")])
        both = adjudicate([_diff("vulnerable"), _timing("vulnerable")])
        assert single.confidence < both.confidence < 0.985

    def test_adjudicated_row_is_contract_valid(self):
        a = adjudicate([_diff("vulnerable"), _timing("vulnerable")])
        assert write([a.verdict]).validation["ok"]

    def test_determinism(self):
        a = adjudicate([_diff("vulnerable"), _timing("vulnerable")])
        b = adjudicate([_diff("vulnerable"), _timing("vulnerable")])
        assert a.confidence == b.confidence and a.contributions == b.contributions

    def test_refuses_mixed_candidates(self):
        other = run_boolean_differential(MockSqliTarget("vulnerable"),
                                         asset_id="OTHER", endpoint="/x",
                                         param="q", base_value="book").verdict
        with pytest.raises(ValueError):
            adjudicate([_diff("vulnerable"), other])


# --------------------------------------------------------------- reliability

class TestReliability:
    def test_the_model_separates_vulnerable_from_safe(self):
        cal = default_calibration()
        pairs = [(score(cal, s)[1], y) for y, s in evaluation_corpus(4)]
        assert separation(pairs)["auc"] == 1.0

    def test_everything_above_the_decision_threshold_is_correct(self):
        """The property that matters for a decision engine: on this corpus every
        finding scored at or above the 0.5 validate threshold is truly
        vulnerable. (Below the threshold the score is conservative -- single-
        channel truths sit under 0.5 -- which is the safe direction.)"""
        cal = default_calibration()
        pairs = [(score(cal, s)[1], y) for y, s in evaluation_corpus(4)]
        assert any(p > 0.5 for p, _ in pairs)
        # a no-evidence case sits at exactly 0.5 (neutral); a positive DECISION
        # is p > 0.5, and every such case is truly vulnerable
        assert all(y for p, y in pairs if p > 0.5)

    def test_reliability_is_deterministic(self):
        cal = default_calibration()
        p1 = [(score(cal, s)[1], y) for y, s in evaluation_corpus(3)]
        p2 = [(score(cal, s)[1], y) for y, s in evaluation_corpus(3)]
        assert p1 == p2
