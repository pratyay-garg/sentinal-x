"""
The adjudicator -- the calibrated replacement for the Phase 4 combiner.

Same merge and decision logic; the confidence is now a calibrated naive-Bayes
posterior instead of an independent-OR guess. It takes the per-oracle verdicts
for ONE candidate, derives each family's signal, sums the fitted per-family LLRs
onto the prior, and reports:

  * status   -- validated / false_positive / inconclusive, gated by corroboration
  * confidence -- a CALIBRATED probability (see calibration.py + the reliability
    diagram): when it says 0.9, ~90% of such findings were truly vulnerable
  * a per-family contribution breakdown that renders straight into the dashboard
    as the explainability artifact

The default calibration is fitted once, lazily, from the labeled corpus and
cached; it is deterministic, so confidences are byte-identical across runs and
processes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from .calibration import Calibration, fit_calibration, score
from .writer import (
    FAILURE_FAMILY, SELF_CORROBORATING, Candidate, Verdict, fingerprint,
)

VALIDATE_AT = 0.5          # posterior threshold for a positive decision


@dataclass
class Adjudication:
    verdict: Verdict
    contributions: list = field(default_factory=list)
    corroborated: bool = False
    logit: float = 0.0

    @property
    def status(self):
        return self.verdict.status

    @property
    def confidence(self):
        return self.verdict.confidence


@lru_cache(maxsize=1)
def default_calibration() -> Calibration:
    from .corpus import fitting_corpus
    return fit_calibration(fitting_corpus())


def _verdict(x) -> Verdict:
    return x.verdict if hasattr(x, "verdict") else x


def _signals(verdicts) -> tuple[dict, set, set]:
    """family -> signal, plus the sets of positive and self-corroborating
    families that fired."""
    signals: dict[str, str] = {}
    positives: set[str] = set()
    self_corr: set[str] = set()
    for v in verdicts:
        for o in v.outcomes:
            fam = FAILURE_FAMILY.get(o.oracle, o.oracle)
            if o.fired:
                signals[fam] = "pos"
                positives.add(fam)
                if o.oracle in SELF_CORROBORATING:
                    self_corr.add(fam)
            elif v.status == "false_positive":
                signals.setdefault(fam, "neg")
            else:
                signals.setdefault(fam, "absent")
    return signals, positives, self_corr


def adjudicate(results, *, calibration: Calibration | None = None) -> Adjudication:
    cal = calibration or default_calibration()
    verdicts = [_verdict(r) for r in results]
    if not verdicts:
        raise ValueError("adjudicate() needs at least one result")
    fps = {fingerprint(v.candidate) for v in verdicts}
    if len(fps) != 1:
        raise ValueError("adjudicate() got more than one candidate")

    candidate: Candidate = verdicts[0].candidate
    outcomes = tuple(o for v in verdicts for o in v.outcomes)
    signals, positives, self_corr = _signals(verdicts)
    negatives = {f for f, s in signals.items() if s == "neg"}

    logit, prob, contribs = score(cal, signals)

    corroborated = bool(self_corr or len(positives) >= 2)
    if positives and negatives:
        status = "inconclusive"          # channels disagree -> abstain
    elif positives:
        # a self-corroborating direct-evidence oracle, or two disjoint families,
        # validates on the strength of the evidence; a lone inferential family
        # must also clear the calibrated threshold.
        status = "validated" if (corroborated or prob >= VALIDATE_AT) else "inconclusive"
    elif negatives:
        status = "false_positive"
    else:
        status = "inconclusive"

    proven_route = next((v.proven_route for v in verdicts if v.proven_route), None)
    discovered = next((v.discovered_target for v in verdicts if v.discovered_target), None)

    v = Verdict(candidate=candidate, status=status, confidence=round(prob, 4),
                outcomes=outcomes, evidence_id=verdicts[0].evidence_id,
                proven_route=proven_route, discovered_target=discovered)
    return Adjudication(verdict=v, contributions=contribs,
                        corroborated=corroborated, logit=round(logit, 4))
