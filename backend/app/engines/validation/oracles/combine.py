"""
Corroboration combiner -- the Phase 4 payoff, and the seed of the Phase 5
adjudicator.

A single oracle produces a single-family verdict. When two oracles with DISJOINT
failure modes agree on the same candidate -- the differential oracle (family
'content', broken by caching) and the timing oracle (family 'time', broken by
load) -- their agreement is real corroboration, because nothing plausible breaks
both at once. This function merges their outcomes into one Verdict so that:

  * writer.corroboration_warnings() sees two disjoint families and stays silent;
  * writer.observations() picks the strongest observed grant across oracles;
  * confidence rises above either oracle alone.

The confidence combination here is deliberately simple (independent-OR on the
per-oracle confidences). PHASE 5 REPLACES IT with a calibrated naive-Bayes sum
of per-family log-likelihood ratios fitted against ground-truth testbeds. The
merge/decision logic below stays; only the number changes.
"""
from __future__ import annotations

from ..writer import Candidate, Verdict, fingerprint


def _verdict(x) -> Verdict:
    return x.verdict if hasattr(x, "verdict") else x


def combine(results, *, evidence_id: str | None = None) -> Verdict:
    """Merge oracle results for ONE candidate into a corroborated Verdict.

    All inputs must concern the same candidate (same fingerprint); mixing
    candidates is a programming error, not a runtime condition.
    """
    verdicts = [_verdict(r) for r in results]
    if not verdicts:
        raise ValueError("combine() needs at least one result")

    fps = {fingerprint(v.candidate) for v in verdicts}
    if len(fps) != 1:
        raise ValueError(f"combine() got {len(fps)} distinct candidates; "
                         f"only one candidate may be corroborated at a time")

    candidate: Candidate = verdicts[0].candidate
    outcomes = tuple(o for v in verdicts for o in v.outcomes)

    validated = [v for v in verdicts if v.status == "validated"]
    false_pos = [v for v in verdicts if v.status == "false_positive"]

    if validated and not false_pos:
        status = "validated"
    elif false_pos and not validated:
        status = "false_positive"
    elif validated and false_pos:
        # genuine disagreement between channels -> abstain rather than pick a side
        status = "inconclusive"
    else:
        status = "inconclusive"

    if status == "validated":
        # independent-OR of per-oracle confidence (Phase 5: calibrated LLR sum)
        prod_miss = 1.0
        for v in validated:
            prod_miss *= (1.0 - float(v.confidence))
        conf = round(min(0.99, 1.0 - prod_miss), 4)
    elif status == "false_positive":
        conf = round(min(v.confidence for v in false_pos), 4)
    else:
        conf = 0.40

    # keep any proven route / discovered target a channel established
    proven_route = next((v.proven_route for v in verdicts if v.proven_route), None)
    discovered = next((v.discovered_target for v in verdicts if v.discovered_target), None)
    evidence = evidence_id or verdicts[0].evidence_id

    return Verdict(candidate=candidate, status=status, confidence=conf,
                   outcomes=outcomes, evidence_id=evidence,
                   proven_route=proven_route, discovered_target=discovered)
