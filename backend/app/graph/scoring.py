"""
Edge probability as an additive log-odds scorecard.

    logit(P) = b + w1*cvss_exploitability + w2*logit(EPSS) + w3*evidence + w4*status

EPSS is a PRIOR, not a multiplier. Multiplying EPSS into the score is wrong for
four reasons and we do not do it:

  1. EPSS is heavily right-skewed (median ~1e-3). Multiplying collapses almost
     every edge to ~0, and a 10k-trial Monte Carlo over near-zero edges reaches
     nothing -- the heat map goes uniformly cold on stage.
  2. EPSS estimates "is this CVE being exploited somewhere in the world in the
     next 30 days". An edge needs "does this step work here, now". Those come
     apart constantly.
  3. EPSS's own model consumes CVSS components as features, so the product is
     the same evidence squared, biased downward.
  4. EPSS keys on CVE ids. Most of what our validator finds (XSS, IDOR, broken
     access control, misconfig) has no CVE, so coverage would be partial and
     edge semantics would be inconsistent across one graph.

In log-odds space the terms add, each contribution is separable, and a missing
EPSS contributes exactly zero instead of an invented default. The contribution
table below renders directly in the dashboard -- it is the explainability
artifact, not a debugging aid.

The same component powers the phishing risk score (Module 5) and the validation
confidence score (Module 2). Build once, use three times.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from .cvss import parse as parse_cvss
from .model import Provenance

# Hand-set weights. We do NOT claim these are calibrated -- we have no labelled
# corpus. sensitivity.py measures how stable the output ranking is under
# +/-30% perturbation of these values, which is the honest version of the claim.
WEIGHTS = {
    "bias": -1.20,
    "cvss_exploitability": 1.80,
    "epss_logit": 0.35,
    "evidence": 2.60,      # dominant by design: our proof outranks any prior
    "inconclusive": -0.80,
    "unvalidated": -0.50,
    "false_positive": -6.00,
    # A real vulnerability class for which no non-destructive oracle exists --
    # a deserialization gadget we deliberately refused to fire. We have a strong
    # prior it is exploitable and no proof either way, so it sits ABOVE
    # unvalidated (an untested candidate) and BELOW evidence (a proven one).
    # Without this branch the status fell through to the `unvalidated` weight,
    # scoring a refused-RCE exactly like a never-tested candidate.
    "unverifiable_safely": 0.60,
}

P_MIN, P_MAX = 0.01, 0.99


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


@dataclass
class Score:
    probability: float
    logit: float
    contributions: dict[str, float] = field(default_factory=dict)
    provenance: Provenance = Provenance.ASSUMED

    def explain(self) -> list[dict]:
        """Ordered per-signal breakdown for the UI."""
        return [
            {"signal": k, "contribution": round(v, 4)}
            for k, v in sorted(self.contributions.items(),
                               key=lambda kv: -abs(kv[1]))
        ]


def edge_probability(finding, weights: dict | None = None) -> Score:
    """P(this exploit step succeeds | attacker holds the preconditions)."""
    w = {**WEIGHTS, **(weights or {})}
    c: dict[str, float] = {"bias": w["bias"]}

    vec = parse_cvss(finding.cvss_vector)
    if vec is not None:
        c["cvss_exploitability"] = w["cvss_exploitability"] * vec.exploitability_norm()
    else:
        # No vector: neutral midpoint, flagged so the provenance report sees it.
        c["cvss_exploitability"] = w["cvss_exploitability"] * 0.5

    if finding.epss is not None:
        # logit(EPSS), not raw EPSS -- the raw scale's skew would swamp an
        # additive model. Normalised by logit(0.5)=0 so EPSS=0.5 is neutral.
        c["epss_logit"] = w["epss_logit"] * (_logit(finding.epss) / 6.0)

    status = (finding.status or "unvalidated").lower()
    if status in ("validated", "remediated"):
        c["evidence"] = w["evidence"] * max(finding.confidence, 0.5)
        prov = Provenance.EVIDENCE
    elif status == "false_positive":
        c["false_positive"] = w["false_positive"]
        prov = Provenance.EVIDENCE
    elif status == "inconclusive":
        c["inconclusive"] = w["inconclusive"]
        prov = Provenance.CVSS_VECTOR if vec else Provenance.CLASS_TABLE
    elif status == "unverifiable_safely":
        # Module 2 identified a real class but had no safe oracle. Keep it in
        # the graph, weighted above an untested candidate, and let the cut
        # report it as a patchable node with an honest uncertainty label.
        c["unverifiable_safely"] = w["unverifiable_safely"]
        prov = Provenance.CVSS_VECTOR if vec else Provenance.CLASS_TABLE
    else:
        # Unvalidated findings STILL produce edges, at reduced weight. This is
        # what lets the graph module be complete and demoable on Day 4, before
        # the validation module exists, and improve automatically as it ships.
        c["unvalidated"] = w["unvalidated"]
        prov = Provenance.CVSS_VECTOR if vec else Provenance.CLASS_TABLE

    z = sum(c.values())
    p = min(max(_sigmoid(z), P_MIN), P_MAX)
    return Score(probability=p, logit=z, contributions=c, provenance=prov)


def phishing_entry_probability(risk_score: float) -> float:
    """Module 5 hands us an explainable phishing risk score in [0,1]; it becomes
    the probability of the Fact(phished_credential) -> State edge."""
    return min(max(risk_score, P_MIN), P_MAX)
