"""
Calibration -- turning "we hand-tuned some weights" into "we measured how much
each oracle is worth" (LAW 7: distinguish a proof from a measurement).

Unlike Module 3's graph weights (which have no ground truth, so we do sensitivity
analysis instead), the VALIDATION oracles DO have an answer key: a known-
vulnerable target is known-vulnerable. So calibration is legitimate here. In
production the labeled corpus is any set of known-vulnerable practice targets;
here it is our deterministic mock targets, whose ground truth we set.

THE MODEL. Naive-Bayes over independent oracle families:

    logit_posterior = logit_prior + sum_families LLR_f

    LLR_pos_f = log[ P(family f fired positive | vulnerable)
                     / P(family f fired positive | not vulnerable) ]
    LLR_neg_f = log[ P(family f actively disproved | vulnerable)
                     / P(family f actively disproved | not vulnerable) ]

estimated from the corpus with Laplace smoothing, clamped to [-CLAMP, CLAMP] so
no single channel can dominate. An absent/inconclusive family contributes 0 --
the Bayes-correct handling of missing evidence.

THE PRIOR IS NEUTRAL (0.5), on purpose. An earlier design anchored on the
scanner's ~12% base rate, but that is wrong for an INDEPENDENT instrument: in
assist mode there is no scanner flag at all, and inheriting the scanner's bias
would drag a directly-observed proof (an OOB callback, a DOM execution) below the
decision line. Starting neutral and letting the MEASURED per-family LLRs move the
posterior is the honest choice -- we weigh our own evidence, not the scanner's
prejudice. The scanner base rate remains available as an alternative prior for
scanner-only triage.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field


CLAMP = 4.0                 # max |LLR| per family
SMOOTH = 0.5                # Laplace alpha
DEFAULT_PRIOR = 0.5         # neutral; we do not inherit the scanner's bias
SCANNER_BASE_RATE = 0.12    # documented alternative prior for scanner-only triage


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


@dataclass(frozen=True)
class CalibrationSample:
    """One family's observed signal on one labeled candidate.
    signal in {'pos','neg','absent'}; label True == genuinely vulnerable."""
    family: str
    signal: str
    label: bool


@dataclass
class Calibration:
    prior: float = DEFAULT_PRIOR
    llr_pos: dict = field(default_factory=dict)
    llr_neg: dict = field(default_factory=dict)
    n_samples: int = 0
    counts: dict = field(default_factory=dict)   # family -> raw counts, for audit

    def contribution(self, family: str, signal: str) -> float:
        if signal == "pos":
            return self.llr_pos.get(family, 0.0)
        if signal == "neg":
            return self.llr_neg.get(family, 0.0)
        return 0.0

    def as_dict(self) -> dict:
        return {"prior": round(self.prior, 4),
                "llr_pos": {k: round(v, 3) for k, v in sorted(self.llr_pos.items())},
                "llr_neg": {k: round(v, 3) for k, v in sorted(self.llr_neg.items())},
                "n_samples": self.n_samples}


def fit_calibration(samples: list[CalibrationSample], *,
                    prior: float = DEFAULT_PRIOR) -> Calibration:
    families = sorted({s.family for s in samples})
    cal = Calibration(prior=prior, n_samples=len(samples))
    a = SMOOTH
    for f in families:
        fs = [s for s in samples if s.family == f]
        vuln = [s for s in fs if s.label]
        notv = [s for s in fs if not s.label]

        def rate(group, sig):
            hit = sum(1 for s in group if s.signal == sig)
            return (hit + a) / (len(group) + 2 * a)

        llr_pos = math.log(rate(vuln, "pos") / rate(notv, "pos"))
        llr_neg = math.log(rate(vuln, "neg") / rate(notv, "neg"))
        cal.llr_pos[f] = max(-CLAMP, min(CLAMP, llr_pos))
        cal.llr_neg[f] = max(-CLAMP, min(CLAMP, llr_neg))
        cal.counts[f] = {
            "n_vuln": len(vuln), "n_not": len(notv),
            "pos_vuln": sum(1 for s in vuln if s.signal == "pos"),
            "pos_not": sum(1 for s in notv if s.signal == "pos"),
            "neg_vuln": sum(1 for s in vuln if s.signal == "neg"),
            "neg_not": sum(1 for s in notv if s.signal == "neg"),
        }
    return cal


def score(cal: Calibration, signals: dict) -> tuple[float, float, list[dict]]:
    """signals: family -> 'pos'|'neg'|'absent'. Returns (logit, probability,
    per-family contribution breakdown for the dashboard)."""
    logit = _logit(cal.prior)
    contribs = [{"signal": "prior", "contribution": round(logit, 4)}]
    for family in sorted(signals):
        c = cal.contribution(family, signals[family])
        if c:
            contribs.append({"signal": f"{family}:{signals[family]}",
                             "contribution": round(c, 4)})
        logit += c
    return logit, sigmoid(logit), contribs


# --------------------------------------------------------------- reliability

@dataclass
class ReliabilityBin:
    lo: float
    hi: float
    count: int
    mean_pred: float
    obs_freq: float

    def as_dict(self) -> dict:
        return {"range": [round(self.lo, 2), round(self.hi, 2)],
                "count": self.count, "mean_pred": round(self.mean_pred, 4),
                "observed": round(self.obs_freq, 4)}


def reliability(pairs: list[tuple[float, bool]], n_bins: int = 10):
    """pairs: (predicted_confidence, true_label). Returns (bins, ECE).

    ECE = expected calibration error = sum over bins of (n/N)*|pred-observed|.
    A well-calibrated model has ECE near 0 and points near the diagonal."""
    bins: list[ReliabilityBin] = []
    N = len(pairs)
    ece = 0.0
    for i in range(n_bins):
        lo, hi = i / n_bins, (i + 1) / n_bins
        members = [(p, y) for p, y in pairs
                   if (lo <= p < hi) or (i == n_bins - 1 and p == 1.0)]
        if not members:
            continue
        mp = sum(p for p, _ in members) / len(members)
        of = sum(1 for _, y in members if y) / len(members)
        bins.append(ReliabilityBin(lo, hi, len(members), mp, of))
        ece += (len(members) / N) * abs(mp - of)
    return bins, ece


def separation(pairs: list[tuple[float, bool]]) -> dict:
    """Complements the reliability diagram. On a cleanly-separable corpus the
    honest claim is DISCRIMINATION, not mid-range calibration: does the score
    rank a vulnerable candidate above a non-vulnerable one?

    Returns mean confidence on each class and AUC (probability a random
    vulnerable case outscores a random non-vulnerable one)."""
    vuln = [p for p, y in pairs if y]
    notv = [p for p, y in pairs if not y]
    if not vuln or not notv:
        return {"auc": None, "mean_vuln": None, "mean_not": None}
    wins = sum((1.0 if a > b else 0.5 if a == b else 0.0)
               for a in vuln for b in notv)
    return {"auc": round(wins / (len(vuln) * len(notv)), 4),
            "mean_vuln": round(sum(vuln) / len(vuln), 4),
            "mean_not": round(sum(notv) / len(notv), 4),
            "n_vuln": len(vuln), "n_not": len(notv)}
