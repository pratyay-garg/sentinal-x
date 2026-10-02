"""
The control engine -- Layer 1. Everything an oracle needs to know about "what
does this endpoint look like when nothing is wrong" BEFORE it fires a probe.

You cannot detect a differential response without a model of how much the page
already varies on its own -- a ticking clock, a rotating banner, a fresh CSRF
token. Get this wrong and every probe looks significant and the detector is pure
noise. The senior move is to LEARN the endpoint's volatility from a handful of
control requests rather than hard-coding brittle regexes to strip timestamps.

  1. Send k unmodified control requests.
  2. Measure how similar those k responses are TO EACH OTHER (shingle Jaccard).
  3. The learned threshold sits just below the worst baseline-to-baseline
     similarity. A probe is "different" only if it falls below that threshold --
     i.e. it changed the page by more than the page changes on its own.

If the endpoint is so volatile that even its own baselines disagree wildly, the
content channel is declared UNUSABLE and downstream must fall back to another
oracle or return `inconclusive`. Refusing to measure is better than measuring
noise (LAW 7).

Timing statistics (median + MAD) are captured here too, because they are control
data the timing oracle (Phase 4) will consume.
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field

from .http import Fetcher, Request, Response

_WORD = re.compile(r"[A-Za-z0-9]+")

DEFAULT_SHINGLE = 3
DEFAULT_MARGIN = 0.05      # threshold sits this far below the worst baseline pair
USABILITY_FLOOR = 0.30     # below this learned threshold, content diff is noise


# --------------------------------------------------------------- text similarity

def shingles(text: str, w: int = DEFAULT_SHINGLE) -> frozenset:
    """w-word overlapping shingles. Falls back to the token set when the text is
    shorter than one shingle, so short pages still compare sensibly."""
    tokens = _WORD.findall((text or "").lower())
    if len(tokens) < w:
        return frozenset(tokens)
    return frozenset(tuple(tokens[i:i + w]) for i in range(len(tokens) - w + 1))


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 1.0


def similarity(body_a: str, body_b: str, w: int = DEFAULT_SHINGLE) -> float:
    return jaccard(shingles(body_a, w), shingles(body_b, w))


# --------------------------------------------------------------- baseline

@dataclass
class Baseline:
    request: Request
    responses: list[Response] = field(default_factory=list)
    status_set: frozenset = frozenset()
    length_median: float = 0.0
    length_mad: float = 0.0
    time_median_ms: float = 0.0
    time_mad_ms: float = 0.0
    content_threshold: float = 0.0
    min_pair_similarity: float = 1.0
    content_usable: bool = False
    shingle_w: int = DEFAULT_SHINGLE
    reason: str = ""

    def similarity_to_baseline(self, resp: Response) -> float:
        """Most-favourable similarity of a probe to any control response."""
        if not self.responses:
            return 0.0
        return max(similarity(resp.body, b.body, self.shingle_w)
                   for b in self.responses)

    def is_different(self, resp: Response) -> bool:
        """True iff the probe changed the page by more than the page changes on
        its own. Guards against use when the channel was declared unusable."""
        if not self.content_usable:
            raise ValueError(
                "content channel is not usable for this endpoint "
                f"({self.reason}); use another oracle or return inconclusive")
        return self.similarity_to_baseline(resp) < self.content_threshold


def _mad(values: list[float], med: float) -> float:
    if not values:
        return 0.0
    return statistics.median([abs(v - med) for v in values])


def sample_baseline(fetch: Fetcher, request: Request, *, k: int = 5,
                    margin: float = DEFAULT_MARGIN,
                    w: int = DEFAULT_SHINGLE) -> Baseline:
    """Send k control requests and learn the endpoint's noise profile.

    Deterministic: given a deterministic Fetcher the Baseline is byte-identical
    across runs. No RNG is used here -- the control requests are literally
    identical, which is the point.
    """
    responses = [fetch(request) for _ in range(max(k, 1))]
    bl = Baseline(request=request, responses=responses, shingle_w=w)
    bl.status_set = frozenset(r.status for r in responses)

    lengths = [float(len(r.body)) for r in responses]
    times = [float(r.elapsed_ms) for r in responses]
    bl.length_median = statistics.median(lengths)
    bl.length_mad = _mad(lengths, bl.length_median)
    bl.time_median_ms = statistics.median(times)
    bl.time_mad_ms = _mad(times, bl.time_median_ms)

    if len(responses) < 2:
        bl.content_usable = False
        bl.reason = "need at least 2 baseline samples to learn volatility"
        bl.content_threshold = 0.0
        return bl

    pair_sims = [similarity(responses[i].body, responses[j].body, w)
                 for i in range(len(responses))
                 for j in range(i + 1, len(responses))]
    bl.min_pair_similarity = min(pair_sims)
    raw = bl.min_pair_similarity - margin
    bl.content_threshold = max(0.0, min(1.0, raw))

    if raw < USABILITY_FLOOR:
        bl.content_usable = False
        bl.reason = (f"endpoint too volatile: baselines agree only to "
                     f"{bl.min_pair_similarity:.2f}, learned threshold "
                     f"{raw:.2f} < floor {USABILITY_FLOOR}")
    else:
        bl.content_usable = True
        bl.reason = "ok"
    return bl
