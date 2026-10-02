"""
The labeled corpus -- ground truth the calibration is fitted and evaluated on.

Every sample is produced by running a REAL oracle against a mock target whose
vulnerability status we set, so the LLRs are measured from actual oracle
behaviour, not hand-typed. In production this module points at known-vulnerable
practice targets instead of the mocks; the shape is identical.

  fitting_corpus()     single-family observations -> fit_calibration
  evaluation_corpus()  composite (candidate, confidence, label) -> reliability
"""
from __future__ import annotations

from .calibration import CalibrationSample
from .mock_target import (
    CanaryListener, MockOOBTarget, MockSqliTarget, MockSstiTarget,
    MockTimingTarget, MockXssTarget, MockAuthzTarget,
)
from .oracles.authz import Account, run_authorization
from .oracles.differential import (
    run_boolean_differential, run_expression_differential,
)
from .oracles.execution import run_execution
from .oracles.oob import run_oob
from .oracles.timing import run_timing_differential
from .writer import FAILURE_FAMILY

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"


def _signal(verdict) -> tuple[str, str]:
    """(family, signal) for a single-oracle verdict."""
    o = verdict.outcomes[0]
    fam = FAILURE_FAMILY.get(o.oracle, o.oracle)
    if o.fired:
        return fam, "pos"
    if verdict.status == "false_positive":
        return fam, "neg"
    return fam, "absent"


def _authz(mode):
    return run_authorization(
        {"vulnerable": MockAuthzTarget.vulnerable,
         "secure": MockAuthzTarget.secure}[mode](),
        asset_id="a", endpoint="/o/{id}",
        account_a=Account("acct-A", owns="10"),
        account_b=Account("acct-B", owns="11")).verdict


def _sqli_diff(mode):
    return run_boolean_differential(MockSqliTarget(mode), asset_id="a",
                                    endpoint="/search", param="q",
                                    base_value="book", cvss_vector=VEC,
                                    cve="CVE-X").verdict


def _ssti(mode):
    return run_expression_differential(MockSstiTarget(mode), asset_id="a",
                                       endpoint="/hello", param="name",
                                       base_value="guest").verdict


def _timing(mode):
    return run_timing_differential(MockTimingTarget(mode), asset_id="a",
                                   endpoint="/search", param="q",
                                   base_value="book", cvss_vector=VEC).verdict


def _xss(mode):
    return run_execution(MockXssTarget(mode), asset_id="a", endpoint="/echo",
                         param="msg", vuln_class="xss_reflected").verdict


def _oob(mode):
    lis = CanaryListener()
    return run_oob(MockOOBTarget(lis, mode), lis, asset_id="a", endpoint="/f",
                   param="url", oracle="oob_ssrf", target_asset_id="db").verdict


# label True == genuinely vulnerable
_FIT_CASES = [
    (_authz, "vulnerable", True), (_authz, "secure", False),
    (_sqli_diff, "vulnerable", True), (_sqli_diff, "secure", False),
    (_sqli_diff, "error_on_quote", False), (_sqli_diff, "confounded", True),
    (_ssti, "vulnerable", True), (_ssti, "secure", False),
    (_timing, "vulnerable", True), (_timing, "secure", False),
    (_timing, "tarpit", True), (_timing, "const_on_break", True),
    (_xss, "vulnerable", True), (_xss, "secure", False),
    (_xss, "reflected_safe", False),
    (_oob, "vulnerable", True), (_oob, "secure", False),
    (_oob, "egress_filtered", True),
]


def fitting_corpus(replicas: int = 3) -> list[CalibrationSample]:
    out: list[CalibrationSample] = []
    for _ in range(replicas):
        for run, mode, label in _FIT_CASES:
            fam, sig = _signal(run(mode))
            out.append(CalibrationSample(family=fam, signal=sig, label=label))
    return out


# composite candidates: (label, {family: signal}) built from real runs
_EVAL_SCENARIOS = [
    (True,  lambda: [_sqli_diff("vulnerable"), _timing("vulnerable")]),
    (False, lambda: [_sqli_diff("secure"), _timing("secure")]),
    (False, lambda: [_sqli_diff("error_on_quote"), _timing("secure")]),
    (True,  lambda: [_sqli_diff("vulnerable")]),               # single family
    (True,  lambda: [_timing("vulnerable")]),                  # single family
    (True,  lambda: [_ssti("vulnerable")]),
    (False, lambda: [_ssti("secure")]),
    (True,  lambda: [_xss("vulnerable")]),
    (False, lambda: [_xss("reflected_safe")]),
    (True,  lambda: [_authz("vulnerable")]),
    (False, lambda: [_authz("secure")]),
    (True,  lambda: [_oob("vulnerable")]),
    (False, lambda: [_oob("secure")]),
]


def evaluation_corpus(replicas: int = 5) -> list[tuple[bool, dict]]:
    """Each entry: (label, {family: signal}) -- a held-out composite candidate."""
    out = []
    for _ in range(replicas):
        for label, make in _EVAL_SCENARIOS:
            signals: dict[str, str] = {}
            for verdict in make():
                fam, sig = _signal(verdict)
                # keep the strongest signal if a family recurs
                if signals.get(fam) != "pos":
                    signals[fam] = sig
            out.append((label, signals))
    return out
