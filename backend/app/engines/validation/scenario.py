"""
A deterministic end-to-end scenario: a cached Nuclei scan, each finding
adjudicated against a mock target that models GROUND TRUTH, plus assist-mode
discovery of an IDOR the scanner never flagged. Produces the independence
scoreboard from REAL oracle runs -- nothing here is hand-tallied.

This is the Phase 7 demo backbone and the source of the scoreboard chart.
"""
from __future__ import annotations

from .adjudicate import adjudicate
from .independence import build_scoreboard
from .mock_target import (
    CanaryListener, MockAuthzTarget, MockOOBTarget, MockSqliTarget,
    MockSstiTarget, MockTimingTarget, MockXssTarget,
)
from .oracles.authz import Account, run_authorization
from .oracles.differential import (
    run_boolean_differential, run_expression_differential,
)
from .oracles.execution import run_execution
from .oracles.oob import run_oob
from .oracles.timing import run_timing_differential

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"


def _sqli(mode):
    """A SQLi corroborated by two disjoint families: differential + timing."""
    timing_mode = "vulnerable" if mode == "vulnerable" else "secure"
    d = run_boolean_differential(MockSqliTarget(mode), asset_id="api-01",
                                 endpoint="/search", param="q", base_value="book",
                                 cvss_vector=VEC, cve="CVE-2026-4242")
    t = run_timing_differential(MockTimingTarget(timing_mode), asset_id="api-01",
                                endpoint="/search", param="q", base_value="book",
                                cvss_vector=VEC)
    return adjudicate([d.verdict, t.verdict])


def run_scenario():
    """Returns (scoreboard, detail rows). Ground truth is set by the mock modes:
    two of the scanner's SQLi flags, the SSTI, XSS, SSRF and RCE are real; the
    500-based SQLi and the DOM 'sink' are hallucinations."""
    listener = CanaryListener()
    A, B = Account("acct-A", owns="10"), Account("acct-B", owns="11")

    scanner: list[tuple[str, object]] = []

    # 1. real SQLi (corroborated by differential + timing)
    scanner.append(("sqli-error-based", _sqli("vulnerable")))
    # 2. hallucinated SQLi: a 500 on a quote -> disproved
    scanner.append(("generic-sqli-500", adjudicate([
        run_boolean_differential(MockSqliTarget("error_on_quote"),
                                 asset_id="web-01", endpoint="/q", param="s",
                                 base_value="book", cvss_vector=VEC).verdict])))
    # 3. real reflected XSS (executes)
    scanner.append(("reflected-xss", adjudicate([
        run_execution(MockXssTarget("vulnerable"), asset_id="web-01",
                      endpoint="/echo", param="msg",
                      vuln_class="xss_reflected").verdict])))
    # 4. hallucinated XSS: reflected but not executed -> disproved
    scanner.append(("dom-xss-sink", adjudicate([
        run_execution(MockXssTarget("reflected_safe"), asset_id="web-01",
                      endpoint="/view", param="c",
                      vuln_class="xss_reflected").verdict])))
    # 5. real SSRF (canary callback)
    scanner.append(("ssrf-oob", adjudicate([
        run_oob(MockOOBTarget(listener, "vulnerable"), listener, asset_id="api-01",
                endpoint="/fetch", param="url", oracle="oob_ssrf",
                target_asset_id="db-01").verdict])))
    # 6. real SSTI (computed markers)
    scanner.append(("jinja-ssti", adjudicate([
        run_expression_differential(MockSstiTarget("vulnerable"), asset_id="web-01",
                                    endpoint="/hello", param="name",
                                    base_value="guest").verdict])))
    # 7. RCE flagged but our OOB is egress-filtered -> inconclusive (honest)
    scanner.append(("CVE-2021-44228", adjudicate([
        run_oob(MockOOBTarget(CanaryListener(), "egress_filtered"), CanaryListener(),
                asset_id="api-01", endpoint="/login", param="x",
                oracle="oob_rce").verdict])))

    scanner_results = [v for _, v in scanner]

    # assist mode: the scanner never flagged /orders -- we find the IDOR anyway
    assist = [adjudicate([run_authorization(
        MockAuthzTarget.vulnerable(), asset_id="api-01", endpoint="/orders/{id}",
        account_a=A, account_b=B).verdict])]

    # 'tech-detect-nginx' was unmappable (info-only), counted but never adjudicated
    sb = build_scoreboard(scanner_results, assist, unmappable=1)
    detail = [(tid, v.status, round(v.confidence, 3)) for (tid, v) in scanner]
    detail += [("assist:/orders (IDOR)", assist[0].status, round(assist[0].confidence, 3))]
    return sb, detail
