"""
Hand-authored oracle verdicts. The Module 2 analogue of the 30-node attack-graph
fixture, and it exists for the same reason: the writer is complete and testable
BEFORE a single real oracle runs, before Nuclei is wired, and before the
authorised target is live.

Deliberately contains one of each thing that matters downstream:
    * two findings sharing a CVE          -> the ILP must beat the min-cut
    * an authorization-matrix verdict     -> observed data_read, evidence provenance
    * an execution-oracle verdict         -> observed user_session
    * an SSRF with a canary callback      -> a route PROVEN by experiment
    * a false_positive                    -> must vanish from the graph
    * an inconclusive                     -> stays, at reduced weight
    * an unverifiable_safely              -> the RCE we refused to fire
    * a single-family "validated"         -> must trigger a corroboration warning
"""
from __future__ import annotations

from .writer import Candidate, OracleOutcome, Verdict

RCE_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
SQLI_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"

_DIFF_OK = OracleOutcome("differential", True, effect=0.71,
                         detail="two-sided: TRUE tracked baseline, FALSE diverged",
                         artifacts=("req-1", "req-2", "req-3"))
_TIME_OK = OracleOutcome("timing", True, effect=9.4,
                         detail="MAD z=9.4; SLEEP(3)->2.9s, SLEEP(6)->6.1s (scales)",
                         artifacts=("timing-series-1",))


def verdicts() -> list[Verdict]:
    return [
        # --- SQLi on api-01: differential + timing, two DISJOINT failure modes
        Verdict(
            candidate=Candidate(
                asset_id="api-01", vuln_class="sqli", endpoint="/search",
                param="q", cvss_vector=SQLI_VEC, cve="CVE-2026-4242",
                epss=0.12, epss_snapshot_date="2026-09-01",
            ),
            status="validated", confidence=0.96,
            outcomes=(_DIFF_OK, _TIME_OK),
            evidence_id="e-sqli-api01",
            discovered_target="db-01",     # the injection read the DB host
        ),
        # --- the SAME CVE on a second host: one upgrade fixes both
        Verdict(
            candidate=Candidate(
                asset_id="api-02", vuln_class="sqli", endpoint="/search",
                param="q", cvss_vector=SQLI_VEC, cve="CVE-2026-4242",
                epss=0.12, epss_snapshot_date="2026-09-01",
            ),
            status="validated", confidence=0.94,
            outcomes=(_DIFF_OK, _TIME_OK),
            evidence_id="e-sqli-api02",
            discovered_target="db-01",
        ),
        # --- IDOR: the 2x2 matrix is self-corroborating (positive-control diagonal)
        Verdict(
            candidate=Candidate(
                asset_id="api-01", vuln_class="idor", endpoint="/orders/{id}",
                param="id", root_cause="sequential_ids",
            ),
            status="validated", confidence=0.91,
            outcomes=(OracleOutcome(
                "authorization", True, effect=1.0,
                detail="A->A 200, A->B 200 (finding), B->B 200, B->A 403",
                artifacts=("matrix-aa", "matrix-ab", "matrix-bb", "matrix-ba")),),
            evidence_id="e-idor-api01",
        ),
        # --- stored XSS proved by execution in a real browser
        Verdict(
            candidate=Candidate(
                asset_id="web-01", vuln_class="xss_stored", endpoint="/reviews",
                param="body", method="POST", root_cause="unescaped_render",
            ),
            status="validated", confidence=0.88,
            outcomes=(OracleOutcome(
                "execution", True, effect=1.0,
                detail="window.__x_9f3a === 1 after render",
                artifacts=("screenshot-xss-1",)),),
            evidence_id="e-xss-web01",
        ),
        # --- SSRF: canary callback proves a ROUTE, and grants only network_reach
        Verdict(
            candidate=Candidate(
                asset_id="api-01", vuln_class="ssrf", endpoint="/fetch",
                param="url", component="internal-fetcher@1.2",
            ),
            status="validated", confidence=0.84,
            outcomes=(OracleOutcome(
                "oob_ssrf", True, effect=1.0,
                detail="canary token 7f21 received from 10.0.1.20",
                artifacts=("oob-7f21",)),),
            evidence_id="e-ssrf-api01",
            proven_route=("api-01", "db-01"),
            discovered_target="db-01",
        ),
        # --- the scanner was wrong and we can prove it
        Verdict(
            candidate=Candidate(
                asset_id="web-01", vuln_class="sqli", endpoint="/q", param="s",
                cvss_vector=SQLI_VEC, cve="CVE-2026-0001",
            ),
            status="false_positive", confidence=0.04,
            outcomes=(OracleOutcome(
                "differential", False, effect=0.02,
                detail="TRUE and FALSE both returned the same 500; the server "
                       "crashes on the quote, it does not evaluate SQL"),),
            evidence_id="e-fp-web01",
        ),
        # --- a WAF made the endpoint untestable; we say so rather than guess
        Verdict(
            candidate=Candidate(
                asset_id="web-02", vuln_class="broken_access_control",
                endpoint="/admin", root_cause="waf_shadowed",
            ),
            status="inconclusive", confidence=0.40,
            outcomes=(OracleOutcome(
                "differential", False, effect=0.0,
                detail="sanity canary failed: catch-all handler returns 200 for "
                       "a nonsense path"),),
            evidence_id="e-inconc-web02",
        ),
        # --- a real class with no safe oracle: we refuse to fire the gadget
        Verdict(
            candidate=Candidate(
                asset_id="api-02", vuln_class="deserialization",
                endpoint="/import", cvss_vector=RCE_VEC,
                component="pickle-loader@0.9",
            ),
            status="unverifiable_safely", confidence=0.55,
            outcomes=(),
            evidence_id="e-unsafe-api02",
        ),
        # --- deliberately weak: one family, no self-corroboration -> warning
        Verdict(
            candidate=Candidate(
                asset_id="web-02", vuln_class="ssti", endpoint="/render",
                param="tpl", root_cause="jinja_autoescape_off",
            ),
            status="validated", confidence=0.70,
            outcomes=(_DIFF_OK,),
            evidence_id="e-ssti-web02",
        ),
    ]


def assets() -> list[dict]:
    return [
        {"id": "web-01", "zone": "dmz", "criticality": 2},
        {"id": "web-02", "zone": "dmz", "criticality": 2},
        {"id": "api-01", "zone": "app", "criticality": 3},
        {"id": "api-02", "zone": "app", "criticality": 3},
        {"id": "db-01", "zone": "data", "criticality": 5, "is_crown_jewel": True},
    ]


def scanner_routes() -> list[dict]:
    """What Discovery observed. The SSRF-proven api-01 -> db-01 route is NOT
    here: the writer contributes it, which is the whole point."""
    return [
        {"src": "web-01", "dst": "api-01", "provenance": "observed",
         "reason": "nmap 443/tcp"},
        {"src": "web-02", "dst": "api-02", "provenance": "observed",
         "reason": "nmap 443/tcp"},
        {"src": "api-02", "dst": "db-01", "provenance": "observed",
         "reason": "nmap 5432/tcp"},
    ]


def entries() -> list[str]:
    return ["web-01", "web-02"]
