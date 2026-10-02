"""Phase 3 -- the differential oracle (two-sided rule + negative control)."""
from __future__ import annotations


from app.graph.build import build_graph
from app.graph.loader import from_dict
from app.graph.model import vuln
from app.engines.validation.mock_target import MockSqliTarget, MockSstiTarget
from app.engines.validation.oracles.differential import (
    run_boolean_differential, run_error_differential, run_expression_differential,
)
from app.engines.validation.http import Request, Response
from app.engines.validation.writer import (
    corroboration_warnings, observations, to_finding_row, write,
)

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"


def _sqli(mode, **kw):
    return run_boolean_differential(
        MockSqliTarget(mode), asset_id="api-01", endpoint="/search", param="q",
        base_value="book", cvss_vector=VEC, cve="CVE-2026-1", **kw)


def _ssti(mode, **kw):
    return run_expression_differential(
        MockSstiTarget(mode), asset_id="web-02", endpoint="/hello",
        param="name", base_value="guest", **kw)


# --------------------------------------------------------------- SQLi outcomes

class TestBooleanOutcomes:
    def test_vulnerable_tracks_the_boolean_and_is_validated(self):
        v = _sqli("vulnerable").verdict
        assert v.status == "validated" and v.outcomes[0].fired

    def test_secure_is_disproved(self):
        assert _sqli("secure").verdict.status == "false_positive"

    def test_error_on_quote_is_disproved_not_confirmed(self):
        """The classic hallucination: a 500 on a quote. One-sided detectors fire;
        the two-sided rule proves TRUE does not track and disproves it."""
        v = _sqli("error_on_quote").verdict
        assert v.status == "false_positive"

    def test_confounded_target_is_inconclusive_via_the_negative_control(self):
        """The difference reproduces without breaking the query, so it is not
        proven SQL evaluation. The two-sided rule alone would wrongly validate;
        the no-quote control pair catches it."""
        r = _sqli("confounded")
        assert r.verdict.status == "inconclusive"
        assert "without breaking the query" in r.reason.lower()


# ----------------------------------------------------- error-based SQLi outcomes

class _ErrorTarget:
    """Fake string-context search endpoint keyed on quote balance.

    ``mode`` picks the behaviour:
      injectable       an UNBALANCED quote breaks the query (parser error); a
                       balanced/benign value is valid SQL -- a
                       ``((... LIKE '%q%' ...))`` context.
      errors_on_quote  any quote at all errors (a server that 500s on quotes,
                       the classic false-positive trap).
      secure           parameterised: nothing ever errors.
    """

    def __init__(self, mode: str):
        self.mode = mode

    def __call__(self, request: Request) -> Response:
        value = dict(request.params).get("q", "")
        quotes = value.count("'")
        err = Response(500, "<html><body>SQLITE_ERROR: near \"'\": syntax error"
                            "</body></html>")
        ok = Response(200, "<html><body>results</body></html>")
        if self.mode == "injectable":
            return err if quotes % 2 == 1 else ok
        if self.mode == "errors_on_quote":
            return err if quotes else ok
        return ok


def _err(mode):
    return run_error_differential(
        _ErrorTarget(mode), asset_id="api-01", endpoint="/search", param="q",
        base_value="book", check_sanity=False)


class TestErrorBasedOutcomes:
    def test_unbalanced_quote_error_is_validated(self):
        r = _err("injectable")
        assert r.verdict.status == "validated" and r.verdict.outcomes[0].fired

    def test_server_that_errors_on_any_quote_is_inconclusive_not_confirmed(self):
        """The doubled-quote negative control catches a server that 500s on any
        quote, so it abstains rather than raising a false positive."""
        assert _err("errors_on_quote").verdict.status == "inconclusive"

    def test_no_error_is_disproved(self):
        assert _err("secure").verdict.status == "false_positive"

    def test_error_based_claims_no_observed_privilege(self):
        assert observations(_err("injectable").verdict) == ((), None)


# --------------------------------------------------------------- SSTI outcomes

class TestExpressionOutcomes:
    def test_vulnerable_ssti_is_validated_by_computed_markers(self):
        v = _ssti("vulnerable").verdict
        assert v.status == "validated" and v.outcomes[0].effect == 2.0

    def test_secure_ssti_is_disproved(self):
        assert _ssti("secure").verdict.status == "false_positive"

    def test_marker_must_be_newly_produced_not_already_on_the_page(self):
        r = _ssti("vulnerable")
        # every expr probe records the marker as present
        exprs = [p for p in r.probes if p.label.startswith("expr")]
        assert exprs and all("present=True" in p.detail for p in exprs)


# --------------------------------------------------------------- honesty

class TestHonestyAndSafety:
    def test_differential_claims_no_observed_privilege(self):
        """It proves INJECTION, not extraction, so it must not claim an observed
        grant -- the writer derives grants from the CVSS vector instead."""
        assert observations(_sqli("vulnerable").verdict) == ((), None)

    def test_validated_differential_is_single_family_and_warns(self):
        """A differential-only validation rests on one failure-mode family, so
        the writer flags it -- Phase 4's timing oracle supplies the disjoint
        second family that clears the warning."""
        w = corroboration_warnings(_sqli("vulnerable").verdict)
        assert w and "single failure-mode family" in w[0]

    def test_every_request_is_a_get(self):
        seen = []

        def spy(request):
            seen.append(request.method)
            return MockSqliTarget("vulnerable")(request)

        run_boolean_differential(spy, asset_id="api-01", endpoint="/search",
                                 param="q", base_value="book")
        assert seen and set(seen) == {"GET"}

    def test_sanity_canary_short_circuits(self):
        """A catch-all server must yield inconclusive, never a finding."""
        from app.engines.validation.mock_target import MockTarget
        r = run_boolean_differential(MockTarget("catch_all"), asset_id="x",
                                     endpoint="/search", param="q")
        assert r.verdict.status == "inconclusive"
        assert "sanity canary" in r.reason


# --------------------------------------------------------------- contract + graph

class TestIntegration:
    def test_row_is_contract_valid_with_cve_patch_group(self):
        row = to_finding_row(_sqli("vulnerable").verdict)
        assert row["vuln_class"] == "sqli"
        assert row["patch_group"] == "CVE-2026-1"
        assert write([_sqli("vulnerable").verdict]).validation["ok"]

    def test_validated_sqli_enters_the_graph(self):
        v = _sqli("vulnerable").verdict
        res = write([v])
        gi = from_dict({
            "assets": [{"id": "web-01"}, {"id": "api-01", "criticality": 3},
                       {"id": "db-01", "is_crown_jewel": True, "criticality": 5}],
            "routes": [{"src": "web-01", "dst": "api-01", "provenance": "observed"},
                       {"src": "api-01", "dst": "db-01", "provenance": "observed"}],
            "entries": ["web-01"], "findings": res.findings})
        g = build_graph(gi)
        assert vuln(res.findings[0]["id"]) in g
        # provenance is CVSS-derived (injection proven, extraction not observed)
        assert g.nodes[vuln(res.findings[0]["id"])]["provenance"] == "cvss_vector"

    def test_ssti_row_is_contract_valid(self):
        assert write([_ssti("vulnerable").verdict]).validation["ok"]

    def test_determinism(self):
        assert (to_finding_row(_sqli("vulnerable").verdict)
                == to_finding_row(_sqli("vulnerable").verdict))
