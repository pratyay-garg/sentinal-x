"""Scorecard behaviour, sensitivity analysis, and the API contract."""
from __future__ import annotations

import pytest

from app.graph import scoring
from app.graph.loader import from_dict, load_fixture
from app.graph.model import Finding
from app.graph.sensitivity import validation_ablation, weight_stability

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def f(**kw) -> Finding:
    base = dict(id="X", asset_id="a", vuln_class="sqli", cvss_vector=VEC)
    base.update(kw)
    return Finding(**base)


class TestScorecard:
    def test_validated_beats_unvalidated(self):
        v = scoring.edge_probability(f(status="validated", confidence=0.95))
        u = scoring.edge_probability(f(status="unvalidated", confidence=0.25))
        assert v.probability > u.probability

    def test_unvalidated_findings_still_produce_an_edge(self):
        """This is what lets the graph be complete and demoable on Day 4, before
        the validation module exists."""
        assert scoring.edge_probability(f(status="unvalidated")).probability > 0.01

    def test_false_positive_is_driven_to_the_floor(self):
        assert scoring.edge_probability(f(status="false_positive")).probability <= 0.05

    def test_low_epss_does_not_zero_out_a_validated_finding(self):
        """The whole reason we do NOT multiply EPSS in: the median CVE sits near
        1e-3, and a product would collapse the graph to a uniformly cold heat
        map on stage."""
        s = scoring.edge_probability(f(status="validated", confidence=0.95, epss=0.0008))
        assert s.probability > 0.6

    def test_epss_shifts_the_score_without_dominating_it(self):
        lo = scoring.edge_probability(f(status="validated", confidence=0.9, epss=0.001))
        hi = scoring.edge_probability(f(status="validated", confidence=0.9, epss=0.9))
        assert hi.probability > lo.probability
        assert hi.probability - lo.probability < 0.35

    def test_missing_epss_contributes_exactly_zero(self):
        s = scoring.edge_probability(f(status="validated", confidence=0.9))
        assert "epss_logit" not in s.contributions

    def test_contributions_sum_to_the_logit(self):
        s = scoring.edge_probability(f(status="validated", confidence=0.8, epss=0.3))
        assert sum(s.contributions.values()) == pytest.approx(s.logit)

    def test_explanation_is_ordered_by_magnitude(self):
        e = scoring.edge_probability(f(status="validated", confidence=0.9, epss=0.4)).explain()
        mags = [abs(x["contribution"]) for x in e]
        assert mags == sorted(mags, reverse=True)

    def test_probability_is_clamped(self):
        s = scoring.edge_probability(f(status="validated", confidence=1.0, epss=0.999))
        assert 0.01 <= s.probability <= 0.99


class TestSensitivity:
    def test_top_ranking_is_stable_under_weight_perturbation(self):
        """The honest substitute for a calibration we cannot perform."""
        st = weight_stability(load_fixture(), trials=25, top_k=3, seed=1337)
        assert st.ranking_stable >= 0.8
        assert "unchanged in" in st.as_dict()["claim"]

    def test_stability_is_reproducible(self):
        gi = load_fixture()
        a = weight_stability(gi, trials=15, seed=1337).as_dict()
        b = weight_stability(gi, trials=15, seed=1337).as_dict()
        assert a == b

    def test_ablation_reports_whether_conclusions_need_unvalidated_findings(self):
        r = validation_ablation(load_fixture())
        assert "unchanged" in r and isinstance(r["unchanged"], bool)
        assert r["findings_dropped"] >= 1


class TestIlpSolverCompat:
    def test_ilp_variable_names_are_unique_and_deterministic(self):
        """REGRESSION. Variables were named abs(hash(node)): hash-randomised per
        process, and two distinct nodes could collide onto one name, silently
        merging two ILP variables and yielding a wrong cut with no error."""
        pytest.importorskip("pulp")
        from app.graph.breakchain import label_cut
        from app.graph.build import build_graph
        from app.graph.prune import prune
        g = prune(build_graph(load_fixture()))
        a, b = label_cut(g), label_cut(g)
        assert sorted(a.vulns) == sorted(b.vulns) and a.cost == b.cost

    def test_ilp_cut_survives_hash_randomisation(self):
        pytest.importorskip("pulp")
        import os
        import subprocess
        import sys
        code = ("from app.graph.loader import load_fixture;"
                "from app.graph.build import build_graph;"
                "from app.graph.prune import prune;"
                "from app.graph.breakchain import label_cut;"
                "c=label_cut(prune(build_graph(load_fixture())));"
                "print(sorted(c.vulns), c.cost)")
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # repo root
        cwd = os.path.join(root, "backend")
        outs = [subprocess.run([sys.executable, "-c", code],
                               env={**os.environ, "PYTHONHASHSEED": h,
                                    "PYTHONPATH": cwd},
                               cwd=cwd, capture_output=True, text=True).stdout
                for h in ("0", "99999")]
        assert outs[0] and outs[0] == outs[1]

    def test_solver_selection_never_raises(self):
        pytest.importorskip("pulp")
        import pulp
        from app.graph._pulp_compat import pick_solver
        assert pick_solver(pulp) is not None

    def test_ilp_emits_no_deprecation_warnings(self):
        """PuLP 3.3 deprecates LpVariable(...) and PULP_CBC_CMD ahead of 4.0.
        The shim keeps us off both paths, so a future upgrade won't break us."""
        pytest.importorskip("pulp")
        import warnings
        from app.graph.breakchain import label_cut
        from app.graph.build import build_graph
        from app.graph.prune import prune
        g = prune(build_graph(load_fixture()))
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            label_cut(g)
        ours = [x for x in w if "pulp" in str(x.filename).lower()
                and issubclass(x.category, DeprecationWarning)]
        assert not ours, [str(x.message) for x in ours]


class TestLoader:
    def test_postgres_rows_and_json_produce_the_same_graph(self):
        from app.graph.build import build_graph
        from app.graph.loader import from_rows
        gi = load_fixture()
        rows = from_rows(
            assets=[{"asset_id": a.id, "zone": a.zone,
                     "is_crown_jewel": a.is_crown_jewel,
                     "criticality": a.criticality} for a in gi.assets],
            findings=[{"finding_id": x.id, "asset_id": x.asset_id,
                       "vuln_class": x.vuln_class, "status": x.status,
                       "confidence": x.confidence, "cvss_vector": x.cvss_vector,
                       "epss": x.epss, "patch_hours": x.patch_hours,
                       "patch_group": x.patch_group, "evidence_id": x.evidence_id,
                       "endpoint": x.endpoint, "target_asset_id": x.target_asset_id,
                       "observed_grants": list(x.observed_grants)}
                      for x in gi.findings],
            facts=[{"kind": k.kind, "ref": k.ref, "provenance": k.provenance.value}
                   for k in gi.facts],
            routes=[{"src": r.src, "dst": r.dst, "provenance": r.provenance.value}
                    for r in gi.routes],
            entries=gi.entries,
        )
        assert (sorted(map(str, build_graph(rows).nodes))
                == sorted(map(str, build_graph(gi).nodes)))

    def test_empty_input_does_not_crash(self):
        from app.graph.pipeline import run
        res = run(from_dict({}), trials=50, with_priority=False)
        assert res.reachable_jewels == []


class TestApiSurface:
    def test_post_endpoints_accept_a_json_body(self):
        """REGRESSION. Request models defined INSIDE build_router() are invisible
        to FastAPI (it resolves hints via the function's __globals__), so every
        POST returned 422 'Field required: body' while the router still built
        fine and the route table still looked correct."""
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.graph.api import build_router
        app = FastAPI()
        app.include_router(build_router())
        c = TestClient(app)
        r = c.post("/graph/recompute", json={"patched": ["F4", "F11"], "trials": 300})
        assert r.status_code == 200, r.text
        assert r.json()["jewels_still_reachable"] == []

    def test_breach_endpoint_rejects_a_raw_email_address(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.graph.api import build_router
        app = FastAPI()
        app.include_router(build_router())
        c = TestClient(app)
        assert c.post("/graph/entry/breach",
                      json={"asset_id": "api-01", "ref": "a@b.com"}).status_code == 422

    def test_router_builds_and_exposes_the_integration_endpoints(self):
        pytest.importorskip("fastapi")
        from app.graph.api import build_router
        paths = {r.path for r in build_router().routes}
        for p in ("/graph/analyze", "/graph/cytoscape", "/graph/priority",
                  "/graph/recompute", "/graph/entry/phishing", "/graph/assurance"):
            assert p in paths
