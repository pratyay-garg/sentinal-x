"""Module 2's output adapter, and the round trip into Module 3.

The load-bearing test is TestRoundTrip: fake oracle verdicts -> writer rows ->
loader.from_rows -> build_graph -> a graph whose edges are EVIDENCE-provenance
and whose ILP beats its min-cut. If that passes, Module 2 can be built against
this contract with no Module 3 code in the loop.
"""
from __future__ import annotations

import pytest

from app.graph import breakchain, contract
from app.graph.build import build_graph
from app.graph.fixpoint import sink_reachable
from app.graph.loader import from_dict
from app.graph.model import vuln
from app.graph.pipeline import run
from app.graph.prune import prune
from app.engines.validation import fixtures
from app.engines.validation.writer import (
    Candidate, OracleOutcome, Verdict, corroboration_warnings, fingerprint,
    observations, to_finding_row, to_route_rows, write,
)


def _cand(**kw):
    base = dict(asset_id="api-01", vuln_class="sqli", endpoint="/search",
                param="q", method="GET")
    base.update(kw)
    return Candidate(**base)


def _v(status="validated", outcomes=(), **kw):
    c = kw.pop("candidate", _cand(**kw.pop("cand", {})))
    return Verdict(candidate=c, status=status, confidence=kw.pop("confidence", 0.9),
                   outcomes=tuple(outcomes), evidence_id=kw.pop("evidence_id", "e-1"),
                   **kw)


DIFF = OracleOutcome("differential", True, effect=0.7)
TIME = OracleOutcome("timing", True, effect=9.0)
AUTHZ = OracleOutcome("authorization", True, effect=1.0)
EXEC = OracleOutcome("execution", True, effect=1.0)


# --------------------------------------------------------------- fingerprint

class TestFingerprint:
    def test_is_stable_across_runs(self):
        assert fingerprint(_cand()) == fingerprint(_cand())

    def test_survives_scheme_and_host_differences(self):
        """The same finding reached over http vs https, or via two hostnames for
        one asset, must not fork into two findings -- retest upserts by this id."""
        a = fingerprint(_cand(endpoint="http://x.test/search"))
        b = fingerprint(_cand(endpoint="https://other.test/search/"))
        assert a == b

    def test_different_param_is_a_different_finding(self):
        assert fingerprint(_cand(param="q")) != fingerprint(_cand(param="sort"))

    def test_different_method_is_a_different_finding(self):
        assert fingerprint(_cand(method="GET")) != fingerprint(_cand(method="POST"))


# --------------------------------------------------------------- observations

class TestObservationHonesty:
    def test_differential_and_timing_claim_nothing(self):
        """They prove INJECTION, not extraction. Claiming an observed data_read
        from a two-sided boolean test would be over-claiming."""
        assert observations(_v(outcomes=[DIFF, TIME])) == ((), None)

    def test_authorization_matrix_claims_the_transition_it_proved(self):
        req, grants = observations(_v(outcomes=[AUTHZ]))
        assert grants == "data_read" and "user_session" in req

    def test_strongest_grant_wins_when_several_oracles_prove(self):
        rce = OracleOutcome("oob_rce", True)
        assert observations(_v(outcomes=[EXEC, rce]))[1] == "code_exec"

    def test_an_oracle_may_explicitly_declare_what_it_demonstrated(self):
        """A boolean-differential SQLi that actually returned a row from the
        target table DID demonstrate extraction, so it may say so."""
        proved = OracleOutcome("differential", True, proves="data_read",
                               proves_requires=("network_reach",))
        assert observations(_v(outcomes=[proved])) == (("network_reach",), "data_read")

    def test_a_non_validated_verdict_never_claims_an_observation(self):
        for status in ("inconclusive", "unverifiable_safely", "false_positive"):
            assert observations(_v(status=status, outcomes=[AUTHZ])) == ((), None)

    def test_an_oracle_that_did_not_fire_contributes_nothing(self):
        assert observations(_v(outcomes=[OracleOutcome("authorization", False)])) == ((), None)


class TestCorroboration:
    def test_two_disjoint_families_pass(self):
        assert corroboration_warnings(_v(outcomes=[DIFF, TIME])) == []

    def test_a_single_inferential_family_warns(self):
        w = corroboration_warnings(_v(outcomes=[DIFF]))
        assert w and "single failure-mode family" in w[0]

    def test_direct_evidence_oracles_are_self_corroborating(self):
        """A unique nonce executing in the DOM, or a unique canary token
        arriving from the target, has no plausible alternative explanation."""
        for o in (AUTHZ, EXEC, OracleOutcome("oob_ssrf", True)):
            assert corroboration_warnings(_v(outcomes=[o])) == []

    def test_validated_with_nothing_fired_is_flagged(self):
        assert corroboration_warnings(_v(outcomes=[])) != []

    def test_non_validated_verdicts_are_not_second_guessed(self):
        assert corroboration_warnings(_v(status="inconclusive", outcomes=[])) == []


# --------------------------------------------------------------- rows

class TestRowConstruction:
    def test_patch_group_precedence_cve_then_component_then_root_cause(self):
        assert to_finding_row(_v(cand={"cve": "cve-2026-1", "component": "c",
                                       "root_cause": "r"}))["patch_group"] == "CVE-2026-1"
        assert to_finding_row(_v(cand={"component": "Django", "root_cause": "r"})
                              )["patch_group"] == "component::django"
        assert to_finding_row(_v(cand={"root_cause": "OrmRaw"})
                              )["patch_group"] == "sqli::ormraw"

    def test_patch_hours_come_from_the_class_not_a_default_of_one(self):
        assert to_finding_row(_v())["patch_hours"] == contract.DEFAULT_PATCH_HOURS["sqli"]

    def test_every_fixture_row_is_contract_valid(self):
        assert write(fixtures.verdicts()).validation["ok"] is True

    def test_a_discovered_target_overrides_the_candidate_guess(self):
        row = to_finding_row(_v(cand={"target_asset_id": "guess"},
                                discovered_target="db-01"))
        assert row["target_asset_id"] == "db-01"

    def test_ssrf_callback_emits_a_proven_route(self):
        rows = to_route_rows(_v(cand={"vuln_class": "ssrf"},
                                outcomes=[OracleOutcome("oob_ssrf", True)],
                                proven_route=("api-01", "db-01")))
        assert rows and rows[0]["provenance"] == "observed"
        assert "canary" in rows[0]["reason"]

    def test_no_route_is_claimed_for_an_unproven_verdict(self):
        assert to_route_rows(_v(status="inconclusive",
                                proven_route=("a", "b"))) == []

    def test_rewriting_the_same_finding_upserts_rather_than_accumulates(self):
        """Re-running the pipeline must converge, not grow."""
        v1 = _v(confidence=0.6)
        v2 = _v(confidence=0.95)
        r = write([v1, v2])
        assert len(r.findings) == 1 and r.findings[0]["confidence"] == 0.95

    def test_output_ordering_is_deterministic(self):
        a = [f["id"] for f in write(fixtures.verdicts()).findings]
        b = [f["id"] for f in write(fixtures.verdicts()).findings]
        assert a == b == sorted(a)


# --------------------------------------------------------------- round trip

@pytest.fixture(scope="module")
def graph_input():
    """Module 2's whole output, exactly as Module 3 would receive it."""
    res = write(fixtures.verdicts())
    payload = res.as_payload(assets=fixtures.assets(), entries=fixtures.entries())
    payload["routes"] = fixtures.scanner_routes() + payload["routes"]
    return from_dict(payload), res


class TestRoundTrip:
    def test_module_3_accepts_every_row_without_a_stray_key(self, graph_input):
        gi, _ = graph_input
        assert gi.unknown_keys == {}

    def test_the_crown_jewel_is_reachable(self, graph_input):
        gi, _ = graph_input
        assert sink_reachable(build_graph(gi))

    def test_authorization_backed_findings_carry_evidence_provenance(self, graph_input):
        """The payoff: observed_grants flips the edge from class-table to
        EVIDENCE, which RAISES the derived_fraction Module 3 prints on screen."""
        gi, _ = graph_input
        g = build_graph(gi)
        idor = next(n for n, d in g.nodes(data=True)
                    if d.get("type") == "vuln" and d.get("vuln_class") == "idor")
        assert g.nodes[idor]["provenance"] == "evidence"

    def test_a_disproved_finding_never_enters_the_graph(self, graph_input):
        gi, _ = graph_input
        g = build_graph(gi)
        fp = [f for f in gi.findings if f.status == "false_positive"]
        assert fp and all(vuln(f.id) not in g for f in fp)

    def test_the_refused_rce_stays_as_an_honest_uncertain_node(self, graph_input):
        gi, _ = graph_input
        g = build_graph(gi)
        u = [f for f in gi.findings if f.status == "unverifiable_safely"]
        assert u and all(vuln(f.id) in g for f in u)

    def test_the_derived_patch_group_makes_the_ilp_beat_the_min_cut(self, graph_input):
        """End to end proof the grouping rule does real work: two hosts, one CVE,
        charged once. This is the claim that silently evaporates on live data if
        Module 2 never sets patch_group."""
        gi, _ = graph_input
        g = prune(build_graph(gi))
        mc, ilp = breakchain.min_cut(g), breakchain.label_cut(g)
        assert ilp.cost < mc.cost
        assert "CVE-2026-4242" in ilp.patch_groups

    def test_the_ssrf_proven_route_is_in_the_graph_as_observed(self, graph_input):
        gi, _ = graph_input
        g = build_graph(gi)
        e = g[("state", "api-01", "network_reach")][("state", "db-01", "network_reach")]
        assert e["provenance"] == "observed" and "canary" in e["reason"]

    def test_the_full_pipeline_runs_clean_on_module_2_output(self, graph_input):
        gi, _ = graph_input
        s = run(gi, trials=800, with_priority=False).summary()
        assert s["diagnosis"]["answerable"] is True
        assert not [p for p in s["diagnosis"]["problems"] if p["severity"] == "error"]
        assert s["invariants"]["all_passed"] is True

    def test_no_unknown_class_or_missing_group_warnings(self, graph_input):
        """The two integration failure modes, absent by construction."""
        gi, _ = graph_input
        codes = {p["code"] for p in
                 run(gi, trials=400, with_priority=False).summary()["diagnosis"]["problems"]}
        assert "unknown_vuln_classes" not in codes
        assert "no_patch_groups" not in codes

    def test_patching_the_cut_isolates_the_jewel(self, graph_input):
        """The demo climax, driven entirely by Module 2's rows."""
        from app.graph.pipeline import recompute
        gi, _ = graph_input
        base = run(gi, trials=800, with_priority=False)
        d = recompute(gi, set(base.cut["vulns"]), trials=800)
        assert d["jewels_still_reachable"] == []
        assert all(m["after"] == 0.0 for m in d["jewel_delta"].values())


class TestApiHandoff:
    def test_the_payload_posts_cleanly_to_graph_load(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.graph import api
        from app.graph.api import build_router
        saved = api.store._input
        try:
            app = FastAPI()
            app.include_router(build_router())
            res = write(fixtures.verdicts())
            payload = res.as_payload(assets=fixtures.assets(),
                                     entries=fixtures.entries())
            payload["routes"] = fixtures.scanner_routes() + payload["routes"]
            r = TestClient(app).post("/graph/load", json=payload)
            assert r.status_code == 200
            assert r.json()["validation"]["ok"] is True
            assert r.json()["validation"]["warnings"] == 0
        finally:
            api.store._input = saved
