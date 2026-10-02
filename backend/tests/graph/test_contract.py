"""The Module 2 <-> Module 3 seam.

The guard that matters is test_every_class_module_2_emits_has_semantics: adding
an oracle to Module 2 without adding its graph semantics is now a RED BUILD
rather than a silent downgrade to DEFAULT_SEMANTICS at ASSUMED provenance.
"""
from __future__ import annotations

import pytest

from app.graph import contract, scoring
from app.graph.build import build_graph
from app.graph.fixpoint import reachable, sink_reachable
from app.graph.model import (
    CODE_EXEC, DATA_READ, SEMANTICS, Asset, Finding, GraphInput, Route, vuln,
)
from app.graph.prune import prune

from .test_core import mini


@pytest.fixture(autouse=True)
def _restore_api_store():
    """api.store is a module-level singleton. A test that POSTs /graph/load
    replaces it for every later test in the session, which silently broke an
    unrelated /graph/recompute assertion. Snapshot and restore."""
    from app.graph import api
    saved = api.store._input
    yield
    api.store._input = saved


# --------------------------------------------------------------- vocabulary

class TestSharedVocabulary:
    def test_every_class_module_2_emits_has_semantics(self):
        """THE integration guard. A vuln_class Module 2 emits but Module 3 has
        never heard of does not crash -- it silently becomes
        DEFAULT_SEMANTICS (grants info_disclosure, provenance ASSUMED), which
        breaks the attack path AND lowers the published derived_fraction."""
        missing = contract.M2_EMITTED_CLASSES - contract.VULN_CLASSES
        assert not missing, f"Module 2 emits classes Module 3 cannot model: {sorted(missing)}"

    def test_vuln_classes_are_derived_from_semantics_not_duplicated(self):
        assert contract.VULN_CLASSES == frozenset(SEMANTICS)

    def test_the_fourth_verdict_state_is_in_the_vocabulary(self):
        assert "unverifiable_safely" in contract.VERDICTS

    def test_live_verdicts_exclude_exactly_what_build_skips(self):
        """build.py drops false_positive and remediated; nothing else."""
        assert contract.VERDICTS - contract.LIVE_VERDICTS == {
            "false_positive", "remediated"}

    def test_oracles_that_prove_nothing_specific_do_not_override(self):
        """A boolean-differential test proves INJECTION, not extraction.
        Claiming an observed data_read from it would be over-claiming."""
        for oracle in contract.NON_OVERRIDING_ORACLES:
            assert contract.observations_for(oracle) == ((), None)

    def test_authorization_oracle_reports_the_transition_it_proves(self):
        req, grants = contract.observations_for("authorization")
        assert grants == DATA_READ and "user_session" in req

    def test_every_semantics_class_has_a_patch_hours_estimate(self):
        missing = contract.VULN_CLASSES - set(contract.DEFAULT_PATCH_HOURS)
        assert not missing, f"no patch-hours estimate for {sorted(missing)}"


# --------------------------------------------------------------- patch groups

class TestPatchGrouping:
    def test_cve_wins_and_is_normalised(self):
        assert contract.patch_group_for("rce", cve=" cve-2026-1111 ") == "CVE-2026-1111"

    def test_component_and_root_cause_fall_back_in_order(self):
        assert contract.patch_group_for("sqli", component="Django") == "component::django"
        assert contract.patch_group_for("sqli", root_cause="OrmRaw") == "sqli::ormraw"

    def test_no_signal_returns_none_rather_than_inventing_a_group(self):
        """Over-grouping is worse than not grouping: it would let the ILP claim
        one action fixes findings that really need separate work -- a FALSE
        minimality claim. None surfaces as the no_patch_groups diagnostic."""
        assert contract.patch_group_for("sqli") is None

    def test_shared_cve_actually_makes_the_ilp_beat_the_min_cut(self):
        """End to end: the grouping rule feeds A3 and the divergence appears."""
        from app.graph import breakchain
        from .test_core import sqli
        grp = contract.patch_group_for("sqli", cve="CVE-2026-9999")
        g = build_graph(mini([sqli("S1", patch_group=grp),
                              sqli("S2", patch_group=grp)]))
        assert breakchain.label_cut(g).cost < breakchain.min_cut(g).cost


# --------------------------------------------------------------- new semantics

class TestModule2Semantics:
    @pytest.mark.parametrize("vuln_class,grants", [
        ("ssti", CODE_EXEC),
        ("file_upload_rce", CODE_EXEC),
        ("deserialization", CODE_EXEC),
        ("lfi", DATA_READ),
        ("xxe", DATA_READ),
    ])
    def test_new_classes_grant_a_real_privilege_not_info_disclosure(
            self, vuln_class, grants):
        """DEFAULT_SEMANTICS grants info_disclosure, which reaches no jewel.
        Each new class must carry its actual postcondition."""
        assert SEMANTICS[vuln_class].grants == grants

    def test_ssti_reaches_a_crown_jewel_where_the_fallback_would_not(self):
        gi = GraphInput(
            assets=[Asset("web-01"), Asset("db-01", is_crown_jewel=True, criticality=5)],
            findings=[Finding(id="T1", asset_id="db-01", vuln_class="ssti",
                              status="validated", confidence=0.9,
                              patch_group="tmpl")],
            routes=[Route("web-01", "db-01")], entries=["web-01"],
        )
        assert sink_reachable(build_graph(gi))

    def test_user_interaction_classes_are_genuine_and_nodes(self):
        """CSRF and open redirect need a victim to act -- the same
        Fact(user_interaction) that CVSS UI:R produces."""
        for vc in ("csrf", "open_redirect"):
            assert SEMANTICS[vc].join == "AND"
            assert "user_interaction" in SEMANTICS[vc].requires_facts

    def test_unknown_class_still_warns_after_the_additions(self):
        """Adding classes must not blunt the diagnostic for genuinely unknown
        Nuclei template names."""
        from app.graph.loader import from_dict
        from app.graph.pipeline import run
        gi = from_dict({
            "assets": [{"id": "w"}, {"id": "d", "is_crown_jewel": True}],
            "routes": [{"src": "w", "dst": "d"}], "entries": ["w"],
            "findings": [{"id": "F1", "asset_id": "w", "status": "validated",
                          "vuln_class": "apache-struts-cve-2017-5638"}]})
        codes = {p["code"] for p in
                 run(gi, trials=200, with_priority=False).summary()["diagnosis"]["problems"]}
        assert "unknown_vuln_classes" in codes


# --------------------------------------------------------------- 4th verdict

class TestUnverifiableSafely:
    def _f(self, status):
        return Finding(id="X", asset_id="a", vuln_class="deserialization",
                       status=status, confidence=0.5,
                       cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_it_scores_above_unvalidated_and_below_validated(self):
        """REGRESSION. It used to fall through the elif chain to the
        `unvalidated` weight, scoring an RCE we deliberately refused to fire
        exactly like a never-tested candidate."""
        unval = scoring.edge_probability(self._f("unvalidated")).probability
        unsafe = scoring.edge_probability(self._f("unverifiable_safely")).probability
        valid = scoring.edge_probability(
            Finding(id="X", asset_id="a", vuln_class="deserialization",
                    status="validated", confidence=0.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        ).probability
        assert unval < unsafe < valid

    def test_it_names_its_own_contribution_in_the_explanation(self):
        s = scoring.edge_probability(self._f("unverifiable_safely"))
        assert "unverifiable_safely" in s.contributions
        assert "unvalidated" not in s.contributions

    def test_contributions_still_sum_to_the_logit(self):
        s = scoring.edge_probability(self._f("unverifiable_safely"))
        assert sum(s.contributions.values()) == pytest.approx(s.logit)

    def test_it_stays_in_the_graph_unlike_a_false_positive(self):
        """We neither hide it nor fake proof of it: it remains a patchable node
        carrying an honest uncertainty label."""
        gi = mini([Finding(id="D1", asset_id="web-01",
                           vuln_class="deserialization",
                           status="unverifiable_safely", confidence=0.5,
                           patch_group="pickle")])
        g = build_graph(gi)
        assert vuln("D1") in g
        gi_fp = mini([Finding(id="D1", asset_id="web-01",
                              vuln_class="deserialization",
                              status="false_positive", confidence=0.1)])
        assert vuln("D1") not in build_graph(gi_fp)


# --------------------------------------------------------------- write-time validation

class TestWriteTimeValidation:
    def _row(self, **kw):
        base = {"id": "F1", "asset_id": "web-01", "vuln_class": "sqli",
                "status": "validated", "confidence": 0.9,
                "evidence_id": "e1", "patch_group": "CVE-2026-1"}
        base.update(kw)
        return base

    def test_a_clean_row_produces_no_problems(self):
        assert contract.validate_finding_row(self._row()) == []

    def test_unknown_class_is_an_error_at_write_time(self):
        p = contract.validate_finding_row(self._row(vuln_class="totally-made-up"))
        assert any(x["code"] == "unknown_vuln_classes" and x["severity"] == "error"
                   for x in p)

    def test_unknown_status_is_an_error(self):
        p = contract.validate_finding_row(self._row(status="probably_bad"))
        assert any(x["code"] == "unknown_status" for x in p)

    def test_out_of_range_confidence_is_an_error(self):
        p = contract.validate_finding_row(self._row(confidence=1.4))
        assert any(x["code"] == "confidence_out_of_range" for x in p)

    def test_validated_without_evidence_is_warned(self):
        p = contract.validate_finding_row(self._row(evidence_id=None))
        assert any(x["code"] == "validated_without_evidence" for x in p)

    def test_missing_patch_group_is_warned(self):
        p = contract.validate_finding_row(self._row(patch_group=None))
        assert any(x["code"] == "no_patch_groups" for x in p)

    def test_stray_column_is_caught_before_it_is_silently_dropped(self):
        """The epss_score incident, caught one layer earlier."""
        p = contract.validate_finding_row(self._row(epss_score=0.9))
        assert any(x["code"] == "unrecognised_input_keys" for x in p)

    def test_normalise_fills_patch_hours_from_the_class(self):
        r = contract.normalise_finding_row({"id": "F", "asset_id": "a",
                                            "vuln_class": "sqli"})
        assert r["patch_hours"] == contract.DEFAULT_PATCH_HOURS["sqli"]

    def test_normalise_never_overwrites_a_supplied_value(self):
        r = contract.normalise_finding_row(self._row(patch_hours=9.5))
        assert r["patch_hours"] == 9.5

    def test_batch_report_separates_errors_from_warnings(self):
        rep = contract.validate_batch([self._row(),
                                       self._row(id="F2", vuln_class="nope")])
        assert rep["ok"] is False and rep["errors"] >= 1


# --------------------------------------------------------------- API surface

class TestContractApi:
    def test_load_returns_validation_problems_to_module_2(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.graph.api import build_router
        app = FastAPI()
        app.include_router(build_router())
        c = TestClient(app)
        r = c.post("/graph/load", json={
            "assets": [{"id": "w"}, {"id": "d", "is_crown_jewel": True}],
            "routes": [{"src": "w", "dst": "d"}], "entries": ["w"],
            "findings": [{"id": "F1", "asset_id": "w",
                          "vuln_class": "not-a-real-class", "status": "validated"}]})
        assert r.status_code == 200
        v = r.json()["validation"]
        assert v["ok"] is False
        assert any(p["code"] == "unknown_vuln_classes" for p in v["problems"])

    def test_a_clean_module_2_write_reports_ok(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.graph.api import build_router
        app = FastAPI()
        app.include_router(build_router())
        c = TestClient(app)
        r = c.post("/graph/load", json={
            "assets": [{"id": "w"}, {"id": "d", "is_crown_jewel": True}],
            "routes": [{"src": "w", "dst": "d"}], "entries": ["w"],
            "findings": [{"id": "F1", "asset_id": "w", "vuln_class": "sqli",
                          "status": "validated", "confidence": 0.9,
                          "evidence_id": "e1", "patch_group": "CVE-2026-1",
                          "target_asset_id": "d"}]})
        assert r.json()["validation"]["ok"] is True

    def test_contract_endpoint_serves_the_vocabulary(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.graph.api import build_router
        app = FastAPI()
        app.include_router(build_router())
        body = TestClient(app).get("/graph/contract").json()
        assert set(body["m2_emitted_classes"]) <= set(body["vuln_classes"])
        assert "unverifiable_safely" in body["verdicts"]


# --------------------------------------------------------------- M2 evidence

class TestObservedTransitions:
    def test_observed_grants_upgrade_provenance_to_evidence(self):
        """The highest-value field Module 2 can emit: it flips the edge from
        class-table/CVSS to EVIDENCE, which RAISES the derived_fraction that
        Module 3 already prints on screen."""
        from app.graph.cvss import semantics_from_finding
        plain = Finding(id="A", asset_id="a", vuln_class="idor", status="validated")
        observed = Finding(id="A", asset_id="a", vuln_class="idor",
                           status="validated",
                           observed_requires=("user_session",),
                           observed_grants=("data_read",))
        assert semantics_from_finding(plain)[1].value != "evidence"
        assert semantics_from_finding(observed)[1].value == "evidence"

    def test_an_authorization_oracle_row_round_trips_into_the_graph(self):
        """Emit what contract.observations_for says, and the graph should carry
        an evidence-provenance edge with exactly that postcondition."""
        req, grants = contract.observations_for("authorization")
        gi = GraphInput(
            assets=[Asset("web-01"),
                    Asset("db-01", is_crown_jewel=True, criticality=5)],
            findings=[Finding(id="A1", asset_id="db-01", vuln_class="idor",
                              status="validated", confidence=0.85,
                              patch_group="authz", evidence_id="e-A1",
                              observed_requires=req, observed_grants=(grants,))],
            routes=[Route("web-01", "db-01")], entries=["web-01"],
        )
        g = build_graph(gi)
        assert g.nodes[vuln("A1")]["provenance"] == "evidence"
        post = [d for _u, _v, d in g.out_edges(vuln("A1"), data=True)
                if d.get("kind") == "post"]
        assert post and post[0]["provenance"] == "evidence"

    def test_ssrf_proven_route_is_the_strongest_route_provenance(self):
        """A canary callback is a route PROVEN by experiment -- no scanner can
        produce that. Module 2 writes it as an OBSERVED Route row alongside the
        finding, and the SSRF's own grant is only network_reach, so the chain
        needs a second finding to actually read the jewel. Modelling it any
        other way would have SSRF magically granting data_read.
        """
        from app.graph.model import Provenance
        gi = GraphInput(
            assets=[Asset("api-01"),
                    Asset("db-01", is_crown_jewel=True, criticality=5)],
            findings=[
                Finding(id="S1", asset_id="api-01", vuln_class="ssrf",
                        status="validated", confidence=0.8,
                        target_asset_id="db-01", patch_group="ssrf-allow",
                        observed_requires=("network_reach",),
                        observed_grants=("network_reach",)),
                Finding(id="Q1", asset_id="db-01", vuln_class="sqli",
                        status="validated", confidence=0.9, patch_group="orm"),
            ],
            routes=[Route("api-01", "db-01", provenance=Provenance.OBSERVED,
                          reason="SSRF canary callback from api-01 reached db-01")],
            entries=["api-01"],
        )
        g = build_graph(gi)
        assert vuln("S1") in reachable(g).fired
        assert g.nodes[vuln("S1")]["provenance"] == "evidence"
        route = g[("state", "api-01", "network_reach")][("state", "db-01", "network_reach")]
        assert route["provenance"] == "observed" and "canary" in route["reason"]
        # the jewel falls only because a second finding converts reach into read
        assert sink_reachable(prune(g))
