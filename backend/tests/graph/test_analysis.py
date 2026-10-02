"""Dominators, Monte Carlo, budget ranking, invariants, and the end-to-end
pipeline pinned against the 30-node fixture."""
from __future__ import annotations

import pytest

from app.graph import breakchain, dominators, montecarlo, ranking
from app.graph.build import build_graph, remove_patched
from app.graph.fixpoint import reachable, sink_reachable
from app.graph.loader import load_fixture
from app.graph.model import (Asset, Fact, Finding, GraphInput, Provenance,
                             Route, SUPER_SINK, vuln)
from app.graph.pipeline import recompute, run
from app.graph.prune import prune

from .test_core import mini, sqli


@pytest.fixture(scope="module")
def fx():
    return load_fixture()


@pytest.fixture(scope="module")
def result(fx):
    return run(fx, trials=4000, priority_trials=800)


# --------------------------------------------------------------- AND + facts

class TestFactPreconditions:
    def _idor_setup(self, include_fact: bool):
        """web-01 XSS grants user_session on db-01's neighbour; the IDOR on
        db-01 needs BOTH user_session there AND sequential object ids."""
        facts = [Fact("sequential_object_ids", "db-01",
                      provenance=Provenance.EVIDENCE)] if include_fact else []
        gi = GraphInput(
            assets=[Asset("web-01"), Asset("db-01", is_crown_jewel=True, criticality=5)],
            findings=[
                Finding(id="X1", asset_id="db-01", vuln_class="auth_bypass",
                        status="validated", confidence=0.9),   # -> admin_session -> user_session
                Finding(id="I1", asset_id="db-01", vuln_class="idor",
                        status="validated", confidence=0.9),
            ],
            routes=[Route("web-01", "db-01")], entries=["web-01"],
        )
        return build_graph(gi, include_assumed_facts=False), facts, gi

    def test_and_node_blocked_when_the_enabling_fact_is_absent(self):
        g, _, gi = self._idor_setup(False)
        assert vuln("I1") not in reachable(g).fired

    def test_and_node_fires_once_the_fact_is_observed(self):
        _, facts, gi = self._idor_setup(True)
        gi.facts = facts
        g = build_graph(gi, include_assumed_facts=False)
        r = reachable(g)
        assert vuln("I1") in r.fired
        assert vuln("I1") in r.support        # AND justification recorded

    def test_assumed_facts_included_by_default_but_labelled(self):
        gi = mini([Finding(id="I1", asset_id="db-01", vuln_class="idor",
                           status="validated", confidence=0.9)])
        g = build_graph(gi)
        auto = ("fact", "sequential_object_ids", "db-01")
        assert g.nodes[auto]["provenance"] == "assumed"


# --------------------------------------------------------------- dominators

class TestDominators:
    def test_exclusive_gate_is_a_chokepoint(self):
        """One finding is the only way in -> it must dominate the jewel."""
        g = build_graph(mini([sqli("S1")]))
        chokes = dominators.chokepoints(g)
        assert [c.vuln_id for c in chokes] == ["S1"]
        assert chokes[0].dominated_jewels == ["db-01"]

    def test_redundant_paths_produce_no_dominator(self):
        g = build_graph(mini([sqli("S1"), sqli("S2")]))
        assert dominators.chokepoints(g) == []

    def test_a_dominator_is_always_a_cut_of_size_one(self):
        g = build_graph(mini([sqli("S1")]))
        for c in dominators.chokepoints(g):
            assert not sink_reachable(remove_patched(g, {c.vuln_id}))

    def test_fixture_dominator_gates_backup(self, fx):
        g = prune(build_graph(fx))
        ids = {c.vuln_id for c in dominators.chokepoints(g)}
        assert "F11" in ids       # auth_bypass is the only route to backup-01
        c = next(c for c in dominators.chokepoints(g) if c.vuln_id == "F11")
        assert "backup-01" in c.dominated_jewels

    def test_ranking_is_deterministic(self, fx):
        g = prune(build_graph(fx))
        assert ([c.vuln_id for c in dominators.chokepoints(g)]
                == [c.vuln_id for c in dominators.chokepoints(g)])


# --------------------------------------------------------------- Monte Carlo

class TestMonteCarlo:
    def test_same_seed_gives_byte_identical_numbers(self, fx):
        g = prune(build_graph(fx))
        a = montecarlo.simulate(g, trials=800, seed=1337, target_ci=None)
        b = montecarlo.simulate(g, trials=800, seed=1337, target_ci=None)
        assert a.node_prob == b.node_prob
        assert a.modal_paths == b.modal_paths

    def test_reproducible_across_processes_under_hash_randomisation(self):
        """REGRESSION. jewel_prob was keyed by asset but built from a SET of
        terminal-privilege states, so which marginal won depended on hash order
        -- the numbers changed between processes while claiming reproducibility.
        An asset's compromise probability is the UNION over its terminal
        privileges, and both it and the modal path are now order-independent."""
        import json
        import os
        import subprocess
        import sys
        code = (
            "import json;"
            "from app.graph.loader import load_fixture;"
            "from app.graph.build import build_graph;"
            "from app.graph.prune import prune;"
            "from app.graph.montecarlo import simulate;"
            "g=prune(build_graph(load_fixture()));"
            "m=simulate(g,trials=1500,seed=1337,target_ci=None);"
            "print(json.dumps({'p':m.jewel_prob,'ci':m.jewel_ci,'modal':m.modal_paths},"
            "sort_keys=True))"
        )
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # repo root
        outs = []
        for hs in ("0", "12345"):
            env = {**os.environ, "PYTHONHASHSEED": hs,
                   "PYTHONPATH": os.path.join(root, "backend")}
            outs.append(subprocess.run([sys.executable, "-c", code], env=env,
                                       cwd=os.path.join(root, "backend"),
                                       capture_output=True, text=True).stdout)
        assert outs[0] and outs[0] == outs[1]
        assert set(json.loads(outs[0])["p"]) == {"backup-01", "db-01"}

    def test_jewel_probability_is_the_union_over_terminal_privileges(self, fx):
        """P(asset compromised) >= P(any single terminal privilege on it)."""
        g = prune(build_graph(fx))
        mc = montecarlo.simulate(g, trials=3000, seed=1337, target_ci=None)
        for asset, p in mc.jewel_prob.items():
            # only TERMINAL privileges count; every state of a jewel asset
            # carries jewel=True, including network_reach
            marginals = [mc.node_prob[n] for n, d in g.nodes(data=True)
                         if d.get("jewel") and d.get("asset") == asset
                         and g.has_edge(n, SUPER_SINK)]
            assert p >= max(marginals) - 1e-9

    def test_different_seed_agrees_within_the_confidence_interval(self, fx):
        g = prune(build_graph(fx))
        a = montecarlo.simulate(g, trials=4000, seed=1, target_ci=None)
        b = montecarlo.simulate(g, trials=4000, seed=2, target_ci=None)
        for k in a.jewel_prob:
            assert abs(a.jewel_prob[k] - b.jewel_prob[k]) < 0.05

    def test_correlated_sampling_lowers_union_risk_vs_independent(self):
        """UNION topology: two PARALLEL paths to the jewel gated by one CVE.

        The old name of this test ("raises risk") contradicted its own
        assertion. Positive dependence LOWERS the probability of a union:
        independent sampling gives the attacker two independent shots at what is
        really one exploit -- 1-(1-p)^2 = 2p-p^2 versus a correlated p -- so
        naive sampling OVERSTATES risk here. The series case is the mirror image
        and is covered by the next test.
        """
        gi = GraphInput(
            assets=[Asset("web-01"), Asset("web-02"),
                    Asset("db-01", is_crown_jewel=True, criticality=5)],
            findings=[sqli("S1", asset_id="web-01", patch_group="G", confidence=0.5),
                      sqli("S2", asset_id="web-02", patch_group="G", confidence=0.5)],
            routes=[Route("web-01", "db-01"), Route("web-02", "db-01")],
            entries=["web-01", "web-02"],
        )
        g = prune(build_graph(gi))
        corr = montecarlo.simulate(g, trials=6000, seed=7, correlated=True, target_ci=None)
        indep = montecarlo.simulate(g, trials=6000, seed=7, correlated=False, target_ci=None)
        # independent sampling gets two shots at the same exploit
        assert indep.jewel_prob["db-01"] > corr.jewel_prob["db-01"]

    def test_correlated_sampling_raises_series_risk_vs_independent(self):
        """SERIES topology: a CHAIN whose two steps reuse the same CVE.

        The mirror image of the union case. Positive dependence RAISES the
        probability of an intersection -- the two steps succeed together, so
        independent sampling (p*p) UNDERSTATES the risk that correlated sampling
        (min(p,p) = p) reports. Together these two tests are why the claim has
        to be stated as topology-dependent rather than one-directional.

        Chain: web-01 -> api-01, RCE on api-01 grants code_exec (which implies
        user_session), which is the PR:L precondition of the SQLi that reads
        db-01. Both findings share patch_group 'G'.
        """
        gi = GraphInput(
            assets=[Asset("web-01"), Asset("api-01"),
                    Asset("db-01", is_crown_jewel=True, criticality=5)],
            findings=[
                Finding(id="R1", asset_id="api-01", vuln_class="rce",
                        status="validated", confidence=0.9, patch_group="G",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                Finding(id="Q1", asset_id="api-01", vuln_class="sqli",
                        status="validated", confidence=0.9, patch_group="G",
                        target_asset_id="db-01",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N"),
            ],
            routes=[Route("web-01", "api-01")], entries=["web-01"],
        )
        g = prune(build_graph(gi))
        for _u, _v, d in g.edges(data=True):
            if d.get("kind") == "post":
                d["p"] = 0.50                      # exercise the estimator
        corr = montecarlo.simulate(g, trials=6000, seed=7, correlated=True,
                                   target_ci=None)
        indep = montecarlo.simulate(g, trials=6000, seed=7, correlated=False,
                                    target_ci=None)
        assert corr.jewel_prob["db-01"] > indep.jewel_prob["db-01"]
        assert corr.jewel_prob["db-01"] == pytest.approx(0.50, abs=0.03)
        assert indep.jewel_prob["db-01"] == pytest.approx(0.25, abs=0.03)

    def test_probability_beats_single_path_when_paths_overlap(self):
        """Eight independent paths at p=0.3 give the attacker ~0.94, while a
        shortest-path metric reports 0.3. This is exactly why we do not rank
        risk by shortest path. Edge probabilities are set directly so the test
        exercises the estimator, not the scorecard."""
        gi = GraphInput(
            assets=[Asset("web-01"), Asset("db-01", is_crown_jewel=True)],
            findings=[sqli(f"S{i}", patch_group=f"G{i}") for i in range(8)],
            routes=[Route("web-01", "db-01")], entries=["web-01"],
        )
        g = prune(build_graph(gi))
        for u, v, d in g.edges(data=True):
            if d.get("kind") == "post":
                d["p"] = 0.30
        mc = montecarlo.simulate(g, trials=8000, seed=3, target_ci=None)
        single = ranking.display_path(g)["probability"]
        assert single == pytest.approx(0.30, abs=0.01)
        assert mc.jewel_prob["db-01"] == pytest.approx(1 - 0.7 ** 8, abs=0.03)
        assert mc.jewel_prob["db-01"] > 3 * single

    def test_confidence_interval_shrinks_with_trials(self, fx):
        g = prune(build_graph(fx))
        small = montecarlo.simulate(g, trials=500, seed=5, target_ci=None)
        big = montecarlo.simulate(g, trials=8000, seed=5, target_ci=None)
        j = next(iter(small.jewel_prob))
        k = next(n for n, d in g.nodes(data=True) if d.get("asset") == j and d.get("jewel"))
        assert big.node_ci[k] < small.node_ci[k]

    def test_adaptive_stopping_reports_the_trials_it_needed(self, fx):
        g = prune(build_graph(fx))
        mc = montecarlo.simulate(g, trials=50_000, seed=9, target_ci=0.02,
                                 check_every=500, min_trials=500)
        assert mc.stopped_early and mc.trials < 50_000

    def test_modal_path_is_a_real_witness_not_a_separate_computation(self, fx):
        g = prune(build_graph(fx))
        mc = montecarlo.simulate(g, trials=3000, seed=1337, target_ci=None)
        for asset, m in mc.modal_paths.items():
            assert m["count"] >= 1 and 0 < m["share"] <= 1.0
            assert m["path"][0] == "meta|SUPER_SOURCE"

    def test_witness_frequency_never_exceeds_participation(self, fx):
        """Only one route is credited per world, so witness <= participation."""
        g = prune(build_graph(fx))
        mc = montecarlo.simulate(g, trials=2000, seed=11, target_ci=None)
        for e, w in mc.edge_witness.items():
            assert w <= mc.edge_participation.get(e, 0.0) + 1e-9


# --------------------------------------------------------------- ranking

class TestRanking:
    def test_greedy_respects_the_budget(self, fx):
        g = prune(build_graph(fx))
        plan = ranking.budget_plan(g, budget_hours=4.0, k=50)
        assert plan.hours_used <= 4.0
        assert plan.paths_covered <= plan.paths_total

    def test_more_budget_never_covers_fewer_paths(self, fx):
        g = prune(build_graph(fx))
        small = ranking.budget_plan(g, 2.0, k=50)
        large = ranking.budget_plan(g, 12.0, k=50)
        assert large.paths_covered >= small.paths_covered

    def test_display_path_probability_is_the_product_of_edge_probabilities(self):
        g = build_graph(mini([sqli("S1", confidence=0.95)]))
        d = ranking.display_path(g)
        assert 0 < d["probability"] <= 1.0
        assert "visualisation only" in d["note"]

    def test_priority_ranking_is_deterministic(self, fx):
        g = prune(build_graph(fx))
        mc = montecarlo.simulate(g, trials=800, seed=1337, target_ci=None)
        a = ranking.priority_ranking(g, mc, trials=400, seed=1337)
        b = ranking.priority_ranking(g, mc, trials=400, seed=1337)
        assert [x["vuln_id"] for x in a] == [x["vuln_id"] for x in b]


# --------------------------------------------------------------- invariants

class TestInvariants:
    def test_every_invariant_passes_on_the_fixture(self, result):
        assert result.invariants["all_passed"], result.invariants

    def test_patching_never_increases_reachability(self, fx):
        g = prune(build_graph(fx))
        base = reachable(g).reached
        for n, d in g.nodes(data=True):
            if d.get("type") == "vuln":
                assert reachable(remove_patched(g, {n[1]})).reached <= base

    def test_prune_preserves_and_preconditions(self):
        """REGRESSION. Naive fwd-and-rev pruning drops a precondition that leads
        nowhere useful; the AND node then degrades into an OR node and invents a
        path to the crown jewel. Pruning is AND-aware for exactly this reason."""
        gi = GraphInput(
            assets=[Asset("web-01"), Asset("db-01", is_crown_jewel=True, criticality=5)],
            findings=[Finding(id="I1", asset_id="db-01", vuln_class="idor",
                              status="validated", confidence=0.9)],
            routes=[], entries=["web-01"],
        )
        full = build_graph(gi)
        assert not sink_reachable(full)
        assert not sink_reachable(prune(full))      # pruning must agree

    def test_pruning_changes_no_answer(self, fx):
        full = build_graph(fx)
        assert sink_reachable(full) == sink_reachable(prune(full))
        assert (sorted(breakchain.solve(full).vulns)
                == sorted(breakchain.solve(prune(full)).vulns))


# --------------------------------------------------------------- pipeline

class TestPipeline:
    def test_fixture_reaches_both_crown_jewels(self, result):
        assert result.reachable_jewels == ["backup-01", "db-01"]

    def test_pruning_removes_most_of_the_graph(self, result):
        assert result.prune["reduction"] > 0.5

    def test_cut_is_sound_and_irreducible(self, result):
        assert result.cut["sound"] and result.cut["irreducible"]

    def test_grouped_patch_is_detected(self, fx):
        """F1 and F2 share nginx-CVE-2026-1111: one action, charged once."""
        g = prune(build_graph(fx))
        ilp = breakchain.label_cut(g)
        mc = breakchain.min_cut(g)
        assert ilp.cost <= mc.cost

    def test_mutual_compromise_cluster_is_reported_not_condensed(self, result):
        assert ["cache-01", "web-01"] in result.cycles
        # and the cycle members are still individually present in the graph
        assert ("state", "cache-01", "network_reach") in result.graph

    def test_provenance_report_is_published(self, result):
        p = result.provenance
        assert 0.0 <= p["derived_fraction"] <= 1.0
        assert p["derived_fraction"] > 0.5      # most of this graph is not guessed

    def test_no_reachable_jewel_yields_a_nearest_miss_not_an_empty_screen(self):
        gi = mini([], routes=[])
        gi.findings = [Finding(id="I1", asset_id="db-01", vuln_class="idor",
                               status="validated")]
        res = run(gi, trials=200, with_priority=False)
        assert res.reachable_jewels == []
        assert "nearest_miss" in res.summary()

    def test_timings_are_recorded_for_every_stage(self, result):
        for stage in ("build", "A1_prune", "A2_A3_cut", "A4_dominators", "A5_montecarlo"):
            assert stage in result.timings_ms


# --------------------------------------------------------------- retest

class TestRetest:
    def test_patching_the_cut_isolates_the_jewels(self, fx):
        base = run(fx, trials=1500, with_priority=False)
        d = recompute(fx, set(base.cut["vulns"]), trials=1500)
        assert d["jewels_still_reachable"] == []
        for asset, m in d["jewel_delta"].items():
            assert m["after"] == 0.0 and m["delta"] < 0

    def test_partial_patch_reduces_but_does_not_zero_risk(self, fx):
        d = recompute(fx, {"F4"}, trials=1500)
        assert d["paths_after"] <= d["paths_before"]

    def test_retest_is_reproducible(self, fx):
        a = recompute(fx, {"F4"}, trials=1000, seed=1337)
        b = recompute(fx, {"F4"}, trials=1000, seed=1337)
        assert a["jewel_delta"] == b["jewel_delta"]


# --------------------------------------------------------------- export

class TestExport:
    def test_node_ids_are_stable_across_renders(self, result):
        a = result.cytoscape()
        b = result.cytoscape()
        assert [n["data"]["id"] for n in a["elements"]["nodes"]] == \
               [n["data"]["id"] for n in b["elements"]["nodes"]]

    def test_every_validated_edge_carries_its_evidence_id(self, result):
        posts = [e for e in result.cytoscape()["elements"]["edges"]
                 if e["data"]["kind"] == "post"]
        assert posts and any(e["data"]["evidence_id"] for e in posts)

    def test_heat_map_metric_is_labelled_and_is_not_called_flow(self, result):
        legend = result.cytoscape()["legend"]
        assert "witness" in legend["heat_metric"]
        assert "not" in legend["not_flow"].lower()

    def test_cut_and_dominator_overlays_are_present(self, result):
        vulns = [n for n in result.cytoscape()["elements"]["nodes"]
                 if n["data"]["type"] == "vuln"]
        assert any(n["data"]["in_min_cut"] for n in vulns)
        assert all("compromise_prob" in n["data"] for n in vulns)


# --------------------------------------------------------------- integration

class TestCrossModuleIntegration:
    def test_phishing_finding_creates_an_entry_point(self):
        """The 3-mark phishing module must measurably move the 15-mark graph.
        Here the jewel is UNREACHABLE without the phishing entry."""
        from app.graph.build import attach_phishing_entry
        gi = GraphInput(
            assets=[Asset("corp-ws"),
                    Asset("db-01", is_crown_jewel=True, criticality=5)],
            findings=[Finding(id="A1", asset_id="db-01", vuln_class="broken_access_control",
                              status="validated", confidence=0.9)],
            routes=[Route("corp-ws", "db-01")], entries=[],
        )
        base = prune(build_graph(gi))
        assert not sink_reachable(base)

        g2 = build_graph(gi)
        attach_phishing_entry(g2, asset_id="db-01", risk_score=0.82, ref="h1")
        g2 = prune(g2)
        after = montecarlo.simulate(g2, trials=4000, seed=1337, target_ci=None)
        assert sink_reachable(g2)
        assert after.jewel_prob["db-01"] > 0.5

    def test_breached_credential_uses_a_digest_not_an_address(self, fx):
        from app.graph.build import attach_breached_credential
        g = build_graph(fx)
        v = attach_breached_credential(g, asset_id="admin-ws", ref="hmac-abc123")
        assert "@" not in str(v)


class TestDiagnostics:
    """REGRESSION. Real Discovery rows with no is_crown_jewel produced an empty
    analysis, seven green invariants, and `all_passed: True` -- a completely
    vacuous result reported as a clean success. Worse than crashing, because
    nobody investigates a green run."""

    def _gi(self, **over):
        base = {"assets": [{"id": "web-01"}, {"id": "db-01"}],
                "routes": [{"src": "web-01", "dst": "db-01"}],
                "entries": ["web-01"],
                "findings": [{"id": "F1", "asset_id": "web-01",
                              "vuln_class": "sqli", "status": "validated"}]}
        base.update(over)
        from app.graph.loader import from_dict
        return from_dict(base)

    def test_missing_crown_jewel_is_an_error_not_an_empty_result(self):
        s = run(self._gi(), trials=200, with_priority=False).summary()
        assert s["diagnosis"]["status"] == "no_crown_jewels"
        assert s["diagnosis"]["answerable"] is False
        assert s["invariants"]["all_passed"] is False

    def test_missing_entry_points_is_an_error(self):
        s = run(self._gi(entries=[]), trials=200, with_priority=False).summary()
        assert s["diagnosis"]["status"] in ("no_entry_points", "no_crown_jewels")
        assert s["diagnosis"]["answerable"] is False

    def test_no_live_findings_is_an_error(self):
        gi = self._gi(assets=[{"id": "web-01"},
                              {"id": "db-01", "is_crown_jewel": True}],
                      findings=[{"id": "F1", "asset_id": "web-01",
                                 "vuln_class": "sqli", "status": "false_positive"}])
        s = run(gi, trials=200, with_priority=False).summary()
        assert s["diagnosis"]["status"] == "no_findings"

    def test_unreachable_jewels_is_a_RESULT_not_an_error(self):
        """The distinction that matters: well-posed question, answer is 'no'."""
        gi = self._gi(assets=[{"id": "web-01"},
                              {"id": "db-01", "is_crown_jewel": True}],
                      routes=[])
        s = run(gi, trials=200, with_priority=False).summary()
        assert s["diagnosis"]["status"] == "jewels_unreachable"
        assert s["diagnosis"]["answerable"] is True
        assert s["invariants"]["all_passed"] is True
        assert run(gi, trials=200, with_priority=False).cytoscape()["elements"]["nodes"]

    def test_unknown_vuln_class_raises_a_warning_not_silence(self):
        """Nuclei template names will not match SEMANTICS keys."""
        gi = self._gi(assets=[{"id": "web-01"},
                              {"id": "db-01", "is_crown_jewel": True}],
                      findings=[{"id": "F1", "asset_id": "web-01",
                                 "vuln_class": "apache-struts-cve-2017-5638",
                                 "status": "validated"}])
        codes = {p["code"] for p in
                 run(gi, trials=200, with_priority=False).summary()["diagnosis"]["problems"]}
        assert "unknown_vuln_classes" in codes

    def test_missing_routes_raises_a_warning(self):
        gi = self._gi(assets=[{"id": "web-01"},
                              {"id": "db-01", "is_crown_jewel": True}], routes=[])
        codes = {p["code"] for p in
                 run(gi, trials=200, with_priority=False).summary()["diagnosis"]["problems"]}
        assert "no_routes" in codes

    def test_healthy_fixture_is_ok_with_no_errors(self, fx):
        s = run(fx, trials=500, with_priority=False).summary()
        assert s["diagnosis"]["status"] == "ok"
        assert s["diagnosis"]["answerable"] is True
        assert not [p for p in s["diagnosis"]["problems"] if p["severity"] == "error"]
        assert s["invariants"]["all_passed"] is True


class TestInputKeyDiagnostics:
    """REGRESSION. A generated 100-asset topology wrote `epss_score` where the
    loader reads `epss`. Every EPSS value was silently dropped and the analysis
    still reported diagnosis.status == 'ok' with zero problems."""

    def _base(self):
        return {"assets": [{"id": "w"}, {"id": "d", "is_crown_jewel": True}],
                "routes": [{"src": "w", "dst": "d"}], "entries": ["w"],
                "findings": [{"id": "F1", "asset_id": "w", "vuln_class": "sqli",
                              "status": "validated", "target_asset_id": "d",
                              "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"}]}

    def test_near_miss_key_is_reported_with_a_suggestion(self):
        from app.graph.loader import from_dict
        d = self._base()
        d["findings"][0]["epss_score"] = 0.97
        gi = from_dict(d)
        assert gi.findings[0].epss is None            # genuinely dropped
        probs = run(gi, trials=200, with_priority=False).summary()["diagnosis"]["problems"]
        p = next(x for x in probs if x["code"] == "unrecognised_input_keys")
        assert "epss_score" in p["message"] and "'epss'" in p["message"]

    def test_correct_key_produces_no_warning(self):
        from app.graph.loader import from_dict
        d = self._base()
        d["findings"][0]["epss"] = 0.97
        gi = from_dict(d)
        assert gi.findings[0].epss == 0.97
        codes = {x["code"] for x in
                 run(gi, trials=200, with_priority=False).summary()["diagnosis"]["problems"]}
        assert "unrecognised_input_keys" not in codes

    def test_missing_patch_group_is_warned(self):
        from app.graph.loader import from_dict
        codes = {x["code"] for x in run(from_dict(self._base()), trials=200,
                                        with_priority=False).summary()["diagnosis"]["problems"]}
        assert "no_patch_groups" in codes

    def test_fixture_has_patch_groups_and_no_stray_keys(self, fx):
        probs = {x["code"] for x in
                 run(fx, trials=300, with_priority=False).summary()["diagnosis"]["problems"]}
        assert "no_patch_groups" not in probs
        assert "unrecognised_input_keys" not in probs


class TestCycleReporting:
    def test_mutual_compromise_is_reported_even_when_off_the_jewel_path(self):
        """REGRESSION. Cycles were detected on the pruned graph, so a pair of
        hosts that can compromise each other but does not lead to a crown jewel
        was silently dropped. Mutual compromise is a finding on its own."""
        from app.graph.loader import from_dict
        gi = from_dict({
            "assets": [{"id": "w"}, {"id": "d", "is_crown_jewel": True},
                       {"id": "x"}, {"id": "y"}],       # x <-> y, unrelated to d
            "routes": [{"src": "w", "dst": "d"},
                       {"src": "x", "dst": "y"}, {"src": "y", "dst": "x"}],
            "entries": ["w", "x"],
            "findings": [
                {"id": "F1", "asset_id": "w", "vuln_class": "sqli",
                 "status": "validated", "target_asset_id": "d", "patch_group": "g1",
                 "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
                {"id": "F2", "asset_id": "x", "vuln_class": "rce",
                 "status": "validated", "patch_group": "g2"},
                {"id": "F3", "asset_id": "y", "vuln_class": "rce",
                 "status": "validated", "patch_group": "g3"},
            ]})
        res = run(gi, trials=300, with_priority=False)
        assert res.reachable_jewels == ["d"]
        assert ["x", "y"] in res.cycles      # off the jewel path, still reported
