"""Core correctness: privilege lattice, CVSS derivation, AND semantics, and the
four canonical break-the-chain tests."""
from __future__ import annotations

import pytest

from app.graph import breakchain, cvss
from app.graph.build import build_graph, or_relaxation, provenance_report, remove_patched
from app.graph.fixpoint import reachable, sink_reachable
from app.graph.model import (
    ADMIN_SESSION, CODE_EXEC, DATA_READ, NETWORK_REACH, USER_SESSION,
    Asset, Fact, Finding, GraphInput, Route, implies, state, vuln,
)

SQLI_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"


def mini(findings, *, facts=(), routes=None) -> GraphInput:
    """web-01 (entry) -> db-01 (crown jewel)."""
    return GraphInput(
        assets=[Asset("web-01", zone="dmz"),
                Asset("db-01", zone="data", is_crown_jewel=True, criticality=5)],
        findings=list(findings),
        facts=list(facts),
        routes=list(routes if routes is not None else [Route("web-01", "db-01")]),
        entries=["web-01"],
    )


def sqli(fid="S1", **kw) -> Finding:
    base = dict(id=fid, asset_id="web-01", vuln_class="sqli", status="validated",
                confidence=0.95, cvss_vector=SQLI_VEC, target_asset_id="db-01",
                patch_hours=2.0)
    base.update(kw)
    return Finding(**base)


# --------------------------------------------------------------- lattice

class TestPrivilegeLattice:
    def test_downward_implication(self):
        assert implies(CODE_EXEC, ADMIN_SESSION)
        assert implies(CODE_EXEC, USER_SESSION)
        assert implies(CODE_EXEC, NETWORK_REACH)

    def test_code_exec_does_not_imply_data_read(self):
        """The chain version of this lattice invents lateral movement: owning
        the web server is not owning the database."""
        assert not implies(CODE_EXEC, DATA_READ)

    def test_data_read_implies_reach_but_not_code_exec(self):
        assert implies(DATA_READ, NETWORK_REACH)
        assert not implies(DATA_READ, CODE_EXEC)

    def test_no_upward_implication(self):
        assert not implies(NETWORK_REACH, CODE_EXEC)
        assert not implies(USER_SESSION, ADMIN_SESSION)


# --------------------------------------------------------------- CVSS

class TestCVSS:
    def test_max_exploitability_normalises_to_one(self):
        v = cvss.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert v.exploitability() == pytest.approx(3.887, abs=0.002)
        assert v.exploitability_norm() == pytest.approx(1.0, abs=0.001)

    def test_scope_changed_detected(self):
        assert cvss.parse(SQLI_VEC).scope_changed
        assert not cvss.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").scope_changed

    def test_preconditions_from_exploitability_metrics(self):
        s = cvss.derive_semantics(cvss.parse("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N"))
        assert USER_SESSION in s.requires        # AV:L
        assert ADMIN_SESSION in s.requires       # PR:H
        assert s.join == "AND"                   # two distinct preconditions

    def test_user_interaction_creates_a_fact(self):
        s = cvss.derive_semantics(cvss.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"))
        assert "user_interaction" in s.requires_facts

    def test_postcondition_from_impact_metrics(self):
        assert cvss.derive_semantics(cvss.parse(SQLI_VEC)).grants == DATA_READ
        rce = cvss.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert cvss.derive_semantics(rce).grants == CODE_EXEC

    def test_malformed_vector_returns_none_not_a_guess(self):
        assert cvss.parse("CVSS:3.1/AV:N/AC:L") is None
        assert cvss.parse(None) is None
        assert cvss.parse("garbage") is None

    def test_evidence_overrides_vector(self):
        f = sqli(observed_grants=("code_exec",))
        sem, prov = cvss.semantics_from_finding(f)
        assert sem.grants == CODE_EXEC
        assert prov.value == "evidence"


# --------------------------------------------------------------- AND semantics

class TestAndSemantics:
    def test_and_node_does_not_fire_without_every_precondition(self):
        """An IDOR needs BOTH a session AND sequential object ids. Treating
        that as OR invents an attack path that does not exist."""
        gi = mini([Finding(id="I1", asset_id="db-01", vuln_class="idor",
                           status="validated", confidence=0.9)])
        g = build_graph(gi)
        r = reachable(g)
        # the enabling Fact was auto-created as ASSUMED and is not reachable
        assert vuln("I1") not in r.fired

    def test_or_relaxation_is_a_superset(self):
        gi = mini([Finding(id="I1", asset_id="db-01", vuln_class="idor",
                           status="validated", confidence=0.9)])
        g = build_graph(gi)
        assert reachable(g).reached <= reachable(or_relaxation(g)).reached

    def test_and_fires_when_last_precondition_arrives(self):
        gi = mini(
            [sqli("S1"),                                   # grants data_read on db-01
             Finding(id="C1", asset_id="db-01", vuln_class="cred_reuse",
                     status="validated", confidence=0.8)],
            facts=[Fact("shared_credential", "db-01", provenance=__import__(
                "app.graph.model", fromlist=["Provenance"]).Provenance.OBSERVED)],
        )
        g = build_graph(gi)
        r = reachable(g)
        assert vuln("C1") in r.fired
        assert vuln("C1") in r.support        # recorded as an AND justification


# ------------------------------------------ the four canonical cut tests

class TestBreakTheChain:
    def test_1_without_the_finding_the_jewel_is_unreachable(self):
        g = build_graph(mini([]))
        assert not sink_reachable(g)
        assert state("db-01", DATA_READ) not in reachable(g).reached

    def test_2_with_it_reachable_and_the_cut_is_exactly_that_finding(self):
        g = build_graph(mini([sqli("S1")]))
        assert sink_reachable(g)
        cut = breakchain.solve(g)
        assert cut.vulns == ["S1"]
        assert cut.sound and cut.irreducible
        assert not sink_reachable(remove_patched(g, {"S1"}))

    def test_3_two_independent_paths_give_a_cut_of_size_two(self):
        g = build_graph(mini([sqli("S1"), sqli("S2")]))
        cut = breakchain.solve(g)
        assert sorted(cut.vulns) == ["S1", "S2"]
        assert not sink_reachable(remove_patched(g, {"S1", "S2"}))
        assert sink_reachable(remove_patched(g, {"S1"}))   # one alone is not enough

    def test_4_same_patch_group_makes_the_ilp_beat_the_min_cut(self):
        """This divergence is the proof the ILP is doing real work: max-flow
        assumes edges are cut independently, but one action fixes both."""
        g = build_graph(mini([sqli("S1", patch_group="api-orm-upgrade"),
                              sqli("S2", patch_group="api-orm-upgrade")]))
        mc = breakchain.min_cut(g)
        ilp = breakchain.label_cut(g)
        assert mc.cost == pytest.approx(4.0)        # 2 findings x 2h, charged twice
        assert ilp.cost == pytest.approx(2.0)       # one action, charged once
        assert ilp.patch_groups == ["api-orm-upgrade"]
        assert sorted(ilp.vulns) == ["S1", "S2"]

    def test_already_isolated_reports_zero_not_an_error(self):
        g = build_graph(mini([], routes=[]))
        cut = breakchain.solve(g)
        assert cut.cost == 0 and cut.vulns == []

    def test_unpatchable_path_reports_infinite_cost(self):
        """Every path routes through a non-patchable Fact -> architectural
        change, not a patch. A valid finding, not a crash."""
        from app.graph.model import Provenance, SUPER_SOURCE, fact
        gi = mini([])
        g = build_graph(gi)
        f = fact("trust_relationship", "domain")
        g.add_node(f, type="fact", patchable=False, provenance=Provenance.OBSERVED.value)
        g.add_edge(SUPER_SOURCE, f, p=1.0, kind="entry")
        g.add_edge(f, state("db-01", DATA_READ), p=1.0, kind="post")
        cut = breakchain.min_cut(g)
        assert cut.cost == float("inf")
        assert "architectural" in " ".join(cut.notes)

    def test_reduction_removes_redundant_elements(self):
        g = build_graph(mini([sqli("S1"), sqli("S2")]))
        fat = breakchain.Cut(vulns=["S1", "S2"], cost=4.0)
        # both are genuinely needed here, so nothing should be dropped
        assert sorted(breakchain.reduce_cut(g, fat).vulns) == ["S1", "S2"]


class TestProvenance:
    def test_report_sums_to_one(self):
        rep = provenance_report(build_graph(mini([sqli("S1")])))
        assert rep["derived_fraction"] + rep["assumed_fraction"] == pytest.approx(1.0)

    def test_cvss_backed_finding_is_not_counted_as_assumed(self):
        g = build_graph(mini([sqli("S1")]))
        assert g.nodes[vuln("S1")]["provenance"] in ("cvss_vector", "evidence")
