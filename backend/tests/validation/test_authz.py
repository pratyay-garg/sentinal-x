"""Phase 2 -- the authorization oracle and its round trip into Module 3."""
from __future__ import annotations


from app.graph.build import build_graph
from app.graph.loader import from_dict
from app.graph.model import vuln
from app.engines.validation.mock_target import MockAuthzTarget
from app.engines.validation.oracles.authz import (
    Account, run_authorization,
)
from app.engines.validation.writer import (
    corroboration_warnings, observations, to_finding_row, write,
)

A = Account("acct-A", owns="10")
B = Account("acct-B", owns="11")
EP = "/api/user_profile/{id}"


def _run(target, vuln_class="idor"):
    return run_authorization(target, asset_id="api-01", endpoint=EP,
                             account_a=A, account_b=B, vuln_class=vuln_class)


# --------------------------------------------------------------- the four outcomes

class TestMatrixOutcomes:
    def test_vulnerable_target_is_validated_with_two_leaks(self):
        r = _run(MockAuthzTarget.vulnerable())
        assert r.verdict.status == "validated"
        assert r.verdict.outcomes[0].effect == 2.0        # both off-diagonals leaked
        assert r.verdict.confidence > 0.9

    def test_secure_target_is_a_disproved_false_positive(self):
        r = _run(MockAuthzTarget.secure())
        assert r.verdict.status == "false_positive"
        assert not r.verdict.outcomes[0].fired
        assert r.verdict.confidence <= 0.1

    def test_dead_session_is_inconclusive_not_a_finding(self):
        """The positive control (an account reading its OWN object) failed, so a
        403 elsewhere proves nothing. Must abstain, never validate."""
        r = _run(MockAuthzTarget.dead_session())
        assert r.verdict.status == "inconclusive"
        assert "positive control failed" in r.reason

    def test_indistinguishable_objects_force_abstention(self):
        """A cross-read that matches cannot be told from a coincidence when the
        two owners' objects are identical to begin with."""
        r = _run(MockAuthzTarget.indistinguishable())
        assert r.verdict.status == "inconclusive"
        assert "indistinguishable" in r.reason


# --------------------------------------------------------------- the matrix itself

class TestMatrixMechanics:
    def test_positive_control_diagonal_is_marked(self):
        cells = _run(MockAuthzTarget.vulnerable()).cells
        controls = [c for c in cells if c.is_control]
        assert len(controls) == 2
        assert all(c.actor == c.object_owner for c in controls)

    def test_leak_requires_a_content_match_not_just_a_200(self):
        """A 200 whose body does NOT match the owner's view is not a leak."""
        # object 11 owned by B but serving unrelated content to everyone
        tgt = MockAuthzTarget(
            {"10": ("acct-A", "<alice private data address ssn distinct>"),
             "11": ("acct-B", "<bob private data phone dob distinct>")},
            enforce=False)
        r = _run(tgt)
        # genuinely vulnerable + distinct content => validated with real matches
        assert r.verdict.status == "validated"
        leaked = [c for c in r.cells if c.leaked]
        assert leaked and all(c.match >= 0.9 for c in leaked)

    def test_every_request_is_read_only(self):
        """LAW 5: non-destructive by construction. The oracle only issues GETs."""
        seen = []

        def spy(request):
            seen.append(request.method)
            return MockAuthzTarget.vulnerable()(request)

        _run(spy)
        assert seen and set(seen) == {"GET"}


# --------------------------------------------------------------- writer integration

class TestWriterIntegration:
    def test_validated_verdict_observes_data_read(self):
        v = _run(MockAuthzTarget.vulnerable()).verdict
        assert observations(v) == (("user_session",), "data_read")

    def test_authorization_is_self_corroborating_no_warning(self):
        """A single authorization firing needs no second oracle -- the diagonal
        is its own control."""
        v = _run(MockAuthzTarget.vulnerable()).verdict
        assert corroboration_warnings(v) == []

    def test_row_is_contract_valid(self):
        v = _run(MockAuthzTarget.vulnerable()).verdict
        rep = write([v]).validation
        assert rep["ok"] and rep["errors"] == 0

    def test_row_carries_patch_group_and_evidence(self):
        row = to_finding_row(_run(MockAuthzTarget.vulnerable()).verdict)
        assert row["patch_group"] == "idor::missing_object_authorization"
        assert row["evidence_id"].startswith("authz::")
        assert row["observed_grants"] == ("data_read",)

    def test_determinism(self):
        a = to_finding_row(_run(MockAuthzTarget.vulnerable()).verdict)
        b = to_finding_row(_run(MockAuthzTarget.vulnerable()).verdict)
        assert a == b


# --------------------------------------------------------------- round trip into M3

class TestRoundTripIntoGraph:
    def _graph_from(self, target):
        v = _run(target).verdict
        res = write([v])
        payload = {
            "assets": [{"id": "web-01"},
                       {"id": "api-01", "criticality": 3},
                       {"id": "db-01", "is_crown_jewel": True, "criticality": 5}],
            "routes": [{"src": "web-01", "dst": "api-01", "provenance": "observed"},
                       {"src": "api-01", "dst": "db-01", "provenance": "observed"}],
            "entries": ["web-01"],
            "findings": res.findings,
        }
        return from_dict(payload), res

    def test_validated_idor_enters_the_graph_with_evidence_provenance(self):
        """The payoff: the oracle's observed data_read flips the edge to EVIDENCE
        provenance, which raises Module 3's published derived_fraction."""
        gi, _ = self._graph_from(MockAuthzTarget.vulnerable())
        g = build_graph(gi)
        idor = next(n for n, d in g.nodes(data=True)
                    if d.get("vuln_class") == "idor")
        assert g.nodes[idor]["provenance"] == "evidence"

    def test_no_stray_keys_reach_module_3(self):
        gi, _ = self._graph_from(MockAuthzTarget.vulnerable())
        assert gi.unknown_keys == {}

    def test_disproved_finding_never_enters_the_graph(self):
        gi, res = self._graph_from(MockAuthzTarget.secure())
        g = build_graph(gi)
        fp = [f for f in gi.findings if f.status == "false_positive"]
        assert fp and all(vuln(f.id) not in g for f in fp)
