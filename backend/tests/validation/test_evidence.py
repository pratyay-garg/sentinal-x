"""Phase 6 -- evidence store, replay, retest, and the M2->M3 retest climax."""
from __future__ import annotations

import pytest

from app.graph.loader import from_dict
from app.graph.pipeline import recompute, run
from app.engines.validation.evidence import (
    EvidenceStore, record_run, register_default_oracles, replay,
    retest,
)
from app.engines.validation.mock_target import MockSqliTarget, MockAuthzTarget
from app.engines.validation.oracles.authz import Account, run_authorization
from app.engines.validation.oracles.differential import run_boolean_differential
from app.engines.validation.writer import write

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"


def _record_sqli(store, target_mode="vulnerable", target_asset_id=None):
    kw = dict(asset_id="api-01", endpoint="/search", param="q", base_value="book",
              cvss_vector=VEC, cve="CVE-1", target_asset_id=target_asset_id)
    return record_run(store, lambda f: run_boolean_differential(f, **kw),
                      MockSqliTarget(target_mode), oracle="differential.boolean",
                      kwargs=kw)


# --------------------------------------------------------------- capture

class TestManifestCapture:
    def test_manifest_records_the_ordered_transaction_array(self):
        store = EvidenceStore()
        res, man = _record_sqli(store)
        assert res.verdict.status == "validated"
        # sanity(2) + baseline(5) + true/false/ctrl_true/ctrl_false(4)
        assert len(man.transactions) == 11
        assert [t.seq for t in man.transactions] == list(range(11))

    def test_manifest_is_stored_and_retrievable_by_evidence_id(self):
        store = EvidenceStore()
        res, _ = _record_sqli(store)
        assert store.exists(res.verdict.evidence_id)
        assert store.get(res.verdict.evidence_id).expected_status == "validated"

    def test_manifest_serialises_with_full_request_response(self):
        store = EvidenceStore()
        res, man = _record_sqli(store)
        d = man.to_dict()
        assert d["generated_by"] == "tool"
        tx = d["transactions"][-1]
        assert "request" in tx and "response" in tx
        assert tx["response"]["status"] == 200

    def test_capture_does_not_change_the_verdict(self):
        """The RecordingFetcher is transparent."""
        store = EvidenceStore()
        res, _ = _record_sqli(store)
        plain = run_boolean_differential(
            MockSqliTarget("vulnerable"), asset_id="api-01", endpoint="/search",
            param="q", base_value="book", cvss_vector=VEC, cve="CVE-1")
        assert res.verdict.status == plain.verdict.status


# --------------------------------------------------------------- replay

class TestReplay:
    def test_replay_reproduces_the_verdict_on_the_same_target(self):
        store = EvidenceStore()
        _, man = _record_sqli(store)
        assert replay(man, MockSqliTarget("vulnerable")).status == "validated"

    def test_replay_is_deterministic(self):
        store = EvidenceStore()
        _, man = _record_sqli(store)
        a = replay(man, MockSqliTarget("vulnerable"))
        b = replay(man, MockSqliTarget("vulnerable"))
        assert a.status == b.status and a.confidence == b.confidence

    def test_registry_replay_works_without_the_closure(self):
        """Cross-process path: no captured closure, re-run from the registry +
        stored kwargs."""
        register_default_oracles()
        store = EvidenceStore()
        _, man = _record_sqli(store)
        man._run_fn = None                      # simulate a reloaded manifest
        assert man.replay(MockSqliTarget("vulnerable")).status == "validated"


# --------------------------------------------------------------- retest flip

class TestRetest:
    def test_patched_target_flips_to_remediated(self):
        store = EvidenceStore()
        res, _ = _record_sqli(store)
        rt = retest(store, res.verdict.evidence_id, MockSqliTarget("secure"))
        assert rt.remediated and rt.before_status == "validated"
        assert rt.after_status == "false_positive"

    def test_still_vulnerable_is_not_remediated(self):
        store = EvidenceStore()
        res, _ = _record_sqli(store)
        rt = retest(store, res.verdict.evidence_id, MockSqliTarget("vulnerable"))
        assert not rt.remediated and rt.after_status == "validated"

    def test_environmental_interference_is_not_a_fix(self):
        from app.engines.validation.mock_target import MockTarget
        store = EvidenceStore()
        res, _ = _record_sqli(store)
        rt = retest(store, res.verdict.evidence_id, MockTarget("catch_all"))
        assert not rt.remediated and rt.after_status == "inconclusive"

    def test_authz_retest_round_trips(self):
        store = EvidenceStore()
        A, B = Account("acct-A", owns="10"), Account("acct-B", owns="11")
        kw = dict(asset_id="api-01", endpoint="/o/{id}", account_a=A, account_b=B)
        res, _ = record_run(store, lambda f: run_authorization(f, **kw),
                            MockAuthzTarget.vulnerable(), oracle="authz", kwargs=kw)
        rt = retest(store, res.verdict.evidence_id, MockAuthzTarget.secure())
        assert rt.remediated


# --------------------------------------------------------------- M2 -> M3 climax

class TestRetestIntoGraph:
    def test_validate_patch_retest_recompute_delta(self):
        """The demo climax, end to end and driven by Module 2:
        validate a SQLi that reaches the crown jewel, capture the manifest,
        patch, retest -> flip to remediated, then Module 3 recompute() shows the
        compromise probability collapse."""
        store = EvidenceStore()
        res, _ = _record_sqli(store, target_asset_id="db-01")
        assert res.verdict.status == "validated"

        # the fix is verified by the identical experiment failing
        rt = retest(store, res.verdict.evidence_id, MockSqliTarget("secure"))
        assert rt.remediated

        # feed the validated finding into Module 3
        rows = write([res.verdict]).findings
        gi = from_dict({
            "assets": [{"id": "web-01"}, {"id": "api-01", "criticality": 3},
                       {"id": "db-01", "is_crown_jewel": True, "criticality": 5}],
            "routes": [{"src": "web-01", "dst": "api-01", "provenance": "observed"},
                       {"src": "api-01", "dst": "db-01", "provenance": "observed"}],
            "entries": ["web-01"], "findings": rows})

        before = run(gi, trials=800, with_priority=False)
        assert before.monte_carlo.jewel_prob.get("db-01", 0) > 0.0

        fid = rows[0]["id"]
        delta = recompute(gi, {fid}, trials=800)
        assert delta["jewel_delta"]["db-01"]["after"] == 0.0
        assert delta["paths_after"] <= delta["paths_before"]


# --------------------------------------------------------------- api

class TestEvidenceApi:
    def test_get_evidence_returns_the_manifest(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.engines.validation.api import build_evidence_router

        store = EvidenceStore()
        res, _ = _record_sqli(store)
        app = FastAPI()
        app.include_router(build_evidence_router(store))
        r = TestClient(app).get(f"/evidence/{res.verdict.evidence_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["expected_status"] == "validated"
        assert len(body["transactions"]) == 11

    def test_unknown_evidence_is_404(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.engines.validation.api import build_evidence_router

        app = FastAPI()
        app.include_router(build_evidence_router(EvidenceStore()))
        assert TestClient(app).get("/evidence/nope").status_code == 404
