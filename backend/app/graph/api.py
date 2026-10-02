"""
FastAPI router for Module 3. This is the entire integration surface -- the other
modules consume these endpoints and nothing else.

CONTRACTS
  Discovery       -> assets(asset_id STABLE across re-scans, zone, is_crown_jewel,
                     criticality), routes(src, dst, provenance, reason)
  Validation      -> findings(finding_id, asset_id, vuln_class, status, confidence,
                     cvss_vector, patch_hours, patch_group, evidence_id, endpoint)
                     No graph semantics required from them -- this module owns
                     the mapping, so their schema cannot break ours.
  Remediation     <- GET /graph/priority
  Retest          <- POST /graph/recompute {patched: [...]}
  Frontend        <- GET /graph/cytoscape
  Phishing (M5)   -> POST /graph/entry/phishing
  Exposure  (M6)  -> POST /graph/entry/breach
"""
from __future__ import annotations

from typing import Any

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel, Field

    # NOTE: these MUST live at module scope. FastAPI resolves endpoint type
    # hints through the function's __globals__, so request models defined inside
    # build_router() are invisible to it and every POST returns 422
    # "Field required: body". Pinned by test_post_endpoints_accept_a_json_body.
    class Payload(BaseModel):
        assets: list[dict] = Field(default_factory=list)
        findings: list[dict] = Field(default_factory=list)
        facts: list[dict] = Field(default_factory=list)
        routes: list[dict] = Field(default_factory=list)
        entries: list[str] = Field(default_factory=list)

    class RecomputeBody(BaseModel):
        patched: list[str]
        trials: int = 10_000
        seed: int = 1337

    class PhishingBody(BaseModel):
        asset_id: str
        risk_score: float
        ref: str
        granted: str = "user_session"

    class BreachBody(BaseModel):
        asset_id: str
        ref: str               # HMAC digest -- never a raw address
        granted: str = "user_session"
        p: float = 0.6

except ImportError:                                   # allow import without FastAPI
    APIRouter = None                                  # type: ignore

from . import contract
from .loader import from_dict
from .model import GraphInput
from .pipeline import recompute, run
from .sensitivity import validation_ablation, weight_stability


class _Store:
    """Swap for a real Postgres read in one place. The engine is developed and
    tested entirely against the JSON fixture, so nothing here blocks Day 4."""
    _input: GraphInput | None = None

    def set(self, gi: GraphInput) -> None:
        self._input = gi

    def get(self) -> GraphInput:
        if self._input is None:
            from .loader import load_fixture
            self._input = load_fixture()
        return self._input


store = _Store()


def build_router():
    if APIRouter is None:
        raise RuntimeError("FastAPI is not installed")

    router = APIRouter(prefix="/graph", tags=["attack-path"])

    @router.post("/load")
    def load(payload: Payload) -> dict:
        """Module 2 writes here.

        Rows are validated against contract.py at WRITE time and the problems
        are returned in the response, so Module 2 learns about an unknown
        vuln_class or a missing patch_group immediately instead of discovering a
        quietly degraded graph on Day 11. The load itself never fails on a
        validation problem -- a partially-valid graph is more useful than a
        rejected one, and diagnostics.py reports the same codes at analysis
        time -- but `validation.ok` is False when any error-severity row exists.
        """
        rows = payload.model_dump()
        report = contract.validate_batch(rows.get("findings", []))
        rows["findings"] = [contract.normalise_finding_row(f)
                            for f in rows.get("findings", [])]
        store.set(from_dict(rows))
        return {"ok": True, "assets": len(payload.assets),
                "findings": len(payload.findings), "validation": report}

    @router.get("/contract")
    def contract_vocabulary() -> dict:
        """The shared vocabulary, served so Module 2 can assert against it in CI
        rather than duplicating the lists and letting them drift."""
        return {
            "vuln_classes": sorted(contract.VULN_CLASSES),
            "m2_emitted_classes": sorted(contract.M2_EMITTED_CLASSES),
            "verdicts": sorted(contract.VERDICTS),
            "live_verdicts": sorted(contract.LIVE_VERDICTS),
            "oracle_proves": {k: {"observed_requires": list(v[0]),
                                  "observed_grants": [v[1]]}
                              for k, v in contract.ORACLE_PROVES.items()},
            "non_overriding_oracles": sorted(contract.NON_OVERRIDING_ORACLES),
            "default_patch_hours": contract.DEFAULT_PATCH_HOURS,
        }

    @router.get("/analyze")
    def analyze(trials: int = 10_000, seed: int = 1337,
                budget_hours: float = 8.0) -> dict[str, Any]:
        return run(store.get(), trials=trials, seed=seed,
                   budget_hours=budget_hours).summary()

    @router.get("/cytoscape")
    def cytoscape(trials: int = 10_000, seed: int = 1337) -> dict:
        return run(store.get(), trials=trials, seed=seed,
                   with_priority=False).cytoscape()

    @router.get("/priority")
    def priority(top: int = 20) -> dict:
        """What Remediation (Module 8) consumes."""
        res = run(store.get())
        by_id = {c["vuln_id"]: c for c in res.chokepoints}
        cut = set(res.cut.get("vulns", []))
        budget = {p["vuln_id"] for p in res.budget_plan.get("picks", [])}
        out = []
        for p in res.priority[:top]:
            c = by_id.get(p["vuln_id"], {})
            n = ("vuln", p["vuln_id"])
            out.append({
                **p,
                "dominated_assets": c.get("dominated_assets", []),
                "dominated_jewels": c.get("dominated_jewels", []),
                "in_min_cut": p["vuln_id"] in cut,
                "in_budget_set": p["vuln_id"] in budget,
                "mitre_ids": res.graph.nodes.get(n, {}).get("mitre", []),
                "evidence_id": res.graph.nodes.get(n, {}).get("evidence_id"),
            })
        return {"items": out, "cut": res.cut, "budget_plan": res.budget_plan}

    @router.post("/recompute")
    def recompute_ep(body: RecomputeBody) -> dict:
        """What Retest (Module 9) calls after flipping findings to remediated."""
        return recompute(store.get(), set(body.patched), trials=body.trials,
                         seed=body.seed)

    @router.post("/entry/phishing")
    def phishing_entry(body: PhishingBody) -> dict:
        """Module 5 contributes an entry point. Returns the resulting change in
        crown-jewel compromise probability."""
        from .build import attach_phishing_entry, build_graph
        from .montecarlo import simulate
        from .prune import prune
        gi = store.get()
        before = simulate(prune(build_graph(gi)), trials=4000)
        g = build_graph(gi)
        attach_phishing_entry(g, asset_id=body.asset_id, risk_score=body.risk_score,
                              ref=body.ref, granted=body.granted)
        after = simulate(prune(g), trials=4000)
        return {"before": before.jewel_prob, "after": after.jewel_prob}

    @router.post("/entry/breach")
    def breach_entry(body: BreachBody) -> dict:
        """Module 6 contributes an entry point. `ref` MUST already be an HMAC
        digest -- this module never receives or stores a raw address."""
        if "@" in body.ref:
            raise HTTPException(422, "ref must be a digest, not an email address")
        from .build import attach_breached_credential, build_graph
        from .montecarlo import simulate
        from .prune import prune
        g = build_graph(store.get())
        attach_breached_credential(g, asset_id=body.asset_id, ref=body.ref,
                                   granted=body.granted, p=body.p)
        return {"jewel_prob": simulate(prune(g), trials=4000).jewel_prob}

    @router.get("/assurance")
    def assurance(trials: int = 100) -> dict:
        """Runtime invariants + weight sensitivity + validation ablation.

        This is the 'how do you know your numbers are right' endpoint. It is
        cheap enough to run live in front of a judge.
        """
        gi = store.get()
        res = run(gi, with_priority=False)
        return {
            "invariants": res.invariants,
            "provenance": res.provenance,
            "weight_stability": weight_stability(gi, trials=trials).as_dict(),
            "validation_ablation": validation_ablation(gi),
            "reproducibility": {"seed": 1337,
                                "note": "all stochastic components are seeded; "
                                        "re-running yields identical output"},
        }

    return router
