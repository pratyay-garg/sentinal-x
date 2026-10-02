from __future__ import annotations

import pytest

from app.graph.loader import from_rows
from app.graph.pipeline import run
from app.api.graph_service import analysis_hash, priority_payload
from app.main import app
from app.schemas import GraphAssetUpdate, GraphRecomputeRequest, GraphRouteCreate


def integrated_input():
    return from_rows(
        assets=[{
            "id": "shop",
            "zone": "external",
            "is_crown_jewel": True,
            "criticality": 5,
        }],
        findings=[{
            "id": "finding-1",
            "asset_id": "shop",
            "vuln_class": "sqli",
            "status": "validated",
            "confidence": 0.95,
            "patch_hours": 4.0,
            "patch_group": "shop-query-parameterisation",
            "evidence_id": "evidence-1",
            "endpoint": "GET https://shop.test/search?q=x",
            "observed_requires": ["network_reach"],
            "observed_grants": ["data_read"],
        }],
        entries=["shop"],
    )


def test_validation_rows_form_an_evidence_backed_reachable_attack_path():
    result = run(
        integrated_input(), trials=500, seed=1337,
        priority_trials=100, with_priority=True,
    )
    assert result.reachable_jewels == ["shop"]
    assert result.invariants["all_passed"] is True
    assert result.priority[0]["vuln_id"] == "finding-1"
    post_edges = [
        edge["data"] for edge in result.cytoscape()["elements"]["edges"]
        if edge["data"]["kind"] == "post"
    ]
    assert post_edges[0]["evidence_id"] == "evidence-1"


def test_snapshot_hash_is_reproducible_and_parameter_sensitive():
    gi = integrated_input()
    parameters = {
        "trials": 500, "seed": 1337, "budget_hours": 8.0,
        "k_paths": 50, "priority_trials": 100,
    }
    assert analysis_hash(gi, parameters) == analysis_hash(gi, dict(parameters))
    assert analysis_hash(gi, parameters) != analysis_hash(
        gi, {**parameters, "seed": 42}
    )


def test_cytoscape_uses_human_hostname_without_destabilising_node_id():
    gi = from_rows(
        assets=[{"id": "stable-id", "hostnames": ["shop.test"],
                 "is_crown_jewel": True}],
        findings=[], entries=["stable-id"],
    )
    nodes = run(gi, trials=100, with_priority=False).cytoscape()["elements"]["nodes"]
    state = next(node["data"] for node in nodes if node["data"]["type"] == "state")
    assert state["id"].startswith("state|stable-id|")
    assert state["label"].startswith("shop.test:")
    assert state["hostname"] == "shop.test"


def test_priority_contract_preserves_evidence_and_cut_membership():
    result = run(
        integrated_input(), trials=500, seed=1337,
        priority_trials=100, with_priority=True,
    )
    item = priority_payload(result)[0]
    assert item["evidence_id"] == "evidence-1"
    assert item["in_min_cut"] is True
    assert item["dominated_jewels"] == ["shop"]


def test_graph_request_schemas_reject_unsafe_or_ambiguous_inputs():
    with pytest.raises(ValueError):
        GraphRouteCreate(src_asset_id="same", dst_asset_id="same", reason="invalid")
    with pytest.raises(ValueError):
        GraphRecomputeRequest(patched=[])
    with pytest.raises(ValueError):
        GraphAssetUpdate()


def test_integrated_fastapi_surface_is_complete():
    paths = {route.path for route in app.routes}
    expected = {
        "/api/v1/graph/contract",
        "/api/v1/graph/view",
        "/api/v1/graph/assets",
        "/api/v1/graph/assets/{asset_id}",
        "/api/v1/graph/routes",
        "/api/v1/graph/facts",
        "/api/v1/graph/analyze",
        "/api/v1/graph/cytoscape",
        "/api/v1/graph/priority",
        "/api/v1/graph/recompute",
        "/api/v1/graph/snapshots/latest",
        "/api/v1/graph/snapshots/{snapshot_id}",
    }
    assert expected <= paths
