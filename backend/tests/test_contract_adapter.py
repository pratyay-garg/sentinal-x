from __future__ import annotations

import dataclasses
from datetime import date

from app.engines.discovery import contract_adapter
from app.graph import contract
from app.graph.loader import from_rows


@dataclasses.dataclass
class FakeFinding:
    id: str = "11111111-1111-1111-1111-111111111111"
    asset_id: str = "asset-abc"
    vuln_class_candidate: str = "sqli"
    vuln_class: str | None = "sqli"
    mapping_status: str = "mapped"
    cvss_vector: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    epss: float | None = 0.42
    epss_snapshot_date: date | None = date(2026, 9, 1)
    cve_id: str | None = "CVE-2024-12345"
    cpe: str | None = "cpe:2.3:a:example:widget:1.0"
    evidence_id: str | None = None
    endpoint: str | None = "GET https://example.test/product"
    param: str | None = "id"


def test_actual_shared_vocabulary_and_registry_are_compatible():
    contract_adapter.assert_vocabulary_matches_graph()


def test_persisted_projection_passes_actual_contract_with_zero_errors():
    row = contract_adapter.discovery_finding_to_contract_row(FakeFinding())
    assert row is not None
    assert [p for p in contract.validate_finding_row(row) if p["severity"] == "error"] == []
    assert row["status"] == "unvalidated"
    assert row["confidence"] is None
    assert "observed_grants" not in row
    assert "observed_requires" not in row
    assert "target_asset_id" not in row


def test_patch_values_come_from_actual_contract():
    row = contract_adapter.discovery_finding_to_contract_row(FakeFinding())
    assert row["patch_hours"] == contract.patch_hours_for("sqli")
    assert row["patch_group"] == contract.patch_group_for(
        "sqli", cve="CVE-2024-12345", component="cpe:2.3:a:example:widget:1.0"
    )


def test_unknown_class_is_quarantined_not_mislabeled_info_leak():
    mapped = contract_adapter.promote_candidate("novel-template-with-no-semantics")
    assert mapped.vuln_class is None
    assert mapped.mapping_status == "unmapped"
    finding = FakeFinding(
        vuln_class_candidate="novel-template-with-no-semantics",
        vuln_class=None,
        mapping_status="unmapped",
    )
    assert contract_adapter.discovery_finding_to_contract_row(finding) is None


def test_alias_mapping_is_explicit_and_versioned():
    mapped = contract_adapter.promote_candidate("idor_bola")
    assert mapped.vuln_class == "idor"
    assert mapped.mapping_status == "mapped"
    assert mapped.mapping_version == contract_adapter.MAPPING_VERSION


def test_ambiguous_labels_are_quarantined_instead_of_overclaimed():
    assert contract_adapter.promote_candidate("jwt_weakness").vuln_class is None
    assert contract_adapter.promote_candidate("xss_dom").vuln_class is None
    assert (
        contract_adapter.promote_candidate("missing-security-headers").vuln_class
        == "misconfig_open_service"
    )


def test_db_only_graph_loader_applies_contract_default_to_null_confidence():
    finding = FakeFinding()
    graph_input = from_rows(
        [{"id": "asset-abc", "criticality": 3}], [finding], entries=["asset-abc"]
    )
    assert len(graph_input.findings) == 1
    assert graph_input.findings[0].confidence == 0.25
    assert graph_input.findings[0].vuln_class == "sqli"


def test_db_only_graph_loader_ignores_quarantine_rows():
    unknown = FakeFinding(vuln_class=None, mapping_status="unmapped")
    graph_input = from_rows([{"id": "asset-abc"}], [unknown])
    assert graph_input.findings == []


def test_internal_audit_fields_do_not_cross_contract_projection():
    row = contract_adapter.discovery_finding_to_contract_row(FakeFinding())
    assert row is not None
    assert not (set(row) & set(contract_adapter._INTERNAL_ONLY_FIELDS))
