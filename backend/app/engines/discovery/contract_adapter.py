"""Discovery's fail-loud database boundary to the shared graph contract.

The shared vocabulary and patch rules are loaded from the executable
``app.graph.contract``/``app.graph.model`` modules. Discovery never keeps a second
class enum or patch-effort table. Unknown scanner classifications remain durable
but are quarantined with ``vuln_class = NULL`` and cannot silently acquire graph
semantics.
"""
from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.config import settings

MAPPING_VERSION = "2026-09-13.v1"
_REGISTRY_PATH = Path(__file__).with_name("vuln_mapping.json")
_contract = None
_model = None
_registry: dict[str, Any] | None = None


class ContractProjectionError(ValueError):
    """A mapped finding failed the executable downstream contract."""


@dataclass(frozen=True)
class ClassMappingResult:
    vuln_class: str | None
    raw_finding_type: str
    mapping_status: str
    reason: str
    mapping_version: str = MAPPING_VERSION


def _load_contract():
    global _contract, _model
    if _contract is None:
        _contract = importlib.import_module(settings.graph_contract_module)
    if _model is None:
        _model = importlib.import_module(settings.graph_model_module)
    return _contract, _model


def _load_registry() -> dict[str, Any]:
    global _registry
    if _registry is None:
        payload = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
        if payload.get("version") != MAPPING_VERSION:
            raise RuntimeError("vulnerability mapping registry version mismatch")
        aliases = payload.get("aliases")
        if not isinstance(aliases, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in aliases.items()
        ):
            raise RuntimeError("vulnerability mapping registry aliases must be string pairs")
        _registry = payload
    return _registry


def reset_contract_cache() -> None:
    global _contract, _model, _registry
    _contract = _model = _registry = None


def promote_candidate(vuln_class_candidate: str) -> ClassMappingResult:
    """Map deterministically or quarantine; never guess a graph class."""
    contract, _ = _load_contract()
    raw = (vuln_class_candidate or "").strip().lower()
    if raw in contract.VULN_CLASSES:
        return ClassMappingResult(raw, raw, "mapped", "exact_contract_class")
    mapped = _load_registry()["aliases"].get(raw)
    if mapped is not None:
        if mapped not in contract.VULN_CLASSES:
            raise RuntimeError(f"mapping registry target is outside shared contract: {mapped}")
        return ClassMappingResult(mapped, raw, "mapped", "registry_alias")
    return ClassMappingResult(None, raw, "unmapped", "no_deterministic_mapping")


def assert_vocabulary_matches_graph() -> None:
    contract, model = _load_contract()
    if frozenset(model.SEMANTICS) != contract.VULN_CLASSES:
        raise AssertionError("shared contract VULN_CLASSES has drifted from model.SEMANTICS")
    invalid = sorted(set(_load_registry()["aliases"].values()) - set(contract.VULN_CLASSES))
    if invalid:
        raise AssertionError(f"mapping registry targets unknown graph classes: {invalid}")


def contract_projection_values(
    *,
    finding_id: str,
    asset_id: str,
    vuln_class: str,
    cvss_vector: str | None,
    epss: float | None,
    epss_snapshot_date: Any,
    cve_id: str | None,
    cpe: str | None,
    evidence_id: str | None,
    endpoint: str | None,
    param: str | None,
    status: str = "unvalidated",
    confidence: float | None = None,
    observed_grants: list[str] | tuple[str, ...] = (),
    observed_requires: list[str] | tuple[str, ...] = (),
    target_asset_id: str | None = None,
    generated_by: str = "tool",
) -> dict[str, Any]:
    """Build and validate the canonical columns persisted on ``findings``."""
    contract, _ = _load_contract()
    row = {
        "id": str(finding_id),
        "asset_id": asset_id,
        "vuln_class": vuln_class,
        "status": status,
        "confidence": confidence,
        "cvss_vector": cvss_vector,
        "epss": epss,
        "epss_snapshot_date": (
            epss_snapshot_date.isoformat() if epss_snapshot_date else None
        ),
        "patch_hours": contract.patch_hours_for(vuln_class),
        # An explicit per-finding action is the conservative fallback: it never
        # claims one patch fixes two unrelated findings, while still giving the
        # label-cut solver a complete action vocabulary.
        "patch_group": (
            contract.patch_group_for(vuln_class, cve=cve_id, component=cpe)
            or f"finding::{finding_id}"
        ),
        "evidence_id": str(evidence_id) if evidence_id else None,
        "endpoint": endpoint,
        "param": param,
    }
    if observed_grants:
        row["observed_grants"] = tuple(observed_grants)
    if observed_requires:
        row["observed_requires"] = tuple(observed_requires)
    if target_asset_id:
        row["target_asset_id"] = target_asset_id
    errors = [p for p in contract.validate_finding_row(row) if p["severity"] == "error"]
    if errors:
        raise ContractProjectionError(json.dumps(errors, sort_keys=True))
    return row


def discovery_finding_to_contract_row(finding, endpoint=None) -> dict[str, Any] | None:
    """Read the canonical persisted projection without inventing mappings.

    Returns ``None`` for a quarantined candidate; callers surface it through
    diagnostics/coverage rather than sending it into the graph.
    """
    if getattr(finding, "mapping_status", None) == "unmapped":
        return None
    vuln_class = getattr(finding, "vuln_class", None)
    if vuln_class is None:
        mapped = promote_candidate(finding.vuln_class_candidate)
        if mapped.vuln_class is None:
            return None
        vuln_class = mapped.vuln_class
    endpoint_value = getattr(finding, "endpoint", None)
    if endpoint_value is None and endpoint is not None:
        endpoint_value = f"{endpoint.method} {getattr(endpoint, 'url', endpoint.path)}"
    return contract_projection_values(
        finding_id=str(finding.id), asset_id=finding.asset_id, vuln_class=vuln_class,
        cvss_vector=finding.cvss_vector,
        epss=getattr(finding, "epss", getattr(finding, "epss_score", None)),
        epss_snapshot_date=finding.epss_snapshot_date,
        cve_id=finding.cve_id, cpe=finding.cpe,
        evidence_id=finding.evidence_id, endpoint=endpoint_value,
        param=getattr(finding, "param", getattr(finding, "matched_param", None)),
        status=getattr(finding, "status", "unvalidated"),
        confidence=getattr(finding, "confidence", None),
        observed_grants=getattr(finding, "observed_grants", ()) or (),
        observed_requires=getattr(finding, "observed_requires", ()) or (),
        target_asset_id=getattr(finding, "target_asset_id", None),
        generated_by=getattr(finding, "generated_by", "tool"),
    )


_INTERNAL_ONLY_FIELDS = (
    "discovery_confidence", "confidence_basis", "generated_by", "source_tool",
    "template_id", "dedup_key", "first_seen_scan_run_id", "raw_finding_type",
    "mapping_status", "mapping_diagnostics", "classification_version",
)
