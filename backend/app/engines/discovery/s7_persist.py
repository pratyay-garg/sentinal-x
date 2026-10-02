"""S7 — contract-validated, idempotent persistence with observation history."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .contract_adapter import MAPPING_VERSION, contract_projection_values, promote_candidate
from .dedup import compute_dedup_key
from .identity import stable_asset_id
from app.models import (
    Asset, AssetAlias, Endpoint, Finding, FindingObservation, Service, TechFingerprint,
)

CONFIDENCE_BASIS_WEIGHTS = {
    "spec_backed": 0.9,
    "traffic_observed": 0.7,
    "js_referenced": 0.5,
    "wordlist_only": 0.3,
    "inferred_business_logic": 0.2,
}


def observation_source_ref(
    source_tool: str, template_id: str | None, raw_data: dict[str, Any] | None
) -> str:
    """Identify one tool observation without folding distinct matchers together."""
    parts = [template_id or ""]
    if source_tool == "nuclei" and isinstance(raw_data, dict):
        matcher = raw_data.get("matcher-name")
        if matcher:
            parts.append(str(matcher))
    return ":".join(part for part in parts if part)


def compute_discovery_confidence(confidence_basis: str, severity_raw: str | None) -> float:
    base = CONFIDENCE_BASIS_WEIGHTS.get(confidence_basis, 0.4)
    if severity_raw and severity_raw.lower() in ("critical", "high"):
        base = min(1.0, base + 0.1)
    return round(base, 2)


async def upsert_asset(session: AsyncSession, hostname: str, asset_type: str = "host") -> Asset:
    asset_id = stable_asset_id(hostname)
    existing = await session.get(Asset, asset_id)
    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        if existing.type == "host" and asset_type in {"web_app", "api"}:
            existing.type = asset_type
        # Every host reached directly by the external Discovery worker is an
        # observed attacker entry point. Internal-only assets can be added via
        # a proven GraphRoute with this flag explicitly disabled.
        existing.is_entry_point = True
        return existing
    asset = Asset(
        id=asset_id, canonical_hostname=hostname, type=asset_type,
        zone="external", is_entry_point=True,
    )
    session.add(asset)
    await session.flush()
    return asset


async def upsert_service(
    session: AsyncSession,
    asset_id: str,
    port: int,
    protocol: str,
    banner: str | None,
    *,
    application_protocol: str | None = None,
    product: str | None = None,
    version: str | None = None,
    confidence: float | None = None,
) -> Service:
    values = {
        "id": str(uuid.uuid4()), "asset_id": asset_id, "port": port,
        "protocol": protocol, "banner": banner, "application_protocol": application_protocol,
        "product": product, "version": version, "confidence": confidence, "state": "open",
    }
    stmt = pg_insert(Service).values(**values).on_conflict_do_update(
        constraint="uq_service",
        set_={k: v for k, v in values.items() if k not in {"id", "asset_id", "port", "protocol"}},
    ).returning(Service)
    result = await session.execute(stmt)
    await session.flush()
    return result.scalar_one()


async def persist_http_observations(
    session: AsyncSession, *, asset: Asset, service: Service, probe: dict[str, Any]
) -> None:
    """Persist bounded, tool-observed HTTP identity and technology facts."""
    meta = dict(asset.meta or {})
    http_meta = dict(meta.get("http") or {})
    if probe.get("title"):
        http_meta["title"] = str(probe["title"])[:512]
    if probe.get("url"):
        http_meta["last_observed_url"] = str(probe["url"])[:2048]
    if probe.get("status_code") is not None:
        http_meta["status_code"] = int(probe["status_code"])
    if probe.get("content_type"):
        http_meta["content_type"] = str(probe["content_type"])[:256]
    meta["http"] = http_meta
    asset.meta = meta

    raw_addresses: list[Any] = [probe.get("host_ip")]
    for key in ("a", "aaaa"):
        value = probe.get(key) or []
        raw_addresses.extend(value if isinstance(value, (list, tuple, set)) else [value])
    addresses = {
        str(value).strip()
        for value in raw_addresses
        if str(value or "").strip()
    }
    for address in sorted(addresses):
        existing_alias = await session.scalar(select(AssetAlias).where(
            AssetAlias.asset_id == asset.id,
            AssetAlias.alias_type == "ip",
            AssetAlias.alias_value == address,
        ))
        if existing_alias:
            existing_alias.confidence = 1.0
        else:
            session.add(AssetAlias(
                asset_id=asset.id, alias_type="ip", alias_value=address, confidence=1.0,
            ))

    raw_products = probe.get("tech") or probe.get("technologies") or []
    if isinstance(raw_products, str):
        raw_products = [raw_products]
    products = sorted({str(value).strip() for value in raw_products if str(value).strip()})
    for product in products:
        existing_tech = await session.scalar(select(TechFingerprint).where(
            TechFingerprint.asset_id == asset.id,
            TechFingerprint.service_id == service.id,
            TechFingerprint.product == product,
            TechFingerprint.method == "httpx_native",
        ))
        if existing_tech:
            existing_tech.confidence = 0.9
        else:
            session.add(TechFingerprint(
                asset_id=asset.id, service_id=service.id, product=product,
                confidence=0.9, method="httpx_native",
            ))


async def upsert_endpoint(
    session: AsyncSession,
    service_id: str,
    asset_id: str,
    *,
    url: str,
    path: str,
    method: str,
    param_names: list[str],
    source: str,
    auth_context: str,
    page_class: str | None = None,
    endpoint_class: str | None = None,
    request_template: dict | None = None,
) -> Endpoint:
    existing_result = await session.execute(
        select(Endpoint).where(
            Endpoint.service_id == service_id,
            Endpoint.path == path,
            Endpoint.method == method.upper(),
            Endpoint.auth_context == auth_context,
        )
    )
    existing = existing_result.scalar_one_or_none()
    if existing:
        existing.param_names = sorted(set(existing.param_names or ()) | set(param_names))
        existing.url = url
        if request_template:
            existing.request_template = request_template
        if source != "crawl" or existing.source == "crawl":
            existing.source = source
        if endpoint_class and endpoint_class != "unknown":
            existing.endpoint_class = endpoint_class
        if page_class:
            existing.page_class = page_class
        return existing
    endpoint = Endpoint(
        service_id=service_id, asset_id=asset_id, url=url, path=path,
        method=method.upper(), param_names=sorted(set(param_names)), source=source,
        auth_context=auth_context, page_class=page_class, endpoint_class=endpoint_class,
        request_template=request_template,
    )
    session.add(endpoint)
    await session.flush()
    return endpoint


async def _record_observation(
    session: AsyncSession,
    *,
    finding_id: str,
    scan_run_id: str,
    source_tool: str,
    source_ref: str | None,
    raw_data: dict[str, Any] | None,
    partial: bool,
) -> None:
    stmt = pg_insert(FindingObservation).values(
        id=str(uuid.uuid4()), finding_id=finding_id, scan_run_id=scan_run_id,
        source_tool=source_tool, source_ref=source_ref or "", raw_data=raw_data,
        partial=partial,
    ).on_conflict_do_update(
        constraint="uq_finding_observation",
        set_={"observed_at": datetime.now(timezone.utc), "raw_data": raw_data, "partial": partial},
    )
    await session.execute(stmt)


async def persist_finding(
    session: AsyncSession,
    *,
    scan_run_id: str,
    asset_id: str,
    endpoint: Endpoint | None,
    service_id: str | None,
    matched_param: str | None,
    vuln_class_candidate: str,
    source_tool: str,
    template_id: str | None,
    severity_raw: str | None,
    evidence_stub: str | None,
    cve_id: str | None,
    cpe: str | None,
    epss_score: float | None,
    epss_snapshot_date,
    cvss_vector: str | None,
    confidence_basis: str,
    raw_data: dict[str, Any] | None = None,
    partial: bool = False,
) -> Finding:
    mapping = promote_candidate(vuln_class_candidate)
    identity_class = mapping.vuln_class or f"unmapped:{mapping.raw_finding_type}"
    path_or_url = endpoint.url if endpoint else "/"
    dedup_key = compute_dedup_key(
        asset_id=asset_id, source_tool=source_tool,
        vuln_class_candidate=identity_class, template_id_or_type=template_id,
        path_or_url=path_or_url, method=endpoint.method if endpoint else "GET",
        matched_param=matched_param, cve_id=cve_id,
    )
    source_ref = observation_source_ref(source_tool, template_id, raw_data)
    existing_result = await session.execute(select(Finding).where(Finding.dedup_key == dedup_key))
    existing = existing_result.scalar_one_or_none()
    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        # Security identity is cross-tool, so a later stronger observation
        # must enrich the canonical row rather than being trapped only inside
        # observation history. Validation verdict/evidence are never reset.
        new_confidence = compute_discovery_confidence(confidence_basis, severity_raw)
        if endpoint is not None and endpoint.auth_context != "none":
            # Prefer a usable authenticated request shape for downstream
            # confirmation when public and authenticated crawls saw the same
            # sink. The observations still retain both visibility contexts.
            existing.endpoint_id = endpoint.id
            existing.service_id = endpoint.service_id
            existing.endpoint = f"{endpoint.method} {endpoint.url}"
            existing.param = matched_param
        if new_confidence > existing.discovery_confidence:
            existing.discovery_confidence = new_confidence
            existing.confidence_basis = confidence_basis
            existing.source_tool = source_tool
            existing.template_id = template_id or existing.template_id
            existing.severity_raw = severity_raw or existing.severity_raw
            existing.evidence_stub = evidence_stub or existing.evidence_stub
            existing.cve_id = cve_id or existing.cve_id
            existing.cpe = cpe or existing.cpe
            existing.epss = epss_score if epss_score is not None else existing.epss
            existing.epss_snapshot_date = epss_snapshot_date or existing.epss_snapshot_date
            existing.cvss_vector = cvss_vector or existing.cvss_vector
        await _record_observation(
            session, finding_id=existing.id, scan_run_id=scan_run_id,
            source_tool=source_tool, source_ref=source_ref, raw_data=raw_data, partial=partial,
        )
        return existing

    finding_id = str(uuid.uuid4())
    projection: dict[str, Any] = {}
    if mapping.vuln_class is not None:
        projection = contract_projection_values(
            finding_id=finding_id, asset_id=asset_id, vuln_class=mapping.vuln_class,
            cvss_vector=cvss_vector, epss=epss_score,
            epss_snapshot_date=epss_snapshot_date, cve_id=cve_id, cpe=cpe,
            evidence_id=None,
            endpoint=f"{endpoint.method} {endpoint.url}" if endpoint else None,
            param=matched_param,
        )

    finding = Finding(
        id=finding_id, first_seen_scan_run_id=scan_run_id, asset_id=asset_id,
        endpoint_id=endpoint.id if endpoint else None, service_id=service_id,
        matched_param=matched_param, vuln_class_candidate=vuln_class_candidate,
        raw_finding_type=mapping.raw_finding_type if mapping.mapping_status == "unmapped" else None,
        vuln_class=mapping.vuln_class, mapping_status=mapping.mapping_status,
        mapping_diagnostics={"reason": mapping.reason}, classification_version=MAPPING_VERSION,
        source_tool=source_tool, template_id=template_id, severity_raw=severity_raw,
        evidence_stub=evidence_stub, cve_id=cve_id, cpe=cpe, epss=epss_score,
        epss_snapshot_date=epss_snapshot_date, cvss_vector=cvss_vector,
        patch_hours=projection.get("patch_hours"), patch_group=projection.get("patch_group"),
        endpoint=projection.get("endpoint"), param=matched_param, confidence=None,
        dedup_key=dedup_key,
        discovery_confidence=compute_discovery_confidence(confidence_basis, severity_raw),
        confidence_basis=confidence_basis, status="unvalidated", generated_by="tool",
    )
    session.add(finding)
    await session.flush()
    await _record_observation(
        session, finding_id=finding.id, scan_run_id=scan_run_id,
        source_tool=source_tool, source_ref=source_ref, raw_data=raw_data, partial=partial,
    )
    return finding
