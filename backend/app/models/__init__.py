"""
Discovery's own database schema. This is deliberately richer than the flat
row Module 2/3's contract expects — see app/contract_adapter.py for the
translation between the two. Do not "simplify" this schema to look more like
the contract row; they serve different purposes on purpose
(IMPLEMENTATION_SPEC_v4.md §6/§7).
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, Date, DateTime, Float,
    ForeignKey, Integer, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def new_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    profile: Mapped[str] = mapped_column(Text, nullable=False)  # 'fast' | 'deep'
    status: Mapped[str] = mapped_column(Text, nullable=False, default="running")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stats: Mapped[dict | None] = mapped_column(JSONB)
    coverage: Mapped[dict | None] = mapped_column(JSONB)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    scan_run_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_runs.id"))
    target: Mapped[str] = mapped_column(Text, nullable=False)
    profile: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    custom_header_names: Mapped[list | None] = mapped_column(JSONB)  # NAMES only, never values
    claimed_by: Mapped[str | None] = mapped_column(Text)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanCredential(Base):
    """Short-lived encrypted request headers for one authenticated scan.

    Header values are never stored on scan jobs/events or emitted in logs. The
    authenticated encryption associated data binds a ciphertext to its job.
    """

    __tablename__ = "scan_credentials"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    scan_job_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    scan_run_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False
    )
    auth_context: Mapped[str] = mapped_column(Text, nullable=False, default="authenticated")
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        UniqueConstraint("scan_job_id", "auth_context", name="uq_scan_credential_context"),
    )


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_jobs.id"), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)  # never header VALUES or secret material
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class SystemControl(Base):
    __tablename__ = "system_control"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    killswitch_engaged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (CheckConstraint("id = 1", name="system_control_singleton"),)


class Asset(Base):
    __tablename__ = "assets"

    # SHA256(canonical_root_hostname) — see app/scope.py::stable_asset_id.
    # Never re-derived from IP/cert/favicon. See IMPLEMENTATION_SPEC_v4.md §6.
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    canonical_hostname: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)  # host|web_app|api_endpoint
    parent_id: Mapped[str | None] = mapped_column(Text, ForeignKey("assets.id"))
    criticality: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    zone: Mapped[str] = mapped_column(Text, nullable=False, default="external")
    is_crown_jewel: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_entry_point: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    meta: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (CheckConstraint("criticality BETWEEN 1 AND 5", name="criticality_range"),)


class AssetAlias(Base):
    """Identity SIGNALS only. Never used as a transitive merge key across
    registrable domains — see the merge rule in IMPLEMENTATION_SPEC_v4.md §6."""
    __tablename__ = "asset_aliases"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    asset_id: Mapped[str] = mapped_column(Text, ForeignKey("assets.id"), nullable=False)
    alias_type: Mapped[str] = mapped_column(Text, nullable=False)  # ip | cert_san | favicon_hash
    alias_value: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float)


class Service(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    asset_id: Mapped[str] = mapped_column(Text, ForeignKey("assets.id"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(Text, nullable=False)
    application_protocol: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text, nullable=False, default="open")
    product: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    banner: Mapped[str | None] = mapped_column(Text)
    tls_info: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_service"),)


class TechFingerprint(Base):
    __tablename__ = "tech_fingerprints"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    service_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("services.id"))
    asset_id: Mapped[str | None] = mapped_column(Text, ForeignKey("assets.id"))
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    version_range: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    method: Mapped[str | None] = mapped_column(Text)  # banner|header|dom|js|httpx_native|wappalyzer_native


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    service_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("services.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(Text, ForeignKey("assets.id"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(Text, nullable=False)
    param_names: Mapped[list | None] = mapped_column(JSONB)  # ALL known param names on this endpoint
    request_template: Mapped[dict | None] = mapped_column(JSONB)
    source: Mapped[str] = mapped_column(Text, nullable=False)  # crawl|openapi|graphql|js_extract|kiterunner
    auth_context: Mapped[str] = mapped_column(Text, nullable=False, default="none")  # none|authenticated
    auth_required: Mapped[bool | None] = mapped_column(Boolean)
    page_class: Mapped[str | None] = mapped_column(Text)
    endpoint_class: Mapped[str | None] = mapped_column(Text)  # rest|graphql|soap|xhr|unknown

    __table_args__ = (
        UniqueConstraint(
            "service_id", "path", "method", "auth_context", name="uq_endpoint_identity"
        ),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    first_seen_scan_run_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scan_runs.id"), nullable=False
    )
    asset_id: Mapped[str] = mapped_column(Text, ForeignKey("assets.id"), nullable=False)
    endpoint_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("endpoints.id"))
    service_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("services.id"))

    # The ONE parameter THIS finding implicates. Distinct from
    # endpoints.param_names (the endpoint's full known parameter set).
    # This is what maps to contract.py's flat `param` field — see
    # app/contract_adapter.py.
    matched_param: Mapped[str | None] = mapped_column(Text)

    # Discovery's PROPOSAL. Never asserted as final `vuln_class` — see
    # app/contract_adapter.py::VULN_CLASS_MAP for the promotion rule.
    vuln_class_candidate: Mapped[str] = mapped_column(Text, nullable=False)
    raw_finding_type: Mapped[str | None] = mapped_column(Text)  # original unmapped tag, if any
    # Canonical shared-contract projection. NULL vuln_class means the raw
    # candidate is durably quarantined rather than guessed or discarded.
    vuln_class: Mapped[str | None] = mapped_column(Text)
    mapping_status: Mapped[str] = mapped_column(Text, nullable=False, default="mapped")
    mapping_diagnostics: Mapped[dict | None] = mapped_column(JSONB)
    classification_version: Mapped[str] = mapped_column(Text, nullable=False, default="v1")

    source_tool: Mapped[str] = mapped_column(Text, nullable=False)
    template_id: Mapped[str | None] = mapped_column(Text)
    severity_raw: Mapped[str | None] = mapped_column(Text)
    evidence_stub: Mapped[str | None] = mapped_column(Text)

    cve_id: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(Text)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_snapshot_date: Mapped[date | None] = mapped_column(Date)
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    patch_hours: Mapped[float | None] = mapped_column(Float)
    patch_group: Mapped[str | None] = mapped_column(Text)
    endpoint: Mapped[str | None] = mapped_column(Text)
    param: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    observed_grants: Mapped[list | None] = mapped_column(JSONB)
    observed_requires: Mapped[list | None] = mapped_column(JSONB)
    target_asset_id: Mapped[str | None] = mapped_column(Text, ForeignKey("assets.id"))

    dedup_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    # ALWAYS populated. Discovery/M2-internal only — never reaches the M2->M3
    # contract row. See IMPLEMENTATION_SPEC_v4.md §7.3.
    discovery_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_basis: Mapped[str | None] = mapped_column(Text)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    status: Mapped[str] = mapped_column(Text, nullable=False, default="unvalidated")
    generated_by: Mapped[str] = mapped_column(Text, nullable=False, default="tool")

    evidence_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("evidence.id", use_alter=True))

    __table_args__ = (
        CheckConstraint(
            "status IN ('unvalidated','validated','false_positive','inconclusive',"
            "'unverifiable_safely','remediated')",
            name="finding_validation_status",
        ),
        CheckConstraint("generated_by = 'tool'", name="finding_discovery_provenance"),
        CheckConstraint(
            "(mapping_status = 'mapped' AND vuln_class IS NOT NULL) OR "
            "(mapping_status = 'unmapped' AND vuln_class IS NULL)",
            name="finding_mapping_state",
        ),
    )


class FindingObservation(Base):
    """One durable sighting of a global finding in one scan run.

    A finding is deduplicated by security identity; observations retain every
    run/tool/template sighting so retries and repeated scans never erase
    provenance or leave `scan_run_id` pointing only at the first run.
    """

    __tablename__ = "finding_observations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    scan_run_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_runs.id"), nullable=False)
    source_tool: Mapped[str] = mapped_column(Text, nullable=False)
    source_ref: Mapped[str] = mapped_column(Text, nullable=False, default="")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    partial: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        UniqueConstraint(
            "finding_id", "scan_run_id", "source_tool", "source_ref",
            name="uq_finding_observation",
        ),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    redacted_request_excerpt: Mapped[str | None] = mapped_column(Text)  # max 4KB; secrets stripped
    har_ref: Mapped[str | None] = mapped_column(Text)          # filesystem path, never a DB blob
    screenshot_ref: Mapped[str | None] = mapped_column(Text)   # filesystem path, never a DB blob
    generated_by: Mapped[str] = mapped_column(Text, nullable=False, default="tool")
    oracle: Mapped[str | None] = mapped_column(Text)
    expected_status: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    seed: Mapped[int] = mapped_column(Integer, nullable=False, default=1337)
    manifest: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        CheckConstraint(
            "generated_by IN ('tool','ai','human')", name="evidence_generated_by"
        ),
    )


class ValidationJob(Base):
    __tablename__ = "validation_jobs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False
    )
    scan_run_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scan_runs.id")
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    claimed_by: Mapped[str | None] = mapped_column(Text)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','claimed','running','completed','failed')",
            name="validation_job_status",
        ),
    )


class ValidationEvent(Base):
    __tablename__ = "validation_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("validation_jobs.id"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (UniqueConstraint("job_id", "seq", name="uq_validation_event_seq"),)


class GraphRoute(Base):
    """Directed network reachability observed or explicitly modelled by Discovery."""

    __tablename__ = "graph_routes"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    src_asset_id: Mapped[str] = mapped_column(
        Text, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    dst_asset_id: Mapped[str] = mapped_column(
        Text, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    provenance: Mapped[str] = mapped_column(Text, nullable=False, default="observed")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        UniqueConstraint("src_asset_id", "dst_asset_id", name="uq_graph_route"),
        CheckConstraint("src_asset_id <> dst_asset_id", name="graph_route_distinct_assets"),
        CheckConstraint(
            "provenance IN ('evidence','cvss_vector','observed','class_table','assumed')",
            name="graph_route_provenance",
        ),
    )


class GraphFact(Base):
    """Durable non-patchable precondition used by AND-aware graph analysis."""

    __tablename__ = "graph_facts"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    ref: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    provenance: Mapped[str] = mapped_column(Text, nullable=False, default="assumed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        UniqueConstraint("kind", "ref", name="uq_graph_fact"),
        CheckConstraint(
            "provenance IN ('evidence','cvss_vector','observed','class_table','assumed')",
            name="graph_fact_provenance",
        ),
    )


class GraphSnapshot(Base):
    """Immutable, reproducible analysis artifact keyed by inputs and parameters."""

    __tablename__ = "graph_snapshots"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    input_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    trials: Mapped[int] = mapped_column(Integer, nullable=False)
    budget_hours: Mapped[float] = mapped_column(Float, nullable=False)
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    cytoscape: Mapped[dict] = mapped_column(JSONB, nullable=False)
    priority: Mapped[list] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        CheckConstraint("trials BETWEEN 100 AND 100000", name="graph_snapshot_trials"),
        CheckConstraint("budget_hours > 0", name="graph_snapshot_budget"),
    )


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    group_key: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    code_diff: Mapped[str | None] = mapped_column(Text)
    action_kind: Mapped[str] = mapped_column(Text, nullable=False, default="guidance")
    generated_by: Mapped[str] = mapped_column(Text, nullable=False, default="ai")
    applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="proposed")
    confidence: Mapped[float | None] = mapped_column(Float)
    risk_snapshot: Mapped[dict | None] = mapped_column(JSONB)
    generation_metadata: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint("generated_by IN ('tool','ai','human')", name="remediation_generated_by"),
        CheckConstraint(
            "action_kind IN ('code_fix','virtual_patch','config_hardening','guidance')",
            name="remediation_action_kind",
        ),
        CheckConstraint(
            "status IN ('proposed','applied','retested','superseded')",
            name="remediation_action_status",
        ),
    )


class RemediationActionFinding(Base):
    __tablename__ = "remediation_action_findings"

    action_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("remediation_actions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    finding_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    )


class RetestResult(Base):
    __tablename__ = "retest_results"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    action_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("remediation_actions.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False,
    )
    evidence_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False,
    )
    verdict: Mapped[str] = mapped_column(Text, nullable=False)
    before_status: Mapped[str] = mapped_column(Text, nullable=False)
    after_status: Mapped[str] = mapped_column(Text, nullable=False)
    still_reproducible: Mapped[bool | None] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        CheckConstraint(
            "verdict IN ('remediated','still_vulnerable','inconclusive','error')",
            name="retest_verdict",
        ),
    )


class RuntimeSettings(Base):
    """Operator overrides for runtime-tunable settings (ADR-0007 D6).

    A single JSONB row holding {setting_key: override_value}. The effective value
    of any setting is: this override -> .env -> code default. Only keys in
    app.core.runtime_config.SETTINGS_REGISTRY may appear here; values are validated
    and type-coerced before they are stored.
    """

    __tablename__ = "runtime_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    overrides: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_by: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (CheckConstraint("id = 1", name="runtime_settings_singleton"),)


class ConfigAudit(Base):
    """Append-only audit of runtime-settings changes (ADR-0007 D6)."""

    __tablename__ = "config_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    actor: Mapped[str] = mapped_column(Text, nullable=False, default="operator")
    change: Mapped[dict] = mapped_column(JSONB, nullable=False)
