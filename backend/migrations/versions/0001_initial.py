"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-13
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("target", sa.Text, nullable=False),
        sa.Column("profile", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("stats", postgresql.JSONB),
        sa.Column("coverage", postgresql.JSONB),
    )

    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("scan_runs.id")),
        sa.Column("target", sa.Text, nullable=False),
        sa.Column("profile", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="queued"),
        sa.Column("custom_header_names", postgresql.JSONB),
        sa.Column("claimed_by", sa.Text),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cancel_requested", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_scan_jobs_status_created", "scan_jobs", ["status", "created_at"])
    op.create_index("ix_scan_jobs_heartbeat", "scan_jobs", ["heartbeat_at"])

    op.create_table(
        "scan_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("event", sa.Text, nullable=False),
        sa.Column("data", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_events_job_seq", "scan_events", ["job_id", "seq"])

    op.create_table(
        "system_control",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("killswitch_engaged", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("reason", sa.Text),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("id = 1", name="system_control_singleton"),
    )
    op.execute("INSERT INTO system_control (id, killswitch_engaged) VALUES (1, false)")

    op.create_table(
        "assets",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("canonical_hostname", sa.Text, nullable=False),
        sa.Column("type", sa.Text, nullable=False),
        sa.Column("parent_id", sa.Text, sa.ForeignKey("assets.id")),
        sa.Column("criticality", sa.Integer, nullable=False, server_default="3"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("meta", postgresql.JSONB),
        sa.CheckConstraint("criticality BETWEEN 1 AND 5", name="criticality_range"),
    )

    op.create_table(
        "asset_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("asset_id", sa.Text, sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("alias_type", sa.Text, nullable=False),
        sa.Column("alias_value", sa.Text, nullable=False),
        sa.Column("confidence", sa.Float),
    )
    op.create_index("ix_asset_aliases_asset_id", "asset_aliases", ["asset_id"])

    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("asset_id", sa.Text, sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.Text, nullable=False),
        sa.Column("banner", sa.Text),
        sa.Column("tls_info", postgresql.JSONB),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_service"),
    )

    op.create_table(
        "tech_fingerprints",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("service_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("services.id")),
        sa.Column("asset_id", sa.Text, sa.ForeignKey("assets.id")),
        sa.Column("vendor", sa.Text),
        sa.Column("product", sa.Text),
        sa.Column("version_range", sa.Text),
        sa.Column("cpe", sa.Text),
        sa.Column("confidence", sa.Float),
        sa.Column("method", sa.Text),
    )

    op.create_table(
        "endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("service_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("asset_id", sa.Text, sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("method", sa.Text, nullable=False),
        sa.Column("param_names", postgresql.JSONB),
        sa.Column("request_template", postgresql.JSONB),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("auth_context", sa.Text, nullable=False, server_default="none"),
        sa.Column("auth_required", sa.Boolean),
        sa.Column("page_class", sa.Text),
        sa.Column("endpoint_class", sa.Text),
    )
    op.create_index("ix_endpoints_service_path_method", "endpoints", ["service_id", "path", "method"])

    # findings.evidence_id -> evidence.id is a circular reference (evidence.finding_id
    # -> findings.id also exists). Create findings WITHOUT that FK enforced yet,
    # create evidence, then add the FK via ALTER — the standard pattern for a
    # genuine circular dependency between two tables.
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("asset_id", sa.Text, sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("endpoints.id")),
        sa.Column("service_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("services.id")),
        sa.Column("matched_param", sa.Text),
        sa.Column("vuln_class_candidate", sa.Text, nullable=False),
        sa.Column("raw_finding_type", sa.Text),
        sa.Column("source_tool", sa.Text, nullable=False),
        sa.Column("template_id", sa.Text),
        sa.Column("severity_raw", sa.Text),
        sa.Column("evidence_stub", sa.Text),
        sa.Column("cve_id", sa.Text),
        sa.Column("cpe", sa.Text),
        sa.Column("epss_score", sa.Float),
        sa.Column("epss_snapshot_date", sa.Date),
        sa.Column("cvss_vector", sa.Text),
        sa.Column("dedup_key", sa.Text, nullable=False, unique=True),
        sa.Column("discovery_confidence", sa.Float, nullable=False),
        sa.Column("confidence_basis", sa.Text),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("status", sa.Text, nullable=False, server_default="unvalidated"),
        sa.Column("generated_by", sa.Text, nullable=False, server_default="tool"),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=False)),  # FK added below
    )
    op.create_index("ix_findings_scan_run_id", "findings", ["scan_run_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_status", "findings", ["status"])

    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("redacted_request_excerpt", sa.Text),
        sa.Column("har_ref", sa.Text),
        sa.Column("screenshot_ref", sa.Text),
    )

    op.create_foreign_key(
        "fk_findings_evidence_id", "findings", "evidence", ["evidence_id"], ["id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_findings_evidence_id", "findings", type_="foreignkey")
    op.drop_table("evidence")
    op.drop_table("findings")
    op.drop_table("endpoints")
    op.drop_table("tech_fingerprints")
    op.drop_table("services")
    op.drop_table("asset_aliases")
    op.drop_table("assets")
    op.drop_table("system_control")
    op.drop_table("scan_events")
    op.drop_table("scan_jobs")
    op.drop_table("scan_runs")
