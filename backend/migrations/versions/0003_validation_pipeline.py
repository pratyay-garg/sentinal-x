"""Persistent, replayable Validation pipeline.

Revision ID: 0003_validation_pipeline
Revises: 0002_contract_persistence
Create Date: 2026-09-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_validation_pipeline"
down_revision = "0002_contract_persistence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("finding_discovery_status", "findings", type_="check")
    op.create_check_constraint(
        "finding_validation_status", "findings",
        "status IN ('unvalidated','validated','false_positive','inconclusive',"
        "'unverifiable_safely','remediated')",
    )
    op.add_column("findings", sa.Column("observed_grants", postgresql.JSONB()))
    op.add_column("findings", sa.Column("observed_requires", postgresql.JSONB()))
    op.add_column("findings", sa.Column("target_asset_id", sa.Text()))
    op.create_foreign_key(
        "fk_findings_target_asset", "findings", "assets", ["target_asset_id"], ["id"]
    )

    op.add_column("evidence", sa.Column("oracle", sa.Text()))
    op.add_column("evidence", sa.Column("expected_status", sa.Text()))
    op.add_column("evidence", sa.Column("confidence", sa.Float()))
    op.add_column("evidence", sa.Column("seed", sa.Integer(), nullable=False, server_default="1337"))
    op.add_column("evidence", sa.Column("manifest", postgresql.JSONB()))
    op.add_column(
        "evidence", sa.Column("created_at", sa.DateTime(timezone=True),
                              nullable=False, server_default=sa.func.now())
    )
    op.create_check_constraint(
        "evidence_expected_status", "evidence",
        "expected_status IS NULL OR expected_status IN "
        "('validated','false_positive','inconclusive','unverifiable_safely')",
    )
    op.create_check_constraint(
        "evidence_confidence_range", "evidence",
        "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
    )

    op.create_table(
        "validation_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scan_runs.id")),
        sa.Column("status", sa.Text(), nullable=False, server_default="queued"),
        sa.Column("claimed_by", sa.Text()),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text()),
        sa.Column("result", postgresql.JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('queued','claimed','running','completed','failed')",
            name="validation_job_status",
        ),
    )
    op.create_index("ix_validation_jobs_status_created", "validation_jobs", ["status", "created_at"])
    op.create_index("ix_validation_jobs_finding", "validation_jobs", ["finding_id"])
    op.create_table(
        "validation_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("validation_jobs.id"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("event", sa.Text(), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("job_id", "seq", name="uq_validation_event_seq"),
    )
    op.create_index("ix_validation_events_job_seq", "validation_events", ["job_id", "seq"])


def downgrade() -> None:
    op.drop_index("ix_validation_events_job_seq", table_name="validation_events")
    op.drop_table("validation_events")
    op.drop_index("ix_validation_jobs_finding", table_name="validation_jobs")
    op.drop_index("ix_validation_jobs_status_created", table_name="validation_jobs")
    op.drop_table("validation_jobs")
    op.drop_constraint("evidence_confidence_range", "evidence", type_="check")
    op.drop_constraint("evidence_expected_status", "evidence", type_="check")
    for name in ("created_at", "manifest", "seed", "confidence", "expected_status", "oracle"):
        op.drop_column("evidence", name)
    op.drop_constraint("fk_findings_target_asset", "findings", type_="foreignkey")
    for name in ("target_asset_id", "observed_requires", "observed_grants"):
        op.drop_column("findings", name)
    op.drop_constraint("finding_validation_status", "findings", type_="check")
    op.create_check_constraint("finding_discovery_status", "findings", "status = 'unvalidated'")
