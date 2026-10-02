"""Add grouped remediation actions and immutable retest results.

Revision ID: 0007_remediation_retest
Revises: 0006_scan_credentials
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007_remediation_retest"
down_revision = "0006_scan_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "remediation_actions",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("group_key", sa.Text(), nullable=False),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("code_diff", sa.Text()),
        sa.Column("action_kind", sa.Text(), nullable=False, server_default="guidance"),
        sa.Column("generated_by", sa.Text(), nullable=False, server_default="ai"),
        sa.Column("applied", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.Text(), nullable=False, server_default="proposed"),
        sa.Column("confidence", sa.Float()),
        sa.Column("risk_snapshot", postgresql.JSONB()),
        sa.Column("generation_metadata", postgresql.JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("generated_by IN ('tool','ai','human')", name="remediation_generated_by"),
        sa.CheckConstraint("action_kind IN ('code_fix','virtual_patch','config_hardening','guidance')", name="remediation_action_kind"),
        sa.CheckConstraint("status IN ('proposed','applied','retested','superseded')", name="remediation_action_status"),
    )
    op.create_index(
        "uq_remediation_active_group", "remediation_actions", ["group_key"], unique=True,
        postgresql_where=sa.text("status IN ('proposed','applied')"),
    )
    op.create_index("ix_remediation_created", "remediation_actions", ["created_at"])
    op.create_table(
        "remediation_action_findings",
        sa.Column("action_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("remediation_actions.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_index("ix_remediation_action_finding", "remediation_action_findings", ["finding_id"])
    op.create_table(
        "retest_results",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("action_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("remediation_actions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("before_status", sa.Text(), nullable=False),
        sa.Column("after_status", sa.Text(), nullable=False),
        sa.Column("still_reproducible", sa.Boolean()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("verdict IN ('remediated','still_vulnerable','inconclusive','error')", name="retest_verdict"),
    )
    op.create_index("ix_retest_action", "retest_results", ["action_id"])
    op.create_index("ix_retest_finding", "retest_results", ["finding_id"])


def downgrade() -> None:
    op.drop_table("retest_results")
    op.drop_table("remediation_action_findings")
    op.drop_index("uq_remediation_active_group", table_name="remediation_actions")
    op.drop_table("remediation_actions")
