"""Add encrypted, expiring authenticated-scan credentials.

Revision ID: 0006_scan_credentials
Revises: 0005_graph_patch_groups
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006_scan_credentials"
down_revision = "0005_graph_patch_groups"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("auth_context", sa.Text, nullable=False),
        sa.Column("ciphertext", sa.Text, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_job_id", "auth_context", name="uq_scan_credential_context"),
    )
    op.create_index("ix_scan_credentials_expiry", "scan_credentials", ["expires_at"])
    op.create_index("ix_scan_credentials_run", "scan_credentials", ["scan_run_id"])


def downgrade() -> None:
    op.drop_table("scan_credentials")
