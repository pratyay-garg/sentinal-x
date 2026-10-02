"""Operator-editable runtime settings and a config-change audit (ADR-0007 D6).

Revision ID: 0009_runtime_settings
Revises: 0008_ground_confidence
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_runtime_settings"
down_revision = "0008_ground_confidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("overrides", postgresql.JSONB(astext_type=sa.Text()),
                  server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=True),
        sa.CheckConstraint("id = 1", name="runtime_settings_singleton"),
        sa.PrimaryKeyConstraint("id"),
    )
    # Seed the singleton row so the API can always UPDATE it.
    op.execute("INSERT INTO runtime_settings (id, overrides) VALUES (1, '{}'::jsonb)")

    op.create_table(
        "config_audit",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("actor", sa.Text(), server_default=sa.text("'operator'"), nullable=False),
        sa.Column("change", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("config_audit")
    op.drop_table("runtime_settings")
