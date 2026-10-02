"""Persist attack-graph topology, asset roles, and reproducible snapshots.

Revision ID: 0004_attack_graph
Revises: 0003_validation_pipeline
Create Date: 2026-09-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004_attack_graph"
down_revision = "0003_validation_pipeline"
branch_labels = None
depends_on = None


_PROVENANCE = "('evidence','cvss_vector','observed','class_table','assumed')"


def upgrade() -> None:
    op.add_column(
        "assets", sa.Column("zone", sa.Text(), nullable=False, server_default="external")
    )
    op.add_column(
        "assets", sa.Column("is_crown_jewel", sa.Boolean(), nullable=False,
                             server_default=sa.false())
    )
    op.add_column(
        "assets", sa.Column("is_entry_point", sa.Boolean(), nullable=False,
                             server_default=sa.true())
    )

    op.create_table(
        "graph_routes",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("src_asset_id", sa.Text(),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dst_asset_id", sa.Text(),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provenance", sa.Text(), nullable=False, server_default="observed"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("src_asset_id", "dst_asset_id", name="uq_graph_route"),
        sa.CheckConstraint("src_asset_id <> dst_asset_id", name="graph_route_distinct_assets"),
        sa.CheckConstraint(f"provenance IN {_PROVENANCE}", name="graph_route_provenance"),
    )
    op.create_index("ix_graph_routes_src", "graph_routes", ["src_asset_id"])
    op.create_index("ix_graph_routes_dst", "graph_routes", ["dst_asset_id"])

    op.create_table(
        "graph_facts",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("ref", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("provenance", sa.Text(), nullable=False, server_default="assumed"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("kind", "ref", name="uq_graph_fact"),
        sa.CheckConstraint(f"provenance IN {_PROVENANCE}", name="graph_fact_provenance"),
    )

    op.create_table(
        "graph_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("input_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("trials", sa.Integer(), nullable=False),
        sa.Column("budget_hours", sa.Float(), nullable=False),
        sa.Column("summary", postgresql.JSONB(), nullable=False),
        sa.Column("cytoscape", postgresql.JSONB(), nullable=False),
        sa.Column("priority", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint("trials BETWEEN 100 AND 100000", name="graph_snapshot_trials"),
        sa.CheckConstraint("budget_hours > 0", name="graph_snapshot_budget"),
    )
    op.create_index("ix_graph_snapshots_created", "graph_snapshots", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_graph_snapshots_created", table_name="graph_snapshots")
    op.drop_table("graph_snapshots")
    op.drop_table("graph_facts")
    op.drop_index("ix_graph_routes_dst", table_name="graph_routes")
    op.drop_index("ix_graph_routes_src", table_name="graph_routes")
    op.drop_table("graph_routes")
    op.drop_column("assets", "is_entry_point")
    op.drop_column("assets", "is_crown_jewel")
    op.drop_column("assets", "zone")
