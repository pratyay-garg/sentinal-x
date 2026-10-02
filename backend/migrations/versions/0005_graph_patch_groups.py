"""Backfill conservative identity patch groups for existing findings.

Revision ID: 0005_graph_patch_groups
Revises: 0004_attack_graph
Create Date: 2026-09-14
"""
from __future__ import annotations

from alembic import op

revision = "0005_graph_patch_groups"
down_revision = "0004_attack_graph"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE findings SET patch_group = 'finding::' || id::text "
        "WHERE mapping_status = 'mapped' AND patch_group IS NULL"
    )


def downgrade() -> None:
    # Identity groups are distinguishable from evidence-derived CVE/component
    # groups, so only this migration's values are reverted.
    op.execute(
        "UPDATE findings SET patch_group = NULL "
        "WHERE patch_group = 'finding::' || id::text"
    )
