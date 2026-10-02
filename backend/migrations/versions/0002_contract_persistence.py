"""Persist canonical graph columns and per-run finding observations.

Revision ID: 0002_contract_persistence
Revises: 0001_initial
Create Date: 2026-09-13
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_contract_persistence"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("findings", "scan_run_id", new_column_name="first_seen_scan_run_id")
    op.alter_column("findings", "epss_score", new_column_name="epss")

    op.add_column("services", sa.Column("application_protocol", sa.Text()))
    op.add_column("services", sa.Column("state", sa.Text(), nullable=False, server_default="open"))
    op.add_column("services", sa.Column("product", sa.Text()))
    op.add_column("services", sa.Column("version", sa.Text()))
    op.add_column("services", sa.Column("confidence", sa.Float()))

    op.add_column("endpoints", sa.Column("url", sa.Text()))
    op.execute("""
        UPDATE endpoints AS e
        SET url = 'http://' || a.canonical_hostname || ':' || s.port || e.path
        FROM assets AS a, services AS s
        WHERE e.asset_id = a.id AND e.service_id = s.id
    """)
    op.alter_column("endpoints", "url", nullable=False)
    # The legacy schema had only a non-unique index for this identity. Collapse
    # any pre-existing duplicates deterministically and preserve finding FKs
    # before enforcing the new invariant.
    op.execute("""
        UPDATE findings AS f
        SET endpoint_id = duplicates.keep_id
        FROM (
            SELECT id,
                   first_value(id) OVER (
                       PARTITION BY service_id, path, method, auth_context
                       ORDER BY id::text
                   ) AS keep_id,
                   row_number() OVER (
                       PARTITION BY service_id, path, method, auth_context
                       ORDER BY id::text
                   ) AS duplicate_number
            FROM endpoints
        ) AS duplicates
        WHERE duplicates.duplicate_number > 1 AND f.endpoint_id = duplicates.id
    """)
    op.execute("""
        DELETE FROM endpoints AS e
        USING (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY service_id, path, method, auth_context
                       ORDER BY id::text
                   ) AS duplicate_number
            FROM endpoints
        ) AS duplicates
        WHERE duplicates.duplicate_number > 1 AND e.id = duplicates.id
    """)
    op.create_unique_constraint(
        "uq_endpoint_identity", "endpoints", ["service_id", "path", "method", "auth_context"]
    )

    op.add_column("findings", sa.Column("vuln_class", sa.Text()))
    op.add_column("findings", sa.Column("confidence", sa.Float()))
    op.add_column("findings", sa.Column("patch_hours", sa.Float()))
    op.add_column("findings", sa.Column("patch_group", sa.Text()))
    op.add_column("findings", sa.Column("endpoint", sa.Text()))
    op.add_column("findings", sa.Column("param", sa.Text()))
    op.add_column(
        "findings", sa.Column("mapping_status", sa.Text(), nullable=False, server_default="unmapped")
    )
    op.add_column("findings", sa.Column("mapping_diagnostics", postgresql.JSONB()))
    op.add_column(
        "findings",
        sa.Column("classification_version", sa.Text(), nullable=False, server_default="legacy-unmapped"),
    )
    # Existing rows cannot be safely classified by a migration. Preserve them
    # as explicit review items; new writes validate against the live contract.
    op.execute("""
        UPDATE findings
        SET raw_finding_type = COALESCE(raw_finding_type, vuln_class_candidate),
            mapping_diagnostics = '{"reason":"requires_reclassification_after_upgrade"}'::jsonb
    """)
    op.create_check_constraint(
        "finding_mapping_state",
        "findings",
        "(mapping_status = 'mapped' AND vuln_class IS NOT NULL) OR "
        "(mapping_status = 'unmapped' AND vuln_class IS NULL)",
    )
    op.create_check_constraint("finding_discovery_status", "findings", "status = 'unvalidated'")
    op.create_check_constraint("finding_discovery_provenance", "findings", "generated_by = 'tool'")

    op.create_table(
        "finding_observations",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "finding_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("findings.id"), nullable=False
        ),
        sa.Column(
            "scan_run_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("scan_runs.id"), nullable=False
        ),
        sa.Column("source_tool", sa.Text(), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=False, server_default=""),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("raw_data", postgresql.JSONB()),
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint(
            "finding_id", "scan_run_id", "source_tool", "source_ref",
            name="uq_finding_observation",
        ),
    )
    op.create_index("ix_finding_observations_run", "finding_observations", ["scan_run_id"])
    # Retain the single observation represented by each legacy finding. New
    # scans append observations without rewriting the finding's first-seen run.
    op.execute("""
        INSERT INTO finding_observations (
            id, finding_id, scan_run_id, source_tool, source_ref, observed_at, partial
        )
        SELECT id, id, first_seen_scan_run_id, source_tool,
               COALESCE(template_id, ''), COALESCE(last_seen, now()), false
        FROM findings
    """)
    op.add_column(
        "evidence", sa.Column("generated_by", sa.Text(), nullable=False, server_default="tool")
    )
    op.create_check_constraint(
        "evidence_generated_by", "evidence", "generated_by IN ('tool','ai','human')"
    )


def downgrade() -> None:
    op.drop_constraint("evidence_generated_by", "evidence", type_="check")
    op.drop_column("evidence", "generated_by")
    op.drop_index("ix_finding_observations_run", table_name="finding_observations")
    op.drop_table("finding_observations")
    op.drop_constraint("finding_discovery_provenance", "findings", type_="check")
    op.drop_constraint("finding_discovery_status", "findings", type_="check")
    op.drop_constraint("finding_mapping_state", "findings", type_="check")
    for column in (
        "classification_version", "mapping_diagnostics", "mapping_status", "param", "endpoint",
        "patch_group", "patch_hours", "confidence", "vuln_class",
    ):
        op.drop_column("findings", column)
    op.drop_constraint("uq_endpoint_identity", "endpoints", type_="unique")
    op.drop_column("endpoints", "url")
    for column in ("confidence", "version", "product", "state", "application_protocol"):
        op.drop_column("services", column)
    op.alter_column("findings", "epss", new_column_name="epss_score")
    op.alter_column("findings", "first_seen_scan_run_id", new_column_name="scan_run_id")
