"""Ground remediation confidence in validated evidence.

Revision ID: 0008_ground_confidence
Revises: 0007_remediation_retest
"""
from __future__ import annotations

from alembic import op

revision = "0008_ground_confidence"
down_revision = "0007_remediation_retest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        WITH bounds AS (
            SELECT
                raf.action_id,
                MIN(COALESCE(e.confidence, f.confidence, f.discovery_confidence)) AS evidence_bound,
                jsonb_agg(
                    COALESCE(e.confidence, f.confidence, f.discovery_confidence)
                    ORDER BY f.id
                ) AS evidence_values,
                jsonb_agg(
                    jsonb_build_object(
                        'source', COALESCE('evidence:' || e.id::text, 'finding:' || f.id::text),
                        'confidence', COALESCE(e.confidence, f.confidence, f.discovery_confidence)
                    ) ORDER BY f.id
                ) AS sources
            FROM remediation_action_findings raf
            JOIN findings f ON f.id = raf.finding_id
            LEFT JOIN evidence e
                ON e.id = f.evidence_id AND e.generated_by IN ('tool', 'human')
            GROUP BY raf.action_id
        )
        UPDATE remediation_actions ra
        SET
            generation_metadata = COALESCE(ra.generation_metadata, '{}'::jsonb)
                || jsonb_build_object(
                    'confidence_basis', jsonb_build_object(
                        'method', 'conservative_min',
                        'formula', 'min(provider_self_reported, weakest_validated_evidence)',
                        'provider_self_reported', ra.confidence,
                        'validated_evidence_values', bounds.evidence_values,
                        'validated_evidence_bound', bounds.evidence_bound,
                        'final', LEAST(COALESCE(ra.confidence, bounds.evidence_bound), bounds.evidence_bound),
                        'sources', bounds.sources
                    )
                ),
            confidence = LEAST(COALESCE(ra.confidence, bounds.evidence_bound), bounds.evidence_bound)
        FROM bounds
        WHERE ra.id = bounds.action_id
          AND ra.generated_by = 'ai'
          AND bounds.evidence_bound IS NOT NULL
    """)


def downgrade() -> None:
    op.execute("""
        UPDATE remediation_actions
        SET
            confidence = COALESCE(
                (generation_metadata #>> '{confidence_basis,provider_self_reported}')::double precision,
                confidence
            ),
            generation_metadata = generation_metadata - 'confidence_basis'
        WHERE generated_by = 'ai'
          AND generation_metadata ? 'confidence_basis'
    """)
