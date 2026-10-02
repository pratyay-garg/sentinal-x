#!/usr/bin/env bash
set -Eeuo pipefail

# Set this to true to export every public Discovery/Validation/Graph table as CSV.
EXPORT_CSV=false

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CSV_OUTPUT_ROOT="${SCRIPT_DIR}/db_exports"

usage() {
  cat <<'EOF'
Usage: ./inspect_database.sh [--export-csv true|false] [--output-dir PATH]

Without arguments, EXPORT_CSV near the top of this file controls CSV export.
The script only reads PostgreSQL; it never changes or deletes database rows.
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --export-csv)
      (( $# >= 2 )) || { printf 'ERROR: --export-csv needs true or false\n' >&2; exit 2; }
      EXPORT_CSV=$2
      shift 2
      ;;
    --output-dir)
      (( $# >= 2 )) || { printf 'ERROR: --output-dir needs a path\n' >&2; exit 2; }
      CSV_OUTPUT_ROOT=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$EXPORT_CSV" in
  true|false) ;;
  *) printf 'ERROR: EXPORT_CSV must be exactly true or false\n' >&2; exit 2 ;;
esac

command -v docker >/dev/null 2>&1 || { printf 'ERROR: docker is unavailable\n' >&2; exit 1; }
docker compose version >/dev/null 2>&1 || {
  printf 'ERROR: the Docker Compose plugin is unavailable\n' >&2
  exit 1
}

cd "$SCRIPT_DIR"
if ! docker compose ps --status running --services | grep -qx db; then
  printf 'ERROR: the Discovery database is not running. Start it with:\n' >&2
  printf '  docker compose up -d db api worker validation-worker\n' >&2
  exit 1
fi

PSQL=(docker compose exec -T db psql -X -v ON_ERROR_STOP=1 -U discovery -d discovery)

printf '\n============================================================\n'
printf ' DISCOVERY + VALIDATION + ATTACK GRAPH — DATABASE VERIFICATION REPORT\n'
printf '============================================================\n'
"${PSQL[@]}" -P pager=off -c "
SELECT
    current_database() AS database,
    current_user AS database_user,
    current_timestamp AS report_time_utc,
    (SELECT version_num FROM alembic_version) AS migration_version;
"

printf '\n[1] Tables created in the public schema\n'
"${PSQL[@]}" -P pager=off -c "
SELECT
    tablename AS table_name,
    pg_size_pretty(pg_total_relation_size(format('%I.%I', schemaname, tablename))) AS total_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
"

printf '\n[2] Row count in every table\n'
TABLES=()
while IFS= read -r table; do
  [[ -n "$table" ]] && TABLES+=("$table")
done < <("${PSQL[@]}" -Atc "
SELECT tablename
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
")

printf '%-30s %12s\n' 'TABLE' 'ROWS'
printf '%-30s %12s\n' '------------------------------' '------------'
for table in "${TABLES[@]}"; do
  count=$("${PSQL[@]}" -Atc "SELECT COUNT(*) FROM \"${table}\";")
  printf '%-30s %12s\n' "$table" "$count"
done

printf '\n[3] Column definitions for all pipeline tables\n'
"${PSQL[@]}" -P pager=off -c "
SELECT
    table_name,
    ordinal_position AS position,
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_schema = 'public'
ORDER BY table_name, ordinal_position;
"

printf '\n[4] Recent scan jobs and runs\n'
"${PSQL[@]}" -P pager=off -c "
SELECT
    j.id AS job_id,
    j.target,
    j.profile,
    j.status AS job_status,
    j.attempt_count,
    r.id AS scan_run_id,
    r.status AS run_status,
    j.created_at,
    j.completed_at,
    j.error
FROM scan_jobs j
LEFT JOIN scan_runs r ON r.id = j.scan_run_id
ORDER BY j.created_at DESC
LIMIT 10;
"

printf '\n[5] Assets, services, and endpoints discovered\n'
"${PSQL[@]}" -P pager=off -c "
SELECT
    a.canonical_hostname AS asset,
    s.port,
    s.protocol,
    s.application_protocol,
    s.product,
    s.version,
    e.method,
    e.url AS endpoint,
    e.source
FROM assets a
LEFT JOIN services s ON s.asset_id = a.id
LEFT JOIN endpoints e ON e.service_id = s.id
ORDER BY a.canonical_hostname, s.port, e.url;
"

printf '\n[6] Findings with provenance and observation counts\n'
"${PSQL[@]}" -P pager=off -c "
SELECT
    f.id AS finding_id,
    f.vuln_class,
    f.mapping_status,
    f.status,
    f.severity_raw,
    f.source_tool,
    f.template_id,
    f.generated_by,
    f.endpoint,
    f.first_seen,
    f.last_seen,
    COUNT(o.id) AS total_observations,
    COUNT(DISTINCT o.scan_run_id) AS observed_scan_runs
FROM findings f
LEFT JOIN finding_observations o ON o.finding_id = f.id
GROUP BY f.id
ORDER BY f.last_seen DESC;
"

printf '\n[7] Individual finding observations\n'
"${PSQL[@]}" -P pager=off -c "
SELECT
    o.id AS observation_id,
    o.scan_run_id,
    o.finding_id,
    o.source_tool,
    o.source_ref,
    o.observed_at,
    o.partial
FROM finding_observations o
ORDER BY o.observed_at DESC
LIMIT 100;
"

printf '\n[8] Validation verdict inventory (zero is valid when no candidate produced that outcome)\n'
"${PSQL[@]}" -P pager=off -c "
WITH verdicts(verdict, display_order) AS (
    VALUES
        ('unvalidated', 1), ('validated', 2), ('false_positive', 3),
        ('inconclusive', 4), ('unverifiable_safely', 5), ('remediated', 6)
)
SELECT v.verdict, COUNT(f.id) AS finding_count
FROM verdicts v
LEFT JOIN findings f ON f.status = v.verdict
GROUP BY v.verdict, v.display_order
ORDER BY v.display_order;
"

printf '\n[9] Validation jobs and evidence integrity\n'
"${PSQL[@]}" -P pager=off -c "
WITH statuses(status, display_order) AS (
    VALUES ('queued', 1), ('claimed', 2), ('running', 3),
           ('completed', 4), ('failed', 5)
)
SELECT s.status, COUNT(j.id) AS job_count
FROM statuses s
LEFT JOIN validation_jobs j ON j.status = s.status
GROUP BY s.status, s.display_order
ORDER BY s.display_order;
"
"${PSQL[@]}" -P pager=off -c "
SELECT
    COUNT(*) FILTER (WHERE f.status = 'unvalidated') AS stranded_unvalidated,
    COUNT(*) FILTER (
        WHERE f.status = 'validated' AND (f.evidence_id IS NULL OR e.id IS NULL)
    ) AS validated_without_evidence,
    COUNT(*) FILTER (
        WHERE e.id IS NOT NULL AND e.expected_status IS DISTINCT FROM f.status
    ) AS current_verdict_mismatches,
    COUNT(*) FILTER (
        WHERE e.id IS NOT NULL AND e.generated_by NOT IN ('tool','ai','human')
    ) AS invalid_evidence_provenance
FROM findings f
LEFT JOIN evidence e ON e.id = f.evidence_id;
"
"${PSQL[@]}" -P pager=off -c "
SELECT
    COUNT(*) AS completed_jobs,
    COUNT(*) FILTER (WHERE e.id IS NULL) AS completed_jobs_missing_evidence,
    COUNT(DISTINCT e.id) AS resolved_evidence_records
FROM validation_jobs j
LEFT JOIN evidence e ON e.id::text = j.result->>'evidence_id'
WHERE j.status = 'completed';
"

printf '\n[10] Evidence provenance summary\n'
"${PSQL[@]}" -P pager=off -c "
SELECT generated_by, expected_status, oracle, COUNT(*) AS evidence_records
FROM evidence
GROUP BY generated_by, expected_status, oracle
ORDER BY generated_by, expected_status, oracle;
"

printf '\n[11] Attack-graph topology and latest durable snapshot\n'
"${PSQL[@]}" -P pager=off -c "
SELECT
    COUNT(*) AS assets,
    COUNT(*) FILTER (WHERE is_entry_point) AS entry_points,
    COUNT(*) FILTER (WHERE is_crown_jewel) AS crown_jewels,
    (SELECT COUNT(*) FROM graph_routes) AS routes,
    (SELECT COUNT(*) FROM graph_facts) AS facts,
    (SELECT COUNT(*) FROM graph_snapshots) AS snapshots
FROM assets;
"
"${PSQL[@]}" -P pager=off -c "
SELECT
    id AS latest_snapshot_id,
    summary->'diagnosis'->>'status' AS diagnosis,
    summary->'diagnosis'->>'answerable' AS answerable,
    summary->'invariants'->>'all_passed' AS invariants_passed,
    created_at
FROM graph_snapshots
ORDER BY created_at DESC
LIMIT 1;
"

printf '\n[12] Global kill-switch state\n'
"${PSQL[@]}" -P pager=off -c "
SELECT id, killswitch_engaged, reason, updated_at
FROM system_control;
"

if [[ "$EXPORT_CSV" == true ]]; then
  timestamp=$(date -u +'%Y%m%dT%H%M%SZ')
  export_dir="${CSV_OUTPUT_ROOT%/}/discovery_${timestamp}_$$"
  mkdir -p "$export_dir"
  chmod 700 "$export_dir"

  printf '\n[13] Exporting all tables and verification summaries to CSV\n'
  for table in "${TABLES[@]}"; do
    output_file="${export_dir}/${table}.csv"
    "${PSQL[@]}" --csv -c "SELECT * FROM \"${table}\" ORDER BY 1;" >"$output_file"
    chmod 600 "$output_file"
    printf '  %-30s -> %s\n' "$table" "$output_file"
  done

  "${PSQL[@]}" --csv -c "
SELECT table_name, ordinal_position, column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public'
ORDER BY table_name, ordinal_position;
" >"${export_dir}/_schema_columns.csv"
  chmod 600 "${export_dir}/_schema_columns.csv"

  "${PSQL[@]}" --csv -c "
SELECT
    conrelid::regclass AS table_name,
    conname AS constraint_name,
    CASE contype
        WHEN 'c' THEN 'check' WHEN 'f' THEN 'foreign_key'
        WHEN 'p' THEN 'primary_key' WHEN 'u' THEN 'unique'
        ELSE contype::text
    END AS constraint_type,
    pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE connamespace = 'public'::regnamespace
ORDER BY conrelid::regclass::text, conname;
" >"${export_dir}/_schema_constraints.csv"
  chmod 600 "${export_dir}/_schema_constraints.csv"

  "${PSQL[@]}" --csv -c "
WITH metrics(metric, value, display_order) AS (
    SELECT 'migration_version', version_num, 1 FROM alembic_version
    UNION ALL SELECT 'findings_total', COUNT(*)::text, 10 FROM findings
    UNION ALL SELECT 'verdict_unvalidated', COUNT(*)::text, 11 FROM findings WHERE status='unvalidated'
    UNION ALL SELECT 'verdict_validated', COUNT(*)::text, 12 FROM findings WHERE status='validated'
    UNION ALL SELECT 'verdict_false_positive', COUNT(*)::text, 13 FROM findings WHERE status='false_positive'
    UNION ALL SELECT 'verdict_inconclusive', COUNT(*)::text, 14 FROM findings WHERE status='inconclusive'
    UNION ALL SELECT 'verdict_unverifiable_safely', COUNT(*)::text, 15 FROM findings WHERE status='unverifiable_safely'
    UNION ALL SELECT 'verdict_remediated', COUNT(*)::text, 16 FROM findings WHERE status='remediated'
    UNION ALL SELECT 'validation_jobs_total', COUNT(*)::text, 20 FROM validation_jobs
    UNION ALL SELECT 'validation_jobs_completed', COUNT(*)::text, 21 FROM validation_jobs WHERE status='completed'
    UNION ALL SELECT 'validation_jobs_active', COUNT(*)::text, 22 FROM validation_jobs WHERE status IN ('queued','claimed','running')
    UNION ALL SELECT 'validation_jobs_failed', COUNT(*)::text, 23 FROM validation_jobs WHERE status='failed'
    UNION ALL SELECT 'evidence_total', COUNT(*)::text, 30 FROM evidence
    UNION ALL SELECT 'stranded_unvalidated', COUNT(*)::text, 40 FROM findings WHERE status='unvalidated'
    UNION ALL SELECT 'validated_without_evidence', COUNT(*)::text, 41
      FROM findings f LEFT JOIN evidence e ON e.id=f.evidence_id
      WHERE f.status='validated' AND (f.evidence_id IS NULL OR e.id IS NULL)
    UNION ALL SELECT 'current_verdict_mismatches', COUNT(*)::text, 42
      FROM findings f JOIN evidence e ON e.id=f.evidence_id
      WHERE e.expected_status IS DISTINCT FROM f.status
    UNION ALL SELECT 'completed_jobs_missing_evidence', COUNT(*)::text, 43
      FROM validation_jobs j LEFT JOIN evidence e ON e.id::text=j.result->>'evidence_id'
      WHERE j.status='completed' AND e.id IS NULL
    UNION ALL SELECT 'graph_entry_points', COUNT(*)::text, 50 FROM assets WHERE is_entry_point
    UNION ALL SELECT 'graph_crown_jewels', COUNT(*)::text, 51 FROM assets WHERE is_crown_jewel
    UNION ALL SELECT 'graph_routes', COUNT(*)::text, 52 FROM graph_routes
    UNION ALL SELECT 'graph_facts', COUNT(*)::text, 53 FROM graph_facts
    UNION ALL SELECT 'graph_snapshots', COUNT(*)::text, 54 FROM graph_snapshots
    UNION ALL SELECT 'latest_graph_diagnosis', COALESCE((
      SELECT summary->'diagnosis'->>'status' FROM graph_snapshots
      ORDER BY created_at DESC LIMIT 1
    ), ''), 55
    UNION ALL SELECT 'latest_graph_invariants_passed', COALESCE((
      SELECT summary->'invariants'->>'all_passed' FROM graph_snapshots
      ORDER BY created_at DESC LIMIT 1
    ), 'false'), 56
)
SELECT metric, value
FROM metrics
ORDER BY display_order, metric;
" >"${export_dir}/_verification_summary.csv"
  chmod 600 "${export_dir}/_verification_summary.csv"

  printf '\nCSV export complete: %s\n' "$export_dir"
  printf 'Warning: exports can contain targets, raw scanner responses, and evidence. Keep them private.\n'
else
  printf '\n[13] CSV export disabled (EXPORT_CSV=false)\n'
fi

printf '\nDatabase verification complete. No database rows were changed.\n'
