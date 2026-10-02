# ADR-0006: Canonical Discovery finding columns with observation history

- Status: accepted
- Date: 2026-09-13

## Context

The original Discovery implementation built a contract-shaped dictionary in an
adapter but persisted only its richer internal fields. A database-only Graph
consumer therefore saw no `vuln_class`, `confidence`, `patch_hours`,
`patch_group`, flattened `endpoint`, or singular `param`. Globally deduplicated
findings also retained only the first `scan_run_id`, so repeat observations were
lost. Unknown Nuclei templates were forced into `info_leak`, creating semantics
without evidence.

The architecture reference allows either canonical fields on `findings` or one
versioned projection. Two separately writable finding sources would be
ambiguous.

## Decision

`findings` is the one canonical source. It contains the exact flat columns the
shared `Slice_6.contract` and `Slice_6.loader` consume, alongside Discovery's
audit fields. Every mapped row is validated with the executable shared contract
before it is flushed. `confidence` remains SQL `NULL` for a new Discovery
candidate; the shared normalizer supplies the graph's documented 0.25 default
at read time.

`finding_observations` records each `(finding, scan run, source tool, source
reference)` occurrence. The global finding identity excludes tool/template
identity and includes the mapped class, endpoint, method, and singular implicated
parameter. This correlates independent observations without destroying their
provenance.

Unmapped candidates remain in `findings` with `vuln_class = NULL`,
`mapping_status = 'unmapped'`, their raw type, and a diagnostic. The Graph loader
selects only mapped rows. Discovery never supplies `observed_grants`,
`observed_requires`, or `target_asset_id`.

## Consequences

- Graph and Validation can consume committed rows without importing Discovery.
- Repeat scans are idempotent while retaining per-run history.
- Unknown scanner output remains visible but cannot inherit the graph's
  `info_leak` fallback.
- Existing rows are migrated to an explicit `legacy-unmapped` state because a
  schema migration has insufficient evidence to classify them safely.
- A coordinated contract change is required before a new vulnerability class
  becomes graph-visible.
