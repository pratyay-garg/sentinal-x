export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface Overview {
  counts: {
    scans: number; active_scans: number; assets: number; findings: number;
    validated: number; unvalidated: number; critical: number; high: number;
    active_validations: number; evidence: number; graph_snapshots: number;
  };
  killswitch: { engaged: boolean; reason: string | null; updated_at: string | null };
  latest_graph: { id: string; seed: number; trials: number; diagnosis: string;
    answerable: boolean; invariants_passed: boolean; summary: Record<string, Json>;
    created_at: string } | null;
}

export interface Scan {
  id: string; scan_run_id: string | null; target: string; profile: string; status: string;
  attempt_count: number; cancel_requested: boolean; error: string | null;
  created_at: string; started_at: string | null; completed_at: string | null;
  event_count: number; finding_count: number;
}

export interface Finding {
  id: string; asset_id: string; hostname: string; vuln_class: string | null;
  vuln_class_candidate: string; mapping_status: string; status: string;
  confidence: number | null; discovery_confidence: number; severity: string | null;
  cvss_vector: string | null; epss: number | null; cve_id: string | null;
  endpoint: string | null; param: string | null; patch_hours: number | null;
  patch_group: string | null; evidence_id: string | null; source_tool: string;
  generated_by: string; observed_requires: string[] | null; observed_grants: string[] | null;
  first_seen: string; last_seen: string; observation_count: number;
}

export interface Evidence {
  id: string; finding_id: string; generated_by: string; oracle: string | null;
  expected_status: string | null; confidence: number | null; seed: number;
  manifest: Json; redacted_request_excerpt: string | null; har_ref: string | null;
  screenshot_ref: string | null; created_at: string;
}

export interface ScanEvent {
  seq: number; event: string; data: Record<string, Json>; created_at: string;
}

export interface ScanResults {
  job_id: string; scan_run_id: string; status: string;
  coverage: Record<string, Json> | null; stats: Record<string, Json> | null;
  findings: Array<Record<string, Json>>;
}

export interface ValidatedFinding {
  id: string; asset_id: string; vuln_class: string | null; status: string;
  confidence: number | null; endpoint: string | null; param: string | null;
  patch_group: string | null; evidence_id: string | null;
  observed_requires: string[]; observed_grants: string[]; target_asset_id: string | null;
  evidence: Omit<Evidence, "id" | "finding_id" | "redacted_request_excerpt" | "har_ref" | "screenshot_ref"> | null;
}

export interface GraphAsset {
  id: string; hostname: string; zone: string; criticality: number;
  is_entry_point: boolean; is_crown_jewel: boolean;
}

export interface CyElement {
  data: {
    id: string; source?: string; target?: string; label?: string; type?: string;
    kind?: string; probability?: number; evidence_id?: string | null;
    in_min_cut?: boolean; is_dominator?: boolean; provenance?: string;
    [key: string]: Json | undefined;
  };
}

export interface CytoscapePayload {
  snapshot_id: string; cached: boolean;
  elements: { nodes: CyElement[]; edges: CyElement[] };
}

export interface PriorityItem {
  vuln_id: string; label?: string; evidence_id?: string | null; score?: number;
  patch_hours?: number; in_min_cut?: boolean; dominated_jewels?: string[];
  [key: string]: Json | undefined;
}

export interface PriorityPayload {
  snapshot_id: string; items: PriorityItem[];
  cut: Record<string, Json>; budget_plan: Record<string, Json>;
}

export interface GraphAnalysis {
  snapshot_id: string; cached: boolean; seed: number; trials: number;
  budget_hours: number; created_at: string; summary: Record<string, Json>;
  inventory: Record<string, Json>; cytoscape: CytoscapePayload;
  priority: PriorityItem[];
}

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }

export interface RemediationAction {
  id: string; group_key: string; finding_ids: string[]; root_cause: string;
  recommendation: string; code_diff: string | null;
  action_kind: "code_fix" | "virtual_patch" | "config_hardening" | "guidance";
  generated_by: "tool" | "ai" | "human"; applied: boolean;
  status: "proposed" | "applied" | "retested"; confidence: number | null;
  risk_snapshot: Record<string, Json> | null;
  generation_metadata: Record<string, Json> | null;
  created_at: string; updated_at: string;
}

export interface RetestAttempt {
  id: string; action_id: string; finding_id: string; evidence_id: string;
  verdict: "remediated" | "still_vulnerable" | "inconclusive" | "error";
  before_status: string; after_status: string; still_reproducible: boolean | null;
  created_at: string;
}
