"""
IMPLEMENTATION_SPEC_v4.md §6/§10 risk #10: dedup_key MUST include
vuln_class_candidate. Without it, two genuinely different vulnerabilities in
the same parameter (a boolean SQLi and a reflected XSS, both in `id`) collapse
into one row whenever template_id is NULL — which it always is for any
non-Nuclei finding (e.g. an httpx-header-based finding).

Formula: SHA256(asset_id + mapped_or_raw_class + CVE-if-known + canonical_path
                 + method + implicated_parameter)

Tool and template identity are observation provenance, not security identity.
They deliberately do not participate in this key: two tools observing the same
class at the same sink correlate to one finding while retaining two observation
rows. The singular implicated parameter is load-bearing and prevents `id` and
`sort` findings on one endpoint from collapsing.
"""
from __future__ import annotations

import hashlib
from urllib.parse import parse_qs, urlsplit


def normalize_path_for_dedup(path_or_url: str) -> tuple[str, tuple[str, ...]]:
    """Returns (bare_path, sorted_param_names). Strips query-string VALUES,
    keeps parameter NAMES sorted. Path is everything before the '?'.
    """
    split = urlsplit(path_or_url)
    bare_path = split.path or "/"
    params = parse_qs(split.query, keep_blank_values=True)
    sorted_names = tuple(sorted(params.keys()))
    return bare_path, sorted_names


def compute_dedup_key(
    *,
    asset_id: str,
    source_tool: str,
    vuln_class_candidate: str,
    template_id_or_type: str | None,
    path_or_url: str,
    method: str,
    matched_param: str | None = None,
    cve_id: str | None = None,
) -> str:
    bare_path, sorted_param_names = normalize_path_for_dedup(path_or_url)
    parts = [
        asset_id,
        vuln_class_candidate,
        (cve_id or "no-cve").strip().upper(),
        bare_path,
        (matched_param or ",".join(sorted_param_names) or "no-param").strip().lower(),
        method.upper(),
    ]
    digest_input = "|".join(parts).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()
