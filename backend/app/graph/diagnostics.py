"""Input diagnostics for the attack-graph pipeline.

Diagnostics answer whether the requested analysis is well posed separately
from the analysis result.  In particular, an unreachable crown jewel is a
valid answer; a graph with no crown jewel is not.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from .contract import VULN_CLASSES
from .fixpoint import sink_reachable
from .model import GraphInput, SUPER_SINK, SUPER_SOURCE


@dataclass(frozen=True)
class Diagnosis:
    status: str
    answerable: bool
    problems: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "answerable": self.answerable,
            "problems": list(self.problems),
        }


def _problem(code: str, severity: str, message: str, fix: str) -> dict:
    return {"code": code, "severity": severity, "message": message, "fix": fix}


def diagnose(gi: GraphInput, graph: nx.DiGraph) -> Diagnosis:
    """Diagnose omissions and lossy input mappings without raising.

    The ordering is deterministic so API responses and judge demos remain
    reproducible across processes.
    """
    problems: list[dict] = []

    if not gi.assets:
        problems.append(_problem(
            "no_assets", "error", "the graph contains no assets",
            "run Discovery successfully before graph analysis"))

    if not gi.jewels():
        problems.append(_problem(
            "no_crown_jewels", "error", "no asset is marked as a crown jewel",
            "mark at least one business-critical asset is_crown_jewel=true"))

    if not gi.entries:
        problems.append(_problem(
            "no_entry_points", "error", "no attacker entry point was supplied",
            "select at least one externally reachable asset as an entry point"))

    live = [f for f in gi.findings if f.status not in {"false_positive", "remediated"}]
    if not live:
        problems.append(_problem(
            "no_findings", "error", "there are no live findings to analyse",
            "run Discovery and Validation, or include non-remediated findings"))

    unknown = sorted({f.vuln_class for f in gi.findings
                      if f.vuln_class not in VULN_CLASSES})
    if unknown:
        problems.append(_problem(
            "unknown_vuln_classes", "warning",
            f"classes use assumed fallback semantics: {unknown}",
            "map each class to the shared contract before relying on its path"))

    if gi.assets and len(gi.assets) > 1 and not gi.routes:
        problems.append(_problem(
            "no_routes", "warning", "multiple assets were supplied without network routes",
            "persist Discovery connectivity observations as graph routes"))

    missing_groups = sorted(f.id for f in live if not f.patch_group)
    if missing_groups:
        problems.append(_problem(
            "no_patch_groups", "warning",
            f"findings lack patch grouping: {missing_groups}",
            "set patch_group from CVE, component, or demonstrated root cause"))

    if gi.unknown_keys:
        details = ", ".join(
            f"{kind}={keys}" for kind, keys in sorted(gi.unknown_keys.items()))
        suggestions = []
        if "epss_score" in gi.unknown_keys.get("findings", []):
            suggestions.append("use 'epss' instead of 'epss_score'")
        suggestion = "; ".join(suggestions) or "use the shared contract column names"
        problems.append(_problem(
            "unrecognised_input_keys", "warning",
            f"input keys were ignored: {details}; {suggestion}", suggestion))

    # Structural omissions determine whether there is a meaningful question.
    error_codes = {p["code"] for p in problems if p["severity"] == "error"}
    if "no_assets" in error_codes:
        status, answerable = "no_assets", False
    elif "no_crown_jewels" in error_codes:
        status, answerable = "no_crown_jewels", False
    elif "no_entry_points" in error_codes:
        status, answerable = "no_entry_points", False
    elif "no_findings" in error_codes:
        status, answerable = "no_findings", False
    elif (SUPER_SOURCE not in graph or SUPER_SINK not in graph
          or not sink_reachable(graph)):
        status, answerable = "jewels_unreachable", True
    else:
        status, answerable = "ok", True
    return Diagnosis(status=status, answerable=answerable, problems=problems)
