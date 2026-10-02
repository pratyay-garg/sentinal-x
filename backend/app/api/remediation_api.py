"""AI remediation and explicit, evidence-preserving retest API.

Provider secrets exist only in the inbound generation request and are never
written to the database, logs, action metadata, or prompt artifacts.
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import uuid
from collections import Counter
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.remediation.service import GenerationRequest, generate_remediation
from app.engines.remediation.retest import replay
from app.llm.client import ProviderConfig, list_models
from app.engines.remediation.knowledge_base import guidance

from app.core.credentials import load_for_run
from app.core.db import get_session_dep
from .graph_service import analyze_and_persist
from app.models import (
    Asset, Endpoint, Evidence, Finding, RemediationAction,
    RemediationActionFinding, RetestResult, ScanJob, ScanRun,
)


class AppliedUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    applied: bool


class ManualAction(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)
    root_cause: str = Field(min_length=1, max_length=8000)
    recommendation: str = Field(min_length=1, max_length=30000)
    action_kind: str = Field(default="guidance", pattern="^(code_fix|virtual_patch|config_hardening|guidance)$")
    code_diff: str | None = Field(default=None, max_length=30000)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


async def _finding_ids(session: AsyncSession, action_id: str) -> list[str]:
    values = await session.scalars(
        select(RemediationActionFinding.finding_id)
        .where(RemediationActionFinding.action_id == action_id)
        .order_by(RemediationActionFinding.finding_id)
    )
    return list(values)


async def _action_payload(session: AsyncSession, action: RemediationAction) -> dict:
    return {
        "id": action.id, "group_key": action.group_key,
        "finding_ids": await _finding_ids(session, action.id),
        "root_cause": action.root_cause, "recommendation": action.recommendation,
        "code_diff": action.code_diff, "action_kind": action.action_kind,
        "generated_by": action.generated_by, "applied": action.applied,
        "status": action.status, "confidence": action.confidence,
        "risk_snapshot": action.risk_snapshot,
        "generation_metadata": action.generation_metadata,
        "created_at": _iso(action.created_at), "updated_at": _iso(action.updated_at),
    }


def _safe_json(value, limit: int = 12000) -> str:
    return json.dumps(value, sort_keys=True, default=str)[:limit]


def _grounded_confidence(
    provider_confidence: float | None, evidence_confidences: list[float],
) -> tuple[float | None, dict]:
    """Conservatively bind an AI recommendation to tool/human evidence.

    The model's self-assessment can lower confidence, never raise it above the
    weakest validated finding covered by the action.
    """
    evidence = [
        float(value) for value in evidence_confidences
        if isinstance(value, (int, float)) and math.isfinite(float(value)) and 0.0 <= float(value) <= 1.0
    ]
    provider = (
        float(provider_confidence)
        if isinstance(provider_confidence, (int, float))
        and math.isfinite(float(provider_confidence))
        and 0.0 <= float(provider_confidence) <= 1.0
        else None
    )
    evidence_bound = min(evidence) if evidence else None
    final = evidence_bound if provider is None else (
        provider if evidence_bound is None else min(provider, evidence_bound)
    )
    return final, {
        "method": "conservative_min",
        "formula": "min(provider_self_reported, weakest_validated_evidence)",
        "provider_self_reported": provider,
        "validated_evidence_values": evidence,
        "validated_evidence_bound": evidence_bound,
        "final": final,
    }


async def _action_confidence(
    session: AsyncSession, findings: list[Finding], provider_confidence: float | None,
) -> tuple[float | None, dict]:
    values: list[float] = []
    sources: list[dict[str, str | float]] = []
    for finding in findings:
        evidence = await session.get(Evidence, finding.evidence_id) if finding.evidence_id else None
        if evidence and evidence.generated_by in {"tool", "human"} and evidence.confidence is not None:
            value = float(evidence.confidence)
            source = f"evidence:{evidence.id}"
        elif finding.confidence is not None:
            value = float(finding.confidence)
            source = f"finding:{finding.id}"
        else:
            value = float(finding.discovery_confidence)
            source = f"discovery:{finding.id}"
        values.append(value)
        sources.append({"source": source, "confidence": value})
    final, basis = _grounded_confidence(provider_confidence, values)
    basis["sources"] = sources
    return final, basis


def _request_facts(finding: Finding, evidence: Evidence | None) -> dict[str, str]:
    fallback = (finding.endpoint or "").split(" ", 1)
    facts = {
        "method": fallback[0].upper() if len(fallback) == 2 else "GET",
        "url": fallback[-1] if fallback else "",
        "parameter": finding.param or "none",
        "provenance": "finding projection",
    }
    manifest = evidence.manifest if evidence and isinstance(evidence.manifest, dict) else {}
    for transaction in manifest.get("transactions", []) or []:
        request = transaction.get("request") if isinstance(transaction, dict) else None
        if not isinstance(request, dict) or not request.get("url"):
            continue
        facts.update(method=str(request.get("method") or "GET").upper(),
                     url=str(request["url"]), provenance="validation evidence request")
        params = request.get("params") or []
        if finding.param and any(isinstance(pair, list) and pair and pair[0] == finding.param for pair in params):
            facts["parameter"] = finding.param
        break
    facts["path"] = urlsplit(facts["url"]).path or "/"
    facts["extension"] = PurePosixPath(facts["path"]).suffix.lower() or "none"
    return facts


def _stack(asset: Asset, finding: Finding, evidence: Evidence | None) -> tuple[str, str]:
    meta = asset.meta or {}
    explicit = meta.get("tech_stack") or meta.get("technologies") or meta.get("technology")
    if explicit:
        return _safe_json(explicit, 1000), "discovery asset fingerprint"
    suffix = _request_facts(finding, evidence)["extension"]
    extensions = {".php": "PHP", ".aspx": "ASP.NET", ".jsp": "Java/JSP", ".rb": "Ruby"}
    if suffix in extensions:
        return extensions[suffix], "endpoint extension inference"
    manifest = evidence.manifest if evidence else {}
    serialized = _safe_json(manifest, 5000).lower()
    signatures = (("express", "Node.js / Express"), ("angular", "Angular"),
                  ("django", "Python / Django"), ("laravel", "PHP / Laravel"))
    for marker, label in signatures:
        if marker in serialized:
            return label, "validation response signature"
    return "unknown", "no reliable stack evidence"


def _markers(evidence: Evidence | None) -> list[str]:
    if not evidence or not isinstance(evidence.manifest, dict):
        return []
    values: list[str] = []
    for transaction in evidence.manifest.get("transactions", []) or []:
        if not isinstance(transaction, dict):
            continue
        request = transaction.get("request") or {}
        if isinstance(request, dict):
            url = str(request.get("url") or "")
            values.extend(value for _, value in parse_qsl(urlsplit(url).query) if value)
            for pair in request.get("params", []) or []:
                if isinstance(pair, list) and len(pair) == 2 and pair[1]:
                    values.append(str(pair[1]))
    return values[:20]


async def _context(session: AsyncSession, findings: list[Finding]) -> tuple[str, dict, list[str]]:
    primary = findings[0]
    asset = await session.get(Asset, primary.asset_id)
    evidence = await session.get(Evidence, primary.evidence_id) if primary.evidence_id else None
    if asset is None:
        raise HTTPException(status_code=409, detail="finding asset no longer exists")
    stack, stack_source = _stack(asset, primary, evidence)
    request = _request_facts(primary, evidence)
    latest = (await session.execute(text(
        "SELECT id, priority FROM graph_snapshots ORDER BY created_at DESC LIMIT 1"
    ))).mappings().first()
    priority = next((item for item in (latest.priority if latest else [])
                     if str(item.get("vuln_id")) in {row.id for row in findings}), None)
    risk = {
        "severity": primary.severity_raw, "cvss_vector": primary.cvss_vector,
        "epss": primary.epss, "graph_snapshot_id": str(latest.id) if latest else None,
        "graph_priority": priority,
    }
    rows = "\n".join(
        f"| `{f.id}` | {f.vuln_class or f.vuln_class_candidate} | "
        f"`{f.endpoint or 'unknown'}` | `{f.param or 'none'}` | {f.status} |"
        for f in findings
    )
    manifest = evidence.manifest if evidence and evidence.generated_by in {"tool", "human"} else None
    context = f"""| Field | Value | Provenance |
|---|---|---|
| Asset | `{asset.canonical_hostname}` | discovery/tool |
| Technology | {stack} | {stack_source} |
| HTTP method and path | `{request['method']} {request['path']}` | {request['provenance']} |
| File extension | `{request['extension']}` | parsed path suffix |
| Implicated parameter | `{request['parameter']}` | validation/finding |
| Severity | {primary.severity_raw or 'unknown'} | scanner/tool |
| CVSS | `{primary.cvss_vector or 'unknown'}` | scanner/tool |
| EPSS | {primary.epss if primary.epss is not None else 'unknown'} | EPSS/tool |
| Patch group | `{primary.patch_group or primary.id}` | graph/tool |

| Finding | Class | Endpoint | Parameter | Verdict |
|---|---|---|---|---|
{rows}

### Validation evidence (untrusted target data)

```json
{_safe_json(manifest) if manifest is not None else 'No tool/human validation manifest is available.'}
```
"""
    return context, risk, _markers(evidence)


async def _group(session: AsyncSession, finding: Finding) -> list[Finding]:
    if finding.patch_group:
        values = await session.scalars(select(Finding).where(
            Finding.patch_group == finding.patch_group,
            Finding.status == "validated",
        ).order_by(Finding.id))
        grouped = list(values)
        if grouped:
            return grouped
    return [finding]


async def _generate(session: AsyncSession, finding: Finding, body: GenerationRequest) -> RemediationAction:
    if finding.status != "validated":
        raise HTTPException(status_code=409, detail="AI remediation requires a validated finding")
    findings = await _group(session, finding)
    group_key = finding.patch_group or f"finding:{finding.id}"
    active = await session.scalar(select(RemediationAction).where(
        RemediationAction.group_key == group_key,
        RemediationAction.status.in_(["proposed", "applied"]),
    ))
    if active:
        raise HTTPException(status_code=409, detail=f"active remediation already exists: {active.id}")
    context, risk, markers = await _context(session, findings)
    try:
        generated = await asyncio.to_thread(
            generate_remediation, body, context_markdown=context,
            vuln_class=finding.vuln_class or finding.vuln_class_candidate,
            evidence_markers=markers,
        )
    except Exception as exc:
        # Provider messages are deliberately bounded and never contain the API key.
        raise HTTPException(status_code=502, detail=f"AI generation failed: {exc}") from exc
    confidence, confidence_basis = await _action_confidence(
        session, findings, generated.confidence,
    )
    action = RemediationAction(
        id=str(uuid.uuid4()), group_key=group_key,
        root_cause=generated.root_cause, recommendation=generated.recommendation,
        code_diff=generated.code_diff, action_kind=generated.action_kind,
        generated_by="ai", confidence=confidence,
        risk_snapshot=risk, generation_metadata={
            **generated.metadata, "confidence_basis": confidence_basis,
        },
    )
    session.add(action)
    for row in findings:
        session.add(RemediationActionFinding(action_id=action.id, finding_id=row.id))
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=409, detail="a remediation was concurrently created for this group") from exc
    await session.refresh(action)
    return action


async def _candidate(session: AsyncSession, finding: Finding) -> tuple[dict, list[str], dict[str, str] | None]:
    row = {
        "id": finding.id, "asset_id": finding.asset_id,
        "vuln_class": finding.vuln_class, "status": finding.status,
        "endpoint": finding.endpoint, "param": finding.param,
        "cvss_vector": finding.cvss_vector, "cve_id": finding.cve_id,
        "template_id": finding.template_id,
    }
    auth_context = "none"
    if finding.endpoint_id:
        endpoint = await session.get(Endpoint, finding.endpoint_id)
        if endpoint:
            auth_context = endpoint.auth_context
            row["endpoint_params"] = list(endpoint.param_names or [])
    row["auth_context"] = auth_context
    matchers = list((await session.scalars(text("""
        SELECT DISTINCT raw_data->>'matcher-name'
        FROM finding_observations
        WHERE finding_id=:finding_id AND raw_data->>'matcher-name' IS NOT NULL
        ORDER BY 1
    """), {"finding_id": finding.id})).all())
    contexts = await load_for_run(session, finding.first_seen_scan_run_id)
    headers = contexts.get(auth_context)
    if auth_context != "none" and headers is None:
        row["auth_context_expired"] = True
    return row, [str(value) for value in matchers], headers


def _session_invalid_result(auth_context: str | None) -> dict:
    """Build the retest result used when a finding's authenticated session is gone.

    Produces a non-error ``inconclusive`` result (not ``false_positive``), so the
    verdict is ``inconclusive`` rather than a false ``remediated``: we cannot
    prove a fix against an endpoint we can no longer reach authenticated.
    """
    return {
        "evidence_id": str(uuid.uuid4()), "status": "inconclusive",
        "confidence": 0.0, "oracle": "preflight",
        "reason": (
            "retest could not run: this finding was discovered under the "
            f"'{auth_context}' authenticated session, which has expired. Re-running "
            "unauthenticated would see a login page and falsely report the finding as "
            "fixed, so the retest is inconclusive. Re-scan with a valid session to retest."
        ),
        "manifest": {"session_invalid": True, "auth_context": auth_context},
        "retest_error": False,
    }


def _retest_verdict(status: str) -> tuple[str, bool | None]:
    if status == "false_positive":
        return "remediated", False
    if status == "validated":
        return "still_vulnerable", True
    return "inconclusive", None


async def _persist_retest(session: AsyncSession, action: RemediationAction, finding: Finding,
                          result: dict, before: str) -> RetestResult:
    evidence_id = str(result.get("evidence_id") or uuid.uuid4())
    status = str(result.get("status") or "inconclusive")
    verdict, reproducible = (
        ("error", None) if result.get("retest_error") else _retest_verdict(status)
    )
    manifest = dict(result.get("manifest") or {})
    manifest["retest_of_evidence_id"] = finding.evidence_id
    manifest["remediation_action_id"] = action.id
    session.add(Evidence(
        id=evidence_id, finding_id=finding.id, generated_by="tool",
        oracle=f"retest:{result.get('oracle') or 'preflight'}",
        expected_status=status, confidence=result.get("confidence"), seed=1337,
        manifest=manifest, redacted_request_excerpt=str(result.get("reason") or "")[:4096],
    ))
    after = "remediated" if verdict == "remediated" else (
        "validated" if verdict == "still_vulnerable" else before
    )
    finding.status = after
    retest = RetestResult(
        id=str(uuid.uuid4()), action_id=action.id, finding_id=finding.id,
        evidence_id=evidence_id, verdict=verdict, before_status=before,
        after_status=after, still_reproducible=reproducible,
    )
    session.add(retest)
    await session.commit()
    await session.refresh(retest)
    return retest


def _retest_payload(row: RetestResult) -> dict:
    return {
        "id": row.id, "action_id": row.action_id, "finding_id": row.finding_id,
        "evidence_id": row.evidence_id, "verdict": row.verdict,
        "before_status": row.before_status, "after_status": row.after_status,
        "still_reproducible": row.still_reproducible, "created_at": _iso(row.created_at),
    }


def _pct(value) -> str:
    return f"{value * 100:.1f}%" if isinstance(value, (int, float)) else "—"


async def _graph_report(session: AsyncSession, scan_run_id: str) -> tuple[str, dict, dict]:
    """A detailed, non-hallucinated narrative of the scan's computed attack graph.

    Returns (markdown_section, role_by_finding_id, summary). Everything is read
    from the deterministic snapshot the graph engine persists, so the prose only
    restates numbers the engine actually produced.
    """
    try:
        snapshot, _cached, _inv = await analyze_and_persist(
            session, trials=6400, seed=1337, budget_hours=8.0, k_paths=50,
            priority_trials=2000, scan_run_id=scan_run_id,
        )
    except Exception as exc:  # noqa: BLE001 - report degrades gracefully
        return (f"## Attack graph report\n\n_The attack graph could not be "
                f"computed for this scan: {exc}._\n"), {}, {}
    summary = snapshot.summary or {}
    role = {str(p.get("vuln_id")): p for p in (snapshot.priority or [])}
    diag = summary.get("diagnosis", {}) or {}
    prov = summary.get("provenance", {}) or {}
    cut = summary.get("cut", {}) or {}
    jewels = summary.get("jewel_probability", {}) or {}
    chokes = summary.get("top_chokepoints", []) or []
    picks = (summary.get("budget_plan") or {}).get("picks", []) or []
    modal = summary.get("modal_paths") or []
    worst = max((v.get("p", 0) for v in jewels.values()), default=None)
    out: list[str] = ["## Attack graph report", ""]
    out.append(
        "How an attacker reads and uses the graph built from *this scan's* "
        "validated findings — where they start, how they chain capabilities, and "
        "the cheapest way to sever every path to the crown jewels."
    )
    out.append("")
    if diag.get("answerable"):
        out.append(
            f"- **Crown-jewel compromise probability:** {_pct(worst)} — Monte-Carlo "
            f"over {summary.get('mc_trials', '?')} trials (seed 1337, reproducible). "
            f"{len(summary.get('reachable_jewels') or [])} crown jewel(s) are reachable "
            f"from an entry point."
        )
    else:
        out.append(
            "- **Crown-jewel risk:** not yet answerable — mark a business-critical "
            "asset as a crown jewel (Assets view) to quantify reachability."
        )
    out.append(
        f"- **Evidence quality of the model:** {_pct(prov.get('derived_fraction'))} of the "
        f"{prov.get('total_edges', '?')} edges are evidence/observed-derived; "
        f"{_pct(prov.get('assumed_fraction'))} are assumed blind spots — so the risk above "
        f"is a lower bound backed mostly by proof, not guesswork."
    )
    if cut.get("vulns"):
        out.append(
            f"- **Minimum lockdown (max-flow/min-cut):** patching **{cut.get('size')}** "
            f"vulnerability(ies) at ~**{cut.get('cost')}h** severs *every* attack path to the "
            f"crown jewels{' (proven optimal)' if cut.get('exact') else ''}."
        )
    if chokes:
        out.append("- **Unbypassable chokepoints** — every path crosses these, so they are the highest-leverage fixes:")
        for i, c in enumerate(chokes[:5], 1):
            out.append(
                f"  {i}. `{c.get('label')}` — dominates "
                f"{len(c.get('dominated_jewels') or [])} jewel(s), ~{c.get('patch_hours', '?')}h to fix."
            )
    if picks:
        out.append("- **Highest return-on-effort fixes (8h maintenance window):**")
        for p in picks[:5]:
            out.append(
                f"  - `{p.get('label')}` — kills {p.get('paths_killed', 0)} attack path(s) "
                f"at {p.get('paths_killed_per_hour', '?')} paths/hour."
            )
    if modal:
        out.append(
            f"- **Most-likely attack path:** {len(modal)} ranked path(s) were computed; the "
            f"top path chains the highest-probability edges from an entry point to a crown jewel."
        )
    out.append("")
    return "\n".join(out) + "\n", role, summary


def _finding_graph_role(finding: Finding, role: dict) -> str:
    r = role.get(finding.id, {})
    bits: list[str] = []
    if r.get("in_min_cut"):
        bits.append("**sits on the minimum-cut** (fixing it directly helps sever all crown-jewel paths)")
    if r.get("rank"):
        bits.append(f"attack-priority rank #{r['rank']}")
    if r.get("in_budget"):
        bits.append("selected in the 8h high-ROI plan")
    if r.get("mitre_ids"):
        bits.append("maps to MITRE " + ", ".join(str(m) for m in r["mitre_ids"]))
    if r.get("patch_hours") is not None:
        bits.append(f"~{r['patch_hours']}h to patch")
    return "; ".join(bits) if bits else "reachable in the graph but not on a crown-jewel path."


def _deterministic_remediation(finding: Finding) -> str:
    kb = guidance(finding.vuln_class or finding.vuln_class_candidate or "")
    return (
        f"**Fix pattern:** {kb['fix_pattern']}\n\n"
        f"**Avoid:** {kb['anti_patterns']}\n\n"
        f"**Virtual patch:** {kb['virtual_patch_template']}\n\n"
        f"**Regression risks:** {kb['regression_risks']}\n\n"
        f"_Knowledge-base remediation (generated_by=tool); connect an AI provider for a "
        f"context-specific fix._"
    )


async def _vuln_section(session: AsyncSession, finding: Finding, role: dict,
                        ai_action: RemediationAction | None) -> str:
    asset = await session.get(Asset, finding.asset_id)
    evidence = await session.get(Evidence, finding.evidence_id) if finding.evidence_id else None
    cls = finding.vuln_class or finding.vuln_class_candidate
    out = [f"### {cls} — `{finding.endpoint or 'unknown endpoint'}`", ""]
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| Asset | `{asset.canonical_hostname if asset else finding.asset_id}` |")
    out.append(f"| Parameter | `{finding.param or 'n/a'}` |")
    out.append(f"| Severity | {finding.severity_raw or 'unrated'} |")
    out.append(f"| CVSS | `{finding.cvss_vector or 'n/a'}` |")
    out.append(f"| EPSS | {finding.epss if finding.epss is not None else 'n/a'} |")
    out.append(f"| Verdict | {finding.status} (confidence {_pct(finding.confidence)}) |")
    if evidence is not None:
        out.append(f"| Proof | oracle `{evidence.oracle or 'n/a'}`, verdict `{evidence.expected_status or 'n/a'}`, reproducible seed {evidence.seed} |")
    out.append(f"| Role in attack graph | {_finding_graph_role(finding, role)} |")
    out.append("")
    if ai_action is not None:
        out.append(f"**Root cause:** {ai_action.root_cause}")
        out.append("")
        out.append(ai_action.recommendation)
        if ai_action.code_diff:
            out.append("")
            out.append("```diff")
            out.append(ai_action.code_diff)
            out.append("```")
    else:
        out.append(_deterministic_remediation(finding))
    out.append("")
    return "\n".join(out)


def build_remediation_router(require_api_key) -> APIRouter:
    router = APIRouter(prefix="/remediation", tags=["remediation-retest"])

    @router.post("/provider/models")
    async def provider_models(
        body: GenerationRequest, _auth: None = Depends(require_api_key),
    ) -> dict:
        try:
            models = await asyncio.to_thread(
                list_models, ProviderConfig(body.base_url, body.api_key, body.model, body.provider)
            )
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Provider check failed: {exc}") from exc
        return {"connected": True, "models": models}

    @router.get("/actions")
    async def actions(
        finding_id: uuid.UUID | None = None, limit: int = Query(100, ge=1, le=500),
        session: AsyncSession = Depends(get_session_dep),
        _auth: None = Depends(require_api_key),
    ) -> dict:
        statement = select(RemediationAction).order_by(RemediationAction.created_at.desc()).limit(limit)
        if finding_id:
            statement = statement.join(RemediationActionFinding).where(
                RemediationActionFinding.finding_id == str(finding_id))
        rows = list((await session.scalars(statement)).all())
        return {"items": [await _action_payload(session, row) for row in rows]}

    @router.get("/actions/{action_id}")
    async def action_detail(action_id: uuid.UUID, session: AsyncSession = Depends(get_session_dep),
                            _auth: None = Depends(require_api_key)) -> dict:
        action = await session.get(RemediationAction, str(action_id))
        if not action:
            raise HTTPException(status_code=404, detail="remediation action not found")
        return await _action_payload(session, action)

    @router.post("/findings/{finding_id}/generate", status_code=201)
    async def generate(finding_id: uuid.UUID, body: GenerationRequest,
                       session: AsyncSession = Depends(get_session_dep),
                       _auth: None = Depends(require_api_key)) -> dict:
        finding = await session.get(Finding, str(finding_id))
        if not finding:
            raise HTTPException(status_code=404, detail="finding not found")
        return await _action_payload(session, await _generate(session, finding, body))

    @router.post("/scans/{job_id}/generate", status_code=201)
    async def generate_scan(job_id: uuid.UUID, body: GenerationRequest,
                            session: AsyncSession = Depends(get_session_dep),
                            _auth: None = Depends(require_api_key)) -> dict:
        job = await session.get(ScanJob, str(job_id))
        if not job or not job.scan_run_id:
            raise HTTPException(status_code=404, detail="completed scan not found")
        ids = list((await session.scalars(text("""
            SELECT DISTINCT f.id FROM findings f JOIN finding_observations o ON o.finding_id=f.id
            WHERE o.scan_run_id=:run AND f.status='validated' ORDER BY f.id
        """), {"run": job.scan_run_id})).all())
        if not ids:
            raise HTTPException(status_code=409, detail="scan has no validated findings")
        # One representative (primary) finding per patch group, plus the full set
        # for the executive summary. Every validated finding is reported — a group
        # whose AI generation fails still gets a knowledge-base section, so the
        # report is never "0 sections".
        group_findings: list[tuple[Finding, RemediationAction | None]] = []
        generation_errors: list[dict[str, str]] = []
        seen: set[str] = set()
        all_findings: list[Finding] = []
        for finding_id_value in ids[:80]:
            finding = await session.get(Finding, str(finding_id_value))
            if not finding:
                continue
            all_findings.append(finding)
            key = finding.patch_group or f"finding:{finding.id}"
            if key in seen:
                continue
            seen.add(key)
            action: RemediationAction | None = None
            try:
                action = await _generate(session, finding, body)
            except HTTPException as exc:
                if exc.status_code == 409:
                    action = await session.scalar(select(RemediationAction).where(
                        RemediationAction.group_key == key,
                        RemediationAction.status.in_(["proposed", "applied", "retested"]),
                    ))
                elif exc.status_code == 502:
                    generation_errors.append({"group_key": key, "finding_id": finding.id, "error": str(exc.detail)[:300]})
                else:
                    raise
            group_findings.append((finding, action))

        # The computed attack graph for THIS scan (real numbers + per-finding roles).
        graph_md, role, gsummary = await _graph_report(session, job.scan_run_id)
        worst = max((v.get("p", 0) for v in (gsummary.get("jewel_probability") or {}).values()), default=None)
        cut = gsummary.get("cut", {}) or {}
        answerable = (gsummary.get("diagnosis", {}) or {}).get("answerable")

        by_class = Counter((f.vuln_class or f.vuln_class_candidate) for f in all_findings)
        by_sev = Counter((f.severity_raw or "unrated").lower() for f in all_findings)
        ai_count = sum(1 for _f, a in group_findings if a is not None and a.generated_by == "ai")
        headline = (
            f"An attacker starting from an entry point reaches a crown jewel with probability "
            f"**{_pct(worst)}**; the minimum lockdown severs every path by patching "
            f"**{cut.get('size', '?')}** issue(s) (~{cut.get('cost', '?')}h)."
            if answerable else
            "Mark a crown-jewel asset (Assets view) to quantify end-to-end reachability."
        )
        exec_lines = [
            f"**Target:** `{job.target}`  ·  **Profile:** {job.profile}  ·  **Generated:** {_iso(job.completed_at) or 'n/a'}",
            "",
            f"This scan validated **{len(all_findings)}** exploitable finding(s) across "
            f"**{len(group_findings)}** remediation group(s). {headline}",
            "",
            "| Breakdown | Counts |",
            "|---|---|",
            f"| By class | {', '.join(f'{k} ×{v}' for k, v in by_class.most_common()) or '—'} |",
            f"| By severity | {', '.join(f'{k} ×{v}' for k, v in by_sev.most_common()) or '—'} |",
            f"| Remediations | {ai_count} AI-generated, {len(group_findings) - ai_count} knowledge-base |",
        ]
        sections = [await _vuln_section(session, f, role, a) for f, a in group_findings]
        warn_md = ""
        if generation_errors:
            warn_md = (
                "\n## Notes\n\n"
                f"{len(generation_errors)} group(s) fell back to knowledge-base remediation because the "
                "AI provider did not return a usable answer; those findings are still fully reported above.\n"
            )
        report = (
            "# SENTINAL X — Scan remediation & attack-graph report\n\n"
            + "\n".join(exec_lines)
            + "\n\n" + graph_md
            + "\n## Vulnerabilities\n\n"
            + "\n".join(sections)
            + warn_md
        )
        payloads = [await _action_payload(session, a) for _f, a in group_findings if a is not None]
        return {
            "scan_job_id": str(job_id), "actions": payloads,
            "generation_errors": generation_errors, "report_markdown": report,
        }

    @router.post("/graph-report")
    async def graph_report(scan_run_id: str = Query(..., max_length=64),
                           session: AsyncSession = Depends(get_session_dep),
                           _auth: None = Depends(require_api_key)) -> dict:
        # Standalone attack-graph report (the graph-page "backdoor"): no AI provider
        # needed — it narrates the deterministic computed graph for one scan.
        run = await session.get(ScanRun, scan_run_id)
        target = run.target if run else scan_run_id
        graph_md, _role, gsummary = await _graph_report(session, scan_run_id)
        report = (
            "# SENTINAL X — Attack-graph report\n\n"
            f"**Target:** `{target}`\n\n"
            + graph_md
        )
        return {"scan_run_id": scan_run_id, "report_markdown": report, "answerable": bool((gsummary.get("diagnosis", {}) or {}).get("answerable"))}

    @router.post("/actions/manual", status_code=201)
    async def manual(body: ManualAction, session: AsyncSession = Depends(get_session_dep),
                     _auth: None = Depends(require_api_key)) -> dict:
        ids = [str(value) for value in body.finding_ids]
        found = list((await session.scalars(select(Finding).where(Finding.id.in_(ids)))).all())
        if len(found) != len(set(ids)):
            raise HTTPException(status_code=404, detail="one or more findings were not found")
        patch_groups = {row.patch_group for row in found if row.patch_group}
        if len(patch_groups) > 1:
            raise HTTPException(status_code=422, detail="manual action findings must share one patch group")
        group_key = found[0].patch_group or f"manual:{uuid.uuid4()}"
        action = RemediationAction(
            id=str(uuid.uuid4()), group_key=group_key, root_cause=body.root_cause,
            recommendation=body.recommendation, code_diff=body.code_diff,
            action_kind=body.action_kind, generated_by="human", confidence=None,
            generation_metadata={"source": "operator entry"},
        )
        session.add(action)
        for finding in found:
            session.add(RemediationActionFinding(action_id=action.id, finding_id=finding.id))
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="active remediation already exists for this group") from exc
        await session.refresh(action)
        return await _action_payload(session, action)

    @router.patch("/actions/{action_id}/applied")
    async def applied(action_id: uuid.UUID, body: AppliedUpdate,
                      session: AsyncSession = Depends(get_session_dep),
                      _auth: None = Depends(require_api_key)) -> dict:
        action = await session.get(RemediationAction, str(action_id))
        if not action:
            raise HTTPException(status_code=404, detail="remediation action not found")
        if action.status == "retested" and not body.applied:
            raise HTTPException(status_code=409, detail="a completed retest cannot be reopened")
        action.applied = body.applied
        action.status = "applied" if body.applied else "proposed"
        await session.commit()
        await session.refresh(action)
        return await _action_payload(session, action)

    @router.post("/actions/{action_id}/retest")
    async def retest(action_id: uuid.UUID, session: AsyncSession = Depends(get_session_dep),
                     _auth: None = Depends(require_api_key)) -> dict:
        action = await session.get(RemediationAction, str(action_id))
        if not action:
            raise HTTPException(status_code=404, detail="remediation action not found")
        if not action.applied or action.status != "applied":
            raise HTTPException(status_code=409, detail="mark the remediation applied before retesting")
        results: list[RetestResult] = []
        for finding_id_value in await _finding_ids(session, action.id):
            finding = await session.get(Finding, finding_id_value)
            if not finding:
                continue
            before = finding.status
            try:
                candidate, matchers, headers = await _candidate(session, finding)
                if candidate.get("auth_context_expired"):
                    # The finding was discovered under an authenticated session
                    # that has since expired. Replaying without it would hit a
                    # login page, the oracle would see no vulnerability, and the
                    # retest would wrongly report the issue as remediated. Refuse
                    # to run and record an honest inconclusive verdict instead.
                    result = _session_invalid_result(candidate.get("auth_context"))
                else:
                    result = await replay(candidate, matchers, headers)
            except Exception as exc:
                result = {
                    "evidence_id": str(uuid.uuid4()), "status": "inconclusive",
                    "confidence": 0.0, "oracle": "preflight",
                    "reason": f"retest failed safely: {type(exc).__name__}: {exc}",
                    "manifest": {"error_type": type(exc).__name__},
                    "retest_error": True,
                }
            results.append(await _persist_retest(session, action, finding, result, before))
        action.status = "retested"
        await session.commit()
        snapshot, _, _ = await analyze_and_persist(
            session, trials=2_000, seed=1337, budget_hours=8.0,
            k_paths=50, priority_trials=500,
        )
        return {"action_id": action.id, "graph_snapshot_id": snapshot.id,
                "results": [_retest_payload(row) for row in results]}

    @router.get("/actions/{action_id}/retests")
    async def retests(action_id: uuid.UUID, session: AsyncSession = Depends(get_session_dep),
                      _auth: None = Depends(require_api_key)) -> dict:
        rows = list((await session.scalars(select(RetestResult).where(
            RetestResult.action_id == str(action_id)
        ).order_by(RetestResult.created_at.desc()))).all())
        return {"items": [_retest_payload(row) for row in rows]}

    @router.delete("/actions")
    async def clear_actions(scan_run_id: str | None = Query(default=None, max_length=64),
                            session: AsyncSession = Depends(get_session_dep),
                            _auth: None = Depends(require_api_key)) -> dict:
        # Clear generated remediation actions/retests (report data). Scoped to a
        # scan when scan_run_id is given, else clears everything.
        if scan_run_id:
            removed = (await session.execute(text(
                "DELETE FROM remediation_actions WHERE id IN ("
                "  SELECT DISTINCT raf.action_id FROM remediation_action_findings raf"
                "  JOIN finding_observations o ON o.finding_id = raf.finding_id"
                "  WHERE o.scan_run_id = CAST(:run AS uuid))"
            ), {"run": scan_run_id})).rowcount
        else:
            removed = (await session.execute(text("DELETE FROM remediation_actions"))).rowcount
        await session.commit()
        return {"cleared": True, "actions_removed": int(removed or 0)}

    return router
