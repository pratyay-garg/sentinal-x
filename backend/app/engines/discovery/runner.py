"""Restartable S0-S7 orchestration for one durably claimed scan job."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

from app.core.config import settings
from app.core.credentials import load_for_job
from app.core.db import get_session
from .enrichment import epss_from_nuclei_classification, fetch_epss_batch
from app.core.killswitch import is_job_cancelled, is_killswitch_engaged
from app.models import Asset, Endpoint, ScanRun, Service
from app.tasks.queue import HeartbeatLoop, emit_event
from app.core.scope import canonical_root_hostname, is_in_scope, parse_allowlist, parse_target
from . import s1_recon, s2_ports, s3_fingerprint, s4_crawl, s5_vuln_scan
from .s5_vuln_scan import build_tag_allowlist
from .parameter_candidates import candidates_for_endpoints, dast_seed_urls, signature_scan_targets
from .s7_persist import (
    persist_finding, persist_http_observations, upsert_asset, upsert_endpoint, upsert_service,
)
from app.tasks.validation_queue import enqueue_validation

logger = logging.getLogger(__name__)


class ScopeViolation(RuntimeError):
    pass


class KillswitchTripped(RuntimeError):
    pass


async def _gate(job_id: str, candidate: str) -> None:
    rules = parse_allowlist(settings.scope_allowlist)
    if not is_in_scope(rules, candidate):
        raise ScopeViolation(f"target '{candidate}' is not in the configured allowlist")
    async with get_session() as session:
        engaged, reason = await is_killswitch_engaged(session)
        if engaged:
            raise KillswitchTripped(reason or "killswitch engaged")
        if await is_job_cancelled(session, job_id):
            raise KillswitchTripped("job cancelled")


def web_url_for_service(host: str, service: dict) -> str | None:
    """Derive a web origin only from observed service protocol evidence."""
    app = str(service.get("application_protocol") or "").lower()
    tunnel = str(service.get("tunnel") or "").lower()
    if "http" not in app:
        return None
    scheme = "https" if tunnel == "ssl" or app in {"https", "ssl/http", "https-alt"} else "http"
    port = int(service["port"])
    display_host = f"[{host}]" if ":" in host else host
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{display_host}" if default else f"{scheme}://{display_host}:{port}"


def explicit_web_target(target: str) -> tuple[str, dict] | None:
    """Turn an authorized URL into one constrained seed service.

    An explicit URL authorizes that origin/path, not a broad top-ports scan of
    its host. Keeping it as the seed also makes an in-network target on a
    non-default port reachable without first rediscovering its declared port.
    """
    parsed = parse_target(target)
    if parsed.scheme is None or parsed.port is None:
        return None
    display_host = f"[{parsed.host}]" if ":" in parsed.host else parsed.host
    default_port = (
        (parsed.scheme == "http" and parsed.port == 80)
        or (parsed.scheme == "https" and parsed.port == 443)
    )
    netloc = display_host if default_port else f"{display_host}:{parsed.port}"
    origin = f"{parsed.scheme}://{netloc}{parsed.path}"
    return origin, {
        "port": parsed.port,
        "protocol": "tcp",
        "application_protocol": parsed.scheme,
        "tunnel": "ssl" if parsed.scheme == "https" else None,
        "banner": None,
        "product": None,
        "version": None,
        "confidence": 1.0,
        "authorized_origin": origin,
    }


def _list_value(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return sorted({str(v).strip() for v in value if str(v).strip()})
    if isinstance(value, str):
        return sorted({part.strip() for part in value.split(",") if part.strip()})
    return [str(value)]


def _classification(finding: dict) -> dict:
    info = finding.get("info")
    if not isinstance(info, dict):
        return {}
    classification = info.get("classification")
    return classification if isinstance(classification, dict) else {}


def _mapping_candidate(finding: dict) -> str:
    """Stable priority mapping; unknown templates remain explicit review items."""
    info = finding.get("info") or {}
    if not isinstance(info, dict):
        return f"nuclei:{finding.get('template-id') or 'unknown-template'}"
    template_id = str(finding.get("template-id") or "").lower()
    template_map = {
        "http-missing-security-headers": "security_misconfig_headers",
    }
    if template_id in template_map:
        return template_map[template_id]
    classification = _classification(finding)
    cwe_values = {x.upper() for x in _list_value(classification.get("cwe-id"))}
    cwe_map = {
        "CWE-89": "sqli", "CWE-79": "xss_reflected", "CWE-918": "ssrf",
        "CWE-22": "lfi", "CWE-611": "xxe", "CWE-94": "rce",
        "CWE-352": "csrf", "CWE-601": "open_redirect", "CWE-639": "idor",
    }
    for cwe in sorted(cwe_values):
        if cwe in cwe_map:
            return cwe_map[cwe]
    tags = {x.lower() for x in _list_value(info.get("tags"))}
    ordered = (
        ("sqli", "sqli"), ("sql-injection", "sqli"), ("ssti", "ssti"),
        ("ssrf", "ssrf"), ("xxe", "xxe"), ("rce", "rce"), ("lfi", "lfi"),
        ("idor", "idor"), ("xss", "xss_reflected"), ("csrf", "csrf"),
        ("open-redirect", "open_redirect"), ("auth-bypass", "auth_bypass"),
        ("default-login", "cred_reuse"), ("file-upload", "file_upload_rce"),
        ("deserialization", "deserialization"),
    )
    for tag, mapped in ordered:
        if tag in tags:
            return mapped
    return f"nuclei:{finding.get('template-id') or 'unknown-template'}"


def _match_endpoint(matched_at: str, endpoints: list[Endpoint],
                    auth_context: str | None = None) -> Endpoint | None:
    split = urlsplit(matched_at or "")
    if not split.hostname:
        return None
    try:
        port = split.port or (443 if split.scheme == "https" else 80)
    except ValueError:
        return None
    path = split.path or "/"
    candidates = []
    for ep in endpoints:
        endpoint_url = urlsplit(ep.url)
        try:
            endpoint_port = endpoint_url.port or (443 if endpoint_url.scheme == "https" else 80)
        except ValueError:
            continue
        if endpoint_url.hostname == split.hostname and endpoint_port == port and ep.path == path:
            candidates.append(ep)
    if auth_context:
        exact = [ep for ep in candidates if ep.auth_context == auth_context]
        if exact:
            candidates = exact
    return sorted(candidates, key=lambda ep: (ep.auth_context != "none", ep.method, ep.id))[0] if candidates else None


def _extract_matched_param(finding: dict) -> str | None:
    metadata = finding.get("metadata") or {}
    explicit = (
        metadata.get("parameter") if isinstance(metadata, dict) else None
    ) or finding.get("matched-param")
    if explicit:
        return str(explicit)
    params = sorted(parse_qs(urlsplit(finding.get("matched-at", "") or "").query).keys())
    return params[0] if len(params) == 1 else None


def _origin_key(value: str) -> tuple[str, str, int] | None:
    split = urlsplit(value or "")
    if split.scheme not in {"http", "https"} or not split.hostname:
        return None
    try:
        port = split.port or (443 if split.scheme == "https" else 80)
    except ValueError:
        return None
    return split.scheme, split.hostname.lower(), port


async def run_pipeline(job: dict) -> None:
    job_id, target, scan_run_id = job["id"], job["target"], job["scan_run_id"]
    coverage: dict[str, Any] = {
        "authorized_roots": [target], "stages": {}, "unmapped_types": []
    }
    async with get_session() as session:
        authenticated_contexts = await load_for_job(session, job_id)
        await session.commit()
    request_contexts: dict[str, dict[str, str]] = {"none": {}, **authenticated_contexts}

    async with get_session() as session:
        await emit_event(session, job_id, "stage:start", {"stage": "S0"})
    await _gate(job_id, target)
    explicit_target = explicit_web_target(target)
    hostname = canonical_root_hostname(target)
    async with get_session() as session:
        await upsert_asset(session, hostname)
        await session.commit()
    coverage["stages"]["S0"] = {"status": "completed", "authorized_target": target}
    async with get_session() as session:
        await emit_event(session, job_id, "stage:done", {"stage": "S0", **coverage["stages"]["S0"]})

    async with get_session() as session:
        await emit_event(session, job_id, "stage:start", {"stage": "S1"})
    await _gate(job_id, target)
    if explicit_target is None:
        async with HeartbeatLoop(get_session, job_id):
            discovered = await s1_recon.run_s1_passive_recon(hostname)
    else:
        discovered = []
    rules = parse_allowlist(settings.scope_allowlist)
    accepted = sorted({h for h in discovered if is_in_scope(rules, h)})
    rejected = sorted(set(discovered) - set(accepted))
    hosts_to_scan = sorted({hostname, *accepted})
    coverage["stages"]["S1"] = {
        "status": "skipped" if settings.offline_mode or explicit_target else "completed",
        "accepted": len(accepted), "rejected": len(rejected),
        "reason": (
            "explicit_url_target" if explicit_target
            else "offline_mode" if settings.offline_mode else None
        ),
    }
    async with get_session() as session:
        await emit_event(session, job_id, "stage:done", {"stage": "S1", **coverage["stages"]["S1"]})

    async with get_session() as session:
        await emit_event(session, job_id, "stage:start", {"stage": "S2"})
    all_services: dict[str, list[dict]] = {}
    if explicit_target is not None:
        all_services[hostname] = [explicit_target[1]]
    else:
        async with HeartbeatLoop(get_session, job_id):
            for host in hosts_to_scan:
                await _gate(job_id, host)
                all_services[host] = (await s2_ports.run_s2_port_scan(host))["services"]
    coverage["stages"]["S2"] = {
        "status": "constrained" if explicit_target else "completed", "hosts": len(hosts_to_scan),
        "open_services": sum(map(len, all_services.values())),
        "reason": "explicit_url_target" if explicit_target else None,
    }

    service_rows: dict[tuple[str, int], Service] = {}
    web_targets: list[tuple[str, Service]] = []
    async with get_session() as session:
        for host in sorted(all_services):
            has_web_service = any(
                "http" in str(svc.get("application_protocol") or "").lower()
                for svc in all_services[host]
            )
            asset = await upsert_asset(
                session, host, asset_type="web_app" if has_web_service else "host"
            )
            for svc in sorted(all_services[host], key=lambda x: (x["port"], x["protocol"])):
                row = await upsert_service(
                    session, asset.id, svc["port"], svc["protocol"], svc.get("banner"),
                    application_protocol=svc.get("application_protocol"), product=svc.get("product"),
                    version=svc.get("version"), confidence=svc.get("confidence"),
                )
                service_rows[(host, svc["port"])] = row
                origin = svc.get("authorized_origin") or web_url_for_service(host, svc)
                if origin:
                    web_targets.append((origin, row))
        await session.commit()
    async with get_session() as session:
        await emit_event(session, job_id, "stage:done", {"stage": "S2", **coverage["stages"]["S2"]})

    async with get_session() as session:
        await emit_event(session, job_id, "stage:start", {"stage": "S3"})
    live_origins = [origin for origin, _ in sorted(web_targets, key=lambda x: x[0])]
    for origin in live_origins:
        await _gate(job_id, origin)
    async with HeartbeatLoop(get_session, job_id):
        s3_result = await s3_fingerprint.run_s3_fingerprint(live_origins)
    technologies: list[dict] = []
    for probe in s3_result["probes"]:
        for product in _list_value(probe.get("tech") or probe.get("technologies")):
            technologies.append({"product": product})
    waf_detected = any(p.get("waf") for p in s3_result["probes"])
    services_by_origin = {
        _origin_key(origin): service for origin, service in web_targets if _origin_key(origin)
    }
    async with get_session() as session:
        for probe in s3_result["probes"]:
            service = services_by_origin.get(_origin_key(
                str(probe.get("url") or probe.get("input") or "")
            ))
            if service is None:
                continue
            asset = await session.get(Asset, service.asset_id)
            if asset is not None:
                await persist_http_observations(
                    session, asset=asset, service=service, probe=probe,
                )
        await session.commit()
    s3_failed = s3_result.get("diagnostics", {}).get("returncode") not in {None, 0}
    coverage["stages"]["S3"] = {
        "status": "degraded" if live_origins and s3_failed else
                  "completed" if live_origins else "skipped",
        "origins": len(live_origins),
        "diagnostics": s3_result.get("diagnostics", {}),
        "reason": None if live_origins else "no_observed_http_services",
    }
    async with get_session() as session:
        await emit_event(session, job_id, "stage:done", {"stage": "S3", **coverage["stages"]["S3"]})

    async with get_session() as session:
        await emit_event(session, job_id, "stage:start", {"stage": "S4"})
    discovered_endpoints: list[tuple[dict, Service]] = []
    crawl_diagnostics: list[dict] = []
    async with HeartbeatLoop(get_session, job_id):
        for origin, service in sorted(web_targets, key=lambda x: x[0]):
            await _gate(job_id, origin)
            for context_name, context_headers in sorted(request_contexts.items()):
                result = await s4_crawl.run_s4_crawl(
                    origin, s3_result["soft_404"].get(origin), headers=context_headers,
                    auth_context=context_name, profile=job["profile"],
                )
                crawl_diagnostics.append({"origin": origin, "auth_context": context_name,
                                          **result["diagnostics"]})
                in_scope = [ep for ep in result["endpoints"] if is_in_scope(rules, ep["url"])]
                discovered_endpoints.extend((ep, service) for ep in in_scope)
                async with get_session() as session:
                    await emit_event(session, job_id, "stage:progress", {
                        "stage": "S4", "phase": "crawl:done", "origin": origin,
                        "auth_context": context_name, "endpoints": len(in_scope),
                    })
    crawl_degraded = any(item.get("returncode") not in {None, 0} for item in crawl_diagnostics)
    coverage["stages"]["S4"] = {
        "status": "degraded" if live_origins and crawl_degraded else
                  "completed" if live_origins else "skipped",
        "public_endpoints": sum(ep["auth_context"] == "none" for ep, _ in discovered_endpoints),
        "authenticated_endpoints": sum(ep["auth_context"] != "none" for ep, _ in discovered_endpoints),
        "diagnostics": crawl_diagnostics,
        "reason": None if live_origins else "no_observed_http_services",
    }
    async with get_session() as session:
        await emit_event(session, job_id, "stage:done", {"stage": "S4", **coverage["stages"]["S4"]})

    endpoint_objs: list[Endpoint] = []
    async with get_session() as session:
        for ep, service in sorted(discovered_endpoints, key=lambda x: (x[0]["url"], x[0]["method"])):
            obj = await upsert_endpoint(
                session, service.id, service.asset_id, url=ep["url"], path=ep["path"],
                method=ep["method"], param_names=ep.get("param_names", []),
                source=ep.get("source", "crawl"), auth_context=ep.get("auth_context", "none"),
                page_class=ep.get("page_class"), endpoint_class=ep.get("endpoint_class"),
                request_template=ep.get("request_template"),
            )
            endpoint_objs.append(obj)
        public_shapes = {
            (ep.service_id, ep.path, ep.method) for ep in endpoint_objs
            if ep.auth_context == "none"
        }
        for ep in endpoint_objs:
            ep.auth_required = (
                ep.auth_context != "none" and (ep.service_id, ep.path, ep.method) not in public_shapes
            )
        await session.commit()

    async with get_session() as session:
        await emit_event(session, job_id, "stage:start", {"stage": "S5"})
    raw_findings: list[dict] = []
    scan_diagnostics: list[dict] = []
    tag_allowlist = build_tag_allowlist(technologies)
    async with HeartbeatLoop(get_session, job_id):
        for context_name, context_headers in sorted(request_contexts.items()):
            context_endpoints = [ep for ep in endpoint_objs if ep.auth_context == context_name]
            signature_targets = signature_scan_targets(
                context_endpoints, settings.discovery_max_signature_targets
            )
            dast_seeds = dast_seed_urls(context_endpoints, settings.discovery_max_dast_seed_urls)
            # A silent multi-minute Nuclei stage reads as a hang; announce the
            # target counts before each context so operators see live progress.
            async with get_session() as session:
                await emit_event(session, job_id, "stage:progress", {
                    "stage": "S5", "phase": "scan:start", "auth_context": context_name,
                    "signature_targets": len(signature_targets), "dast_seeds": len(dast_seeds),
                })
            scan_result = await s5_vuln_scan.run_s5_vuln_scan(
                signature_targets, dast_seeds, tag_allowlist, waf_detected,
                profile=job["profile"], headers=context_headers,
            )
            for raw in scan_result["findings"]:
                raw["_sentinalx_auth_context"] = context_name
                raw_findings.append(raw)
            scan_diagnostics.extend({"auth_context": context_name, **item}
                                    for item in scan_result["diagnostics"])
            async with get_session() as session:
                await emit_event(session, job_id, "stage:progress", {
                    "stage": "S5", "phase": "scan:done", "auth_context": context_name,
                    "raw_findings": len(scan_result["findings"]),
                    "passes": scan_result["diagnostics"],
                })
    parameter_candidates = candidates_for_endpoints(
        endpoint_objs, settings.discovery_max_parameter_candidates
    )
    scan_degraded = any(item.get("returncode") not in {None, 0} for item in scan_diagnostics)
    coverage["stages"]["S5"] = {
        "status": "degraded" if endpoint_objs and scan_degraded else
                  "completed" if endpoint_objs else "skipped",
        "raw_findings": len(raw_findings),
        "parameter_candidates": len(parameter_candidates), "diagnostics": scan_diagnostics,
        "reason": None if endpoint_objs else "no_scoped_endpoints",
    }
    async with get_session() as session:
        await emit_event(session, job_id, "stage:done", {"stage": "S5", **coverage["stages"]["S5"]})

    cves = sorted({
        cve for finding in raw_findings
        for cve in _list_value(_classification(finding).get("cve-id"))
    })
    async with get_session() as session:
        await emit_event(session, job_id, "stage:start", {"stage": "S6"})
    live_epss = await fetch_epss_batch(cves)
    coverage["stages"]["S6"] = {
        "status": "skipped" if settings.offline_mode or not cves else "completed",
        "requested_cves": len(cves), "live_epss_scores": len(live_epss),
        "reason": (
            "offline_mode" if settings.offline_mode
            else "no_cves" if not cves else None
        ),
    }
    async with get_session() as session:
        await emit_event(session, job_id, "stage:done", {"stage": "S6", **coverage["stages"]["S6"]})

    async with get_session() as session:
        await emit_event(session, job_id, "stage:start", {"stage": "S7"})
    mapped_finding_ids: set[str] = set()
    unmapped_types: set[str] = set()
    async with get_session() as session:
        for candidate in parameter_candidates:
            candidate_endpoint = candidate.endpoint
            finding = await persist_finding(
                session, scan_run_id=scan_run_id, asset_id=candidate_endpoint.asset_id,
                endpoint=candidate_endpoint, service_id=candidate_endpoint.service_id,
                matched_param=candidate.param, vuln_class_candidate=candidate.vuln_class,
                source_tool="surface-analysis",
                template_id=f"parameter-candidate:v1:{candidate.vuln_class}",
                severity_raw=None, evidence_stub=candidate.reason,
                cve_id=None, cpe=None, epss_score=None, epss_snapshot_date=None,
                cvss_vector=None, confidence_basis="inferred_business_logic",
                raw_data={"reason": candidate.reason, "endpoint_source": candidate_endpoint.source,
                          "auth_context": candidate_endpoint.auth_context}, partial=False,
            )
            if finding.mapping_status == "mapped":
                mapped_finding_ids.add(str(finding.id))
        for raw in sorted(raw_findings, key=lambda f: (f.get("template-id", ""), f.get("matched-at", ""))):
            raw_info = raw.get("info")
            info = raw_info if isinstance(raw_info, dict) else {}
            classification = _classification(raw)
            cve_values = _list_value(classification.get("cve-id"))
            cpe_values = _list_value(classification.get("cpe"))
            cve_id = cve_values[0] if len(cve_values) == 1 else None
            cpe = cpe_values[0] if len(cpe_values) == 1 else None
            template_epss, template_snapshot = epss_from_nuclei_classification(classification)
            score_and_date = live_epss.get(cve_id) if cve_id else None
            epss_score, epss_snapshot = score_and_date or (template_epss, template_snapshot)
            matched_at = raw.get("matched-at") or raw.get("host") or ""
            endpoint = _match_endpoint(matched_at, endpoint_objs,
                                       raw.get("_sentinalx_auth_context"))
            finding_host = urlsplit(matched_at).hostname
            if not finding_host or not is_in_scope(rules, matched_at):
                coverage.setdefault("rejected_findings", 0)
                coverage["rejected_findings"] += 1
                continue
            asset = await upsert_asset(session, finding_host)
            mapping_candidate = _mapping_candidate(raw)
            finding = await persist_finding(
                session, scan_run_id=scan_run_id, asset_id=asset.id, endpoint=endpoint,
                service_id=endpoint.service_id if endpoint else None,
                matched_param=_extract_matched_param(raw), vuln_class_candidate=mapping_candidate,
                source_tool="nuclei", template_id=raw.get("template-id"),
                severity_raw=info.get("severity"), evidence_stub=str(matched_at)[:500],
                cve_id=cve_id, cpe=cpe, epss_score=epss_score,
                epss_snapshot_date=epss_snapshot, cvss_vector=classification.get("cvss-metrics"),
                confidence_basis="spec_backed" if cve_id else "traffic_observed",
                raw_data=raw, partial=False,
            )
            if finding.mapping_status == "mapped":
                mapped_finding_ids.add(str(finding.id))
            else:
                if finding.raw_finding_type:
                    unmapped_types.add(finding.raw_finding_type)

        coverage["unmapped_types"] = sorted(unmapped_types)
        coverage["stages"]["S7"] = {
            "status": "completed", "mapped": len(mapped_finding_ids),
            "unmapped": len(unmapped_types), "raw_tool_matches": len(raw_findings),
            "parameter_candidates": len(parameter_candidates),
        }
        run = await session.get(ScanRun, scan_run_id)
        if run:
            run.coverage = coverage
            run.stats = {
                "mapped_findings": len(mapped_finding_ids),
                "unmapped_findings": len(unmapped_types),
                "raw_tool_matches": len(raw_findings),
                "parameter_candidates": len(parameter_candidates),
            }
            run.status = "completed"
            run.completed_at = datetime.now(timezone.utc)
        await session.commit()
        await emit_event(session, job_id, "stage:done", {"stage": "S7", **coverage["stages"]["S7"]})
        validation_jobs = [
            await enqueue_validation(session, finding_id, scan_run_id)
            for finding_id in sorted(mapped_finding_ids)
        ]
        await session.commit()
        await emit_event(session, job_id, "validation:queued", {
            "jobs": validation_jobs, "count": len(validation_jobs),
        })
