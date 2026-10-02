"""
S3 — Web probe, tech fingerprint, CPE resolution, soft-404 baseline, passive
WAF signal. IMPLEMENTATION_SPEC_v4.md §5/§10 risk #13: always pass
-tech-detect AND -cpe together — -cpe alone was a documented, real bug
(httpx#2476/#2509) that silently skipped detection entirely.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets

import httpx as pyhttpx  # Python HTTP client for the soft-404 probe; the
                          # `httpx` CLI binary below is invoked as a subprocess.

from app.core.config import settings
from app.core.subprocess_utils import ToolNotFoundError, run_tool

logger = logging.getLogger(__name__)


async def run_s3_fingerprint(live_hosts: list[str]) -> dict:
    """Returns {"probes": [...httpx JSON per host...], "soft_404": {host: signature|None}}."""
    if not live_hosts:
        return {"probes": [], "soft_404": {}, "diagnostics": {"status": "skipped"}}

    argv = [
        settings.httpx_bin,
        "-silent", "-status-code", "-title", "-tls-grab",
        "-tech-detect", "-cpe",   # ALWAYS together — see module docstring
        "-json",
    ]
    try:
        result = await run_tool(argv, timeout=settings.httpx_timeout_seconds, input_data="\n".join(live_hosts).encode())
    except ToolNotFoundError as exc:
        logger.error("httpx (CLI) binary missing — check the Docker image build")
        return {"probes": [], "soft_404": {}, "diagnostics": {
            "returncode": 127, "timed_out": False, "stderr": str(exc), "parsed_probes": 0,
        }}

    probes = []
    for line in result.stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            probes.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    soft_404 = {}
    for host in live_hosts:
        soft_404[host] = await establish_soft_404_signature(host)

    diagnostics = {
        "returncode": result.returncode, "timed_out": result.timed_out,
        "stderr": result.stderr.decode(errors="replace")[-2000:], "parsed_probes": len(probes),
    }
    if result.returncode != 0:
        logger.warning("S3 httpx exited %s: %s", result.returncode, diagnostics["stderr"])
    return {"probes": probes, "soft_404": soft_404, "diagnostics": diagnostics}


async def establish_soft_404_signature(base_url: str) -> dict | None:
    """IMPLEMENTATION_SPEC_v4.md §5 S3: "the single highest-impact omission
    any prior draft had." Probe 2-3 random nonexistent paths; if responses
    collapse to a near-identical signature, record it so S4 can filter mass
    false endpoints on any SPA or custom-404 app. Returns None if the target
    behaves like a normal 404-returning server (no filtering needed) or on
    any network failure (fail open on THIS check specifically — better to
    risk a few false endpoints than to accidentally suppress real ones
    because the baseline probe itself failed).
    """
    probe_paths = [f"/__discovery_soft404_probe_{secrets.token_hex(8)}" for _ in range(3)]
    signatures = []
    try:
        async with pyhttpx.AsyncClient(timeout=settings.soft404_timeout_seconds, verify=False, follow_redirects=False,
                                       trust_env=False) as client:
            for path in probe_paths:
                resp = await client.get(base_url.rstrip("/") + path)
                content_hash = hashlib.sha256(resp.content[:4096]).hexdigest()
                signatures.append((resp.status_code, len(resp.content), content_hash))
    except Exception:
        logger.info("soft-404 baseline probe failed for %s; proceeding without a filter", base_url)
        return None

    if len(set(signatures)) == 1:
        status, length, content_hash = signatures[0]
        return {"status_code": status, "content_length": length, "content_hash": content_hash}
    return None  # responses varied — this target returns real 404s, no filter needed


def matches_soft_404(signature: dict | None, status_code: int, content_length: int, content_hash: str) -> bool:
    """Used by S4 to filter crawl results. `signature` is whatever
    establish_soft_404_signature() returned for this host (may be None)."""
    if signature is None:
        return False
    return (
        signature["status_code"] == status_code
        and signature["content_length"] == content_length
        and signature["content_hash"] == content_hash
    )
