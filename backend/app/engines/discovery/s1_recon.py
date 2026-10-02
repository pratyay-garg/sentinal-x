"""
S1 — Passive recon. subfinder -> dnsx. Gated by OFFLINE_MODE (subfinder's
passive sources require network access).
"""
from __future__ import annotations

import json
import logging

from app.core.config import settings
from app.core.subprocess_utils import ToolNotFoundError, run_tool

logger = logging.getLogger(__name__)


async def run_s1_passive_recon(domain: str) -> list[str]:
    """Returns a list of resolved, live subdomains (dead/wildcard-noise
    entries already filtered out by dnsx). Empty list on any failure or under
    OFFLINE_MODE — S2 onward simply operates on the single pinned target in
    that case, which is a graceful degradation, not a hard failure.
    """
    if settings.offline_mode:
        logger.info("S1 skipped: OFFLINE_MODE is set")
        return []

    try:
        subfinder_result = await run_tool(
            [settings.subfinder_bin, "-d", domain, "-silent", "-json"],
            timeout=settings.subfinder_timeout_seconds,
        )
    except ToolNotFoundError:
        logger.error("subfinder binary missing — check the Docker image build")
        return []

    if subfinder_result.timed_out or subfinder_result.returncode != 0:
        logger.warning("S1 subfinder degraded: rc=%s", subfinder_result.returncode)
        return []

    subdomains: list[str] = []
    for line in subfinder_result.stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            subdomains.append(json.loads(line)["host"])
        except (json.JSONDecodeError, KeyError):
            continue

    if not subdomains:
        return []

    try:
        dnsx_result = await run_tool(
            [settings.dnsx_bin, "-silent", "-a", "-resp-only", "-json"],
            timeout=settings.dnsx_timeout_seconds,
            input_data="\n".join(subdomains).encode(),
        )
    except ToolNotFoundError:
        logger.error("dnsx binary missing — check the Docker image build")
        return subdomains  # degrade gracefully: return unresolved list rather than nothing

    live: list[str] = []
    for line in dnsx_result.stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            live.append(json.loads(line)["host"])
        except (json.JSONDecodeError, KeyError):
            continue

    return live or subdomains
