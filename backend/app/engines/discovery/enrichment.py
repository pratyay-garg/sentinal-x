"""
S6 — Enrichment. IMPLEMENTATION_SPEC_v4.md §5/§7: check Nuclei's own
classification.cpe/classification.epss-score FIRST (per finding — there is no
clean date rule governing corpus coverage, never assume it's universal); only
call out to EPSS/NVD for gaps or freshness. Every external call here is
best-effort, non-blocking, and skipped entirely under OFFLINE_MODE.
"""
from __future__ import annotations

import logging
from datetime import date

import httpx as pyhttpx  # Python HTTP client library — see requirements.txt note.
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_CPE_MATCH_URL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8), reraise=False)
async def fetch_epss_batch(cve_ids: list[str]) -> dict[str, tuple[float, date]]:
    """Returns {cve_id: (epss_score, snapshot_date)}. Best-effort: any
    failure returns an empty dict rather than raising, so a flaky/unreachable
    EPSS API never fails the whole pipeline (IMPLEMENTATION_SPEC_v4.md §9).
    """
    if settings.offline_mode or not cve_ids:
        return {}

    try:
        async with pyhttpx.AsyncClient(timeout=10) as client:
            resp = await client.get(EPSS_API_URL, params={"cve": ",".join(cve_ids)})
            resp.raise_for_status()
            payload = resp.json()
    except Exception:
        logger.warning("EPSS batch fetch failed; continuing without live scores", exc_info=True)
        return {}

    out: dict[str, tuple[float, date]] = {}
    for entry in payload.get("data", []):
        try:
            snapshot_raw = entry.get("date")
            if not snapshot_raw:
                continue  # never substitute the local clock for upstream provenance
            out[entry["cve"]] = (float(entry["epss"]), date.fromisoformat(snapshot_raw))
        except (KeyError, TypeError, ValueError):
            continue
    return out


async def fetch_nvd_cpe_match(product_keyword: str) -> str | None:
    """Only called for S2/S3-sourced (non-Nuclei) findings that have no CPE
    already. Uses the free NVD API key if configured (50 req/30s instead of
    5 req/30s — https://nvd.nist.gov/developers/request-an-api-key). Never
    blind-keyword-matches into a CVE lookup; this only resolves a CPE string,
    which is a materially safer operation than the false-positive-prone
    "guess a CVE from a product name" pattern documented in the spec.
    """
    if settings.offline_mode:
        return None

    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        async with pyhttpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                NVD_CPE_MATCH_URL,
                params={"keywordSearch": product_keyword, "resultsPerPage": 1},
                headers=headers,
            )
            resp.raise_for_status()
            payload = resp.json()
    except Exception:
        logger.warning("NVD CPE-match lookup failed; continuing without it", exc_info=True)
        return None

    matches = payload.get("matchStrings", [])
    if matches:
        return matches[0].get("matchString", {}).get("criteria")
    return None


def epss_from_nuclei_classification(classification: dict | None) -> tuple[float | None, date | None]:
    """Extract Nuclei's own template-embedded epss-score/cpe, if present.
    This is a STATIC value baked in whenever the template was last updated —
    treat as a reasonable starting point, not a live score. Refresh via
    fetch_epss_batch() for anything demo-critical.
    """
    if not classification:
        return None, None
    score = classification.get("epss-score")
    if score is None:
        return None, None
    try:
        # Nuclei does not attach the EPSS source snapshot date. Preserve the
        # score but leave provenance date unknown instead of mislabelling the
        # local observation date as an upstream snapshot.
        return float(score), None
    except (TypeError, ValueError):
        return None, None
