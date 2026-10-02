"""
intelligence/reputation.py
---------------------------
SentinelX - URL reputation intelligence module (Area 6 support).

This is a STANDALONE module, independent of url_analyzer.py. It is NOT
wired into analyze_url()'s risk scoring yet - that integration is an
explicitly separate future step.

Purpose
-------
Look up a URL's existing reputation against a third-party threat-
intelligence provider (VirusTotal) and return a small, explainable,
JSON-serializable result: whether the provider flagged it malicious or
suspicious, a detection count out of the total engines that scanned it,
and a provider-specific reputation score when one is available.

Design choices worth knowing about
-----------------------------------
* READ-ONLY lookup only. This queries VirusTotal's *existing* analysis
  for a URL (GET .../urls/{id}). It deliberately does NOT submit the
  URL for a fresh scan (POST .../urls) - that would mean actively
  sending the URL to a third party and triggering new analysis, rather
  than simply reading back what is already known. That is out of scope
  for a reputation *lookup*.
* The API key is read from an environment variable
  (VIRUSTOTAL_API_KEY) and is never hardcoded. It is used only as the
  outgoing request's auth header value - it is never logged, printed,
  or included in any returned error message, raw_summary, or evidence
  entry.
* Every failure mode - a missing API key, a request timeout, a network
  failure, a malformed/non-JSON response, or an API error status - is
  caught and turned into a ReputationResult with `error` set. This
  module's public function never raises.
* Standard library only (urllib, json, base64) - no new third-party
  dependency, matching the rest of this dependency-light project.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Reference data / configuration
# ---------------------------------------------------------------------------

DISCLAIMER = (
    "This reputation result reflects third-party provider data at query "
    "time. It is not proof that a URL is malicious or safe, and should be "
    "combined with other evidence before acting on it."
)

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_PROVIDER_NAME = "VirusTotal"

# Name of the environment variable holding the API key. The key itself is
# never hardcoded anywhere in this file.
API_KEY_ENV_VAR = "VIRUSTOTAL_API_KEY"

_VT_URL_LOOKUP_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{url_id}"


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------

@dataclass
class ReputationResult:
    """
    Structured, JSON-serializable result of a URL reputation lookup.

    `available` is True only when a usable response was obtained from
    the provider - including a legitimate "this URL has no prior
    analysis" response, which is still useful information, just an
    empty verdict rather than an error.

    Every other field defaults to a safe "unknown" value, so a caller
    can always inspect this result directly without special-casing
    failure paths.
    """
    target: str
    provider: str = DEFAULT_PROVIDER_NAME
    available: bool = False
    malicious: bool = False
    suspicious: bool = False
    reputation_score: Optional[float] = None
    detection_count: Optional[int] = None
    total_engines: Optional[int] = None
    error: Optional[str] = None
    raw_summary: Optional[str] = None
    # Short, human-readable evidence lines suitable for later display
    # (e.g. in a report or UI) - deliberately plain strings, not a nested
    # structure, to keep this simple for a first version.
    evidence: List[str] = field(default_factory=list)
    disclaimer: str = DISCLAIMER


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_api_key() -> Optional[str]:
    """
    Read the API key from the environment on every call (never cached
    at import time, and never returned to a caller except as the value
    of an outgoing request header).
    """
    return os.environ.get(API_KEY_ENV_VAR)


def _url_to_vt_id(url: str) -> str:
    """
    VirusTotal v3 identifies a URL by the URL-safe base64 encoding of the
    URL string, with '=' padding stripped.
    """
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def check_url_reputation(
    url: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ReputationResult:
    """
    Look up `url`'s existing reputation on VirusTotal.

    Input:  a URL string, plus an optional timeout override (seconds).
    Output: a ReputationResult. Never raises - a missing API key, a
            request timeout, a network failure, a malformed response,
            or an API error status are all captured on the result's
            `error` field instead of being propagated.
    """
    result = ReputationResult(target=url, provider=DEFAULT_PROVIDER_NAME)

    if not url or not isinstance(url, str):
        result.error = "no URL provided"
        result.raw_summary = "Reputation check skipped: no URL provided."
        return result

    api_key = _get_api_key()
    if not api_key:
        result.error = f"{API_KEY_ENV_VAR} environment variable is not set."
        result.raw_summary = "Reputation check skipped: no API key configured."
        return result

    try:
        url_id = _url_to_vt_id(url)
        endpoint = _VT_URL_LOOKUP_ENDPOINT.format(url_id=url_id)
        request = urllib.request.Request(
            endpoint,
            method="GET",
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # A legitimate, successful response: VirusTotal simply has no
            # prior analysis for this URL. That is "available" data, just
            # an empty verdict - not an error.
            result.available = True
            result.raw_summary = "URL not found in VirusTotal's database (no prior analysis)."
            result.evidence.append("No prior VirusTotal analysis exists for this URL.")
            return result
        result.error = f"provider returned HTTP {exc.code}: {exc.reason}"
        result.raw_summary = f"Reputation check failed: HTTP {exc.code} from {DEFAULT_PROVIDER_NAME}."
        return result
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        text = str(reason)
        if isinstance(exc, TimeoutError) or "timed out" in text.lower() or "timeout" in text.lower():
            result.error = f"request to {DEFAULT_PROVIDER_NAME} timed out after {timeout}s"
        else:
            result.error = f"network error contacting {DEFAULT_PROVIDER_NAME}: {text}"
        result.raw_summary = "Reputation check failed: could not reach the provider."
        return result
    except Exception as exc:  # defensive: this function must never raise
        result.error = f"unexpected error contacting {DEFAULT_PROVIDER_NAME}: {exc}"
        result.raw_summary = "Reputation check failed unexpectedly."
        return result

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        result.error = f"invalid response from {DEFAULT_PROVIDER_NAME}: {exc}"
        result.raw_summary = "Reputation check failed: response was not valid JSON."
        return result

    try:
        attributes = payload["data"]["attributes"]
        stats = attributes.get("last_analysis_stats") or {}

        malicious_count = int(stats.get("malicious", 0) or 0)
        suspicious_count = int(stats.get("suspicious", 0) or 0)
        total_engines = sum(int(v or 0) for v in stats.values()) if stats else None

        result.available = True
        result.malicious = malicious_count > 0
        result.suspicious = suspicious_count > 0
        result.detection_count = malicious_count
        result.total_engines = total_engines
        result.reputation_score = attributes.get("reputation")

        if total_engines:
            result.raw_summary = (
                f"{malicious_count}/{total_engines} engines flagged this URL as malicious "
                f"({suspicious_count} additional flagged it suspicious)."
            )
        else:
            result.raw_summary = "VirusTotal returned analysis data with no engine statistics."

        for category, count in stats.items():
            if count:
                result.evidence.append(f"{category}: {count} engine(s)")

    except (KeyError, TypeError, ValueError) as exc:
        result.error = f"unexpected response shape from {DEFAULT_PROVIDER_NAME}: {exc}"
        result.raw_summary = "Reputation check failed: response did not match the expected format."
        result.available = False

    return result
