"""
exposure_analyzer.py
--------------------
SentinelX - Email Exposure Scanner (Area 7 support).

A small, dependency-free (standard-library-only) module that answers one
question about a single email address: has it appeared in known public data
breaches? It is the "Have I Been Pwned"-style lookup the problem statement asks
for, implemented on top of the free, open XposedOrNot API
(https://xposedornot.com) -- no API key required.

PRIVACY, BY DESIGN. The problem statement is explicit: "Preserve privacy and
avoid exposing passwords or unauthorized leaked data." This module honours that:

  * It NEVER returns leaked passwords, hashes, or any raw record content. The
    upstream API does not serve them either; it returns only breach *metadata*
    (which site, when, and the CATEGORIES of data exposed, e.g. "Passwords",
    "Email addresses"). We surface only those categories.
  * The email address is masked in the result object (``a***@example.com``) so a
    stored or logged result never carries the full identifier.
  * The lookup is a metadata query about the user's OWN address; it is not a
    scan of a third-party system, so it needs no scope allow-list entry.

Like the sibling analyzers, the output is a heuristic, explainable risk score
(0-100 with LOW/MEDIUM/HIGH/CRITICAL) built from named signals, so a human can
see exactly why the score is what it is.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

from .url_analyzer import HeuristicSignal, calculate_risk_score, classify_risk

# XposedOrNot: free HIBP-style breach intelligence, no key required.
_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"
_CHECK_URL = "https://api.xposedornot.com/v1/check-email/{email}"
_USER_AGENT = "SentinelX-ExposureScanner/1.0"

# RFC-5322 is huge; this deliberately conservative pattern is enough to reject
# obvious garbage before we make a network call.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Categories of exposed data that raise the stakes, and the label fragments that
# identify them in XposedOrNot's ``xposed_data`` field.
_PASSWORD_MARKERS = ("password",)
_FINANCIAL_MARKERS = ("financial", "credit card", "bank", "cvv", "payment")
_IDENTITY_MARKERS = ("social security", "passport", "government", "national id")

_DISCLAIMER = (
    "This exposure report is breach metadata only, sourced from the public "
    "XposedOrNot dataset. It lists which breaches an address appeared in and the "
    "categories of data involved -- never passwords or raw leaked records. "
    "Absence of results is not proof an address is safe."
)


@dataclass
class BreachRecord:
    name: str
    domain: Optional[str]
    year: Optional[str]
    exposed_data: List[str]           # categories only, never values
    records: Optional[int]
    password_risk: Optional[str]      # e.g. "plaintext" / "hashed" / "unknown"
    verified: bool


@dataclass
class ExposureResult:
    email: str                        # masked, e.g. "a***@example.com"
    found: bool
    breach_count: int
    paste_count: int
    breaches: List[BreachRecord]
    exposed_categories: List[str]
    risk_score: int
    risk_level: str
    signals: List[HeuristicSignal]
    source: str                       # "xposedornot" | "unavailable" | "invalid"
    disclaimer: str = _DISCLAIMER
    error: Optional[str] = None


def _mask_email(email: str) -> str:
    local, sep, domain = email.partition("@")
    if not sep:
        return "***"
    shown = local[0] if local else ""
    return f"{shown}***@{domain}"


def _http_get_json(url: str, timeout: float) -> tuple[Optional[dict], Optional[int], Optional[str]]:
    """Return (json, status, error). Network/parse failures are values, not raises."""
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(2_000_000)  # bounded read
            return json.loads(body.decode("utf-8", "replace")), response.status, None
    except urllib.error.HTTPError as exc:
        # 404 is XposedOrNot's "no breaches found" for an address; not an error.
        if exc.code == 404:
            return None, 404, None
        return None, exc.code, f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        return None, None, f"network unavailable: {type(exc).__name__}"
    except (json.JSONDecodeError, ValueError):
        return None, None, "unparseable response"


def _parse_breaches(analytics: dict) -> List[BreachRecord]:
    details = (((analytics.get("ExposedBreaches") or {}).get("breaches_details")) or [])
    records: List[BreachRecord] = []
    for entry in details if isinstance(details, list) else []:
        if not isinstance(entry, dict):
            continue
        raw_data = str(entry.get("xposed_data") or "")
        categories = [c.strip() for c in re.split(r"[;,]", raw_data) if c.strip()]
        records.append(BreachRecord(
            name=str(entry.get("breach") or "unknown"),
            domain=str(entry.get("domain")) if entry.get("domain") else None,
            year=str(entry.get("xposed_date")) if entry.get("xposed_date") else None,
            exposed_data=categories,
            records=int(entry["xposed_records"]) if str(entry.get("xposed_records") or "").isdigit() else None,
            password_risk=str(entry.get("password_risk")) if entry.get("password_risk") else None,
            verified=str(entry.get("verified") or "").lower() in {"yes", "true"},
        ))
    return records


def _build_signals(breaches: List[BreachRecord], paste_count: int) -> List[HeuristicSignal]:
    lowered = [cat.lower() for b in breaches for cat in b.exposed_data]
    has = lambda markers: any(any(m in cat for m in markers) for cat in lowered)
    plaintext = any((b.password_risk or "").lower() == "plaintext" for b in breaches)
    count = len(breaches)
    return [
        HeuristicSignal("appears_in_breach", f"Address appears in {count} known breach(es).", 30, count > 0),
        HeuristicSignal("passwords_exposed", "A breach exposed password data for this address.", 35, has(_PASSWORD_MARKERS)),
        HeuristicSignal("plaintext_passwords", "A breach stored passwords in plaintext or reversibly.", 15, plaintext),
        HeuristicSignal("financial_data_exposed", "A breach exposed financial/payment data.", 20, has(_FINANCIAL_MARKERS)),
        HeuristicSignal("identity_data_exposed", "A breach exposed government/identity data.", 20, has(_IDENTITY_MARKERS)),
        HeuristicSignal("many_breaches", "Address appears in five or more breaches.", 15, count >= 5),
        HeuristicSignal("appears_in_paste", f"Address appears in {paste_count} public paste(s).", 10, paste_count > 0),
    ]


def analyze_email_exposure(email: str, *, timeout: float = 8.0, offline: bool = False) -> ExposureResult:
    """Look up an email address's public breach exposure and score the risk."""
    email = (email or "").strip()
    masked = _mask_email(email)

    if not _EMAIL_RE.match(email) or len(email) > 254:
        return ExposureResult(masked, False, 0, 0, [], [], 0, classify_risk(0), [], "invalid",
                              error="not a valid email address")

    if offline:
        return ExposureResult(masked, False, 0, 0, [], [], 0, classify_risk(0), [], "unavailable",
                              error="offline mode: external breach lookup was skipped")

    quoted = urllib.parse.quote(email, safe="@.")
    analytics, status, error = _http_get_json(f"{_ANALYTICS_URL}?email={quoted}", timeout)

    # 404 (clean address) OR a transient failure that a lighter endpoint can still answer.
    if analytics is None and status != 404 and error:
        # Fall back to the simpler check-email endpoint before giving up.
        fallback, fb_status, fb_error = _http_get_json(_CHECK_URL.format(email=quoted), timeout)
        if fallback is None and fb_status == 404:
            analytics, status, error = None, 404, None
        elif fallback is None:
            return ExposureResult(masked, False, 0, 0, [], [], 0, classify_risk(0), [], "unavailable",
                                  error=error or fb_error)
        else:
            names = fallback.get("breaches") or []
            flat = names[0] if names and isinstance(names[0], list) else names
            breaches = [BreachRecord(str(n), None, None, [], None, None, False) for n in (flat or [])]
            signals = _build_signals(breaches, 0)
            score = calculate_risk_score(signals)
            cats = sorted({c for b in breaches for c in b.exposed_data})
            return ExposureResult(masked, bool(breaches), len(breaches), 0, breaches, cats,
                                  score, classify_risk(score), signals, "xposedornot")

    if status == 404 or analytics is None:
        signals = _build_signals([], 0)
        return ExposureResult(masked, False, 0, 0, [], [], calculate_risk_score(signals),
                              classify_risk(calculate_risk_score(signals)), signals, "xposedornot")

    breaches = _parse_breaches(analytics)
    pastes = analytics.get("ExposedPastes") or {}
    paste_count = 0
    if isinstance(pastes, dict):
        summary = pastes.get("pastes_details") or pastes.get("paste_details") or []
        paste_count = len(summary) if isinstance(summary, list) else 0
    signals = _build_signals(breaches, paste_count)
    score = calculate_risk_score(signals)
    categories = sorted({c for b in breaches for c in b.exposed_data})
    return ExposureResult(
        email=masked, found=bool(breaches), breach_count=len(breaches), paste_count=paste_count,
        breaches=breaches, exposed_categories=categories, risk_score=score,
        risk_level=classify_risk(score), signals=signals, source="xposedornot",
    )
