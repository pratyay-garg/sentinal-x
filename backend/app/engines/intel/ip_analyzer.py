"""
intelligence/ip_analyzer.py
SentinelX — IP Intelligence

Passive IP address analysis:
  - Validates and normalises the input with stdlib ipaddress.
  - Detects IPv4 vs IPv6 and classifies the address space
    (public / private / loopback / link-local / multicast /
     reserved / unspecified).
  - Performs a reverse-DNS (PTR) lookup with a bounded timeout.
  - For **public IPs only**, optionally queries VirusTotal's
    /ip_addresses/{ip} endpoint and extracts threat verdicts,
    ASN, AS owner, and country.
  - Never sends private or special-use IPs to external services.
  - Feeds six heuristic signals into the project-wide 0-100 risk
    score with LOW / MEDIUM / HIGH / CRITICAL classification.
  - Returns a fully JSON-serialisable IPAnalysisResult.
  - The public function analyze_ip() never raises.

Out of scope: port scanning, banner grabbing, service enumeration,
exploitation, credential activity.

Read-only reuse from frozen modules
-------------------------------------
  reputation.py  : API_KEY_ENV_VAR, _get_api_key, ReputationResult
  url_analyzer.py: HeuristicSignal, calculate_risk_score, classify_risk
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

from .reputation import API_KEY_ENV_VAR, ReputationResult, _get_api_key
from .url_analyzer import HeuristicSignal, calculate_risk_score, classify_risk

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT: float = 5.0
_GENERATED_BY: str = "tool"
_DISCLAIMER: str = (
    "This IP analysis is heuristic evidence only. "
    "Results are not proof of malicious intent. "
    "Always combine with additional context before acting."
)

_VT_IP_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Address-space labels — stable strings used in the result and signals.
CLASS_PUBLIC      = "public"
CLASS_PRIVATE     = "private"
CLASS_LOOPBACK    = "loopback"
CLASS_LINK_LOCAL  = "link_local"
CLASS_MULTICAST   = "multicast"
CLASS_RESERVED    = "reserved"
CLASS_UNSPECIFIED = "unspecified"


# ---------------------------------------------------------------------------
# Result data structures
# ---------------------------------------------------------------------------

@dataclass
class IPIntelligence:
    """Extended fields extracted from VirusTotal when available."""
    asn:      Optional[int] = None   # Autonomous System Number
    as_owner: Optional[str] = None   # Organisation / AS owner name
    country:  Optional[str] = None   # ISO 3166-1 alpha-2 country code
    network:  Optional[str] = None   # CIDR block the IP belongs to


@dataclass
class IPAnalysisResult:
    """Complete, JSON-serialisable result returned by analyze_ip()."""
    target:             str
    ip_version:         Optional[int]              # 4 or 6; None on parse failure
    classification:     Optional[str]              # one of CLASS_* labels above
    reverse_dns:        Optional[str]              # PTR hostname if found
    reverse_dns_error:  Optional[str]              # populated when rDNS failed
    intelligence:       Optional[IPIntelligence]
    reputation:         Optional[ReputationResult]
    signals:            List[HeuristicSignal]
    risk_score:         int
    risk_level:         str
    error:              Optional[str]
    disclaimer:         str
    generated_by:       str
    ai_interpretation:  Optional[str] = None       # reserved; always None here


# ---------------------------------------------------------------------------
# 1. Validation and classification
# ---------------------------------------------------------------------------

def _parse_ip(raw: str):
    """Return an ipaddress object, or None for invalid input."""
    if not raw or not isinstance(raw, str):
        return None
    try:
        return ipaddress.ip_address(raw.strip())
    except ValueError:
        return None


def _classify(addr) -> str:
    """
    Classify address space.  Checks are ordered most-specific first so
    that, e.g., loopback (a subset of private in IPv4) is labelled
    correctly rather than landing in the catch-all private bucket.
    """
    if addr.is_loopback:
        return CLASS_LOOPBACK
    if addr.is_link_local:
        return CLASS_LINK_LOCAL
    if addr.is_multicast:
        return CLASS_MULTICAST
    if addr.is_unspecified:
        return CLASS_UNSPECIFIED
    if addr.is_reserved:
        return CLASS_RESERVED
    if addr.is_private:
        return CLASS_PRIVATE
    return CLASS_PUBLIC


# ---------------------------------------------------------------------------
# 2. Reverse DNS
# ---------------------------------------------------------------------------

def _reverse_dns(ip_str: str, timeout: float):
    """
    PTR lookup with a bounded timeout.

    socket.gethostbyaddr() respects socket.getdefaulttimeout(), which is
    the stdlib-only way to bound a reverse-DNS call without threads.
    The original timeout is restored in a finally block.

    Returns (hostname, None) on success, (None, error_message) on any failure.
    """
    original = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip_str)
        return hostname, None
    except socket.herror as exc:
        return None, f"No PTR record: {exc}"
    except socket.gaierror as exc:
        return None, f"Reverse DNS lookup failed: {exc}"
    except socket.timeout:
        return None, "Reverse DNS lookup timed out."
    except OSError as exc:
        return None, f"Reverse DNS error: {exc}"
    finally:
        socket.setdefaulttimeout(original)


# ---------------------------------------------------------------------------
# 3. VirusTotal reputation (public IPs only)
# ---------------------------------------------------------------------------

def _vt_reputation(ip_str: str, timeout: float):
    """
    Query VirusTotal /ip_addresses/{ip}.

    Returns (ReputationResult, IPIntelligence).  Never raises.

    Safety note: the HTTP request targets api.virustotal.com — a fixed,
    known-safe host — not the IP under analysis.  The caller enforces that
    this function is only invoked for public IPs.
    """
    rep   = ReputationResult(target=ip_str)
    intel = IPIntelligence()

    api_key = _get_api_key()
    if not api_key:
        rep.error = f"{API_KEY_ENV_VAR} environment variable is not set."
        rep.raw_summary = "Reputation check skipped: no API key configured."
        return rep, intel

    try:
        req = urllib.request.Request(
            _VT_IP_ENDPOINT.format(ip=ip_str),
            method="GET",
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()

    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            rep.available  = True
            rep.raw_summary = "IP not found in VirusTotal's database (no prior analysis)."
            rep.evidence.append("No prior VirusTotal analysis exists for this IP.")
            return rep, intel
        rep.error = f"provider returned HTTP {exc.code}: {exc.reason}"
        rep.raw_summary = f"Reputation check failed: HTTP {exc.code}."
        return rep, intel

    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        text = str(getattr(exc, "reason", exc))
        if isinstance(exc, TimeoutError) or "timed out" in text.lower() or "timeout" in text.lower():
            rep.error = f"request timed out after {timeout}s"
        else:
            rep.error = f"network error: {text}"
        rep.raw_summary = "Reputation check failed: could not reach VirusTotal."
        return rep, intel

    except Exception as exc:
        rep.error = f"unexpected error: {exc}"
        rep.raw_summary = "Reputation check failed unexpectedly."
        return rep, intel

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        rep.error = f"invalid JSON response: {exc}"
        rep.raw_summary = "Reputation check failed: response was not valid JSON."
        return rep, intel

    try:
        attrs = payload["data"]["attributes"]
        stats = attrs.get("last_analysis_stats") or {}

        malicious  = int(stats.get("malicious",  0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total      = sum(int(v or 0) for v in stats.values()) if stats else None

        rep.available       = True
        rep.malicious       = malicious > 0
        rep.suspicious      = suspicious > 0
        rep.detection_count = malicious
        rep.total_engines   = total
        rep.reputation_score = attrs.get("reputation")

        if total:
            rep.raw_summary = (
                f"{malicious}/{total} engines flagged this IP as malicious "
                f"({suspicious} additional flagged it suspicious)."
            )
        else:
            rep.raw_summary = "VirusTotal returned analysis data with no engine statistics."

        for category, count in stats.items():
            if count:
                rep.evidence.append(f"{category}: {count} engine(s)")

        intel.asn      = attrs.get("asn")
        intel.as_owner = attrs.get("as_owner")
        intel.country  = attrs.get("country")
        intel.network  = attrs.get("network")

    except (KeyError, TypeError, ValueError) as exc:
        rep.error = f"unexpected response shape: {exc}"
        rep.raw_summary = "Reputation check failed: response did not match expected format."
        rep.available = False

    return rep, intel


# ---------------------------------------------------------------------------
# 4. Heuristic signals
# ---------------------------------------------------------------------------

def _sig_non_public(classification: str) -> HeuristicSignal:
    triggered = classification != CLASS_PUBLIC
    return HeuristicSignal(
        name="non_public_address",
        description=(
            f"IP is in a non-public address space ({classification}); "
            "unexpected in public-internet contexts."
            if triggered else
            "IP is in public address space."
        ),
        points=0,
        triggered=triggered,
    )


def _sig_loopback_or_link_local(classification: str) -> HeuristicSignal:
    triggered = classification in (CLASS_LOOPBACK, CLASS_LINK_LOCAL)
    return HeuristicSignal(
        name="loopback_or_link_local",
        description=(
            f"IP is {classification} — a strong SSRF / internal-confusion "
            "indicator when seen in externally-supplied input."
            if triggered else
            "IP is not loopback or link-local."
        ),
        points=0,
        triggered=triggered,
    )


def _sig_reputation_flagged(rep: Optional[ReputationResult]) -> HeuristicSignal:
    triggered = bool(
        rep and rep.available and (rep.malicious or rep.suspicious)
    )
    return HeuristicSignal(
        name="reputation_flagged",
        description=(
            "VirusTotal reports this IP as malicious or suspicious."
            if triggered else
            "No reputation flag from VirusTotal (or reputation not checked)."
        ),
        points=40,
        triggered=triggered,
    )


def _sig_high_detection_ratio(rep: Optional[ReputationResult]) -> HeuristicSignal:
    triggered = bool(
        rep and rep.available
        and rep.detection_count is not None
        and rep.total_engines
        and (rep.detection_count / rep.total_engines) >= 0.25
    )
    ratio_str = "N/A"
    if rep and rep.available and rep.detection_count is not None and rep.total_engines:
        ratio_str = f"{rep.detection_count / rep.total_engines:.0%}"
    return HeuristicSignal(
        name="high_malicious_detection_ratio",
        description=(
            f"High engine detection ratio ({ratio_str}) — broad multi-vendor "
            "consensus this IP is malicious."
            if triggered else
            f"Engine detection ratio ({ratio_str}) below high-confidence threshold."
        ),
        points=20,
        triggered=triggered,
    )


def _sig_negative_vt_score(rep: Optional[ReputationResult]) -> HeuristicSignal:
    triggered = bool(
        rep and rep.available
        and rep.reputation_score is not None
        and rep.reputation_score < -10
    )
    score_str = (
        str(rep.reputation_score)
        if rep and rep.reputation_score is not None else "N/A"
    )
    return HeuristicSignal(
        name="negative_vt_reputation_score",
        description=(
            f"VirusTotal community reputation score is negative ({score_str}), "
            "indicating broad community distrust."
            if triggered else
            f"VirusTotal community reputation score is acceptable ({score_str})."
        ),
        points=15,
        triggered=triggered,
    )


def _sig_no_rdns(rdns_host: Optional[str], classification: str) -> HeuristicSignal:
    # Absence of PTR is only suspicious for public IPs; private/special
    # ranges routinely lack reverse records.
    triggered = (classification == CLASS_PUBLIC and rdns_host is None)
    return HeuristicSignal(
        name="no_reverse_dns",
        description=(
            "No reverse DNS (PTR) record found for this public IP."
            if triggered else
            "Reverse DNS record present, or IP is non-public (PTR absence expected)."
        ),
        points=10,
        triggered=triggered,
    )


# ---------------------------------------------------------------------------
# 5. Public entry point
# ---------------------------------------------------------------------------

def analyze_ip(
    ip: str,
    timeout: float = _DEFAULT_TIMEOUT,
    check_reputation: bool = True,
) -> IPAnalysisResult:
    """
    Full IP Intelligence pipeline for a single IP address string.

    Pipeline:
        validate → classify → reverse DNS
        → (public only) VirusTotal reputation
        → heuristic signals → score → classify → result

    Never raises; every failure is a structured field in IPAnalysisResult.
    """

    def _err(msg: str) -> IPAnalysisResult:
        return IPAnalysisResult(
            target=ip if ip else "",
            ip_version=None,
            classification=None,
            reverse_dns=None,
            reverse_dns_error=None,
            intelligence=None,
            reputation=None,
            signals=[],
            risk_score=0,
            risk_level="LOW",
            error=msg,
            disclaimer=_DISCLAIMER,
            generated_by=_GENERATED_BY,
        )

    try:
        # 1. Validate
        addr = _parse_ip(ip)
        if addr is None:
            return _err(f"Invalid IP address: {ip!r}")

        ip_str         = str(addr)          # normalised (no leading zeros, etc.)
        ip_version     = addr.version
        classification = _classify(addr)
        is_public      = (classification == CLASS_PUBLIC)

        # 2. Reverse DNS (safe for any address space)
        rdns_host, rdns_error = _reverse_dns(ip_str, timeout)

        # 3. Reputation — public IPs only
        reputation: Optional[ReputationResult] = None
        intelligence: Optional[IPIntelligence] = None

        if check_reputation:
            if is_public:
                reputation, intelligence = _vt_reputation(ip_str, timeout)
            else:
                reputation = ReputationResult(target=ip_str)
                reputation.error = (
                    f"Reputation check skipped: IP is {classification} "
                    "(non-public IPs are never sent to external services)."
                )
                reputation.raw_summary = (
                    f"Reputation check skipped: {classification} address."
                )
                intelligence = IPIntelligence()

        # 4. Heuristic signals
        signals = [
            _sig_non_public(classification),
            _sig_loopback_or_link_local(classification),
            _sig_reputation_flagged(reputation),
            _sig_high_detection_ratio(reputation),
            _sig_negative_vt_score(reputation),
            _sig_no_rdns(rdns_host, classification),
        ]

        # 5. Score and classify
        score = calculate_risk_score(signals)
        level = classify_risk(score)

        return IPAnalysisResult(
            target=ip_str,
            ip_version=ip_version,
            classification=classification,
            reverse_dns=rdns_host,
            reverse_dns_error=rdns_error,
            intelligence=intelligence,
            reputation=reputation,
            signals=signals,
            risk_score=score,
            risk_level=level,
            error=None,
            disclaimer=_DISCLAIMER,
            generated_by=_GENERATED_BY,
            ai_interpretation=None,
        )

    except Exception as exc:          # defensive — must never propagate
        return _err(f"Unexpected analysis error: {exc}")
