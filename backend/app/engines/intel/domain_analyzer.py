"""
intelligence/domain_analyzer.py
SentinelX — Domain Intelligence

Passive domain analysis: validates a domain, resolves DNS (A/AAAA only),
optionally probes TLS on port 443, optionally queries VirusTotal's domain
reputation endpoint, and runs structural heuristics to produce a 0-100
risk score using the project-wide LOW/MEDIUM/HIGH/CRITICAL bands.

Public entry point
------------------
    analyze_domain(domain, timeout=5.0, check_reputation=True) -> DomainAnalysisResult

Safety contract
---------------
- SSRF destination gate runs before every network connection to an
  arbitrary host (TLS probe, reputation HTTP call).
- DNS resolution itself is safe (no subsequent connection from it alone).
- Only A/AAAA records; no MX/TXT/NS/SOA (stdlib limitation, in-scope note).
- No port scanning, no banner grabbing, no exploitation.
- No credentials sent or stored.
- Every failure becomes a structured field; analyze_domain() never raises.
- ai_interpretation is reserved and always None.

Frozen reuse
------------
From url_analyzer  : resolve_dns, get_tls_info, _extract_domain,
                     HeuristicSignal, calculate_risk_score, classify_risk,
                     DNSInfo, TLSInfo, KNOWN_BRANDS, RISKY_TLDS
From reputation    : API_KEY_ENV_VAR, _get_api_key, ReputationResult
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Read-only imports from frozen modules
# ---------------------------------------------------------------------------
from .url_analyzer import (
    _extract_domain, KNOWN_BRANDS, RISKY_TLDS, HeuristicSignal, DNSInfo,
    TLSInfo, resolve_dns, get_tls_info, calculate_risk_score, classify_risk,
)
from .reputation import API_KEY_ENV_VAR, _get_api_key, ReputationResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DISCLAIMER = (
    "This domain analysis is heuristic evidence only. "
    "Results are not proof of malicious intent. "
    "Always combine with additional context before acting."
)

_DEFAULT_TIMEOUT: float = 5.0

_VT_DOMAIN_ENDPOINT = "https://www.virustotal.com/api/v3/domains/{domain}"

# Addresses / networks that must not be reached from arbitrary user input
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),        # unspecified
    ipaddress.ip_network("10.0.0.0/8"),        # private
    ipaddress.ip_network("100.64.0.0/10"),     # shared address space
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("172.16.0.0/12"),     # private
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("192.168.0.0/16"),    # private
    ipaddress.ip_network("198.18.0.0/15"),     # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # documentation
    ipaddress.ip_network("203.0.113.0/24"),    # documentation
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("240.0.0.0/4"),       # reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),           # loopback
    ipaddress.ip_network("fc00::/7"),          # unique-local
    ipaddress.ip_network("fe80::/10"),         # link-local
    ipaddress.ip_network("ff00::/8"),          # multicast
]

# Consonant clusters and DGA heuristic support
_VOWELS = set("aeiou")
_MAX_LEGITIMATE_LABEL_LENGTH = 15   # labels longer than this scored
_MIN_CONSONANT_RUN = 5               # consecutive consonants threshold


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DomainCharacteristics:
    """Structural facts about the domain string itself."""
    length: int
    label_count: int
    has_digits: bool
    has_hyphens: bool
    digit_ratio: float
    is_ip_literal: bool
    tld: str
    registrable_domain: str


@dataclass
class DomainAnalysisResult:
    """Complete result returned by analyze_domain()."""
    target_domain: str
    registrable_domain: str
    characteristics: Optional[DomainCharacteristics]
    dns: Optional[DNSInfo]
    tls: Optional[TLSInfo]
    tls_blocked_reason: Optional[str]
    reputation: Optional[ReputationResult]
    signals: List[HeuristicSignal]
    domain_risk_score: int
    domain_risk_level: str
    error: Optional[str]
    disclaimer: str
    ai_interpretation: Optional[str] = None


# ---------------------------------------------------------------------------
# Input validation and normalization
# ---------------------------------------------------------------------------

def _validate_and_normalize_domain(raw: str) -> Optional[str]:
    """
    Accept a bare domain or a full URL (forgives accidental paste).
    Returns the bare hostname/domain on success, or None if the input
    is empty/invalid after stripping.

    No urllib.parse needed: we strip scheme and path with plain string ops.
    """
    if not raw or not isinstance(raw, str):
        return None

    s = raw.strip()
    if not s:
        return None

    # Strip common scheme prefixes
    for prefix in ("https://", "http://", "ftp://"):
        if s.lower().startswith(prefix):
            s = s[len(prefix):]
            break

    # Strip path, query, fragment
    s = s.split("/")[0].split("?")[0].split("#")[0]

    # Strip port
    # Handle IPv6 literals like [::1]:8080
    if s.startswith("["):
        bracket_end = s.find("]")
        if bracket_end != -1:
            s = s[: bracket_end + 1]
    else:
        if ":" in s:
            s = s.rsplit(":", 1)[0]

    s = s.strip()
    return s if s else None


# ---------------------------------------------------------------------------
# SSRF destination safety gate  (locally owned — not delegated to any frozen
# module, per the design contract)
# ---------------------------------------------------------------------------

def _check_destination_safety(ip_str: str) -> Optional[str]:
    """
    Returns None when the IP is safe to connect to, or a human-readable
    reason string when it is blocked (loopback/private/link-local/
    reserved/multicast/unspecified).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"Cannot parse IP address: {ip_str!r}"

    for net in _BLOCKED_NETWORKS:
        if addr in net:
            return (
                f"Destination {ip_str} is in a blocked network range "
                f"({net}); connection suppressed."
            )
    return None


def _ips_are_all_safe(ip_addresses: List[str]) -> tuple[bool, Optional[str]]:
    """
    Returns (True, None) if every resolved IP passes the SSRF gate,
    or (False, reason) on the first blocked address.
    """
    for ip in ip_addresses:
        reason = _check_destination_safety(ip)
        if reason:
            return False, reason
    return True, None


# ---------------------------------------------------------------------------
# Domain characteristics
# ---------------------------------------------------------------------------

def _compute_characteristics(domain: str) -> DomainCharacteristics:
    """Extract structural facts from a bare domain string."""
    is_ip = False
    try:
        ipaddress.ip_address(domain.strip("[]"))
        is_ip = True
    except ValueError:
        pass

    labels = domain.split(".")
    tld = labels[-1].lower() if len(labels) > 1 and not is_ip else ""
    registrable = _extract_domain(domain) if not is_ip else domain

    digits_in_domain = sum(1 for c in domain if c.isdigit())
    alphanum = sum(1 for c in domain if c.isalnum())
    digit_ratio = round(digits_in_domain / alphanum, 3) if alphanum else 0.0

    return DomainCharacteristics(
        length=len(domain),
        label_count=len(labels),
        has_digits=any(c.isdigit() for c in domain),
        has_hyphens="-" in domain,
        digit_ratio=digit_ratio,
        is_ip_literal=is_ip,
        tld=tld,
        registrable_domain=registrable,
    )


# ---------------------------------------------------------------------------
# Domain-reputation via VirusTotal /domains/{domain}
# ---------------------------------------------------------------------------

def _check_domain_reputation(
    domain: str,
    ip_addresses: List[str],
    timeout: float = _DEFAULT_TIMEOUT,
) -> ReputationResult:
    """
    Query VirusTotal's /domains/{domain} endpoint.

    Safety: the outgoing HTTP request targets api.virustotal.com, a
    fixed, known-safe host — not the arbitrary domain under analysis.
    We still apply the SSRF gate on the resolved IPs of the domain
    under analysis before calling this, but the reputation HTTP call
    itself is to a hardcoded provider host, not to the domain.
    """
    result = ReputationResult(target=domain)

    if not domain:
        result.error = "no domain provided"
        result.raw_summary = "Reputation check skipped: no domain."
        return result

    api_key = _get_api_key()
    if not api_key:
        result.error = f"{API_KEY_ENV_VAR} environment variable is not set."
        result.raw_summary = "Reputation check skipped: no API key configured."
        return result

    try:
        endpoint = _VT_DOMAIN_ENDPOINT.format(domain=domain)
        request = urllib.request.Request(
            endpoint,
            method="GET",
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            result.available = True
            result.raw_summary = (
                "Domain not found in VirusTotal's database (no prior analysis)."
            )
            result.evidence.append("No prior VirusTotal analysis exists for this domain.")
            return result
        result.error = f"provider returned HTTP {exc.code}: {exc.reason}"
        result.raw_summary = f"Reputation check failed: HTTP {exc.code}."
        return result
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        text = str(reason)
        if isinstance(exc, TimeoutError) or "timed out" in text.lower() or "timeout" in text.lower():
            result.error = f"request timed out after {timeout}s"
        else:
            result.error = f"network error: {text}"
        result.raw_summary = "Reputation check failed: could not reach provider."
        return result
    except Exception as exc:
        result.error = f"unexpected error: {exc}"
        result.raw_summary = "Reputation check failed unexpectedly."
        return result

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        result.error = f"invalid response: {exc}"
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
                f"{malicious_count}/{total_engines} engines flagged this domain as malicious "
                f"({suspicious_count} additional flagged it suspicious)."
            )
        else:
            result.raw_summary = (
                "VirusTotal returned analysis data with no engine statistics."
            )

        for category, count in stats.items():
            if count:
                result.evidence.append(f"{category}: {count} engine(s)")

    except (KeyError, TypeError, ValueError) as exc:
        result.error = f"unexpected response shape: {exc}"
        result.raw_summary = "Reputation check failed: response did not match expected format."
        result.available = False

    return result


# ---------------------------------------------------------------------------
# Heuristic signal checks
# ---------------------------------------------------------------------------

def _signal_typosquat_or_brand_lookalike(registrable: str) -> HeuristicSignal:
    """
    Check whether the registrable domain is suspiciously close to a known
    brand using simple edit-distance and character-substitution detection.

    Operates on the bare registrable domain (label before TLD), not a
    full URLComponents, so this is fresh domain-specific logic.
    """
    label = registrable.split(".")[0].lower() if "." in registrable else registrable.lower()

    # Common homoglyph / leet substitutions to normalize before comparison
    _SUBSTITUTIONS = str.maketrans("0l1!3@$", "ollieas")
    normalized = label.translate(_SUBSTITUTIONS)

    def _levenshtein(a: str, b: str) -> int:
        if len(a) < len(b):
            return _levenshtein(b, a)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                                prev[j] + (ca != cb)))
            prev = curr
        return prev[-1]

    triggered = False
    matched_brand = None

    for brand in KNOWN_BRANDS:
        brand_lower = brand.lower()
        # Exact hit on the original label → it IS the brand, not a lookalike
        if label == brand_lower:
            break
        # If the normalized label (after leet/homoglyph substitution) becomes
        # an exact match for a brand, that is the clearest lookalike signal.
        if normalized == brand_lower:
            triggered = True
            matched_brand = brand
            break
        # Also catch small-edit-distance variants that survive normalization
        dist = _levenshtein(normalized, brand_lower)
        max_dist = max(1, len(brand_lower) // 4)
        if 0 < dist <= max_dist:
            triggered = True
            matched_brand = brand
            break

    desc = (
        f"Domain label '{label}' closely resembles known brand '{matched_brand}'."
        if triggered
        else "No brand typosquatting detected."
    )
    return HeuristicSignal(
        name="typosquat_or_brand_lookalike",
        description=desc,
        points=30,
        triggered=triggered,
    )


def _signal_reputation_flagged(reputation: Optional[ReputationResult]) -> HeuristicSignal:
    triggered = (
        reputation is not None
        and reputation.available
        and (reputation.malicious or reputation.suspicious)
    )
    desc = (
        "VirusTotal reports this domain as malicious or suspicious."
        if triggered
        else "No reputation flag from VirusTotal (or reputation not checked)."
    )
    return HeuristicSignal(
        name="reputation_flagged",
        description=desc,
        points=30,
        triggered=triggered,
    )


def _signal_no_valid_tls(tls: Optional[TLSInfo]) -> HeuristicSignal:
    triggered = tls is not None and tls.attempted and not tls.success
    desc = (
        "TLS certificate could not be validated on port 443."
        if triggered
        else "TLS certificate is valid or TLS probe was not attempted."
    )
    return HeuristicSignal(
        name="no_valid_tls_certificate",
        description=desc,
        points=15,
        triggered=triggered,
    )


def _signal_tls_hostname_mismatch(tls: Optional[TLSInfo]) -> HeuristicSignal:
    triggered = (
        tls is not None
        and tls.attempted
        and tls.success
        and tls.hostname_matches is False
    )
    desc = (
        "TLS certificate subject does not match the domain."
        if triggered
        else "TLS hostname match passed or probe not attempted."
    )
    return HeuristicSignal(
        name="tls_hostname_mismatch",
        description=desc,
        points=20,
        triggered=triggered,
    )


def _signal_risky_tld(tld: str) -> HeuristicSignal:
    triggered = tld.lower() in RISKY_TLDS
    desc = (
        f"TLD '.{tld}' is associated with high abuse rates."
        if triggered
        else f"TLD '.{tld}' is not in the high-risk list."
    )
    return HeuristicSignal(
        name="risky_tld",
        description=desc,
        points=15,
        triggered=triggered,
    )


def _signal_excessive_subdomains(label_count: int) -> HeuristicSignal:
    # More than 4 labels (e.g. a.b.c.example.com = 5) is unusual
    triggered = label_count > 4
    desc = (
        f"Domain has {label_count} labels, which is unusually many."
        if triggered
        else f"Label count ({label_count}) is within normal range."
    )
    return HeuristicSignal(
        name="excessive_subdomains",
        description=desc,
        points=10,
        triggered=triggered,
    )


def _signal_suspicious_characters(domain: str) -> HeuristicSignal:
    """
    Flag non-ASCII characters (IDN homograph indicator) or unusual
    symbol usage beyond hyphens and dots.
    """
    has_non_ascii = any(ord(c) > 127 for c in domain)
    # Xn-- punycode prefix is a strong IDN homograph indicator
    has_xn = any(lbl.lower().startswith("xn--") for lbl in domain.split("."))
    triggered = has_non_ascii or has_xn
    desc = (
        "Domain contains non-ASCII or punycode characters (possible homograph attack)."
        if triggered
        else "No suspicious Unicode or homograph characters detected."
    )
    return HeuristicSignal(
        name="suspicious_characters_or_unicode",
        description=desc,
        points=20,
        triggered=triggered,
    )


def _signal_randomly_generated(registrable: str) -> HeuristicSignal:
    """
    DGA-style heuristic: flag domains whose primary label looks
    machine-generated (long consonant runs, high digit density,
    or overall label length beyond typical human-chosen names).
    """
    label = registrable.split(".")[0].lower() if "." in registrable else registrable.lower()
    # Strip hyphens for consonant analysis
    alpha_only = re.sub(r"[^a-z]", "", label)

    # Check for long consonant run
    max_consonant_run = 0
    current_run = 0
    for ch in alpha_only:
        if ch not in _VOWELS:
            current_run += 1
            max_consonant_run = max(max_consonant_run, current_run)
        else:
            current_run = 0

    # Digit density in the label
    digits_in_label = sum(1 for c in label if c.isdigit())
    digit_density = digits_in_label / len(label) if label else 0.0

    looks_random = (
        max_consonant_run >= _MIN_CONSONANT_RUN
        or digit_density >= 0.4
        or len(label) >= _MAX_LEGITIMATE_LABEL_LENGTH * 2
    )

    desc = (
        "Domain primary label appears randomly generated "
        f"(consonant run: {max_consonant_run}, digit density: {digit_density:.0%})."
        if looks_random
        else "Domain primary label does not appear randomly generated."
    )
    return HeuristicSignal(
        name="randomly_generated_looking_domain",
        description=desc,
        points=15,
        triggered=looks_random,
    )


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------

def analyze_domain(
    domain: str,
    timeout: float = _DEFAULT_TIMEOUT,
    check_reputation: bool = True,
) -> DomainAnalysisResult:
    """
    Run the full Domain Intelligence pipeline on a single domain string.

    Input:  a bare domain or accidental-paste full URL (normalized internally).
    Output: DomainAnalysisResult — never raises.

    Pipeline:
        validate/normalize → characteristics → DNS A/AAAA
            → SSRF gate → TLS on 443
            → (optional) SSRF gate → VT domain reputation
            → heuristics → score → classify → return
    """
    # ------------------------------------------------------------------ #
    # 0. Prepare an empty-ish result so we can return early on hard errors
    # ------------------------------------------------------------------ #
    def _error_result(msg: str) -> DomainAnalysisResult:
        return DomainAnalysisResult(
            target_domain=domain if domain else "",
            registrable_domain="",
            characteristics=None,
            dns=None,
            tls=None,
            tls_blocked_reason=None,
            reputation=None,
            signals=[],
            domain_risk_score=0,
            domain_risk_level="LOW",
            error=msg,
            disclaimer=_DISCLAIMER,
        )

    try:
        # ---------------------------------------------------------------- #
        # 1. Validate and normalize
        # ---------------------------------------------------------------- #
        normalized = _validate_and_normalize_domain(domain)
        if not normalized:
            return _error_result("Invalid or empty domain input.")

        # ---------------------------------------------------------------- #
        # 2. Characteristics
        # ---------------------------------------------------------------- #
        characteristics = _compute_characteristics(normalized)
        registrable = characteristics.registrable_domain

        # ---------------------------------------------------------------- #
        # 3. DNS resolution (A/AAAA only)
        #    DNS failure is evidence/error state — it does NOT add risk points.
        # ---------------------------------------------------------------- #
        dns_info: DNSInfo = resolve_dns(normalized)

        # ---------------------------------------------------------------- #
        # 4. SSRF gate → TLS probe on port 443
        # ---------------------------------------------------------------- #
        tls_info: Optional[TLSInfo] = None
        tls_blocked_reason: Optional[str] = None

        if dns_info.resolved and dns_info.ip_addresses:
            safe, block_reason = _ips_are_all_safe(dns_info.ip_addresses)
            if not safe:
                tls_blocked_reason = block_reason
            else:
                tls_info = get_tls_info(normalized, port=443, timeout=timeout)
        elif not dns_info.resolved:
            tls_blocked_reason = "TLS probe skipped: DNS resolution failed."

        # ---------------------------------------------------------------- #
        # 5. (Optional) Domain reputation via VirusTotal
        #    SSRF applies to the domain-under-analysis's resolved IPs;
        #    the actual HTTP call goes to the fixed VT API host.
        # ---------------------------------------------------------------- #
        reputation: Optional[ReputationResult] = None

        if check_reputation:
            # Only attempt if DNS resolved and IPs are safe (same gate as TLS)
            if dns_info.resolved and dns_info.ip_addresses:
                safe, _ = _ips_are_all_safe(dns_info.ip_addresses)
                if safe:
                    reputation = _check_domain_reputation(
                        registrable or normalized, dns_info.ip_addresses, timeout=timeout
                    )
                else:
                    rep_skipped = ReputationResult(target=registrable or normalized)
                    rep_skipped.error = "Reputation check skipped: destination is blocked."
                    rep_skipped.raw_summary = "Reputation check skipped: SSRF safety gate."
                    reputation = rep_skipped
            elif not dns_info.resolved:
                # Try reputation even without resolved IPs — the HTTP call
                # goes to VT's own servers, not to the domain under analysis.
                reputation = _check_domain_reputation(
                    registrable or normalized, [], timeout=timeout
                )

        # ---------------------------------------------------------------- #
        # 6. Heuristic signals
        # ---------------------------------------------------------------- #
        signals: List[HeuristicSignal] = [
            _signal_typosquat_or_brand_lookalike(registrable or normalized),
            _signal_reputation_flagged(reputation),
            _signal_no_valid_tls(tls_info),
            _signal_tls_hostname_mismatch(tls_info),
            _signal_risky_tld(characteristics.tld),
            _signal_excessive_subdomains(characteristics.label_count),
            _signal_suspicious_characters(normalized),
            _signal_randomly_generated(registrable or normalized),
        ]

        # ---------------------------------------------------------------- #
        # 7. Score and classify
        # ---------------------------------------------------------------- #
        score = calculate_risk_score(signals)
        level = classify_risk(score)

        return DomainAnalysisResult(
            target_domain=normalized,
            registrable_domain=registrable,
            characteristics=characteristics,
            dns=dns_info,
            tls=tls_info,
            tls_blocked_reason=tls_blocked_reason,
            reputation=reputation,
            signals=signals,
            domain_risk_score=score,
            domain_risk_level=level,
            error=None,
            disclaimer=_DISCLAIMER,
            ai_interpretation=None,
        )

    except Exception as exc:  # defensive: this function must never raise
        return _error_result(f"Unexpected analysis error: {exc}")
