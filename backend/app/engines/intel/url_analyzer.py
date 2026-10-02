"""
url_analyzer.py
----------------
SentinelX - URL Analyzer v0.1

A small, dependency-free (standard library only) module that takes a single
URL and produces an EXPLAINABLE HEURISTIC risk report:

    1. Safely parse the URL (scheme, hostname, domain, path).
    2. Resolve the hostname to IP address(es) via DNS.
    3. If HTTPS is used, connect and read basic TLS certificate info.
    4. Follow the URL's redirect chain (see analyze_redirect_chain()).
    5. Run a set of independent, human-readable heuristic checks,
       including checks on the redirect chain's findings.
    6. Combine the checks into a 0-100 risk score and a LOW/MEDIUM/HIGH/
       CRITICAL label.

IMPORTANT: The risk score is a HEURISTIC signal, not a verdict. It is meant
to help a human (or a later AI-remediation module) prioritize what to look
at next - it does not prove a URL is malicious or safe.

The core analysis above (parsing, DNS, TLS, redirects, heuristics, and
scoring) remains local and dependency-light - no third-party API calls are
involved in producing the risk score itself.

Optional third-party reputation intelligence (currently VirusTotal) is
obtained separately, through the standalone `reputation.py` module, and
attached to the result as `AnalysisResult.reputation`. That reputation
data is evidence only: it is surfaced for a human (or a later module) to
consider, but it is NOT currently factored into risk_score/risk_level.

This module intentionally does NOT do any of the following (by design, for
v0.1): email analysis, webpage/HTML analysis, credential-harvesting
detection, AI scoring, a UI, or database storage. It is meant to be
imported by a larger SentinelX application later.
"""

from __future__ import annotations

import difflib
import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Reputation intelligence module (Area 6) - a standalone, independent module.
# Imported here only to call it from analyze_url() below; nothing in this
# file otherwise depends on it, and a failure inside it must never affect
# URL analysis (see the try/except around the call site in analyze_url()).
#
# Import strategy: prefer the package-relative import, which is what
# resolves correctly when this file is imported as part of the
# `intelligence` package (e.g. `from intelligence.url_analyzer import
# analyze_url`). That relative import raises ImportError when this file
# is instead executed as a flat top-level module - e.g. `python
# intelligence/test_url_analyzer.py`, or pytest collecting
# `intelligence/test_url_analyzer.py` directly - because in that mode
# `url_analyzer` has no parent package for `.reputation` to be relative
# to. The fallback below is the plain flat import used before; it works
# in exactly that situation, because running/collecting a file inside
# `intelligence/` puts that directory itself on sys.path. Both branches
# resolve to the same single reputation.py - this does not duplicate it.
from .reputation import check_url_reputation, ReputationResult


# ---------------------------------------------------------------------------
# Reference data used by the heuristic checks. These are intentionally small
# and are only used to compute a SIGNAL, never to assert that a domain is
# malicious.
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "password",
    "update", "confirm", "signin", "banking", "wallet",
]

# A short list of frequently-impersonated brand names, used only to flag
# possible look-alike ("typosquat") domains. Presence in this list is not
# an accusation against the real brand - it is the opposite: these are the
# names attackers most often imitate.
KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple",
    "netflix", "facebook", "instagram", "chase",
]

# Simple leetspeak-style substitutions used to "normalize" a domain before
# comparing it to KNOWN_BRANDS (e.g. "paypa1" -> "paypal").
_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})

# Top-level domains that see disproportionate abuse in phishing campaigns.
# This is a soft signal, not a blocklist - plenty of legitimate sites use
# these TLDs too.
RISKY_TLDS = {"zip", "mov", "top", "xyz", "country", "gq", "tk", "cf", "ml"}

LONG_URL_THRESHOLD = 75
EXCESSIVE_SUBDOMAIN_THRESHOLD = 3
LONG_DOMAIN_THRESHOLD = 30

DISCLAIMER = (
    "This is a HEURISTIC risk score based on simple structural signals "
    "(URL shape, DNS, and certificate metadata). It is NOT proof that a "
    "URL is malicious or safe, and should not be the sole basis for any "
    "security decision."
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class InvalidURLError(ValueError):
    """Raised when a URL cannot be safely parsed into its components."""


# ---------------------------------------------------------------------------
# Structured data returned by this module
# ---------------------------------------------------------------------------

@dataclass
class URLComponents:
    raw_url: str
    scheme: str
    hostname: str
    domain: str
    path: str
    port: Optional[int] = None


@dataclass
class DNSInfo:
    resolved: bool
    ip_addresses: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TLSInfo:
    attempted: bool
    success: bool = False
    subject: Optional[Dict[str, str]] = None
    issuer: Optional[Dict[str, str]] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    hostname_matches: Optional[bool] = None
    error: Optional[str] = None


@dataclass
class HeuristicSignal:
    name: str
    description: str
    points: int
    triggered: bool


@dataclass
class AnalysisResult:
    url: str
    components: Optional[URLComponents]
    dns_info: Optional[DNSInfo]
    tls_info: Optional[TLSInfo]
    signals: List[HeuristicSignal]
    risk_score: int
    risk_level: str
    disclaimer: str
    error: Optional[str] = None
    # Populated by analyze_url() after a successful parse. Forward reference
    # to RedirectChainResult, defined later in this file - resolvable at
    # runtime because of `from __future__ import annotations` at the top.
    redirect_chain: Optional[RedirectChainResult] = None
    # Populated by analyze_url() after a successful parse, via the
    # standalone reputation.py module. NOT yet factored into risk_score -
    # that is a deliberately separate, future change.
    reputation: Optional[ReputationResult] = None


# ---------------------------------------------------------------------------
# Step 1: Parse the URL
# ---------------------------------------------------------------------------

def parse_url(url: str) -> URLComponents:
    """
    Safely parse a URL string into its components.

    Input:  a URL string, e.g. "https://mail.example.com/login"
    Output: a URLComponents object.
    Raises: InvalidURLError if the URL is empty, has no supported scheme
            (only http/https are supported), or has no hostname.
    """
    cleaned = url.strip()
    if not cleaned:
        raise InvalidURLError("Empty URL provided.")

    parsed = urllib.parse.urlsplit(cleaned)

    if parsed.scheme not in ("http", "https"):
        raise InvalidURLError(
            f"Unsupported or missing scheme: '{parsed.scheme or 'none'}'. "
            "Only 'http' and 'https' URLs are supported in v0.1."
        )

    hostname = parsed.hostname
    if not hostname:
        raise InvalidURLError("URL has no hostname.")
    hostname = hostname.rstrip(".")  # normalize a trailing FQDN dot ("example.com.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidURLError(f"Invalid port in URL: {exc}")

    return URLComponents(
        raw_url=cleaned,
        scheme=parsed.scheme,
        hostname=hostname,
        domain=_extract_domain(hostname),
        path=parsed.path or "/",
        port=port,
    )


# A small, hardcoded set of common multi-part public suffixes (also called
# "effective TLDs"). Used only by _extract_domain() below, to correctly
# extract a registrable domain like "example.co.uk" instead of just "co.uk".
#
# This is deliberately NOT a full Public Suffix List - that would mean
# either bundling/downloading a large, frequently-changing data file or
# adding an external dependency (e.g. `tldextract`), which this
# dependency-light project intentionally avoids. This short list simply
# covers the common cases (e.g. .co.uk, .com.au, .co.jp). Anything not in
# this set falls back to the previous last-two-labels behavior.
_MULTI_PART_PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "com.br", "net.br", "org.br",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.cn", "net.cn", "org.cn",
    "co.kr", "or.kr",
    "com.sg", "net.sg", "org.sg", "gov.sg",
    "co.il",
    "com.mx",
}


def _extract_domain(hostname: str) -> str:
    """
    "Registrable domain" extraction: normally takes the last two
    dot-separated labels of the hostname (e.g. "mail.example.com" ->
    "example.com"), but takes the last THREE when the last two labels
    are themselves a known multi-part public suffix (e.g.
    "mail.example.co.uk" -> "example.co.uk", not "co.uk").

    An IP address is returned as-is, since it has no "domain" in the DNS
    sense - without this check, an IP like "192.168.10.5" would otherwise
    be mangled into a meaningless fake domain like "10.5".

    KNOWN LIMITATION (documented, not hidden): _MULTI_PART_PUBLIC_SUFFIXES
    above is a short hardcoded list of common cases, not the full Public
    Suffix List, so obscure multi-part suffixes it doesn't contain will
    still fall back to the old last-two-labels behavior. A future version
    can swap this out for the `tldextract` library or a full
    public-suffix-list lookup without changing the rest of the module,
    since this is the only function that would need to change.
    """
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname

    last_two = ".".join(labels[-2:])
    if len(labels) >= 3 and last_two in _MULTI_PART_PUBLIC_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


# ---------------------------------------------------------------------------
# Step 2: DNS resolution
# ---------------------------------------------------------------------------

def resolve_dns(hostname: str) -> DNSInfo:
    """
    Resolve a hostname to its IP address(es) using the standard library
    `socket` module (no external DNS library required).

    Input:  a hostname string, e.g. "example.com"
    Output: a DNSInfo object. On failure, `resolved` is False and `error`
            holds a human-readable reason (DNS failures never raise).
    """
    if not hostname:
        return DNSInfo(resolved=False, error="No hostname provided.")
    try:
        infos = socket.getaddrinfo(hostname, None)
        ip_addresses = sorted({info[4][0] for info in infos})
        return DNSInfo(resolved=True, ip_addresses=ip_addresses)
    except socket.gaierror as exc:
        return DNSInfo(resolved=False, error=f"DNS resolution failed: {exc}")
    except UnicodeError as exc:
        return DNSInfo(resolved=False, error=f"Invalid hostname: {exc}")


# ---------------------------------------------------------------------------
# Step 3: HTTPS / TLS certificate info
# ---------------------------------------------------------------------------

def is_https(scheme: str) -> bool:
    """Trivial helper: True if the URL's scheme is 'https'."""
    return scheme == "https"


def get_tls_info(hostname: str, port: int = 443, timeout: float = 5.0) -> TLSInfo:
    """
    Connect to a host on `port` and read basic TLS certificate metadata.
    Only ever called when the URL's scheme is https.

    Input:  hostname string, optional port/timeout.
    Output: a TLSInfo object. Every failure mode (DNS, timeout, connection
            refused, certificate errors) is caught and reported in
            `error` rather than raised, so this function never crashes
            the caller.
    """
    if not hostname:
        return TLSInfo(attempted=False, error="No hostname to check.")

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except socket.gaierror as exc:
        return TLSInfo(attempted=True, error=f"DNS resolution failed: {exc}")
    except socket.timeout:
        return TLSInfo(attempted=True, error="Connection timed out.")
    except ConnectionRefusedError:
        return TLSInfo(attempted=True, error="Connection refused.")
    except ssl.SSLCertVerificationError as exc:
        return TLSInfo(attempted=True, error=f"Certificate verification failed: {exc}")
    except ssl.SSLError as exc:
        return TLSInfo(attempted=True, error=f"TLS/SSL error: {exc}")
    except OSError as exc:
        return TLSInfo(attempted=True, error=f"Connection error: {exc}")

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    return TLSInfo(
        attempted=True,
        success=True,
        subject=subject,
        issuer=issuer,
        valid_from=cert.get("notBefore"),
        valid_until=cert.get("notAfter"),
        hostname_matches=_hostname_matches_cert(hostname, cert),
    )


def _hostname_matches_cert(hostname: str, cert: dict) -> bool:
    """
    Check whether `hostname` is covered by the certificate's Subject
    Alternative Names (with basic '*.example.com' wildcard support).

    Python 3.12 removed ssl.match_hostname(), so this is a small manual
    replacement covering the common cases. It is intentionally simple -
    good enough to flag an obvious mismatch, not a full RFC 6125 client.
    """
    hostname = hostname.lower()
    san_entries = cert.get("subjectAltName", ())
    dns_names = [value.lower() for key, value in san_entries if key == "DNS"]

    for name in dns_names:
        if name == hostname:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if hostname.endswith(suffix) and hostname.count(".") == name.count("."):
                return True
    return False


# ---------------------------------------------------------------------------
# Step 4: Heuristic checks
#
# Each function below inspects ONE thing and returns ONE HeuristicSignal.
# Keeping them separate makes every signal independently readable, testable,
# and easy to re-weight later.
# ---------------------------------------------------------------------------

def _check_long_url(components: URLComponents) -> HeuristicSignal:
    length = len(components.raw_url)
    triggered = length > LONG_URL_THRESHOLD
    return HeuristicSignal(
        name="long_url",
        description=f"URL is {length} characters long (flag threshold: {LONG_URL_THRESHOLD}).",
        points=10,
        triggered=triggered,
    )


def _check_excessive_subdomains(components: URLComponents) -> HeuristicSignal:
    labels = components.hostname.split(".")
    subdomain_count = max(0, len(labels) - 2)
    triggered = subdomain_count >= EXCESSIVE_SUBDOMAIN_THRESHOLD
    return HeuristicSignal(
        name="excessive_subdomains",
        description=f"{subdomain_count} subdomain label(s) detected before the domain.",
        points=10,
        triggered=triggered,
    )


def _check_suspicious_characters(components: URLComponents) -> HeuristicSignal:
    reasons = []
    if "@" in components.raw_url:
        reasons.append("contains '@' (can be used to hide the real destination)")
    if components.hostname.count("-") >= 3:
        reasons.append("hostname contains many hyphens")
    if components.hostname.startswith("xn--") or ".xn--" in components.hostname:
        reasons.append("punycode-encoded hostname (possible look-alike characters)")
    if not components.hostname.isascii():
        reasons.append("hostname contains non-ASCII characters (possible homograph/look-alike attempt)")

    triggered = bool(reasons)
    points = 20 if "@" in components.raw_url else 10
    description = "; ".join(reasons) if reasons else "No suspicious characters found."
    return HeuristicSignal("suspicious_characters", description, points, triggered)


def _check_ip_as_hostname(components: URLComponents) -> HeuristicSignal:
    try:
        ipaddress.ip_address(components.hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    return HeuristicSignal(
        name="ip_as_hostname",
        description="Hostname is a raw IP address rather than a domain name." if is_ip
        else "Hostname is a domain name, not a raw IP.",
        points=25,
        triggered=is_ip,
    )


def _check_suspicious_keywords(components: URLComponents) -> HeuristicSignal:
    host_lower = components.hostname.lower()
    path_lower = components.path.lower()
    found_in_host = [k for k in SUSPICIOUS_KEYWORDS if k in host_lower]
    found_in_path = [k for k in SUSPICIOUS_KEYWORDS if k in path_lower]

    points = 0
    details = []
    if found_in_host:
        points += 15
        details.append(f"in domain/hostname: {', '.join(found_in_host)}")
    if found_in_path:
        points += 5
        details.append(f"in path: {', '.join(found_in_path)}")

    triggered = bool(found_in_host or found_in_path)
    description = "; ".join(details) if details else "No suspicious keywords found."
    return HeuristicSignal("suspicious_keywords", description, points, triggered)


def _check_typosquatting(components: URLComponents) -> HeuristicSignal:
    domain_root = components.domain.split(".")[0].lower()
    normalized = domain_root.translate(_LEET_MAP)

    if domain_root in KNOWN_BRANDS:
        # This is (most likely) the brand's own real domain - e.g. the
        # actual "paypal.com". Checked first and explicitly, so it can
        # never be flagged by either check below.
        return HeuristicSignal(
            "possible_typosquat",
            f"Domain matches known brand '{domain_root}' exactly - not flagged.",
            25, False,
        )

    # Path 1: character-substitution look-alikes, e.g. "paypa1" -> "paypal".
    best_match, best_ratio = None, 0.0
    for brand in KNOWN_BRANDS:
        ratio = difflib.SequenceMatcher(None, normalized, brand).ratio()
        if ratio > best_ratio:
            best_match, best_ratio = brand, ratio
    substitution_hit = best_ratio >= 0.8

    # Path 2: brand name embedded with extra words, e.g. "paypal-secure.info"
    # or "secure-paypal-login.net". A whole-string similarity ratio misses
    # these (the extra characters dilute the score), so also check whether
    # a brand name simply appears inside the domain root.
    embedded_match = next((b for b in KNOWN_BRANDS if b in normalized), None)

    triggered = substitution_hit or embedded_match is not None
    if not triggered:
        description = "No close resemblance to a known, frequently-imitated brand name."
    elif substitution_hit:
        description = (
            f"Domain resembles well-known brand '{best_match}' "
            f"({best_ratio:.0%} similarity after normalizing) but is not an exact match."
        )
    else:
        description = (
            f"Domain contains well-known brand name '{embedded_match}' combined "
            "with other text - a common look-alike pattern."
        )
    return HeuristicSignal("possible_typosquat", description, 25, triggered)


def _check_domain_structure(components: URLComponents) -> HeuristicSignal:
    reasons = []
    tld = components.domain.split(".")[-1].lower() if "." in components.domain else ""
    if tld in RISKY_TLDS:
        reasons.append(f"uses a top-level domain ('.{tld}') that sees disproportionate abuse")
    if len(components.domain) > LONG_DOMAIN_THRESHOLD:
        reasons.append("unusually long domain name")

    triggered = bool(reasons)
    description = "; ".join(reasons) if reasons else "Domain structure looks typical."
    return HeuristicSignal("domain_structure", description, 10, triggered)


def _check_https_usage(components: URLComponents) -> HeuristicSignal:
    triggered = not is_https(components.scheme)
    return HeuristicSignal(
        name="no_https",
        description="Site does not use HTTPS." if triggered else "Site uses HTTPS.",
        points=15,
        triggered=triggered,
    )


def _check_tls_hostname_match(tls_info: Optional[TLSInfo]) -> HeuristicSignal:
    if tls_info is None or not tls_info.attempted or not tls_info.success:
        return HeuristicSignal(
            "tls_hostname_mismatch", "TLS certificate was not available to check.", 0, False
        )
    triggered = tls_info.hostname_matches is False
    description = (
        "Certificate does not cover this hostname." if triggered
        else "Certificate hostname matches the site."
    )
    return HeuristicSignal("tls_hostname_mismatch", description, 20, triggered)


def run_heuristics(components: URLComponents, tls_info: Optional[TLSInfo]) -> List[HeuristicSignal]:
    """
    Run every heuristic check and return the full list of signals
    (both triggered and not-triggered), so the caller can see exactly
    what was checked, not just what fired.

    Input:  URLComponents, and the TLSInfo (or None if the URL was http).
    Output: list of HeuristicSignal.
    """
    return [
        _check_long_url(components),
        _check_excessive_subdomains(components),
        _check_suspicious_characters(components),
        _check_ip_as_hostname(components),
        _check_suspicious_keywords(components),
        _check_typosquatting(components),
        _check_domain_structure(components),
        _check_https_usage(components),
        _check_tls_hostname_match(tls_info),
    ]


def _check_redirect_risks(redirect_chain: Optional["RedirectChainResult"]) -> List[HeuristicSignal]:
    """
    Turn the already-computed redirect_chain result (see
    analyze_redirect_chain(), further down in this file) into scored,
    explainable HeuristicSignals.

    Always returns all 4 checks, triggered or not - same convention as
    run_heuristics() above, so the caller can see exactly what was
    checked. A normal same-domain HTTPS->HTTPS redirect naturally leaves
    every one of these untriggered, since none of the underlying
    conditions (domain change, HTTPS downgrade, excessive hops, a
    blocked destination) apply to it.

    Input:  the RedirectChainResult produced by analyze_redirect_chain(),
            or None if it was never computed.
    Output: list of exactly 4 HeuristicSignal objects.
    """
    if redirect_chain is None:
        return [
            HeuristicSignal("redirect_domain_changed", "Redirect chain was not analyzed.", 15, False),
            HeuristicSignal("https_downgrade", "Redirect chain was not analyzed.", 25, False),
            HeuristicSignal("excessive_redirects", "Redirect chain was not analyzed.", 15, False),
            HeuristicSignal("redirect_blocked", "Redirect chain was not analyzed.", 20, False),
        ]

    final_domain = redirect_chain.final_domain or "an unknown domain"
    final_url = redirect_chain.final_url or "an unresolved destination"

    domain_changed = HeuristicSignal(
        name="redirect_domain_changed",
        description=(
            f"Redirect chain ended on a different domain ('{final_domain}') "
            f"than the original URL." if redirect_chain.domain_changed
            else "Redirect chain (if any) stayed on the same domain."
        ),
        points=15,
        triggered=redirect_chain.domain_changed,
    )

    https_downgrade = HeuristicSignal(
        name="https_downgrade",
        description=(
            f"Redirect chain downgraded from HTTPS to HTTP, ending at '{final_url}'."
            if redirect_chain.https_downgrade
            else "No HTTPS-to-HTTP downgrade occurred in the redirect chain."
        ),
        points=25,
        triggered=redirect_chain.https_downgrade,
    )

    excessive_redirects = HeuristicSignal(
        name="excessive_redirects",
        description=(
            f"Redirect chain exceeded the allowed number of hops "
            f"({redirect_chain.hop_count} redirects) before reaching '{final_url}'; "
            "following was stopped." if redirect_chain.excessive_redirects
            else "Redirect chain length was within the allowed limit."
        ),
        points=15,
        triggered=redirect_chain.excessive_redirects,
    )

    redirect_blocked = HeuristicSignal(
        name="redirect_blocked",
        description=(
            f"Redirect chain was blocked before completing: {redirect_chain.blocked_reason}"
            if redirect_chain.blocked
            else "No unsafe redirect destination was encountered."
        ),
        points=20,
        triggered=redirect_chain.blocked,
    )

    return [domain_changed, https_downgrade, excessive_redirects, redirect_blocked]


# ---------------------------------------------------------------------------
# Step 5-6: Scoring and classification
# ---------------------------------------------------------------------------

def calculate_risk_score(signals: List[HeuristicSignal]) -> int:
    """Sum the points of every triggered signal, capped at 100."""
    return min(sum(s.points for s in signals if s.triggered), 100)


def classify_risk(score: int) -> str:
    """Map a 0-100 score to a LOW / MEDIUM / HIGH / CRITICAL label."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Top-level orchestrator - the only function most callers need.
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> AnalysisResult:
    """
    Run the full v0.1 pipeline on a single URL: parse -> DNS -> TLS (if
    https) -> heuristics -> score -> classify.

    Input:  a URL string.
    Output: an AnalysisResult. This function never raises - a malformed
            URL results in an AnalysisResult with `error` set and
            risk_level "UNKNOWN" instead of a crash, so it's always safe
            to call from a larger application.
    """
    try:
        components = parse_url(url)
    except InvalidURLError as exc:
        return AnalysisResult(
            url=url, components=None, dns_info=None, tls_info=None,
            signals=[], risk_score=0, risk_level="UNKNOWN",
            disclaimer=DISCLAIMER, error=str(exc),
        )

    # analyze_redirect_chain() is documented to never raise, but this call
    # site stays defensive anyway per analyze_url()'s own never-raise
    # contract - any unexpected failure here is captured on the result
    # object instead of propagating.
    try:
        redirect_chain = analyze_redirect_chain(url)
    except Exception as exc:  # noqa: BLE001 - deliberate fail-safe boundary
        redirect_chain = RedirectChainResult(
            original_url=url,
            error=f"redirect analysis failed unexpectedly: {exc}",
        )

    # check_url_reputation() is documented to never raise either (a missing
    # VIRUSTOTAL_API_KEY, a timeout, a network failure, or a bad response
    # all come back as `error` on the ReputationResult) - this call site
    # stays defensive anyway, for the same reason as above: a reputation
    # lookup failure must NEVER make URL analysis itself fail. This is
    # NOT yet factored into risk_score - that is a deliberately separate,
    # future change.
    try:
        reputation = check_url_reputation(url)
    except Exception as exc:  # noqa: BLE001 - deliberate fail-safe boundary
        reputation = ReputationResult(
            target=url,
            error=f"reputation lookup failed unexpectedly: {exc}",
        )

    dns_info = resolve_dns(components.hostname)

    tls_info = None
    if is_https(components.scheme):
        tls_info = get_tls_info(components.hostname, port=components.port or 443)

    signals = run_heuristics(components, tls_info)
    signals.extend(_check_redirect_risks(redirect_chain))

    if not dns_info.resolved:
        signals.append(HeuristicSignal(
            name="dns_resolution_failed",
            description=f"Hostname did not resolve via DNS: {dns_info.error}",
            points=10,
            triggered=True,
        ))

    score = calculate_risk_score(signals)
    level = classify_risk(score)

    return AnalysisResult(
        url=url,
        components=components,
        dns_info=dns_info,
        tls_info=tls_info,
        signals=signals,
        risk_score=score,
        risk_level=level,
        disclaimer=DISCLAIMER,
        redirect_chain=redirect_chain,
        reputation=reputation,
    )


# ---------------------------------------------------------------------------
# Feature: SAFE redirect-chain analysis
#
# Follows a URL's redirect chain one hop at a time (GET only) to discover
# how many redirects occur, whether the domain/protocol changes along the
# way, and where the chain finally ends up.
#
# This IS wired into analyze_url() (see analyze_redirect_chain()'s call
# site there), and its findings ARE scored via _check_redirect_risks()
# further down in this file. It is also independently callable/testable
# on its own, as a standalone function.
#
# SAFETY CONTROLS (all enforced before any network connection is made):
#   - only http/https URLs are ever followed (enforced by re-using
#     parse_url() on every hop, which rejects anything else)
#   - GET only, no request body, no state-changing methods
#   - no credentials: a URL with embedded userinfo (user:pass@host) is
#     rejected before it is ever connected to
#   - short per-request timeout
#   - a bounded maximum number of redirects
#   - every hop's destination hostname is freshly resolved and checked
#     for localhost/loopback/private/link-local/reserved/multicast
#     addresses BEFORE it is followed - not just the first URL
#   - any unsafe or invalid destination stops the chain immediately;
#     this function never raises
# ---------------------------------------------------------------------------

DEFAULT_MAX_REDIRECTS = 5
DEFAULT_REDIRECT_TIMEOUT = 5.0

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


@dataclass
class RedirectHop:
    url: str
    status_code: Optional[int] = None


@dataclass
class RedirectChainResult:
    original_url: str
    redirected: bool = False
    hop_count: int = 0
    hops: List[RedirectHop] = field(default_factory=list)
    final_url: Optional[str] = None
    final_hostname: Optional[str] = None
    final_domain: Optional[str] = None
    final_status_code: Optional[int] = None
    domain_changed: bool = False
    protocol_changed: bool = False
    https_downgrade: bool = False
    excessive_redirects: bool = False
    blocked: bool = False
    blocked_reason: Optional[str] = None
    error: Optional[str] = None


class _NoAutoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Disables urllib's built-in automatic redirect-following.

    Returning None from redirect_request() causes urllib to raise an
    HTTPError carrying the original status code and headers (including
    Location) instead of silently connecting onward. That HTTPError is
    exactly what analyze_redirect_chain() below catches, so every hop
    can be safety-checked before it is followed.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _has_embedded_credentials(url: str) -> bool:
    """True if the URL's authority section contains userinfo (user:pass@host)."""
    return "@" in urllib.parse.urlsplit(url).netloc


class _DestinationUnresolvable(Exception):
    """
    Raised when a redirect destination's hostname cannot be resolved via
    DNS (or is malformed enough that resolution can't even be attempted).

    This is deliberately NOT the same thing as an unsafe destination: DNS
    failure means we don't know where the hostname points, not that we
    determined it's disallowed. analyze_redirect_chain() records this as
    an error on the result, not as a blocked/unsafe destination.
    """


def _check_redirect_destination_safety(hostname: str) -> Tuple[bool, Optional[str]]:
    """
    Resolve `hostname` and inspect every IP address it maps to.

    Returns (True, None) only if ALL resolved addresses are ordinary
    public addresses. Blocks loopback (127.0.0.1, ::1), private
    (RFC1918), link-local, reserved, multicast, and unspecified
    addresses - the standard set of destinations an SSRF-safe fetcher
    must refuse to reach.

    Raises _DestinationUnresolvable if the hostname cannot be resolved at
    all (DNS failure or a malformed hostname) - that is a "don't know",
    not a "blocked", and the caller handles it accordingly. Beyond that,
    this function never raises.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise _DestinationUnresolvable(f"could not resolve destination host: {exc}")
    except UnicodeError as exc:
        raise _DestinationUnresolvable(f"invalid destination hostname: {exc}")

    for info in infos:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"resolved to an un-parseable address: {ip_str}"
        if (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return False, f"resolves to a disallowed address ({ip_str})"
    return True, None


def analyze_redirect_chain(
    url: str,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    timeout: float = DEFAULT_REDIRECT_TIMEOUT,
) -> RedirectChainResult:
    """
    Follow a URL's redirect chain, one hop at a time, re-validating the
    safety of every destination before it is followed.

    Input:  a URL string, plus optional max_redirects/timeout overrides.
    Output: a RedirectChainResult. Never raises - invalid input, blocked
            destinations, and network failures are all reported on the
            result object instead of raised, so it is always safe to
            call from a larger application.
    """
    result = RedirectChainResult(original_url=url)

    try:
        components = parse_url(url)
    except InvalidURLError as exc:
        result.error = str(exc)
        return result

    opener = urllib.request.build_opener(_NoAutoRedirectHandler())
    current_url = components.raw_url
    current_scheme = components.scheme
    current_hostname = components.hostname
    current_domain = components.domain
    final_status: Optional[int] = None

    while True:
        if _has_embedded_credentials(current_url):
            result.blocked = True
            result.blocked_reason = "URL contains embedded credentials; refusing to send them."
            return result

        safe, reason = None, None
        try:
            safe, reason = _check_redirect_destination_safety(current_hostname)
        except _DestinationUnresolvable as exc:
            result.error = f"could not verify safety of '{current_hostname}': {exc}"
            return result

        if not safe:
            result.blocked = True
            result.blocked_reason = f"blocked destination '{current_hostname}': {reason}"
            return result

        request = urllib.request.Request(current_url, method="GET")
        try:
            with opener.open(request, timeout=timeout) as response:
                final_status = response.status
                break  # reached a non-redirect response - chain is complete
        except urllib.error.HTTPError as exc:
            if exc.code not in _REDIRECT_STATUS_CODES:
                final_status = exc.code
                break  # a non-redirect error status is still a final response

            location = exc.headers.get("Location")
            if not location:
                result.error = f"redirect status {exc.code} had no Location header."
                return result

            next_url = urllib.parse.urljoin(current_url, location)
            try:
                next_components = parse_url(next_url)
            except InvalidURLError as parse_exc:
                result.blocked = True
                result.blocked_reason = f"redirect target rejected: {parse_exc}"
                return result

            result.redirected = True
            result.hops.append(RedirectHop(url=next_url, status_code=exc.code))

            current_url = next_components.raw_url
            current_scheme = next_components.scheme
            current_hostname = next_components.hostname
            current_domain = next_components.domain

            # `>=`, not `>`: once max_redirects hops have been recorded, stop
            # immediately - do not go on to connect to this hop's own
            # target just to see whether IT would redirect again. That
            # previous `>` let the chain reach max_redirects + 1 recorded
            # hops (one beyond the configured limit) before stopping;
            # `>=` makes max_redirects an exact ceiling on hops discovered,
            # not "max_redirects, plus one more to check".
            if len(result.hops) >= max_redirects:
                result.excessive_redirects = True
                break  # bounded: stop following, do not connect further
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            result.error = f"request failed: {exc}"
            return result

    result.final_url = current_url
    result.final_hostname = current_hostname
    result.final_domain = current_domain
    result.final_status_code = final_status if not result.excessive_redirects else None
    result.hop_count = len(result.hops)
    result.domain_changed = current_domain != components.domain
    result.protocol_changed = current_scheme != components.scheme
    result.https_downgrade = components.scheme == "https" and current_scheme == "http"
    return result
