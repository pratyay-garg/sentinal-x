"""
intelligence/webpage_analyzer.py
----------------------------------
SentinelX - webpage phishing analyzer (Area 5 support).

This is a STANDALONE module, independent of url_analyzer.py and
reputation.py - it does not import from either, and neither imports from
it. Small reference lists (known brand names, suspicious phrases, field
keywords) are intentionally duplicated here in miniature rather than
imported, to keep this module fully decoupled (matching the pattern
already established by reputation.py).

Purpose
-------
Given a URL, safely fetch the page it points to and inspect the raw HTML
for common PHISHING PAGE indicators: credential-harvesting login forms,
OTP/payment-style fields, forms that submit off-domain, urgency/social-
engineering language, and brand-name mentions that don't match the page's
own domain. Returns a small, explainable, JSON-serializable result with
a separate heuristic phishing risk score - this is NOT merged into
url_analyzer.py's risk score, and url_analyzer.py is not modified.

Design choices worth knowing about
-----------------------------------
* READ-ONLY, PASSIVE analysis only. GET requests only, no request body,
  no cookies/credentials/auth headers ever sent, and forms are only ever
  *read* (action URL, method, field types/names) - never filled in or
  submitted. There is no JavaScript execution: this parses static HTML
  with the standard library's html.parser, so a page whose login form is
  rendered only by client-side JS will not be seen by this tool (see
  test_webpage_analyzer.py / the project handoff notes for this and
  other documented limitations).
* SSRF-safe fetching: before the initial connection AND before following
  each redirect, the destination hostname is resolved and checked against
  loopback / private / link-local / reserved / multicast / unspecified
  addresses - the same rule set used by url_analyzer.py's redirect-chain
  analysis, reimplemented locally here for independence.
* Bounded everything: a timeout per connection attempt, a hard cap on the
  number of redirects actually followed, and a hard cap on response bytes
  read into memory (reading stops and the result is marked `truncated`
  rather than ever buffering an unbounded response).
* Every failure mode - a malformed/unsupported URL, an SSRF-blocked or
  unresolvable destination, a timeout, a network failure, a non-HTML
  response, or unparseable HTML - is caught and turned into a result
  field. The public analyze_webpage() function never raises.
* `PageAnalysisResult.ai_interpretation` is a reserved field that this
  tool NEVER writes to. Everything else on the result (fetch details,
  form findings, signals, score) is mechanical, tool-generated evidence -
  keeping that separate from any future AI-generated interpretation is a
  deliberate design choice, not an oversight.
* Standard library only (html.parser, urllib, socket, ipaddress, re) -
  no BeautifulSoup/lxml/requests, matching the rest of this
  dependency-light project.
"""

from __future__ import annotations

import html.parser
import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Reference data (intentionally duplicated from url_analyzer.py's spirit,
# not imported - see module docstring). Small and soft-signal only, same
# as url_analyzer.py's own reference lists.
# ---------------------------------------------------------------------------

KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple",
    "netflix", "facebook", "instagram", "chase",
]

# Field name/type keywords that suggest an OTP, card, or other payment-
# style field. Matched against lowercased HTML `name`/`id`/`type`
# attributes only - this module never reads or stores field *values*.
OTP_CARD_FIELD_KEYWORDS = [
    "otp", "one-time", "onetime", "cvv", "cvc", "card", "cardnumber",
    "card_number", "expiry", "exp-date", "expdate", "pin", "ssn",
    "routing", "accountnumber", "account_number",
]

# Short, common urgency / social-engineering phrases seen in phishing
# copy. A soft signal, not a blocklist - legitimate transactional email
# and account-security pages sometimes use similar language too.
URGENCY_PHRASES = [
    "verify your account", "account has been suspended", "account suspended",
    "act now", "immediate action required", "unauthorized access",
    "unusual activity", "confirm your identity", "will be locked",
    "click here immediately", "limited time", "within 24 hours",
    "final notice", "your account will be closed", "avoid suspension",
]

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MAX_RESPONSE_BYTES = 1_500_000

DISCLAIMER = (
    "This is a HEURISTIC phishing-indicator score based on static page "
    "structure and content (forms, fields, and wording). It is NOT proof "
    "that a page is a phishing page or is safe, does not execute "
    "JavaScript, and should not be the sole basis for any security "
    "decision."
)


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------

@dataclass
class PageFetchResult:
    """What happened when trying to fetch the page - independent of what
    was found in the HTML, if anything was fetched at all."""
    fetched: bool = False
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length_bytes: Optional[int] = None
    truncated: bool = False
    blocked: bool = False
    blocked_reason: Optional[str] = None
    error: Optional[str] = None


@dataclass
class FormFinding:
    """One <form> found on the page. Field information is structural only
    - names and types, NEVER values - this tool never reads user data."""
    action_url: Optional[str] = None
    method: str = "get"
    is_external_action: bool = False
    has_password_field: bool = False
    has_otp_or_card_field: bool = False
    field_names_sample: List[str] = field(default_factory=list)


@dataclass
class PhishingSignal:
    """Same shape as url_analyzer.py's HeuristicSignal, kept as a
    separate class so this module has zero import dependency on it."""
    name: str
    description: str
    points: int
    triggered: bool


@dataclass
class PageAnalysisResult:
    """
    Structured, JSON-serializable result of a webpage phishing analysis.

    Every field except `ai_interpretation` is mechanical, tool-generated
    evidence. `ai_interpretation` is reserved for a future AI-based
    interpretation layer and is NEVER populated by this module - keeping
    tool evidence and AI interpretation clearly separate is deliberate.
    """
    target_url: str
    fetch: PageFetchResult = field(default_factory=PageFetchResult)
    forms: List[FormFinding] = field(default_factory=list)
    signals: List[PhishingSignal] = field(default_factory=list)
    phishing_risk_score: int = 0
    phishing_risk_level: str = "UNKNOWN"
    error: Optional[str] = None
    disclaimer: str = DISCLAIMER
    # Reserved for a future AI-interpretation layer. This tool NEVER
    # writes to this field.
    ai_interpretation: Optional[str] = None


# ---------------------------------------------------------------------------
# SSRF safety (duplicated locally from url_analyzer.py's redirect-safety
# logic - see module docstring for why this isn't imported instead).
# ---------------------------------------------------------------------------

def _has_embedded_credentials(url: str) -> bool:
    """True if the URL's authority section contains userinfo (user:pass@host)."""
    return "@" in urllib.parse.urlsplit(url).netloc


class _DestinationUnresolvable(Exception):
    """Raised when a destination hostname cannot be resolved via DNS (or
    is malformed enough that resolution can't be attempted). This is a
    "don't know", not a "blocked" - the caller records it as an error,
    not as a safety rejection."""


def _check_destination_safety(hostname: str) -> Tuple[bool, Optional[str]]:
    """
    Resolve `hostname` and inspect every IP it maps to. Returns
    (True, None) only if every resolved address is an ordinary public
    address. Blocks loopback, private (RFC1918), link-local, reserved,
    multicast, and unspecified addresses.

    Raises _DestinationUnresolvable on DNS failure - see above.
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


class _NoAutoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disables urllib's automatic redirect-following, so every hop can be
    safety-checked here before being followed. Same technique as
    url_analyzer.py's redirect-chain analysis."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _naive_domain(hostname: str) -> str:
    """
    Minimal "registrable domain" extraction: last two dot-separated
    labels (e.g. "mail.example.com" -> "example.com"). An IP address is
    returned as-is.

    KNOWN LIMITATION (documented, not hidden): unlike url_analyzer.py's
    _extract_domain(), this does NOT special-case multi-part public
    suffixes like ".co.uk" - it's a supplementary, secondary signal here
    (comparing a form's action domain to the page's own domain), not the
    primary risk driver, so the added complexity wasn't judged worth
    duplicating for a first version.
    """
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    labels = hostname.lower().split(".")
    if len(labels) <= 2:
        return hostname.lower()
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def _read_bounded(response, max_bytes: int) -> Tuple[bytes, bool]:
    """
    Read from a file-like `response` in chunks, stopping at `max_bytes`
    rather than ever buffering an unbounded amount of data. Returns
    (body_bytes, truncated).
    """
    chunks: List[bytes] = []
    total = 0
    truncated = False
    while True:
        chunk = response.read(65536)
        if not chunk:
            break
        remaining = max_bytes - total
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), truncated


def _fetch_page(
    url: str,
    timeout: float,
    max_redirects: int,
    max_response_bytes: int,
) -> Tuple[PageFetchResult, bytes, Optional[str], Optional[str]]:
    """
    Safely fetch `url`: GET only, no credentials, SSRF-checked before the
    initial connection and before every redirect hop, bounded redirects,
    bounded response size.

    Output: (PageFetchResult, body_bytes, final_scheme, final_domain).
    body_bytes/final_scheme/final_domain are empty/None whenever fetched
    is False - the caller must check `result.fetched` before using them.
    Never raises.
    """
    result = PageFetchResult()
    current_url = (url or "").strip()

    if not current_url:
        result.error = "no URL provided"
        return result, b"", None, None

    redirects_followed = 0
    opener = None

    while True:
        parts = urllib.parse.urlsplit(current_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            result.error = (
                f"unsupported or missing scheme/hostname in '{current_url}'. "
                "Only http/https URLs with a hostname are supported."
            )
            return result, b"", None, None

        if _has_embedded_credentials(current_url):
            result.blocked = True
            result.blocked_reason = "URL contains embedded credentials; refusing to send them."
            return result, b"", None, None

        try:
            safe, reason = _check_destination_safety(parts.hostname)
        except _DestinationUnresolvable as exc:
            result.error = f"could not verify safety of '{parts.hostname}': {exc}"
            return result, b"", None, None
        if not safe:
            result.blocked = True
            result.blocked_reason = f"blocked destination '{parts.hostname}': {reason}"
            return result, b"", None, None

        request = urllib.request.Request(
            current_url, method="GET", headers={"Accept": "text/html,*/*"},
        )
        if opener is None:
            # Built lazily: only once every safety gate above has passed,
            # so an invalid/blocked/unresolvable URL never even
            # constructs a network-capable object.
            opener = urllib.request.build_opener(_NoAutoRedirectHandler())
        try:
            with opener.open(request, timeout=timeout) as response:
                result.fetched = True
                result.final_url = current_url
                result.status_code = response.status
                result.content_type = response.headers.get("Content-Type")
                body, truncated = _read_bounded(response, max_response_bytes)
                result.truncated = truncated
                result.content_length_bytes = len(body)
                return result, body, parts.scheme, _naive_domain(parts.hostname)
        except urllib.error.HTTPError as exc:
            if exc.code not in _REDIRECT_STATUS_CODES:
                result.fetched = True
                result.final_url = current_url
                result.status_code = exc.code
                result.error = f"server returned HTTP {exc.code}: {exc.reason}"
                return result, b"", None, None

            location = exc.headers.get("Location") if exc.headers else None
            if not location:
                result.error = f"redirect status {exc.code} had no Location header."
                return result, b"", None, None

            next_url = urllib.parse.urljoin(current_url, location)

            # Check the limit BEFORE following - never make the request
            # that would be one redirect too many.
            if redirects_followed >= max_redirects:
                result.blocked = True
                result.blocked_reason = (
                    f"redirect limit ({max_redirects}) reached; refusing to follow to '{next_url}'"
                )
                return result, b"", None, None

            redirects_followed += 1
            current_url = next_url
            continue
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason_text = str(getattr(exc, "reason", exc))
            if isinstance(exc, TimeoutError) or "timed out" in reason_text.lower() or "timeout" in reason_text.lower():
                result.error = f"request timed out after {timeout}s"
            else:
                result.error = f"network error: {reason_text}"
            return result, b"", None, None
        except Exception as exc:  # defensive: fetching must never raise
            result.error = f"unexpected fetch error: {exc}"
            return result, b"", None, None


# ---------------------------------------------------------------------------
# HTML parsing (standard library html.parser only)
# ---------------------------------------------------------------------------

def _decode_body(body: bytes, content_type: Optional[str]) -> str:
    """Best-effort decode: use the charset from Content-Type if present,
    otherwise UTF-8, and never raise on bad bytes."""
    charset = "utf-8"
    if content_type:
        match = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
        if match:
            charset = match.group(1)
    try:
        return body.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return body.decode("utf-8", errors="replace")


class _PageHTMLParser(html.parser.HTMLParser):
    """
    Single-pass, read-only structural extraction: forms (action, method,
    field types/names), visible text (script/style excluded), and
    outbound link targets. Never executes anything, never renders
    anything - this only walks the static tag/attribute structure.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: List[dict] = []
        self._current_form: Optional[dict] = None
        self._skip_text_depth = 0
        self._text_parts: List[str] = []
        self.link_hrefs: List[str] = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()

        if tag_lower in ("script", "style"):
            self._skip_text_depth += 1
        elif tag_lower == "form":
            self._current_form = {
                "action": attrs_dict.get("action") or None,
                "method": (attrs_dict.get("method") or "get").lower(),
                "fields": [],
            }
        elif tag_lower in ("input", "textarea", "select") and self._current_form is not None:
            field_type = attrs_dict.get("type", "text").lower()
            field_name = (attrs_dict.get("name") or attrs_dict.get("id") or "").lower()
            self._current_form["fields"].append((field_type, field_name))
        elif tag_lower == "a":
            href = attrs_dict.get("href")
            if href:
                self.link_hrefs.append(href)

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower in ("script", "style"):
            if self._skip_text_depth > 0:
                self._skip_text_depth -= 1
        elif tag_lower == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        if self._skip_text_depth == 0:
            self._text_parts.append(data)

    @property
    def visible_text(self) -> str:
        return " ".join(part.strip() for part in self._text_parts if part.strip())

    def finalize(self):
        """
        Flush any form still "open" when parsing ended - e.g. because the
        response was truncated mid-form, so its </form> closing tag never
        arrived. Without this, a form's fields could be silently dropped
        just because the page was cut off, which would hide exactly the
        kind of large/heavy phishing page this tool should still be able
        to flag.
        """
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _build_form_finding(raw_form: dict, page_domain: Optional[str]) -> FormFinding:
    action = raw_form.get("action")
    method = raw_form.get("method", "get")
    fields = raw_form.get("fields", [])

    has_password = any(field_type == "password" for field_type, _ in fields)
    has_otp_or_card = any(
        any(keyword in field_name for keyword in OTP_CARD_FIELD_KEYWORDS)
        for _, field_name in fields
        if field_name
    )
    field_names_sample = [name for _, name in fields if name][:10]

    is_external = False
    if action:
        action_parts = urllib.parse.urlsplit(action)
        if action_parts.hostname:
            action_domain = _naive_domain(action_parts.hostname)
            if page_domain and action_domain != page_domain:
                is_external = True

    return FormFinding(
        action_url=action,
        method=method,
        is_external_action=is_external,
        has_password_field=has_password,
        has_otp_or_card_field=has_otp_or_card,
        field_names_sample=field_names_sample,
    )


# ---------------------------------------------------------------------------
# Heuristic checks - each always returns a signal, triggered or not, same
# convention as url_analyzer.py's run_heuristics().
# ---------------------------------------------------------------------------

def _check_password_field(forms: List[FormFinding]) -> PhishingSignal:
    triggered = any(f.has_password_field for f in forms)
    return PhishingSignal(
        name="password_field_present",
        description=(
            "Page contains at least one password input field."
            if triggered else "No password field found on the page."
        ),
        points=10,
        triggered=triggered,
    )


def _check_otp_or_card_field(forms: List[FormFinding]) -> PhishingSignal:
    triggered = any(f.has_otp_or_card_field for f in forms)
    return PhishingSignal(
        name="otp_or_card_field_present",
        description=(
            "Page contains a field resembling an OTP, card, or other "
            "payment-style field (matched by field name/type keywords)."
            if triggered else "No OTP/card/payment-style field detected."
        ),
        points=20,
        triggered=triggered,
    )


def _check_external_form_action(forms: List[FormFinding]) -> PhishingSignal:
    external_forms = [f for f in forms if f.is_external_action]
    triggered = bool(external_forms)
    description = (
        "Page contains a form that submits to a different domain than the "
        f"page itself (action: {external_forms[0].action_url})."
        if triggered else "No form submits to an external domain."
    )
    return PhishingSignal(
        name="external_form_action",
        description=description,
        points=30,
        triggered=triggered,
    )


def _check_password_over_http(forms: List[FormFinding], scheme: Optional[str]) -> PhishingSignal:
    triggered = scheme == "http" and any(f.has_password_field for f in forms)
    return PhishingSignal(
        name="password_field_over_http",
        description=(
            "A password field is present but the page was served over "
            "plain HTTP, not HTTPS - credentials would be sent unencrypted."
            if triggered else "No password field submitted over plain HTTP."
        ),
        points=25,
        triggered=triggered,
    )


def _check_urgency_language(visible_text: str) -> PhishingSignal:
    lowered = visible_text.lower()
    matched = [phrase for phrase in URGENCY_PHRASES if phrase in lowered]
    triggered = bool(matched)
    description = (
        f"Urgency/social-engineering phrases found: {', '.join(matched[:5])}."
        if triggered else "No urgency/social-engineering phrases detected."
    )
    return PhishingSignal(
        name="urgency_language",
        description=description,
        points=15,
        triggered=triggered,
    )


def _check_brand_mention_mismatch(visible_text: str, page_domain: str) -> PhishingSignal:
    """
    Flags a known brand name mentioned in the page's own text when the
    page's domain does not itself belong to that brand.

    "Belongs to" is judged by an EXACT match against the domain's primary
    label (e.g. "paypal" for both "paypal.com" and "mail.paypal.com" via
    _naive_domain), not by substring containment - a raw substring check
    would wrongly treat a look-alike domain like
    "paypal-secure-verify.example" as "being" PayPal, just because the
    substring "paypal" happens to appear in it.
    """
    lowered_text = visible_text.lower()
    domain_primary_label = (page_domain or "").lower().split(".")[0]
    mentioned = [brand for brand in KNOWN_BRANDS if brand in lowered_text]
    mismatched = [brand for brand in mentioned if brand != domain_primary_label]
    triggered = bool(mismatched)
    description = (
        f"Page mentions brand name(s) {', '.join(mismatched)} but the page's "
        f"own domain ('{page_domain}') does not belong to that brand."
        if triggered else "No brand-name/domain mismatch detected in page content."
    )
    return PhishingSignal(
        name="brand_mention_mismatch",
        description=description,
        points=20,
        triggered=triggered,
    )


def _classify(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_webpage(
    url: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> PageAnalysisResult:
    """
    Fetch `url` and analyze the returned page for phishing indicators.

    Input:  a URL string, plus optional timeout/max_redirects/
            max_response_bytes overrides.
    Output: a PageAnalysisResult. Never raises - every failure mode
            (invalid input, SSRF-blocked or unresolvable destination,
            timeout, network failure, non-HTML content, malformed HTML)
            is captured on the result instead of being propagated.
    """
    result = PageAnalysisResult(target_url=url)
    try:
        fetch, body, final_scheme, final_domain = _fetch_page(
            url, timeout=timeout, max_redirects=max_redirects,
            max_response_bytes=max_response_bytes,
        )
        result.fetch = fetch

        if not fetch.fetched:
            # Nothing was actually retrieved (blocked, error, or refused
            # redirect) - nothing to parse or score.
            result.phishing_risk_score = 0
            result.phishing_risk_level = "UNKNOWN"
            return result

        content_type = fetch.content_type or ""
        is_html = (not content_type) or ("text/html" in content_type.lower())

        forms: List[FormFinding] = []
        visible_text = ""
        if is_html:
            html_text = _decode_body(body, content_type)
            parser = _PageHTMLParser()
            try:
                parser.feed(html_text)
            except Exception:
                pass  # best-effort: malformed HTML must not crash analysis
            finally:
                parser.finalize()
            visible_text = parser.visible_text
            forms = [_build_form_finding(raw, final_domain) for raw in parser.forms]

        result.forms = forms
        signals = [
            _check_password_field(forms),
            _check_otp_or_card_field(forms),
            _check_external_form_action(forms),
            _check_password_over_http(forms, final_scheme),
            _check_urgency_language(visible_text),
            _check_brand_mention_mismatch(visible_text, final_domain or ""),
        ]
        result.signals = signals

        score = min(100, sum(s.points for s in signals if s.triggered))
        result.phishing_risk_score = score
        result.phishing_risk_level = _classify(score)
        return result
    except Exception as exc:  # absolute last resort: this must never raise
        result.error = f"unexpected error during page analysis: {exc}"
        return result
