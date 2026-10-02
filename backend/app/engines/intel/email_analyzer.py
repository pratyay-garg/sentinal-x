"""
intelligence/email_analyzer.py
---------------------------------
SentinelX - email phishing analyzer (Area 5 support).

This is a STANDALONE module, independent of url_analyzer.py,
reputation.py, and webpage_analyzer.py - it does not import from any of
them, and none of them import from it. Small reference lists (known
brand names, urgency phrases, credential-request phrases) are
intentionally duplicated here in miniature rather than imported, to keep
this module fully decoupled (matching the pattern already established by
webpage_analyzer.py relative to url_analyzer.py).

Purpose
-------
Given a raw email (RFC 5322 source text, as a str or bytes - e.g. the
contents of an .eml file), parse it with Python's standard `email`
library and inspect headers, body text, and attachment metadata for
common PHISHING / social-engineering indicators: a From/Reply-To domain
mismatch, a display name or body that impersonates a known brand while
the sender's own domain doesn't match, urgency language, credential/
OTP/payment-request phrasing, structurally suspicious sender domains,
links that point somewhere other than the claimed brand's domain, and
suspicious attachment file extensions. Returns a small, explainable,
JSON-serializable result with its own heuristic risk score - this is NOT
merged into any other module's score, and no other module is modified.

Design choices worth knowing about
-----------------------------------
* STRUCTURALLY NO NETWORK CAPABILITY. This module does not import
  urllib, socket, http, ftplib, or smtplib anywhere - not "doesn't use
  them", but doesn't import them at all. URLs found in the email are
  extracted as plain strings (via regex, never dereferenced) so a later,
  separate step could optionally hand them to url_analyzer.py /
  webpage_analyzer.py - this module itself never visits them. Hostname
  extraction from a found URL is done with a small local regex, not
  urllib.parse, specifically so "does this file import anything
  network-related" stays a simple, blunt, verifiable question (see
  test_email_analyzer.py's test_module_has_no_network_related_imports).
* NEVER READS ATTACHMENT CONTENT. Only the filename and declared
  content-type of an attachment part are ever read - this module never
  calls get_content()/get_payload(decode=True) on an attachment part, so
  attachment bytes are never decoded, inspected, or executed. A
  suspicious file extension is HEURISTIC EVIDENCE ONLY, never proof of
  malware - every such signal's own description says so explicitly.
* NEVER EXTRACTS OR STORES CREDENTIAL VALUES. The credential/OTP/payment
  check only looks for the PRESENCE of a small fixed list of known
  request phrases ("enter your password", "verify your otp", ...) - it
  never attempts to locate or capture a value near such a phrase, and no
  signal's evidence text is ever built from an arbitrary body excerpt;
  only fixed, known phrases are ever quoted back. (The email's own
  plain-text/HTML body is still returned verbatim as part of the result,
  same as an email client would show it - that's required, requested
  output, not something this module manufactures.)
* Every failure mode - unparseable input, a broken individual MIME part,
  or anything else - is caught and turned into a result field. The
  public analyze_email() function never raises.
* `EmailAnalysisResult.ai_interpretation` is a reserved field this tool
  never writes to - same convention as webpage_analyzer.py.
* Standard library only (email, re, dataclasses, typing) - no new
  third-party dependency.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Reference data (intentionally duplicated, not imported - see module
# docstring). Small and soft-signal only, same spirit as the other
# modules' own reference lists.
# ---------------------------------------------------------------------------

KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple",
    "netflix", "facebook", "instagram", "chase",
]

URGENCY_PHRASES = [
    "verify your account", "account has been suspended", "account suspended",
    "act now", "immediate action required", "unauthorized access",
    "unusual activity", "confirm your identity", "will be locked",
    "click here immediately", "limited time", "within 24 hours",
    "final notice", "your account will be closed", "avoid suspension",
    "permanently closed", "permanently deleted",
]

# Known REQUEST phrases only - matching presence of these fixed phrases,
# never extracting or storing any value that might follow them.
CREDENTIAL_REQUEST_PHRASES = [
    "enter your password", "verify your otp", "verify your one-time password",
    "confirm your pin", "confirm your card details", "update your card details",
    "enter your card number", "provide your social security number",
    "confirm your account password", "enter your one-time password",
    "verify your identity by entering", "reset your password by clicking",
    "enter your cvv", "confirm your password", "re-enter your password",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear valued member", "dear account holder", "dear sir/madam",
    "dear member",
]

# Filename EXTENSIONS only - never inspected content. Heuristic evidence,
# not proof of malware (see _check_suspicious_attachment()).
SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar",
    ".lnk", ".msi", ".ps1", ".pif", ".hta", ".wsf",
]

DEFAULT_MAX_BODY_BYTES = 200_000

DISCLAIMER = (
    "This is a HEURISTIC phishing-indicator score based on email headers, "
    "structure, and wording. It is NOT proof that an email is a phishing "
    "email or is safe, does not verify sender identity, does not open or "
    "execute attachments, and should not be the sole basis for any "
    "security decision."
)

# Matches an http(s) URL up to (not including) common trailing punctuation
# or whitespace. Extraction only - this string is never fetched or
# otherwise dereferenced by this module.
_URL_REGEX = re.compile(r'https?://[^\s<>"\'\)\]]+', re.IGNORECASE)
_HREF_REGEX = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
# A tiny, local, non-network hostname extractor for an already-extracted
# URL string - deliberately not urllib.parse, so this module can
# truthfully say it imports nothing URL/network-related at all.
_URL_HOSTNAME_REGEX = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://(?:[^@/]*@)?([^/:?#]+)')


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------

@dataclass
class ParsedAddress:
    """One parsed address from a From/Reply-To header."""
    raw: str = ""
    display_name: Optional[str] = None
    address: Optional[str] = None
    domain: Optional[str] = None


@dataclass
class EmailContent:
    """Everything extracted from the email, before any scoring. Body
    text is included verbatim (same as an email client would show it);
    attachment content is never read - filenames/types only."""
    subject: Optional[str] = None
    from_address: Optional[ParsedAddress] = None
    reply_to_address: Optional[ParsedAddress] = None
    plain_text_body: str = ""
    html_body: str = ""
    urls_found: List[str] = field(default_factory=list)
    attachment_filenames: List[str] = field(default_factory=list)
    has_attachments: bool = False
    truncated: bool = False
    parse_error: Optional[str] = None


@dataclass
class EmailSignal:
    """Same 4-field shape as the other modules' signal classes, kept as
    a separate class so this module has zero import dependency on them."""
    name: str
    description: str
    points: int
    triggered: bool


@dataclass
class EmailAnalysisResult:
    """
    Structured, JSON-serializable result of an email phishing analysis.

    Every field except `ai_interpretation` is mechanical, tool-generated
    evidence. `ai_interpretation` is reserved for a future AI-based
    interpretation layer and is NEVER populated by this module.
    """
    content: EmailContent = field(default_factory=EmailContent)
    signals: List[EmailSignal] = field(default_factory=list)
    email_risk_score: int = 0
    email_risk_level: str = "UNKNOWN"
    error: Optional[str] = None
    disclaimer: str = DISCLAIMER
    # Reserved for a future AI-interpretation layer. This tool NEVER
    # writes to this field.
    ai_interpretation: Optional[str] = None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_raw_email(raw_email) -> Tuple[Optional["email.message.EmailMessage"], Optional[str]]:
    """Parse raw email source text/bytes using the standard library.
    Never raises - returns (None, error_message) on any failure."""
    if raw_email is None:
        return None, "no email content provided"
    try:
        if isinstance(raw_email, bytes):
            if not raw_email.strip():
                return None, "no email content provided"
            msg = email.message_from_bytes(raw_email, policy=email.policy.default)
        elif isinstance(raw_email, str):
            if not raw_email.strip():
                return None, "no email content provided"
            msg = email.message_from_string(raw_email, policy=email.policy.default)
        else:
            return None, f"unsupported input type: {type(raw_email).__name__}"
        return msg, None
    except Exception as exc:  # the stdlib parser is lenient, but stay defensive
        return None, f"failed to parse email: {exc}"


def _parse_address(raw_header_value: Optional[str]) -> Optional[ParsedAddress]:
    """Parse a From/Reply-To header value into display name + address +
    domain. Returns None if the header is absent - callers must handle
    that, not assume an address is always present."""
    if not raw_header_value:
        return None
    try:
        display_name, address = email.utils.parseaddr(str(raw_header_value))
    except Exception:
        return ParsedAddress(raw=str(raw_header_value))
    address = address.lower().strip() if address else None
    domain = None
    if address and "@" in address:
        domain = address.split("@", 1)[1].strip().lower() or None
    return ParsedAddress(
        raw=str(raw_header_value),
        display_name=display_name or None,
        address=address or None,
        domain=domain,
    )


def _naive_domain(hostname: str) -> str:
    """Minimal registrable-domain extraction: last two dot-separated
    labels. Same simplified approach (and same documented limitation
    re: multi-part suffixes like .co.uk) as webpage_analyzer.py's
    version - this is a secondary/comparative signal here, not the
    primary risk driver."""
    if not hostname:
        return ""
    labels = hostname.lower().strip().split(".")
    if len(labels) <= 2:
        return hostname.lower().strip()
    return ".".join(labels[-2:])


def _iter_parts(msg):
    """Yield every part of the message, or just the message itself if
    it isn't multipart. Never raises."""
    try:
        if msg.is_multipart():
            return list(msg.walk())
        return [msg]
    except Exception:
        return []


def _extract_bodies(msg, max_body_bytes: int) -> Tuple[str, str, bool]:
    """
    Walk the message and collect text/plain and text/html parts
    (skipping attachment-disposition parts), each independently bounded
    by max_body_bytes. Never raises - a broken individual part is
    skipped, not fatal to the rest.

    Output: (plain_text_body, html_body, truncated).
    """
    plain_parts: List[str] = []
    html_parts: List[str] = []
    plain_total = 0
    html_total = 0
    truncated = False

    for part in _iter_parts(msg):
        try:
            content_type = part.get_content_type()
        except Exception:
            continue
        try:
            disposition = (part.get_content_disposition() or "").lower()
        except Exception:
            disposition = ""
        if disposition == "attachment":
            continue
        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            text = part.get_content()
            if not isinstance(text, str):
                text = str(text)
        except Exception:
            try:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = ""

        if content_type == "text/plain":
            remaining = max_body_bytes - plain_total
            if remaining <= 0:
                truncated = True
                continue
            chunk = text[:remaining]
            if len(text) > remaining:
                truncated = True
            plain_parts.append(chunk)
            plain_total += len(chunk)
        else:
            remaining = max_body_bytes - html_total
            if remaining <= 0:
                truncated = True
                continue
            chunk = text[:remaining]
            if len(text) > remaining:
                truncated = True
            html_parts.append(chunk)
            html_total += len(chunk)

    return "".join(plain_parts), "".join(html_parts), truncated


def _extract_attachment_filenames(msg) -> List[str]:
    """
    Collect ONLY filename + declared content-type for attachment-
    disposition parts. This never calls get_content()/get_payload() on
    an attachment part - attachment bytes are never read, decoded, or
    executed by this function or anywhere else in this module.
    """
    filenames: List[str] = []
    for part in _iter_parts(msg):
        try:
            disposition = (part.get_content_disposition() or "").lower()
        except Exception:
            disposition = ""
        if disposition != "attachment":
            continue
        try:
            filename = part.get_filename()
        except Exception:
            filename = None
        if filename:
            filenames.append(str(filename))
        else:
            try:
                ctype = part.get_content_type()
            except Exception:
                ctype = "unknown"
            filenames.append(f"(unnamed attachment: {ctype})")
    return filenames


def _extract_urls(plain_text: str, html_body: str) -> List[str]:
    """
    Extract URL strings from the plain-text and HTML bodies via regex
    only. These URLs are NEVER dereferenced/fetched by this module -
    they are returned as plain strings for a possible future step to
    hand elsewhere.
    """
    candidates: List[str] = []
    candidates.extend(_URL_REGEX.findall(plain_text or ""))
    candidates.extend(_HREF_REGEX.findall(html_body or ""))
    candidates.extend(_URL_REGEX.findall(html_body or ""))

    seen = set()
    deduped: List[str] = []
    for candidate in candidates:
        cleaned = candidate.strip().rstrip(").,;'\"")
        lowered = cleaned.lower()
        if lowered.startswith(("http://", "https://")) and cleaned not in seen:
            seen.add(cleaned)
            deduped.append(cleaned)
    return deduped


def _hostname_from_url(url: str) -> Optional[str]:
    """Extract just the hostname from a URL string via regex - no
    urllib.parse, so this module stays free of any URL/network-related
    import (see module docstring)."""
    match = _URL_HOSTNAME_REGEX.match(url or "")
    if not match:
        return None
    return match.group(1).lower().strip() or None


# ---------------------------------------------------------------------------
# Heuristic checks - each always returns a signal, triggered or not, same
# convention as the other modules' checks.
# ---------------------------------------------------------------------------

def _check_sender_replyto_mismatch(
    from_addr: Optional[ParsedAddress], reply_to_addr: Optional[ParsedAddress],
) -> EmailSignal:
    triggered = False
    if from_addr and from_addr.domain and reply_to_addr and reply_to_addr.domain:
        triggered = _naive_domain(from_addr.domain) != _naive_domain(reply_to_addr.domain)
    description = (
        f"Reply-To domain ('{reply_to_addr.domain}') differs from the From "
        f"domain ('{from_addr.domain}')."
        if triggered else "Reply-To domain (if present) matches the From domain."
    )
    return EmailSignal("sender_replyto_mismatch", description, 20, triggered)


def _check_display_name_brand_impersonation(from_addr: Optional[ParsedAddress]) -> EmailSignal:
    triggered = False
    matched_brand = None
    if from_addr and from_addr.display_name:
        lowered_name = from_addr.display_name.lower()
        domain_label = _naive_domain(from_addr.domain or "").split(".")[0] if from_addr.domain else ""
        for brand in KNOWN_BRANDS:
            if brand in lowered_name and brand != domain_label:
                triggered = True
                matched_brand = brand
                break
    description = (
        f"Display name mentions '{matched_brand}' but the sender address domain "
        f"('{from_addr.domain if from_addr else None}') does not belong to that brand."
        if triggered else
        "Display name (if present) does not claim a brand mismatched with the sender domain."
    )
    return EmailSignal("display_name_brand_impersonation", description, 25, triggered)


def _check_brand_mention_mismatch(
    subject: Optional[str], plain_text_body: str, from_addr: Optional[ParsedAddress],
) -> EmailSignal:
    text = f"{subject or ''} {plain_text_body or ''}".lower()
    domain_label = ""
    if from_addr and from_addr.domain:
        domain_label = _naive_domain(from_addr.domain).split(".")[0]
    mismatched = [brand for brand in KNOWN_BRANDS if brand in text and brand != domain_label]
    triggered = bool(mismatched)
    sender_domain = from_addr.domain if from_addr else None
    description = (
        f"Email mentions brand name(s) {', '.join(mismatched)} but the sender "
        f"domain ('{sender_domain}') does not belong to that brand."
        if triggered else "No brand-name/sender-domain mismatch detected in subject or body."
    )
    return EmailSignal("brand_mention_mismatch", description, 20, triggered)


def _check_urgency_language(subject: Optional[str], plain_text_body: str) -> EmailSignal:
    text = f"{subject or ''} {plain_text_body or ''}".lower()
    matched = [phrase for phrase in URGENCY_PHRASES if phrase in text]
    triggered = bool(matched)
    description = (
        f"Urgency/social-engineering phrases found: {', '.join(matched[:5])}."
        if triggered else "No urgency/social-engineering phrases detected."
    )
    return EmailSignal("urgency_language", description, 15, triggered)


def _check_credential_or_otp_request(plain_text_body: str, html_body: str) -> EmailSignal:
    text = f"{plain_text_body or ''} {html_body or ''}".lower()
    matched = [phrase for phrase in CREDENTIAL_REQUEST_PHRASES if phrase in text]
    triggered = bool(matched)
    description = (
        f"Phrase(s) requesting credentials/OTP/payment details found: "
        f"{', '.join(matched[:5])}. (Only presence of these known fixed phrases "
        "is checked - no value is ever extracted or stored.)"
        if triggered else "No credential/OTP/payment-request phrases detected."
    )
    return EmailSignal("credential_or_otp_request", description, 25, triggered)


def _check_suspicious_sender_domain(from_addr: Optional[ParsedAddress]) -> EmailSignal:
    triggered = False
    reasons: List[str] = []
    if from_addr and from_addr.domain:
        domain = from_addr.domain.lower()
        labels = domain.split(".")
        if len(labels) > 4:
            triggered = True
            reasons.append(f"unusually many subdomains ({len(labels)} labels)")
        if re.search(r"\d{4,}", domain):
            triggered = True
            reasons.append("long numeric sequence in domain")
    description = (
        "Sender domain has suspicious characteristics: " + "; ".join(reasons) + "."
        if triggered else "No suspicious sender-domain characteristics detected."
    )
    return EmailSignal("suspicious_sender_domain", description, 15, triggered)


def _check_link_domain_mismatch(
    from_addr: Optional[ParsedAddress], urls_found: List[str],
) -> EmailSignal:
    """
    Flags a link whose domain doesn't match the sender's - but ONLY when
    the sender's OWN domain already equals a known brand (e.g. a
    genuinely-addressed "paypal.com" sender linking somewhere else
    entirely). This is deliberately narrow: a plain "link domain !=
    sender domain" check would false-positive on almost every ordinary
    email (trackers, CDNs, unsubscribe links, etc.).
    """
    triggered = False
    mismatched_domains = set()
    sender_domain_label = None
    if from_addr and from_addr.domain:
        sender_domain_label = _naive_domain(from_addr.domain).split(".")[0]

    if sender_domain_label and sender_domain_label in KNOWN_BRANDS:
        for url in urls_found:
            hostname = _hostname_from_url(url)
            if not hostname:
                continue
            link_domain_label = _naive_domain(hostname).split(".")[0]
            if link_domain_label != sender_domain_label:
                triggered = True
                mismatched_domains.add(link_domain_label)

    description = (
        f"Email claims to be from '{sender_domain_label}' but contains link(s) "
        f"to a different domain: {', '.join(sorted(mismatched_domains))}."
        if triggered else "No link-domain/sender-domain mismatch detected (or not applicable)."
    )
    return EmailSignal("link_domain_mismatch", description, 20, triggered)


def _check_suspicious_attachment(attachment_filenames: List[str]) -> EmailSignal:
    matched = []
    for name in attachment_filenames:
        lowered = name.lower()
        if any(lowered.endswith(ext) for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS):
            matched.append(name)
    triggered = bool(matched)
    description = (
        f"Attachment(s) with suspicious file extension(s): {', '.join(matched)}. "
        "This is HEURISTIC EVIDENCE based on filename/extension only, NOT proof "
        "of malware - attachment content is never opened, read, or executed by "
        "this tool."
        if triggered else "No suspicious attachment file extensions detected."
    )
    return EmailSignal("suspicious_attachment_extension", description, 30, triggered)


def _check_generic_greeting(plain_text_body: str) -> EmailSignal:
    text = (plain_text_body or "").lower()
    matched = [greeting for greeting in GENERIC_GREETINGS if greeting in text]
    triggered = bool(matched)
    description = (
        f"Generic, non-personalized greeting detected: '{matched[0]}'."
        if triggered else "No generic/impersonal greeting detected."
    )
    return EmailSignal("generic_greeting", description, 5, triggered)


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

def analyze_email(
    raw_email,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> EmailAnalysisResult:
    """
    Parse and analyze a raw email (str or bytes, RFC 5322 source text)
    for phishing/social-engineering indicators.

    Input:  raw email source, plus an optional max_body_bytes override.
    Output: an EmailAnalysisResult. Never raises - unparseable input, a
            broken individual MIME part, or any other failure is
            captured on the result instead of being propagated.
    """
    result = EmailAnalysisResult()
    try:
        msg, parse_error = _parse_raw_email(raw_email)
        if msg is None:
            result.content = EmailContent(parse_error=parse_error)
            result.error = parse_error
            result.email_risk_score = 0
            result.email_risk_level = "UNKNOWN"
            return result

        try:
            subject = msg.get("Subject")
            subject = str(subject) if subject is not None else None
        except Exception:
            subject = None

        try:
            from_addr = _parse_address(msg.get("From"))
        except Exception:
            from_addr = None
        try:
            reply_to_addr = _parse_address(msg.get("Reply-To"))
        except Exception:
            reply_to_addr = None

        plain_text_body, html_body, truncated = _extract_bodies(msg, max_body_bytes)
        attachment_filenames = _extract_attachment_filenames(msg)
        urls_found = _extract_urls(plain_text_body, html_body)

        result.content = EmailContent(
            subject=subject,
            from_address=from_addr,
            reply_to_address=reply_to_addr,
            plain_text_body=plain_text_body,
            html_body=html_body,
            urls_found=urls_found,
            attachment_filenames=attachment_filenames,
            has_attachments=bool(attachment_filenames),
            truncated=truncated,
            parse_error=None,
        )

        signals = [
            _check_sender_replyto_mismatch(from_addr, reply_to_addr),
            _check_display_name_brand_impersonation(from_addr),
            _check_brand_mention_mismatch(subject, plain_text_body, from_addr),
            _check_urgency_language(subject, plain_text_body),
            _check_credential_or_otp_request(plain_text_body, html_body),
            _check_suspicious_sender_domain(from_addr),
            _check_link_domain_mismatch(from_addr, urls_found),
            _check_suspicious_attachment(attachment_filenames),
            _check_generic_greeting(plain_text_body),
        ]
        result.signals = signals

        score = min(100, sum(s.points for s in signals if s.triggered))
        result.email_risk_score = score
        result.email_risk_level = _classify(score)
        return result
    except Exception as exc:  # absolute last resort: this must never raise
        result.error = f"unexpected error during email analysis: {exc}"
        return result
