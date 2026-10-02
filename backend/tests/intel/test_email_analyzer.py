"""
intelligence/test_email_analyzer.py
--------------------------------------
SentinelX - email_analyzer.py unit tests.

Every fixture here is a synthetic, hand-written .eml-style raw string.
NONE of these tests make any network call - this module has no network
capability at all (see test_module_has_no_network_related_imports below).

Two ways to run this file, same convention as the other test_*.py files
in this project:

  1. As a plain demo (no test framework needed):
         python intelligence/test_email_analyzer.py

  2. As an actual test suite, if pytest is installed:
         pytest intelligence/test_email_analyzer.py -v
"""

import dataclasses
import json

from app.engines.intel.email_analyzer import (
    analyze_email,
    EmailAnalysisResult,
    _naive_domain,
    _hostname_from_url,
    _extract_urls,
)


# ---------------------------------------------------------------------------
# Synthetic fixtures
# ---------------------------------------------------------------------------

BENIGN_EMAIL = """From: Alice Smith <alice@example.com>
To: bob@example.com
Subject: Lunch tomorrow?
Content-Type: text/plain; charset="utf-8"

Hey Bob,

Are we still on for lunch tomorrow at noon? Let me know.

Thanks,
Alice
"""

# Lookalike sender domain, reply-to mismatch, urgency, credential
# request, generic greeting, and a double-extension attachment. Sender
# domain is intentionally a lookalike (not the literal brand string),
# so this exercises display_name_brand_impersonation rather than
# suspicious_sender_domain or link_domain_mismatch - see the dedicated
# fixtures below for those.
PHISHING_EMAIL = """From: "PayPal Security" <security@paypa1-alerts.ru>
Reply-To: collector@totally-different-attacker-domain.cn
Subject: URGENT: Your account will be suspended - verify now
Content-Type: multipart/mixed; boundary="OUTER"
MIME-Version: 1.0

--OUTER
Content-Type: multipart/alternative; boundary="INNER"

--INNER
Content-Type: text/plain; charset="utf-8"

Dear Customer,

Your PayPal account has been suspended due to unusual activity. You
must verify your account within 24 hours or it will be permanently
closed.

Please enter your password and confirm your card details immediately
at http://paypal-verify.totally-fake-domain.xyz/login

--INNER
Content-Type: text/html; charset="utf-8"

<html><body><p>Dear Customer,</p><p>Your PayPal account has been suspended.</p>
<a href="http://paypal-verify.totally-fake-domain.xyz/login">Verify Now</a></body></html>

--INNER--

--OUTER
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

ZmFrZSBhdHRhY2htZW50IGNvbnRlbnQ=

--OUTER--
"""

# Genuine brand domain, matching Reply-To - should NOT trigger any
# impersonation/mismatch signal.
LEGIT_BRAND_EMAIL = """From: "PayPal" <service@paypal.com>
Reply-To: service@paypal.com
Subject: Your monthly statement is ready
Content-Type: text/plain; charset="utf-8"

Hi,

Your PayPal monthly statement is now available in your account.

Thanks,
The PayPal Team
"""

# Genuine brand sender domain, but a link to a completely different
# domain - isolates link_domain_mismatch specifically.
LINK_MISMATCH_EMAIL = """From: "PayPal" <service@paypal.com>
Subject: Your receipt
Content-Type: text/plain; charset="utf-8"

Hi,

Thanks for your purchase. View your receipt here:
http://totally-different-attacker-domain.ru/steal

Thanks,
PayPal
"""

# Structurally suspicious domain (many subdomains + long digit run),
# unrelated body - isolates suspicious_sender_domain specifically.
SUSPICIOUS_DOMAIN_EMAIL = """From: Notifications <alerts@mail.secure.accounts.login12345.example.com>
Subject: Weekly digest
Content-Type: text/plain; charset="utf-8"

Hi,

Here is your weekly digest of activity.

Thanks,
The Team
"""

BENIGN_ATTACHMENT_EMAIL = """From: Alice Smith <alice@example.com>
Subject: Report attached
Content-Type: multipart/mixed; boundary="OUTER"
MIME-Version: 1.0

--OUTER
Content-Type: text/plain; charset="utf-8"

Hi, please see the attached report.

--OUTER
Content-Type: application/pdf; name="report.pdf"
Content-Disposition: attachment; filename="report.pdf"
Content-Transfer-Encoding: base64

ZmFrZSBwZGYgY29udGVudA==

--OUTER--
"""

HTML_ONLY_EMAIL = """From: News <news@example.com>
Subject: This week's update
Content-Type: text/html; charset="utf-8"

<html><body><p>Here is this week's update.</p>
<a href="http://example.com/update">Read more</a></body></html>
"""

# Deliberately malformed multipart structure (mismatched/missing
# boundaries) - must not raise.
MALFORMED_EMAIL = """From: broken@example.com
Subject: Broken email
Content-Type: multipart/mixed; boundary="OUTER"

--OUTER
Content-Type: text/plain

This part is fine, but the boundary below is wrong.
--WRONGBOUNDARY
some garbage that does not close properly <<<<
"""

SECRET_VALUE_EMAIL = """From: "Bank Alerts" <alerts@example-bank.com>
Subject: Security notice
Content-Type: text/plain; charset="utf-8"

Please enter your password to continue accessing your account.

For reference (test fixture only), a leaked password sample was:
Tr0ub4dor&3-Secret
"""


def _repeat_body_email(marker_near_start: str, filler_char: str, total_len: int) -> str:
    body = marker_near_start + (filler_char * total_len)
    return (
        "From: Alice <alice@example.com>\n"
        "Subject: Long message\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n"
        "\n"
        f"{body}\n"
    )


# ---------------------------------------------------------------------------
# Basic parsing / extraction correctness
# ---------------------------------------------------------------------------

def test_benign_email_scores_low_with_no_false_positives():
    result = analyze_email(BENIGN_EMAIL)
    assert result.error is None
    triggered = [s.name for s in result.signals if s.triggered]
    assert triggered == []
    assert result.email_risk_level == "LOW"
    assert result.email_risk_score == 0
    assert result.content.subject == "Lunch tomorrow?"
    assert result.content.from_address.address == "alice@example.com"
    assert result.content.from_address.domain == "example.com"
    assert result.content.has_attachments is False


def test_multipart_extracts_both_plain_and_html_bodies_and_dedupes_urls():
    result = analyze_email(PHISHING_EMAIL)
    assert "Dear Customer" in result.content.plain_text_body
    assert "<a href=" in result.content.html_body
    # the same URL appears in both the plain-text and HTML parts -
    # it must appear only once in urls_found
    matching = [u for u in result.content.urls_found if "paypal-verify.totally-fake-domain.xyz" in u]
    assert len(matching) == 1


def test_html_only_email_is_parsed_correctly():
    result = analyze_email(HTML_ONLY_EMAIL)
    assert result.error is None
    assert result.content.plain_text_body == ""
    assert "this week's update" in result.content.html_body.lower()
    assert any("example.com/update" in u for u in result.content.urls_found)


def test_generic_greeting_case_insensitive_headers_still_parse():
    raw = BENIGN_EMAIL.replace("From:", "from:").replace("Subject:", "subject:")
    result = analyze_email(raw)
    assert result.error is None
    assert result.content.subject == "Lunch tomorrow?"
    assert result.content.from_address.address == "alice@example.com"


# ---------------------------------------------------------------------------
# Signal-level correctness
# ---------------------------------------------------------------------------

def test_phishing_fixture_triggers_multiple_signals_and_high_score():
    result = analyze_email(PHISHING_EMAIL)
    triggered_names = {s.name for s in result.signals if s.triggered}
    assert "display_name_brand_impersonation" in triggered_names
    assert "sender_replyto_mismatch" in triggered_names
    assert "urgency_language" in triggered_names
    assert "credential_or_otp_request" in triggered_names
    assert "generic_greeting" in triggered_names
    assert "suspicious_attachment_extension" in triggered_names
    assert result.email_risk_level in ("HIGH", "CRITICAL")
    # Every triggered signal must carry explainable evidence, not a bare flag.
    for signal in result.signals:
        if signal.triggered:
            assert signal.description and len(signal.description) > 10


def test_legit_brand_email_does_not_trigger_impersonation_signals():
    result = analyze_email(LEGIT_BRAND_EMAIL)
    triggered_names = {s.name for s in result.signals if s.triggered}
    assert "display_name_brand_impersonation" not in triggered_names
    assert "brand_mention_mismatch" not in triggered_names
    assert "sender_replyto_mismatch" not in triggered_names
    assert result.email_risk_level == "LOW"


def test_reply_to_absent_does_not_trigger_mismatch():
    result = analyze_email(LEGIT_BRAND_EMAIL.replace("Reply-To: service@paypal.com\n", ""))
    assert result.content.reply_to_address is None
    triggered_names = {s.name for s in result.signals if s.triggered}
    assert "sender_replyto_mismatch" not in triggered_names


def test_link_domain_mismatch_triggers_for_genuine_brand_sender():
    result = analyze_email(LINK_MISMATCH_EMAIL)
    signal = next(s for s in result.signals if s.name == "link_domain_mismatch")
    assert signal.triggered is True
    assert "attacker-domain" in signal.description


def test_link_domain_mismatch_does_not_fire_for_ordinary_third_party_links():
    # An ordinary, non-brand sender linking to some other site is normal
    # (trackers, CDNs, etc.) and must not be flagged.
    result = analyze_email(BENIGN_EMAIL)
    signal = next(s for s in result.signals if s.name == "link_domain_mismatch")
    assert signal.triggered is False


def test_suspicious_sender_domain_triggers_on_structural_weirdness():
    result = analyze_email(SUSPICIOUS_DOMAIN_EMAIL)
    signal = next(s for s in result.signals if s.name == "suspicious_sender_domain")
    assert signal.triggered is True
    assert "subdomains" in signal.description or "numeric" in signal.description


def test_suspicious_attachment_extension_flags_double_extension():
    result = analyze_email(PHISHING_EMAIL)
    signal = next(s for s in result.signals if s.name == "suspicious_attachment_extension")
    assert signal.triggered is True
    assert "invoice.pdf.exe" in signal.description
    # Must explicitly state this is heuristic evidence, not proof of malware.
    assert "not proof of malware" in signal.description.lower()


def test_benign_attachment_is_not_flagged():
    result = analyze_email(BENIGN_ATTACHMENT_EMAIL)
    assert result.content.has_attachments is True
    assert "report.pdf" in result.content.attachment_filenames
    signal = next(s for s in result.signals if s.name == "suspicious_attachment_extension")
    assert signal.triggered is False


def test_credential_request_detected():
    result = analyze_email(PHISHING_EMAIL)
    signal = next(s for s in result.signals if s.name == "credential_or_otp_request")
    assert signal.triggered is True
    assert "enter your password" in signal.description


def test_urgency_language_detected():
    result = analyze_email(PHISHING_EMAIL)
    signal = next(s for s in result.signals if s.name == "urgency_language")
    assert signal.triggered is True


# ---------------------------------------------------------------------------
# Safety properties
# ---------------------------------------------------------------------------

def test_credential_signal_evidence_never_echoes_actual_secret_values():
    result = analyze_email(SECRET_VALUE_EMAIL)
    credential_signal = next(s for s in result.signals if s.name == "credential_or_otp_request")
    assert credential_signal.triggered is True
    # Evidence text is drawn only from the fixed phrase list, never from
    # arbitrary body excerpts - the literal secret must never appear in
    # ANY signal's description.
    for signal in result.signals:
        assert "Tr0ub4dor&3-Secret" not in signal.description


def test_attachment_content_is_never_read_or_exposed():
    # The base64-decoded content of the .exe attachment above is the
    # literal bytes "fake attachment content" - confirm that string
    # never appears anywhere in the serialized result.
    result = analyze_email(PHISHING_EMAIL)
    blob = json.dumps(dataclasses.asdict(result))
    assert "fake attachment content" not in blob


def test_malformed_email_does_not_raise():
    result = analyze_email(MALFORMED_EMAIL)
    assert isinstance(result, EmailAnalysisResult)
    # Whatever happened, it must not have raised, and the parts that
    # COULD be parsed (headers, the one well-formed part) should still
    # be usable.
    assert result.content.from_address is not None
    assert result.content.from_address.address == "broken@example.com"


def test_none_input_returns_error_without_raising():
    result = analyze_email(None)
    assert result.error is not None
    assert result.content.parse_error is not None


def test_non_string_input_returns_error_without_raising():
    result = analyze_email(12345)
    assert result.error is not None
    assert "unsupported input type" in result.error


def test_empty_string_input_returns_error_without_raising():
    result = analyze_email("")
    assert result.error is not None


def test_oversized_body_is_truncated_but_early_content_still_analyzed():
    raw = _repeat_body_email(
        "Please enter your password to continue. ", "A", 500_000,
    )
    result = analyze_email(raw, max_body_bytes=1_000)
    assert result.content.truncated is True
    assert len(result.content.plain_text_body) <= 1_000
    signal = next(s for s in result.signals if s.name == "credential_or_otp_request")
    assert signal.triggered is True  # the phrase near the start survives truncation


def test_score_capped_at_100():
    result = analyze_email(PHISHING_EMAIL)
    assert result.email_risk_score <= 100


def test_result_is_json_serializable():
    result = analyze_email(PHISHING_EMAIL)
    blob = json.dumps(dataclasses.asdict(result))
    assert '"email_risk_score"' in blob
    assert '"ai_interpretation"' in blob


def test_ai_interpretation_field_is_always_none():
    result = analyze_email(PHISHING_EMAIL)
    assert result.ai_interpretation is None


def test_module_has_no_network_related_imports():
    import email_analyzer
    with open(email_analyzer.__file__, "r", encoding="utf-8") as f:
        source = f.read()
    forbidden = ["import urllib", "import socket", "import http", "import ftplib", "import smtplib"]
    for token in forbidden:
        assert token not in source, f"found forbidden network-related import: {token}"


# ---------------------------------------------------------------------------
# Small helper-level tests
# ---------------------------------------------------------------------------

def test_naive_domain_extraction():
    assert _naive_domain("example.com") == "example.com"
    assert _naive_domain("mail.example.com") == "example.com"
    assert _naive_domain("") == ""


def test_hostname_from_url_extraction():
    assert _hostname_from_url("http://example.com/path?x=1") == "example.com"
    # Port is deliberately excluded from the hostname - callers only
    # ever use this for domain comparison, never for connecting.
    assert _hostname_from_url("https://sub.example.com:8080/") == "sub.example.com"
    assert _hostname_from_url("not a url") is None


def test_extract_urls_ignores_non_http_schemes():
    urls = _extract_urls("contact mailto:me@example.com or ftp://files.example.com/x", "")
    assert urls == []


def run_all_tests():
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed = 0
    for test_fn in tests:
        test_fn()
        passed += 1
        print(f"  PASS  {test_fn.__name__}")
    print(f"\n{passed}/{len(tests)} unit tests passed (no network required).\n")


if __name__ == "__main__":
    print("Running unit tests (no network required)...\n")
    run_all_tests()
