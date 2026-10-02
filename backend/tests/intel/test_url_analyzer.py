"""
test_url_analyzer.py
---------------------
SentinelX - URL Analyzer v0.1 test / demo script.

Two ways to run this file:

  1. As a plain demo (no test framework needed):
         python intelligence/test_url_analyzer.py

  2. As an actual test suite, if pytest is installed:
         pytest intelligence/test_url_analyzer.py -v

Every function named test_* uses plain `assert` statements, so it works
either way with zero extra dependencies.
"""

import dataclasses
import json
import socket
import os

from unittest.mock import patch, MagicMock
import urllib.error

from app.engines.intel.url_analyzer import (
    analyze_url,
    parse_url,
    resolve_dns,
    calculate_risk_score,
    classify_risk,
    InvalidURLError,
    HeuristicSignal,
    DNSInfo,
    TLSInfo,
    _check_ip_as_hostname,
    _check_typosquatting,
    _check_suspicious_characters,
    analyze_redirect_chain,
    RedirectChainResult,
    _has_embedded_credentials,
    _check_redirect_destination_safety,
    _check_redirect_risks,
    _DestinationUnresolvable,
    ReputationResult,
)


# ---------------------------------------------------------------------------
# Small, fast unit tests - no network required.
# ---------------------------------------------------------------------------

def test_parse_valid_url():
    components = parse_url("https://mail.example.com/login")
    assert components.scheme == "https"
    assert components.hostname == "mail.example.com"
    assert components.domain == "example.com"
    assert components.path == "/login"


def test_domain_extraction_plain_domain_unchanged():
    components = parse_url("https://example.com/")
    assert components.domain == "example.com"


def test_domain_extraction_multi_part_public_suffix():
    components = parse_url("https://example.co.uk/")
    assert components.domain == "example.co.uk"


def test_domain_extraction_subdomain_with_multi_part_public_suffix():
    components = parse_url("https://mail.example.co.uk/")
    assert components.domain == "example.co.uk"


def test_domain_extraction_ip_address_unchanged():
    components = parse_url("http://192.168.10.5/login")
    assert components.domain == "192.168.10.5"


def test_parse_rejects_unsupported_scheme():
    try:
        parse_url("ftp://example.com/file")
        assert False, "Expected InvalidURLError for an ftp:// URL"
    except InvalidURLError:
        pass


def test_parse_rejects_empty_string():
    try:
        parse_url("   ")
        assert False, "Expected InvalidURLError for an empty URL"
    except InvalidURLError:
        pass


def test_risk_score_is_sum_of_triggered_points_capped_at_100():
    signals = [
        HeuristicSignal("a", "desc", 40, True),
        HeuristicSignal("b", "desc", 40, True),
        HeuristicSignal("c", "desc", 40, True),   # would total 120
        HeuristicSignal("d", "desc", 50, False),  # not triggered, ignored
    ]
    assert calculate_risk_score(signals) == 100  # capped


def test_classify_risk_thresholds():
    assert classify_risk(0) == "LOW"
    assert classify_risk(24) == "LOW"
    assert classify_risk(25) == "MEDIUM"
    assert classify_risk(49) == "MEDIUM"
    assert classify_risk(50) == "HIGH"
    assert classify_risk(74) == "HIGH"
    assert classify_risk(75) == "CRITICAL"
    assert classify_risk(100) == "CRITICAL"


def test_analyze_url_never_raises_on_garbage_input():
    result = analyze_url("not a url at all")
    assert result.error is not None
    assert result.risk_level == "UNKNOWN"


def test_resolve_dns_handles_bad_hostname_gracefully():
    info = resolve_dns("this-domain-should-not-exist-sentinelx-test.invalid")
    assert info.resolved is False
    assert info.error is not None


def test_ip_as_hostname_is_flagged_and_domain_is_the_ip():
    components = parse_url("http://192.168.10.5/login")
    assert components.domain == "192.168.10.5"  # not a mangled fake domain like "10.5"
    assert _check_ip_as_hostname(components).triggered is True


def test_typosquat_exact_brand_domain_is_not_flagged():
    components = parse_url("https://paypal.com/signin")
    assert _check_typosquatting(components).triggered is False


def test_typosquat_character_substitution_is_flagged():
    components = parse_url("https://paypa1.com/signin")  # "1" instead of "l"
    assert _check_typosquatting(components).triggered is True


def test_typosquat_embedded_brand_name_is_flagged():
    components = parse_url("https://paypal-secure.info/login")
    assert _check_typosquatting(components).triggered is True


def test_non_ascii_hostname_is_flagged():
    components = parse_url("http://\u0430pple.com/login")  # Cyrillic 'a', not Latin
    assert _check_suspicious_characters(components).triggered is True


def test_port_is_extracted_from_url():
    components = parse_url("https://example.com:8443/secure")
    assert components.port == 8443


def test_trailing_dot_in_hostname_is_normalized():
    components = parse_url("https://example.com./login")
    assert components.hostname == "example.com"
    assert components.domain == "example.com"


# ---------------------------------------------------------------------------
# Redirect-chain analysis tests - all deterministic, NO real network calls.
#
# DNS resolution and the HTTP opener are both mocked, so these test the
# chain-following LOGIC (hop tracking, domain/protocol-change detection,
# excessive-redirect bounding, and safety blocking) without depending on
# any external site being reachable or behaving a particular way.
# ---------------------------------------------------------------------------

import email.message


def _http_error(code, location=None):
    """Build a urllib.error.HTTPError carrying a Location header, like a
    real redirect response would."""
    headers = email.message.Message()
    if location:
        headers["Location"] = location
    return urllib.error.HTTPError(url="http://placeholder", code=code, msg="redirect",
                                   hdrs=headers, fp=None)


def _ok_response(status=200):
    """A fake context-managed response object, like opener.open() returns
    on a non-redirect result."""
    response = MagicMock()
    response.status = status
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    return response


def test_embedded_credentials_are_detected():
    assert _has_embedded_credentials("http://user:pass@evil.com/") is True
    assert _has_embedded_credentials("http://example.com/") is False


def test_redirect_destination_safety_blocks_loopback():
    with patch("url_analyzer.socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 0))]
        safe, reason = _check_redirect_destination_safety("localhost")
    assert safe is False
    assert reason is not None


def test_redirect_destination_safety_blocks_private_ip():
    with patch("url_analyzer.socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("10.0.0.5", 0))]
        safe, reason = _check_redirect_destination_safety("internal.corp")
    assert safe is False


def test_redirect_destination_safety_allows_public_ip():
    with patch("url_analyzer.socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        safe, reason = _check_redirect_destination_safety("example.com")
    assert safe is True
    assert reason is None


def test_redirect_destination_safety_raises_on_dns_failure():
    with patch("url_analyzer.socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        try:
            _check_redirect_destination_safety("this-domain-does-not-resolve.invalid")
            assert False, "Expected _DestinationUnresolvable for a DNS resolution failure"
        except _DestinationUnresolvable:
            pass


def test_redirect_chain_blocks_urls_with_credentials_without_any_network_call():
    fake_opener = MagicMock()
    with patch("url_analyzer.urllib.request.build_opener", return_value=fake_opener):
        result = analyze_redirect_chain("http://user:pass@example.com/")
    assert result.blocked is True
    assert "credential" in result.blocked_reason
    assert fake_opener.open.called is False  # never even attempted to connect


def test_redirect_chain_blocks_unsafe_destination_without_any_network_call():
    fake_opener = MagicMock()
    with patch("url_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("url_analyzer._check_redirect_destination_safety", return_value=(False, "blocked for test")):
        result = analyze_redirect_chain("https://example.com/")
    assert result.blocked is True
    assert result.blocked_reason is not None
    assert fake_opener.open.called is False


def test_redirect_chain_dns_failure_is_recorded_as_error_not_blocked():
    """A destination that simply fails to resolve is NOT the same thing
    as an unsafe destination - it should surface as `error`, and
    `blocked` must stay False so it never produces a redirect_blocked
    signal (see test_redirect_risk_dns_failure_does_not_trigger_redirect_blocked
    below)."""
    fake_opener = MagicMock()
    with patch("url_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("url_analyzer.socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        result = analyze_redirect_chain("https://this-domain-does-not-resolve.invalid/")
    assert result.blocked is False
    assert result.blocked_reason is None
    assert result.error is not None
    assert fake_opener.open.called is False  # still never connects to an unresolvable host


def test_redirect_chain_actual_unsafe_destination_still_blocks():
    """Sanity check that the DNS-failure fix above didn't loosen the real
    safety check - a destination that DOES resolve, but to a disallowed
    address, must still be blocked."""
    fake_opener = MagicMock()
    with patch("url_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("url_analyzer.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 0))]):
        result = analyze_redirect_chain("https://internal.example/")
    assert result.blocked is True
    assert result.error is None
    assert "127.0.0.1" in result.blocked_reason
    assert fake_opener.open.called is False


def test_redirect_chain_no_redirect_returns_final_response_directly():
    fake_opener = MagicMock()
    fake_opener.open.return_value = _ok_response(200)
    with patch("url_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("url_analyzer._check_redirect_destination_safety", return_value=(True, None)):
        result = analyze_redirect_chain("https://example.com/")
    assert result.redirected is False
    assert result.hop_count == 0
    assert result.final_url == "https://example.com/"
    assert result.final_status_code == 200
    assert result.domain_changed is False
    assert result.protocol_changed is False


def test_redirect_chain_detects_domain_change_and_https_downgrade():
    fake_opener = MagicMock()
    fake_opener.open.side_effect = [
        _http_error(302, location="http://evil-cdn.net/final"),
        _ok_response(200),
    ]
    with patch("url_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("url_analyzer._check_redirect_destination_safety", return_value=(True, None)):
        result = analyze_redirect_chain("https://safe-brand.com/login")
    assert result.redirected is True
    assert result.hop_count == 1
    assert result.hops[0].url == "http://evil-cdn.net/final"
    assert result.hops[0].status_code == 302
    assert result.final_url == "http://evil-cdn.net/final"
    assert result.final_status_code == 200
    assert result.domain_changed is True
    assert result.protocol_changed is True
    assert result.https_downgrade is True
    assert result.excessive_redirects is False


def test_redirect_chain_excessive_redirects_stops_and_is_flagged():
    """max_redirects=N means hop discovery is capped AT N - the chain must
    stop as soon as N hops are recorded, without going on to connect to
    the Nth hop's own target just to see if it redirects again. A 3rd
    canned redirect is queued here specifically to prove it is NEVER
    consumed."""
    fake_opener = MagicMock()
    fake_opener.open.side_effect = [
        _http_error(302, location="https://hop1.example.com/"),
        _http_error(302, location="https://hop2.example.com/"),
        _http_error(302, location="https://hop3.example.com/"),  # must never be reached
    ]
    with patch("url_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("url_analyzer._check_redirect_destination_safety", return_value=(True, None)):
        result = analyze_redirect_chain("https://start.example.com/", max_redirects=2)
    assert result.excessive_redirects is True
    assert result.hop_count == 2  # never exceeds max_redirects
    assert len(result.hops) == 2
    assert result.final_url == "https://hop2.example.com/"
    assert result.final_status_code is None  # never actually fetched
    assert fake_opener.open.call_count == 2  # bounded: no 3rd request made


def test_redirect_chain_hop_count_never_exceeds_max_redirects_for_various_limits():
    """Same invariant as above, checked against a different limit
    (max_redirects=1) to make sure the fix is not specific to the
    boundary value used in the test above."""
    fake_opener = MagicMock()
    fake_opener.open.side_effect = [
        _http_error(302, location="https://hop1.example.com/"),
        _http_error(302, location="https://hop2.example.com/"),  # must never be reached
    ]
    with patch("url_analyzer.urllib.request.build_opener", return_value=fake_opener), \
         patch("url_analyzer._check_redirect_destination_safety", return_value=(True, None)):
        result = analyze_redirect_chain("https://start.example.com/", max_redirects=1)
    assert result.excessive_redirects is True
    assert result.hop_count == 1
    assert result.final_url == "https://hop1.example.com/"
    assert fake_opener.open.call_count == 1  # bounded: no 2nd request made


# ---------------------------------------------------------------------------
# analyze_url() <-> analyze_redirect_chain() integration tests.
#
# Both DNS and TLS are mocked here too, so these stay deterministic and
# network-free like the rest of the suite - they test ONLY the wiring
# (is redirect_chain populated, and only when parsing succeeded), not the
# redirect-following logic itself, which is already covered above.
# ---------------------------------------------------------------------------

def test_analyze_url_includes_redirect_chain_result_on_success():
    fake_redirect_result = RedirectChainResult(
        original_url="https://example.com/",
        final_url="https://example.com/",
        final_status_code=200,
    )
    with patch("url_analyzer.analyze_redirect_chain", return_value=fake_redirect_result) as mock_redirect, \
         patch("url_analyzer.check_url_reputation", return_value=ReputationResult(target="https://example.com/")), \
         patch("url_analyzer.resolve_dns", return_value=DNSInfo(resolved=True, ip_addresses=["93.184.216.34"])), \
         patch("url_analyzer.get_tls_info", return_value=TLSInfo(attempted=False)):
        result = analyze_url("https://example.com/")
    assert result.redirect_chain is fake_redirect_result
    mock_redirect.assert_called_once_with("https://example.com/")


def test_analyze_url_skips_redirect_chain_on_parse_error():
    with patch("url_analyzer.analyze_redirect_chain") as mock_redirect:
        result = analyze_url("not a url at all")
    assert result.redirect_chain is None
    assert mock_redirect.called is False
    assert result.error is not None  # existing fail-safe behavior, unchanged


# ---------------------------------------------------------------------------
# analyze_url() <-> check_url_reputation() integration tests.
#
# DNS, TLS, and the redirect chain are all mocked here too, so these stay
# deterministic and network-free - they test ONLY the wiring (is
# `reputation` populated, only when parsing succeeded, and does a
# reputation failure ever break analysis), not the reputation module's own
# lookup logic, which is already covered in test_reputation.py.
# ---------------------------------------------------------------------------

def test_analyze_url_includes_reputation_result_on_success():
    fake_reputation = ReputationResult(target="https://example.com/", available=True)
    with patch("url_analyzer.check_url_reputation", return_value=fake_reputation) as mock_reputation, \
         patch("url_analyzer.analyze_redirect_chain", return_value=RedirectChainResult(original_url="https://example.com/")), \
         patch("url_analyzer.resolve_dns", return_value=DNSInfo(resolved=True, ip_addresses=["93.184.216.34"])), \
         patch("url_analyzer.get_tls_info", return_value=TLSInfo(attempted=False)):
        result = analyze_url("https://example.com/")
    assert result.reputation is fake_reputation
    mock_reputation.assert_called_once_with("https://example.com/")


def test_analyze_url_skips_reputation_lookup_on_parse_error():
    with patch("url_analyzer.check_url_reputation") as mock_reputation:
        result = analyze_url("not a url at all")
    assert result.reputation is None
    assert mock_reputation.called is False
    assert result.error is not None  # existing fail-safe behavior, unchanged


def test_analyze_url_missing_api_key_does_not_break_analysis():
    """Uses the REAL check_url_reputation() (not mocked) with the API key
    genuinely absent from the environment, to verify requirement 4 against
    real code, not just a mock: analysis must complete normally, and the
    failure must land only on `result.reputation`, never on `result`
    itself. The real function makes no network call when the key is
    missing, so this stays safe to run in any environment/CI."""
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("VIRUSTOTAL_API_KEY", None)
        with patch("url_analyzer.analyze_redirect_chain", return_value=RedirectChainResult(original_url="https://example.com/")), \
             patch("url_analyzer.resolve_dns", return_value=DNSInfo(resolved=True, ip_addresses=["93.184.216.34"])), \
             patch("url_analyzer.get_tls_info", return_value=TLSInfo(attempted=False)):
            result = analyze_url("https://example.com/")
    assert result.error is None  # analysis itself did not fail
    assert result.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert result.reputation is not None
    assert result.reputation.available is False
    assert result.reputation.error is not None  # the failure is recorded here, not propagated


def test_analyze_url_preserves_mocked_malicious_reputation_result_without_affecting_score():
    fake_reputation = ReputationResult(
        target="https://evil-example.net/",
        provider="VirusTotal",
        available=True,
        malicious=True,
        suspicious=True,
        reputation_score=-40,
        detection_count=12,
        total_engines=74,
        raw_summary="12/74 engines flagged this URL as malicious (3 additional flagged it suspicious).",
        evidence=["malicious: 12 engine(s)", "suspicious: 3 engine(s)"],
    )
    with patch("url_analyzer.check_url_reputation", return_value=fake_reputation) as mock_reputation, \
         patch("url_analyzer.analyze_redirect_chain", return_value=RedirectChainResult(original_url="https://evil-example.net/")), \
         patch("url_analyzer.resolve_dns", return_value=DNSInfo(resolved=True, ip_addresses=["1.2.3.4"])), \
         patch("url_analyzer.get_tls_info", return_value=TLSInfo(attempted=False)):
        result = analyze_url("https://evil-example.net/")

    # The mocked malicious verdict is preserved verbatim in the final result.
    assert result.reputation is fake_reputation
    mock_reputation.assert_called_once_with("https://evil-example.net/")

    # Not yet factored into scoring: no signal derived from reputation data.
    assert all(
        "reputation" not in s.name.lower() and "virustotal" not in s.name.lower()
        for s in result.signals
    )


# ---------------------------------------------------------------------------
# Redirect-related risk scoring tests (_check_redirect_risks).
#
# These build RedirectChainResult objects directly rather than mocking a
# whole HTTP chain - the chain-following logic itself is already covered
# by the tests above, so these isolate ONLY the scoring behavior: which
# HeuristicSignal fires, with what points, and with what description.
# ---------------------------------------------------------------------------

def test_redirect_risk_same_domain_https_redirect_adds_no_points():
    chain = RedirectChainResult(
        original_url="https://example.com/",
        redirected=True,
        hop_count=1,
        final_url="https://example.com/page",
        final_domain="example.com",
        domain_changed=False,
        protocol_changed=False,
        https_downgrade=False,
        excessive_redirects=False,
        blocked=False,
    )
    signals = _check_redirect_risks(chain)
    assert all(not s.triggered for s in signals)
    assert calculate_risk_score(signals) == 0


def test_redirect_risk_domain_change_adds_15():
    chain = RedirectChainResult(
        original_url="https://safe-brand.com/",
        redirected=True,
        hop_count=1,
        final_url="https://evil-cdn.net/",
        final_domain="evil-cdn.net",
        domain_changed=True,
    )
    signals = _check_redirect_risks(chain)
    triggered = [s for s in signals if s.triggered]
    assert len(triggered) == 1
    assert triggered[0].name == "redirect_domain_changed"
    assert triggered[0].points == 15
    assert "evil-cdn.net" in triggered[0].description
    assert calculate_risk_score(signals) == 15


def test_redirect_risk_https_downgrade_adds_25():
    chain = RedirectChainResult(
        original_url="https://example.com/",
        redirected=True,
        hop_count=1,
        final_url="http://example.com/",
        final_domain="example.com",
        https_downgrade=True,
    )
    signals = _check_redirect_risks(chain)
    triggered = [s for s in signals if s.triggered]
    assert len(triggered) == 1
    assert triggered[0].name == "https_downgrade"
    assert triggered[0].points == 25
    assert "http://example.com/" in triggered[0].description
    assert calculate_risk_score(signals) == 25


def test_redirect_risk_excessive_redirects_adds_15():
    chain = RedirectChainResult(
        original_url="https://start.example.com/",
        redirected=True,
        hop_count=6,
        final_url="https://hop6.example.com/",
        final_domain="example.com",
        excessive_redirects=True,
    )
    signals = _check_redirect_risks(chain)
    triggered = [s for s in signals if s.triggered]
    assert len(triggered) == 1
    assert triggered[0].name == "excessive_redirects"
    assert triggered[0].points == 15
    assert "6 redirects" in triggered[0].description
    assert calculate_risk_score(signals) == 15


def test_redirect_risk_blocked_adds_20():
    chain = RedirectChainResult(
        original_url="https://example.com/",
        blocked=True,
        blocked_reason="blocked destination 'localhost': resolves to a disallowed address (127.0.0.1)",
    )
    signals = _check_redirect_risks(chain)
    triggered = [s for s in signals if s.triggered]
    assert len(triggered) == 1
    assert triggered[0].name == "redirect_blocked"
    assert triggered[0].points == 20
    assert "127.0.0.1" in triggered[0].description
    assert calculate_risk_score(signals) == 20


def test_redirect_risk_dns_failure_does_not_trigger_redirect_blocked():
    """A chain that failed due to plain DNS resolution failure (blocked
    stays False, error is set) must NOT score redirect_blocked - that
    was the bug being fixed."""
    chain = RedirectChainResult(
        original_url="https://this-domain-does-not-resolve.invalid/",
        blocked=False,
        error="could not verify safety of 'this-domain-does-not-resolve.invalid': "
              "could not resolve destination host: [Errno -2] Name or service not known",
    )
    signals = _check_redirect_risks(chain)
    assert all(not s.triggered for s in signals)
    assert calculate_risk_score(signals) == 0


def test_redirect_risk_combined_signals_included_in_final_score_and_capped():
    chain = RedirectChainResult(
        original_url="https://safe-brand.com/",
        redirected=True,
        hop_count=6,
        final_url="http://evil-cdn.net/",
        final_domain="evil-cdn.net",
        domain_changed=True,
        https_downgrade=True,
        excessive_redirects=True,
        blocked=False,
    )
    redirect_signals = _check_redirect_risks(chain)
    # 15 (domain changed) + 25 (downgrade) + 15 (excessive) = 55
    assert calculate_risk_score(redirect_signals) == 55

    # Mix with other already-triggered signals to confirm the existing
    # calculate_risk_score() cap still applies once redirect signals are
    # combined with the rest of the pipeline's signals.
    other_signals = [
        HeuristicSignal("filler_a", "filler", 40, True),
        HeuristicSignal("filler_b", "filler", 40, True),
    ]
    assert calculate_risk_score(redirect_signals + other_signals) == 100  # 55+80=135, capped


def run_all_tests():
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed = 0
    for test_fn in tests:
        test_fn()
        passed += 1
        print(f"  PASS  {test_fn.__name__}")
    print(f"\n{passed}/{len(tests)} unit tests passed (no network required).\n")


# ---------------------------------------------------------------------------
# Demo: run the full pipeline against three safe example URLs and print a
# human-readable report for each.
# ---------------------------------------------------------------------------

DEMO_URLS = [
    # A real, benign site over HTTPS. Expect a low score - only the word
    # "login" in the path should trigger a small signal.
    "https://github.com/login",

    # A real, clean HTTPS site with nothing suspicious at all. Expect
    # score 0 / LOW.
    "https://pypi.org",

    # A deliberately risky-*looking* URL built on "example.com", which is
    # reserved by RFC 2606 specifically for documentation and examples.
    # This subdomain does not really exist, so DNS resolution is expected
    # to fail - that failure is itself one of the signals being tested.
    "http://secure-login.accounts-verify.example.com/verify?account=confirm",
]


def print_report(url: str) -> None:
    result = analyze_url(url)
    print("=" * 70)
    print(f"URL:        {url}")

    if result.error:
        print(f"ERROR:      {result.error}")
        print("=" * 70)
        return

    print(f"Scheme:     {result.components.scheme}")
    print(f"Hostname:   {result.components.hostname}")
    print(f"Domain:     {result.components.domain}")
    print(f"Path:       {result.components.path}")

    print(f"\nDNS resolved: {result.dns_info.resolved}")
    if result.dns_info.resolved:
        print(f"  IP address(es): {', '.join(result.dns_info.ip_addresses)}")
    else:
        print(f"  DNS error: {result.dns_info.error}")

    if result.tls_info is not None:
        print(f"\nTLS attempted: {result.tls_info.attempted}, success: {result.tls_info.success}")
        if result.tls_info.success:
            print(f"  Subject:  {result.tls_info.subject}")
            print(f"  Issuer:   {result.tls_info.issuer}")
            print(f"  Valid:    {result.tls_info.valid_from}  ->  {result.tls_info.valid_until}")
            print(f"  Hostname match: {result.tls_info.hostname_matches}")
        else:
            print(f"  TLS error: {result.tls_info.error}")
    else:
        print("\nTLS: not checked (URL is not https)")

    print("\nHeuristic signals:")
    for signal in result.signals:
        marker = "[TRIGGERED]" if signal.triggered else "[clear]    "
        print(f"  {marker} {signal.name:<24} +{signal.points:<3} {signal.description}")

    print(f"\nRISK SCORE: {result.risk_score}/100  ->  {result.risk_level}")
    print(f"NOTE: {result.disclaimer}")
    print("=" * 70)


def print_json(url: str) -> None:
    """Show that the result is plain, JSON-serializable structured data."""
    result = analyze_url(url)
    print(json.dumps(dataclasses.asdict(result), indent=2))


if __name__ == "__main__":
    print("Running unit tests (no network required)...\n")
    run_all_tests()

    print("Running full demo against example URLs (requires internet access "
          "for DNS/TLS)...\n")
    for demo_url in DEMO_URLS:
        print_report(demo_url)
        print()

    print("Example of raw structured JSON output for one URL:\n")
    print_json(DEMO_URLS[0])
