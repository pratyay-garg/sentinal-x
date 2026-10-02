"""
intelligence/test_domain_analyzer.py
SentinelX — Domain Intelligence tests

All network activity is mocked.  Zero real DNS, TLS, or HTTP calls.

Run:
    python intelligence/test_domain_analyzer.py
"""

import json
import sys
import unittest
from dataclasses import asdict
from unittest.mock import MagicMock, patch

# Make the project root importable when run from the project root
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engines.intel.url_analyzer import DNSInfo, TLSInfo
from app.engines.intel.reputation import ReputationResult
from app.engines.intel.domain_analyzer import (
    DomainAnalysisResult,
    _check_destination_safety,
    _validate_and_normalize_domain,
    _signal_typosquat_or_brand_lookalike,
    _signal_risky_tld,
    _signal_excessive_subdomains,
    _signal_suspicious_characters,
    _signal_randomly_generated,
    analyze_domain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_dns(resolved: bool, ips=None, error=None):
    return DNSInfo(resolved=resolved, ip_addresses=ips or [], error=error)


def _make_tls(success: bool, hostname_matches=None, error=None):
    return TLSInfo(
        attempted=True,
        success=success,
        hostname_matches=hostname_matches,
        error=error,
    )


def _patch_dns(result: DNSInfo):
    return patch("intelligence.domain_analyzer.resolve_dns", return_value=result)


def _patch_tls(result: TLSInfo):
    return patch("intelligence.domain_analyzer.get_tls_info", return_value=result)


def _patch_rep(result: ReputationResult):
    return patch("intelligence.domain_analyzer._check_domain_reputation", return_value=result)


# ---------------------------------------------------------------------------
# 1. Input validation and normalization
# ---------------------------------------------------------------------------

class TestValidateAndNormalizeDomain(unittest.TestCase):

    def test_bare_domain_unchanged(self):
        self.assertEqual(_validate_and_normalize_domain("example.com"), "example.com")

    def test_strips_https_scheme(self):
        self.assertEqual(_validate_and_normalize_domain("https://example.com"), "example.com")

    def test_strips_http_scheme(self):
        self.assertEqual(_validate_and_normalize_domain("http://example.com/path?q=1"), "example.com")

    def test_strips_path_and_query(self):
        self.assertEqual(_validate_and_normalize_domain("example.com/path/to/page"), "example.com")

    def test_strips_port(self):
        self.assertEqual(_validate_and_normalize_domain("example.com:8080"), "example.com")

    def test_empty_string_returns_none(self):
        self.assertIsNone(_validate_and_normalize_domain(""))

    def test_whitespace_only_returns_none(self):
        self.assertIsNone(_validate_and_normalize_domain("   "))

    def test_none_input_returns_none(self):
        self.assertIsNone(_validate_and_normalize_domain(None))

    def test_leading_trailing_whitespace_stripped(self):
        self.assertEqual(_validate_and_normalize_domain("  example.com  "), "example.com")


# ---------------------------------------------------------------------------
# 2. SSRF destination safety gate
# ---------------------------------------------------------------------------

class TestCheckDestinationSafety(unittest.TestCase):

    def test_loopback_blocked(self):
        self.assertIsNotNone(_check_destination_safety("127.0.0.1"))

    def test_private_10_blocked(self):
        self.assertIsNotNone(_check_destination_safety("10.0.0.1"))

    def test_private_192_168_blocked(self):
        self.assertIsNotNone(_check_destination_safety("192.168.1.100"))

    def test_link_local_blocked(self):
        self.assertIsNotNone(_check_destination_safety("169.254.1.1"))

    def test_ipv6_loopback_blocked(self):
        self.assertIsNotNone(_check_destination_safety("::1"))

    def test_public_ip_allowed(self):
        self.assertIsNone(_check_destination_safety("8.8.8.8"))

    def test_public_ip_allowed_2(self):
        self.assertIsNone(_check_destination_safety("104.21.60.1"))

    def test_invalid_ip_blocked(self):
        result = _check_destination_safety("not-an-ip")
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# 3. Individual heuristic signals
# ---------------------------------------------------------------------------

class TestSignalTyposquat(unittest.TestCase):

    def test_close_to_paypal_triggers(self):
        sig = _signal_typosquat_or_brand_lookalike("paypa1.com")
        self.assertTrue(sig.triggered)

    def test_close_to_google_triggers(self):
        sig = _signal_typosquat_or_brand_lookalike("g00gle.com")
        self.assertTrue(sig.triggered)

    def test_legitimate_brand_exact_not_triggered(self):
        sig = _signal_typosquat_or_brand_lookalike("google.com")
        self.assertFalse(sig.triggered)

    def test_unrelated_domain_not_triggered(self):
        sig = _signal_typosquat_or_brand_lookalike("example.com")
        self.assertFalse(sig.triggered)


class TestSignalRiskyTld(unittest.TestCase):

    def test_xyz_triggers(self):
        sig = _signal_risky_tld("xyz")
        self.assertTrue(sig.triggered)

    def test_tk_triggers(self):
        sig = _signal_risky_tld("tk")
        self.assertTrue(sig.triggered)

    def test_com_not_triggered(self):
        sig = _signal_risky_tld("com")
        self.assertFalse(sig.triggered)

    def test_org_not_triggered(self):
        sig = _signal_risky_tld("org")
        self.assertFalse(sig.triggered)


class TestSignalExcessiveSubdomains(unittest.TestCase):

    def test_five_labels_triggers(self):
        sig = _signal_excessive_subdomains(5)
        self.assertTrue(sig.triggered)

    def test_four_labels_not_triggered(self):
        sig = _signal_excessive_subdomains(4)
        self.assertFalse(sig.triggered)

    def test_two_labels_not_triggered(self):
        sig = _signal_excessive_subdomains(2)
        self.assertFalse(sig.triggered)


class TestSignalSuspiciousCharacters(unittest.TestCase):

    def test_xn_prefix_triggers(self):
        sig = _signal_suspicious_characters("xn--paypa1-fwb.com")
        self.assertTrue(sig.triggered)

    def test_non_ascii_triggers(self):
        sig = _signal_suspicious_characters("pàypal.com")
        self.assertTrue(sig.triggered)

    def test_clean_ascii_not_triggered(self):
        sig = _signal_suspicious_characters("example.com")
        self.assertFalse(sig.triggered)


class TestSignalRandomlyGenerated(unittest.TestCase):

    def test_long_consonant_run_triggers(self):
        # "xkqrfmz" → 7 consecutive consonants
        sig = _signal_randomly_generated("xkqrfmz.com")
        self.assertTrue(sig.triggered)

    def test_high_digit_density_triggers(self):
        # "a1b2c3d4" → 50% digits
        sig = _signal_randomly_generated("a1b2c3d4.com")
        self.assertTrue(sig.triggered)

    def test_clean_domain_not_triggered(self):
        sig = _signal_randomly_generated("example.com")
        self.assertFalse(sig.triggered)

    def test_google_not_triggered(self):
        sig = _signal_randomly_generated("google.com")
        self.assertFalse(sig.triggered)


# ---------------------------------------------------------------------------
# 4. Full analyze_domain() integration tests (all network mocked)
# ---------------------------------------------------------------------------

class TestAnalyzeDomainHappyPath(unittest.TestCase):
    """Valid domain that resolves to a public IP, has good TLS, clean rep."""

    def _run(self, domain="example.com"):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        rep = ReputationResult(target="example.com", available=True,
                               malicious=False, suspicious=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            return analyze_domain(domain)

    def test_returns_no_error(self):
        result = self._run()
        self.assertIsNone(result.error)

    def test_risk_level_is_low_for_clean_domain(self):
        result = self._run()
        self.assertEqual(result.domain_risk_level, "LOW")

    def test_target_domain_populated(self):
        result = self._run()
        self.assertEqual(result.target_domain, "example.com")

    def test_dns_resolved(self):
        result = self._run()
        self.assertTrue(result.dns.resolved)

    def test_tls_attempted_and_succeeded(self):
        result = self._run()
        self.assertTrue(result.tls.attempted)
        self.assertTrue(result.tls.success)

    def test_ai_interpretation_is_none(self):
        result = self._run()
        self.assertIsNone(result.ai_interpretation)

    def test_disclaimer_present(self):
        result = self._run()
        self.assertTrue(len(result.disclaimer) > 0)


class TestAnalyzeDomainUrlPastedInstead(unittest.TestCase):
    """User accidentally pastes a full URL; should be forgiven."""

    def test_full_url_input_is_normalized(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        rep = ReputationResult(target="example.com", available=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("https://example.com/some/path?q=1")
        self.assertEqual(result.target_domain, "example.com")
        self.assertIsNone(result.error)


class TestAnalyzeDomainInvalidInput(unittest.TestCase):

    def test_empty_string_returns_error(self):
        result = analyze_domain("")
        self.assertIsNotNone(result.error)

    def test_whitespace_returns_error(self):
        result = analyze_domain("   ")
        self.assertIsNotNone(result.error)

    def test_none_handled_gracefully(self):
        # None is not the declared type but the function must not raise
        result = analyze_domain(None)  # type: ignore[arg-type]
        self.assertIsNotNone(result.error)


class TestAnalyzeDomainSsrfBlocked(unittest.TestCase):
    """DNS resolves to a private IP — TLS must be skipped; SSRF gate fires."""

    def _run(self):
        dns = _make_dns(True, ips=["192.168.1.1"])
        rep = ReputationResult(target="evil.com", available=False)
        with _patch_dns(dns), _patch_rep(rep) as mock_rep:
            with patch("intelligence.domain_analyzer.get_tls_info") as mock_tls:
                result = analyze_domain("evil.com")
                return result, mock_tls

    def test_tls_is_none_when_blocked(self):
        result, mock_tls = self._run()
        self.assertIsNone(result.tls)

    def test_tls_helper_never_called_when_blocked(self):
        result, mock_tls = self._run()
        mock_tls.assert_not_called()

    def test_tls_blocked_reason_is_set(self):
        result, _ = self._run()
        self.assertIsNotNone(result.tls_blocked_reason)
        self.assertIn("blocked", result.tls_blocked_reason.lower())


class TestAnalyzeDomainDnsFailure(unittest.TestCase):
    """DNS fails — must be recorded but must NOT add risk points."""

    def _run(self):
        dns = _make_dns(False, error="DNS resolution failed: NXDOMAIN")
        rep = ReputationResult(target="nxdomain.example", available=False)
        with _patch_dns(dns), _patch_rep(rep):
            with patch("intelligence.domain_analyzer.get_tls_info") as mock_tls:
                result = analyze_domain("nxdomain.example")
                return result, mock_tls

    def test_dns_not_resolved(self):
        result, _ = self._run()
        self.assertFalse(result.dns.resolved)

    def test_dns_failure_does_not_add_risk_points(self):
        """Key design rule: DNS failure is error state, not a risk signal."""
        result, _ = self._run()
        dns_signal_names = [
            s.name for s in result.signals if "dns" in s.name and s.triggered
        ]
        self.assertEqual(dns_signal_names, [],
                         "DNS resolution failure must not trigger any risk signal.")

    def test_tls_skipped_on_dns_failure(self):
        result, mock_tls = self._run()
        mock_tls.assert_not_called()


class TestAnalyzeDomainTlsFailure(unittest.TestCase):

    def test_no_valid_tls_signal_triggered(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(False, error="Connection refused.")
        rep = ReputationResult(target="example.com", available=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("example.com")
        no_tls_sig = next(s for s in result.signals if s.name == "no_valid_tls_certificate")
        self.assertTrue(no_tls_sig.triggered)


class TestAnalyzeDomainTlsHostnameMismatch(unittest.TestCase):

    def test_hostname_mismatch_signal_triggered(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=False)
        rep = ReputationResult(target="example.com", available=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("example.com")
        mismatch_sig = next(s for s in result.signals if s.name == "tls_hostname_mismatch")
        self.assertTrue(mismatch_sig.triggered)


class TestAnalyzeDomainMissingApiKey(unittest.TestCase):
    """Reputation check gracefully unavailable when API key absent."""

    def test_missing_api_key_does_not_crash(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        # Simulate no API key via real _check_domain_reputation path
        with _patch_dns(dns), _patch_tls(tls):
            with patch("intelligence.domain_analyzer._get_api_key", return_value=None):
                result = analyze_domain("example.com")
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.reputation)
        self.assertFalse(result.reputation.available)

    def test_risk_score_unaffected_by_missing_key(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        with _patch_dns(dns), _patch_tls(tls):
            with patch("intelligence.domain_analyzer._get_api_key", return_value=None):
                result = analyze_domain("example.com")
        rep_sig = next(s for s in result.signals if s.name == "reputation_flagged")
        self.assertFalse(rep_sig.triggered)


class TestAnalyzeDomainReputationMalicious(unittest.TestCase):

    def test_reputation_flagged_signal_triggered(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        rep = ReputationResult(target="evil.com", available=True,
                               malicious=True, suspicious=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("evil.com")
        rep_sig = next(s for s in result.signals if s.name == "reputation_flagged")
        self.assertTrue(rep_sig.triggered)
        self.assertGreaterEqual(result.domain_risk_score, 25)

    def test_reputation_clean_signal_not_triggered(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        rep = ReputationResult(target="example.com", available=True,
                               malicious=False, suspicious=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("example.com")
        rep_sig = next(s for s in result.signals if s.name == "reputation_flagged")
        self.assertFalse(rep_sig.triggered)


class TestAnalyzeDomainScoreCap(unittest.TestCase):
    """Score must not exceed 100 even when many signals fire."""

    def test_score_capped_at_100(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(False, error="cert error")
        rep = ReputationResult(target="paypa1.xyz", available=True,
                               malicious=True, suspicious=True)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("paypa1.xyz")
        self.assertLessEqual(result.domain_risk_score, 100)


class TestAnalyzeDomainLegitimateNoFalsePositive(unittest.TestCase):
    """Well-known legitimate domain should score LOW."""

    def test_clean_domain_is_low_risk(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        rep = ReputationResult(target="wikipedia.org", available=True,
                               malicious=False, suspicious=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("wikipedia.org")
        self.assertEqual(result.domain_risk_level, "LOW")
        self.assertLess(result.domain_risk_score, 25)


class TestAnalyzeDomainJsonSerializable(unittest.TestCase):
    """Result must be JSON-serializable via dataclasses.asdict."""

    def test_result_is_serializable(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        rep = ReputationResult(target="example.com", available=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("example.com")
        try:
            serialized = json.dumps(asdict(result))
            self.assertIsInstance(serialized, str)
        except (TypeError, ValueError) as exc:
            self.fail(f"DomainAnalysisResult is not JSON-serializable: {exc}")


class TestAnalyzeDomainAiInterpretationAlwaysNone(unittest.TestCase):

    def test_ai_interpretation_is_none(self):
        dns = _make_dns(True, ips=["93.184.216.34"])
        tls = _make_tls(True, hostname_matches=True)
        rep = ReputationResult(target="example.com", available=False)
        with _patch_dns(dns), _patch_tls(tls), _patch_rep(rep):
            result = analyze_domain("example.com")
        self.assertIsNone(result.ai_interpretation)


class TestSsrfGateBlocksBeforeTlsHelper(unittest.TestCase):
    """
    The SSRF gate must prevent get_tls_info() from being called when
    resolved IPs are in a blocked range.  This proves the architectural
    gap identified in url_analyzer.get_tls_info() does not carry through.
    """

    def test_get_tls_info_not_called_for_private_ip(self):
        dns = _make_dns(True, ips=["10.0.0.1"])
        rep = ReputationResult(target="internal.corp", available=False)
        with _patch_dns(dns), _patch_rep(rep):
            with patch("intelligence.domain_analyzer.get_tls_info") as mock_tls:
                analyze_domain("internal.corp")
                mock_tls.assert_not_called()


class TestAnalyzeDomainNeverRaises(unittest.TestCase):
    """analyze_domain() must never propagate exceptions regardless of input."""

    def test_bizarre_input_does_not_raise(self):
        for bad in ["", "   ", "\x00\x01", "a" * 1000, "!@#$%^&*()"]:
            try:
                result = analyze_domain(bad)
                self.assertIsInstance(result, DomainAnalysisResult)
            except Exception as exc:
                self.fail(f"analyze_domain({repr(bad)[:20]!s}) raised: {exc}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    total = result.testsRun
    failures = len(result.failures) + len(result.errors)
    print(f"\n{'='*60}")
    print(f"Domain Analyzer: {total - failures}/{total} tests passed.")
    sys.exit(0 if failures == 0 else 1)
