"""
intelligence/test_ip_analyzer.py
SentinelX — Comprehensive IP Analyzer Tests

Run:
    python intelligence/test_ip_analyzer.py

All network / DNS / VirusTotal calls are mocked.
No real network traffic is produced.

Test groups:
  A. Validation & parsing          (9 tests)
  B. Classification                (10 tests)
  C. Reverse DNS                   (8 tests)
  D. VirusTotal reputation         (12 tests)
  E. Heuristic signals             (14 tests)
  F. Risk score & level            (8 tests)
  G. Never-raise / safety          (5 tests)
  H. JSON serialisation            (4 tests)
  Total: 70 tests
"""

import json
import socket
import sys
import unittest
from dataclasses import asdict
from unittest.mock import MagicMock, patch

# Make the project root importable when run from the project root
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engines.intel.ip_analyzer import (
    CLASS_LINK_LOCAL,
    CLASS_LOOPBACK,
    CLASS_MULTICAST,
    CLASS_PRIVATE,
    CLASS_PUBLIC,
    CLASS_RESERVED,
    CLASS_UNSPECIFIED,
    IPAnalysisResult,
    IPIntelligence,
    _classify,
    _parse_ip,
    _reverse_dns,
    _vt_reputation,
    analyze_ip,
)
from app.engines.intel.reputation import ReputationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_vt_response(malicious=0, suspicious=0, reputation=0, asn=12345,
                      as_owner="GOOGLE", country="US", network="8.8.8.0/24"):
    """Build a minimal VirusTotal /ip_addresses JSON payload."""
    total = malicious + suspicious + 50  # pad with clean engines
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": total - malicious - suspicious,
        "undetected": 0,
    }
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": stats,
                "reputation": reputation,
                "asn": asn,
                "as_owner": as_owner,
                "country": country,
                "network": network,
            }
        }
    }
    return json.dumps(payload).encode()


def _make_urlopen_ctx(body: bytes, status: int = 200):
    """Return a context-manager mock that yields a readable response."""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.read.return_value = body
    cm.status = status
    return cm


# ---------------------------------------------------------------------------
# A. Validation & parsing
# ---------------------------------------------------------------------------

class TestValidation(unittest.TestCase):

    def test_valid_ipv4(self):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertIsNone(r.error)
        self.assertEqual(r.ip_version, 4)
        self.assertEqual(r.target, "8.8.8.8")

    def test_valid_ipv6(self):
        r = analyze_ip("2001:4860:4860::8888", check_reputation=False)
        self.assertIsNone(r.error)
        self.assertEqual(r.ip_version, 6)

    def test_ipv6_normalised(self):
        # Expanded form must be normalised (Python ipaddress normalises)
        r = analyze_ip("2001:0db8:0000:0000:0000:0000:0000:0001", check_reputation=False)
        self.assertIsNone(r.error)
        self.assertEqual(r.ip_version, 6)

    def test_invalid_hostname(self):
        r = analyze_ip("example.com", check_reputation=False)
        self.assertIsNotNone(r.error)
        self.assertEqual(r.risk_score, 0)
        self.assertEqual(r.risk_level, "LOW")

    def test_invalid_cidr(self):
        r = analyze_ip("192.168.1.0/24", check_reputation=False)
        self.assertIsNotNone(r.error)

    def test_empty_string(self):
        r = analyze_ip("", check_reputation=False)
        self.assertIsNotNone(r.error)

    def test_whitespace_only(self):
        r = analyze_ip("   ", check_reputation=False)
        self.assertIsNotNone(r.error)

    def test_garbage_string(self):
        r = analyze_ip("not-an-ip", check_reputation=False)
        self.assertIsNotNone(r.error)
        self.assertIsNone(r.ip_version)
        self.assertIsNone(r.classification)

    def test_leading_zeros_ipv4(self):
        # Python ipaddress rejects octal-ambiguous leading zeros
        r = analyze_ip("010.0.0.1", check_reputation=False)
        self.assertIsNotNone(r.error)


# ---------------------------------------------------------------------------
# B. Classification
# ---------------------------------------------------------------------------

class TestClassification(unittest.TestCase):

    def _cls(self, ip_str):
        import ipaddress
        return _classify(ipaddress.ip_address(ip_str))

    def test_public_ipv4(self):
        self.assertEqual(self._cls("8.8.8.8"), CLASS_PUBLIC)

    def test_private_192(self):
        self.assertEqual(self._cls("192.168.1.1"), CLASS_PRIVATE)

    def test_private_10(self):
        self.assertEqual(self._cls("10.0.0.1"), CLASS_PRIVATE)

    def test_private_172(self):
        self.assertEqual(self._cls("172.16.0.1"), CLASS_PRIVATE)

    def test_loopback_ipv4(self):
        self.assertEqual(self._cls("127.0.0.1"), CLASS_LOOPBACK)

    def test_loopback_ipv6(self):
        self.assertEqual(self._cls("::1"), CLASS_LOOPBACK)

    def test_link_local_ipv4(self):
        self.assertEqual(self._cls("169.254.0.1"), CLASS_LINK_LOCAL)

    def test_link_local_ipv6(self):
        self.assertEqual(self._cls("fe80::1"), CLASS_LINK_LOCAL)

    def test_multicast_ipv4(self):
        self.assertEqual(self._cls("224.0.0.1"), CLASS_MULTICAST)

    def test_public_ipv6(self):
        self.assertEqual(self._cls("2001:4860:4860::8888"), CLASS_PUBLIC)


# ---------------------------------------------------------------------------
# C. Reverse DNS
# ---------------------------------------------------------------------------

class TestReverseDNS(unittest.TestCase):

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           return_value=("dns.google", [], ["8.8.8.8"]))
    def test_rdns_success(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertEqual(r.reverse_dns, "dns.google")
        self.assertIsNone(r.reverse_dns_error)

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=socket.herror(1, "Unknown host"))
    def test_rdns_herror(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertIsNone(r.reverse_dns)
        self.assertIsNotNone(r.reverse_dns_error)

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=socket.gaierror(11001, "getaddrinfo failed"))
    def test_rdns_gaierror(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertIsNone(r.reverse_dns)
        self.assertIsNotNone(r.reverse_dns_error)

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=socket.timeout())
    def test_rdns_timeout(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertIsNone(r.reverse_dns)
        self.assertIn("timed out", r.reverse_dns_error.lower())

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=OSError("generic OS error"))
    def test_rdns_oserror(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertIsNone(r.reverse_dns)
        self.assertIsNotNone(r.reverse_dns_error)

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=socket.herror(1, "No PTR"))
    def test_rdns_failure_does_not_raise(self, _mock):
        # Must be structured result, no exception
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertIsInstance(r, IPAnalysisResult)

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           return_value=("dns.google", [], ["8.8.8.8"]))
    def test_rdns_timeout_restored_on_success(self, mock_gethostbyaddr):
        """Original socket timeout must be restored after the call."""
        import socket as _sock
        original = _sock.getdefaulttimeout()
        analyze_ip("8.8.8.8", check_reputation=False)
        self.assertEqual(_sock.getdefaulttimeout(), original)

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=socket.timeout())
    def test_rdns_timeout_restored_on_failure(self, _mock):
        """Original socket timeout must be restored even after failure."""
        import socket as _sock
        original = _sock.getdefaulttimeout()
        analyze_ip("8.8.8.8", check_reputation=False)
        self.assertEqual(_sock.getdefaulttimeout(), original)


# ---------------------------------------------------------------------------
# D. VirusTotal reputation
# ---------------------------------------------------------------------------

class TestReputation(unittest.TestCase):

    # --- Public IP with no API key ---

    @patch("intelligence.ip_analyzer._get_api_key", return_value=None)
    def test_no_api_key_returns_structured_error(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=True)
        self.assertIsNotNone(r.reputation)
        self.assertIsNotNone(r.reputation.error)
        self.assertIsNone(r.error)          # top-level error must be None

    # --- Private / special-use IPs never call VT ---

    @patch("intelligence.ip_analyzer._vt_reputation")
    def test_private_ip_skips_vt(self, mock_vt):
        analyze_ip("192.168.1.10", check_reputation=True)
        mock_vt.assert_not_called()

    @patch("intelligence.ip_analyzer._vt_reputation")
    def test_loopback_skips_vt(self, mock_vt):
        analyze_ip("127.0.0.1", check_reputation=True)
        mock_vt.assert_not_called()

    @patch("intelligence.ip_analyzer._vt_reputation")
    def test_link_local_skips_vt(self, mock_vt):
        analyze_ip("169.254.0.1", check_reputation=True)
        mock_vt.assert_not_called()

    @patch("intelligence.ip_analyzer._vt_reputation")
    def test_check_reputation_false_skips_vt(self, mock_vt):
        analyze_ip("8.8.8.8", check_reputation=False)
        mock_vt.assert_not_called()

    # --- Successful VT response ---

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_clean_ip_vt_response(self, mock_urlopen, _mock_key):
        mock_urlopen.return_value = _make_urlopen_ctx(_mock_vt_response(malicious=0))
        r = analyze_ip("8.8.8.8", check_reputation=True)
        self.assertTrue(r.reputation.available)
        self.assertFalse(r.reputation.malicious)
        self.assertEqual(r.intelligence.country, "US")
        self.assertEqual(r.intelligence.asn, 12345)

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_malicious_ip_vt_response(self, mock_urlopen, _mock_key):
        mock_urlopen.return_value = _make_urlopen_ctx(
            _mock_vt_response(malicious=10, suspicious=2, reputation=-50)
        )
        r = analyze_ip("8.8.8.8", check_reputation=True)
        self.assertTrue(r.reputation.malicious)
        self.assertTrue(r.reputation.suspicious)
        self.assertEqual(r.reputation.detection_count, 10)

    # --- VT HTTP errors ---

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_vt_404_structured(self, mock_urlopen, _mock_key):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            None, 404, "Not Found", {}, None)
        r = analyze_ip("8.8.8.8", check_reputation=True)
        self.assertIsNone(r.error)
        self.assertIsNotNone(r.reputation)

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_vt_network_error_structured(self, mock_urlopen, _mock_key):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("network down")
        r = analyze_ip("8.8.8.8", check_reputation=True)
        self.assertIsNone(r.error)
        self.assertIsNotNone(r.reputation.error)

    # --- VT invalid JSON ---

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_vt_invalid_json(self, mock_urlopen, _mock_key):
        mock_urlopen.return_value = _make_urlopen_ctx(b"not json {{{{")
        r = analyze_ip("8.8.8.8", check_reputation=True)
        self.assertIsNone(r.error)
        self.assertIsNotNone(r.reputation.error)

    # --- Private IP reputation skip message ---

    def test_private_ip_reputation_skip_message(self):
        r = analyze_ip("10.0.0.1", check_reputation=True)
        self.assertIsNotNone(r.reputation)
        self.assertIn("skipped", r.reputation.error.lower())


# ---------------------------------------------------------------------------
# E. Heuristic signals
# ---------------------------------------------------------------------------

class TestHeuristicSignals(unittest.TestCase):
    """
    Key policy: non_public and loopback_or_link_local signals are
    INFORMATIONAL ONLY — they must trigger but contribute 0 points.
    """

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           return_value=("dns.google", [], ["8.8.8.8"]))
    def test_public_ip_no_non_public_signal(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        sig = next(s for s in r.signals if s.name == "non_public_address")
        self.assertFalse(sig.triggered)

    def test_private_ip_non_public_signal_triggered_zero_points(self):
        r = analyze_ip("192.168.1.10", check_reputation=False)
        sig = next(s for s in r.signals if s.name == "non_public_address")
        self.assertTrue(sig.triggered)
        self.assertEqual(sig.points, 0)          # 🔑 informational only

    def test_loopback_signal_triggered_zero_points(self):
        r = analyze_ip("127.0.0.1", check_reputation=False)
        sig = next(s for s in r.signals if s.name == "loopback_or_link_local")
        self.assertTrue(sig.triggered)
        self.assertEqual(sig.points, 0)          # 🔑 informational only

    def test_link_local_signal_triggered_zero_points(self):
        r = analyze_ip("169.254.1.1", check_reputation=False)
        sig = next(s for s in r.signals if s.name == "loopback_or_link_local")
        self.assertTrue(sig.triggered)
        self.assertEqual(sig.points, 0)

    def test_private_ip_zero_total_score(self):
        """Private IP with no reputation → score must be 0."""
        r = analyze_ip("192.168.1.10", check_reputation=False)
        self.assertEqual(r.risk_score, 0)
        self.assertEqual(r.risk_level, "LOW")

    def test_loopback_zero_total_score(self):
        r = analyze_ip("127.0.0.1", check_reputation=False)
        self.assertEqual(r.risk_score, 0)
        self.assertEqual(r.risk_level, "LOW")

    # no_reverse_dns signal

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=socket.herror(1, "No PTR"))
    def test_no_rdns_signal_triggers_for_public_ip(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        sig = next(s for s in r.signals if s.name == "no_reverse_dns")
        self.assertTrue(sig.triggered)
        self.assertEqual(sig.points, 10)

    def test_no_rdns_signal_does_not_trigger_for_private_ip(self):
        """PTR absence is normal for private IPs — signal must not fire."""
        r = analyze_ip("192.168.1.10", check_reputation=False)
        sig = next(s for s in r.signals if s.name == "no_reverse_dns")
        self.assertFalse(sig.triggered)

    # reputation signals

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_reputation_flagged_signal(self, mock_urlopen, _mock_key):
        mock_urlopen.return_value = _make_urlopen_ctx(
            _mock_vt_response(malicious=5, suspicious=1)
        )
        r = analyze_ip("8.8.8.8", check_reputation=True)
        sig = next(s for s in r.signals if s.name == "reputation_flagged")
        self.assertTrue(sig.triggered)
        self.assertEqual(sig.points, 40)

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_high_detection_ratio_signal(self, mock_urlopen, _mock_key):
        # 26 malicious out of ~76 total ≥ 25%
        mock_urlopen.return_value = _make_urlopen_ctx(
            _mock_vt_response(malicious=26, suspicious=0)
        )
        r = analyze_ip("8.8.8.8", check_reputation=True)
        sig = next(s for s in r.signals if s.name == "high_malicious_detection_ratio")
        self.assertTrue(sig.triggered)

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_negative_vt_reputation_signal(self, mock_urlopen, _mock_key):
        mock_urlopen.return_value = _make_urlopen_ctx(
            _mock_vt_response(malicious=0, reputation=-50)
        )
        r = analyze_ip("8.8.8.8", check_reputation=True)
        sig = next(s for s in r.signals if s.name == "negative_vt_reputation_score")
        self.assertTrue(sig.triggered)
        self.assertEqual(sig.points, 15)

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_positive_vt_reputation_signal_does_not_trigger(self, mock_urlopen, _mock_key):
        mock_urlopen.return_value = _make_urlopen_ctx(
            _mock_vt_response(malicious=0, reputation=5)
        )
        r = analyze_ip("8.8.8.8", check_reputation=True)
        sig = next(s for s in r.signals if s.name == "negative_vt_reputation_score")
        self.assertFalse(sig.triggered)

    def test_all_six_signals_present(self):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        names = {s.name for s in r.signals}
        expected = {
            "non_public_address",
            "loopback_or_link_local",
            "reputation_flagged",
            "high_malicious_detection_ratio",
            "negative_vt_reputation_score",
            "no_reverse_dns",
        }
        self.assertEqual(names, expected)


# ---------------------------------------------------------------------------
# F. Risk score & level
# ---------------------------------------------------------------------------

class TestRiskScoreAndLevel(unittest.TestCase):

    def test_clean_public_ip_low(self):
        """8.8.8.8 with reverse DNS and no reputation → LOW."""
        with patch("intelligence.ip_analyzer.socket.gethostbyaddr",
                   return_value=("dns.google", [], ["8.8.8.8"])):
            r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertEqual(r.risk_score, 0)
        self.assertEqual(r.risk_level, "LOW")

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=socket.herror())
    def test_public_no_rdns_score_10(self, _mock):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertEqual(r.risk_score, 10)
        self.assertEqual(r.risk_level, "LOW")

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_malicious_ip_high_score(self, mock_urlopen, _mock_key):
        mock_urlopen.return_value = _make_urlopen_ctx(
            _mock_vt_response(malicious=30, suspicious=0, reputation=-100)
        )
        r = analyze_ip("8.8.8.8", check_reputation=True)
        # reputation_flagged(40) + high_detection_ratio(20) + negative_vt(15) = 75
        self.assertGreaterEqual(r.risk_score, 50)
        self.assertIn(r.risk_level, ("HIGH", "CRITICAL"))

    def test_score_capped_at_100(self):
        """Score must never exceed 100 even if signal sum exceeds it."""
        # Patch all signals to trigger
        with patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY"), \
             patch("intelligence.ip_analyzer.urllib.request.urlopen") as mock_u, \
             patch("intelligence.ip_analyzer.socket.gethostbyaddr",
                   side_effect=socket.herror()):
            mock_u.return_value = _make_urlopen_ctx(
                _mock_vt_response(malicious=30, reputation=-200)
            )
            r = analyze_ip("8.8.8.8", check_reputation=True)
        self.assertLessEqual(r.risk_score, 100)

    def test_invalid_input_score_zero_low(self):
        r = analyze_ip("bad_input", check_reputation=False)
        self.assertEqual(r.risk_score, 0)
        self.assertEqual(r.risk_level, "LOW")

    def test_level_bands(self):
        from app.engines.intel.url_analyzer import classify_risk
        self.assertEqual(classify_risk(0),   "LOW")
        self.assertEqual(classify_risk(24),  "LOW")
        self.assertEqual(classify_risk(25),  "MEDIUM")
        self.assertEqual(classify_risk(49),  "MEDIUM")
        self.assertEqual(classify_risk(50),  "HIGH")
        self.assertEqual(classify_risk(74),  "HIGH")
        self.assertEqual(classify_risk(75),  "CRITICAL")
        self.assertEqual(classify_risk(100), "CRITICAL")

    def test_multicast_zero_score(self):
        r = analyze_ip("224.0.0.1", check_reputation=False)
        self.assertEqual(r.risk_score, 0)

    def test_ipv6_loopback_zero_score(self):
        r = analyze_ip("::1", check_reputation=False)
        self.assertEqual(r.risk_score, 0)


# ---------------------------------------------------------------------------
# G. Never-raise / safety
# ---------------------------------------------------------------------------

class TestNeverRaise(unittest.TestCase):

    def test_none_input_does_not_raise(self):
        r = analyze_ip(None, check_reputation=False)  # type: ignore[arg-type]
        self.assertIsInstance(r, IPAnalysisResult)

    def test_integer_input_does_not_raise(self):
        r = analyze_ip(12345, check_reputation=False)  # type: ignore[arg-type]
        self.assertIsInstance(r, IPAnalysisResult)

    @patch("intelligence.ip_analyzer.socket.gethostbyaddr",
           side_effect=Exception("unexpected library explosion"))
    def test_unexpected_rdns_exception_handled(self, _mock):
        # Even unexpected exceptions in reverse DNS must be caught
        # The outer analyze_ip defensive try/except handles any remaining
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertIsInstance(r, IPAnalysisResult)

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen",
           side_effect=Exception("surprise explosion"))
    def test_unexpected_vt_exception_handled(self, _mock_urlopen, _mock_key):
        r = analyze_ip("8.8.8.8", check_reputation=True)
        self.assertIsInstance(r, IPAnalysisResult)

    def test_generated_by_is_tool(self):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertEqual(r.generated_by, "tool")

    def test_ai_interpretation_always_none(self):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        self.assertIsNone(r.ai_interpretation)


# ---------------------------------------------------------------------------
# H. JSON serialisation
# ---------------------------------------------------------------------------

class TestJSONSerialisation(unittest.TestCase):

    def test_valid_result_is_serialisable(self):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        d = asdict(r)
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)

    def test_error_result_is_serialisable(self):
        r = analyze_ip("not-an-ip", check_reputation=False)
        d = asdict(r)
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)

    @patch("intelligence.ip_analyzer._get_api_key", return_value="FAKE_KEY")
    @patch("intelligence.ip_analyzer.urllib.request.urlopen")
    def test_vt_result_is_serialisable(self, mock_urlopen, _mock_key):
        mock_urlopen.return_value = _make_urlopen_ctx(
            _mock_vt_response(malicious=2, reputation=-20)
        )
        r = analyze_ip("8.8.8.8", check_reputation=True)
        json_str = json.dumps(asdict(r))
        self.assertIsInstance(json_str, str)

    def test_disclaimer_and_metadata_present(self):
        r = analyze_ip("8.8.8.8", check_reputation=False)
        d = asdict(r)
        self.assertIn("disclaimer", d)
        self.assertIn("generated_by", d)
        self.assertIn("ai_interpretation", d)
        self.assertIsNone(d["ai_interpretation"])


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestValidation,
        TestClassification,
        TestReverseDNS,
        TestReputation,
        TestHeuristicSignals,
        TestRiskScoreAndLevel,
        TestNeverRaise,
        TestJSONSerialisation,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    import sys
    sys.exit(0 if result.wasSuccessful() else 1)
