"""
intelligence/test_reputation.py
---------------------------------
SentinelX - reputation.py unit tests.

Every test mocks urllib.request.urlopen. NONE of these tests make a real
network call to VirusTotal or anywhere else.

Two ways to run this file, same convention as test_url_analyzer.py:

  1. As a plain demo (no test framework needed):
         python intelligence/test_reputation.py

  2. As an actual test suite, if pytest is installed:
         pytest intelligence/test_reputation.py -v
"""

import dataclasses
import json
import os
import socket
import urllib.error

from unittest.mock import patch, MagicMock

from app.engines.intel.reputation import (
    check_url_reputation,
    ReputationResult,
    API_KEY_ENV_VAR,
    _url_to_vt_id,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _fake_response(payload_dict, status=200):
    """A fake context-managed urlopen() response with a JSON body."""
    body = json.dumps(payload_dict).encode("utf-8")
    response = MagicMock()
    response.status = status
    response.read.return_value = body
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    return response


def _raw_response(raw_bytes, status=200):
    """A fake context-managed urlopen() response with a raw (possibly
    non-JSON) body."""
    response = MagicMock()
    response.status = status
    response.read.return_value = raw_bytes
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    return response


def _http_error(code, reason="error"):
    return urllib.error.HTTPError(
        url="https://www.virustotal.com/api/v3/urls/x",
        code=code, msg=reason, hdrs=None, fp=None,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_url_id_encoding_is_urlsafe_and_deterministic():
    encoded = _url_to_vt_id("https://example.com/")
    assert isinstance(encoded, str)
    assert "=" not in encoded  # padding stripped
    assert encoded == _url_to_vt_id("https://example.com/")  # deterministic


def test_missing_api_key_returns_error_without_any_network_call():
    with patch.dict(os.environ, {}, clear=True), \
         patch("reputation.urllib.request.urlopen") as mock_urlopen:
        result = check_url_reputation("https://example.com/")
    assert result.available is False
    assert result.error is not None
    assert API_KEY_ENV_VAR in result.error
    assert mock_urlopen.called is False  # never even attempted to connect


def test_url_not_previously_analyzed_returns_available_with_no_verdict():
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen", side_effect=_http_error(404)):
        result = check_url_reputation("https://example.com/")
    assert result.available is True
    assert result.error is None
    assert result.malicious is False
    assert result.detection_count is None


def test_clean_url_is_not_flagged():
    payload = {"data": {"attributes": {
        "last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "harmless": 68, "undetected": 5, "timeout": 0,
        },
        "reputation": 12,
    }}}
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen", return_value=_fake_response(payload)):
        result = check_url_reputation("https://example.com/")
    assert result.available is True
    assert result.malicious is False
    assert result.suspicious is False
    assert result.detection_count == 0
    assert result.total_engines == 73
    assert result.reputation_score == 12
    assert result.error is None


def test_malicious_url_is_flagged_with_detection_counts():
    payload = {"data": {"attributes": {
        "last_analysis_stats": {
            "malicious": 12, "suspicious": 3, "harmless": 50, "undetected": 9, "timeout": 0,
        },
        "reputation": -40,
    }}}
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen", return_value=_fake_response(payload)):
        result = check_url_reputation("https://evil-example.net/")
    assert result.available is True
    assert result.malicious is True
    assert result.suspicious is True
    assert result.detection_count == 12
    assert result.total_engines == 74
    assert result.reputation_score == -40
    assert "12" in result.raw_summary


def test_timeout_returns_error_without_raising():
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen", side_effect=socket.timeout("timed out")):
        result = check_url_reputation("https://example.com/", timeout=2.0)
    assert result.available is False
    assert result.error is not None
    assert "timed out" in result.error.lower() or "timeout" in result.error.lower()


def test_network_failure_returns_error_without_raising():
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen",
               side_effect=urllib.error.URLError("name resolution failed")):
        result = check_url_reputation("https://example.com/")
    assert result.available is False
    assert result.error is not None


def test_api_error_status_returns_error_without_raising():
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen", side_effect=_http_error(401, "Unauthorized")):
        result = check_url_reputation("https://example.com/")
    assert result.available is False
    assert result.error is not None
    assert "401" in result.error


def test_invalid_json_response_returns_error_without_raising():
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen",
               return_value=_raw_response(b"not json at all {{{")):
        result = check_url_reputation("https://example.com/")
    assert result.available is False
    assert result.error is not None


def test_unexpected_response_shape_is_handled_gracefully():
    # "data.attributes" exists but has no last_analysis_stats at all -
    # must not crash, and must report an empty (not fabricated) verdict.
    payload = {"data": {"attributes": {}}}
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen", return_value=_fake_response(payload)):
        result = check_url_reputation("https://example.com/")
    assert result.available is True
    assert result.detection_count == 0
    assert result.malicious is False


def test_completely_malformed_response_shape_returns_error_without_raising():
    # Missing "data" entirely - a KeyError inside the parsing logic must
    # be caught, not propagated.
    payload = {"unexpected": "shape"}
    with patch.dict(os.environ, {API_KEY_ENV_VAR: "test-key"}), \
         patch("reputation.urllib.request.urlopen", return_value=_fake_response(payload)):
        result = check_url_reputation("https://example.com/")
    assert result.available is False
    assert result.error is not None


def test_error_messages_never_contain_the_api_key():
    secret = "super-secret-key-do-not-leak-123"
    with patch.dict(os.environ, {API_KEY_ENV_VAR: secret}), \
         patch("reputation.urllib.request.urlopen", side_effect=_http_error(401, "Unauthorized")):
        result = check_url_reputation("https://example.com/")
    serialized = json.dumps(dataclasses.asdict(result))
    assert secret not in serialized


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
