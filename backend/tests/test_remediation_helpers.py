from types import SimpleNamespace

from app.api.remediation_api import (
    _grounded_confidence, _markers, _request_facts, _retest_verdict,
    _session_invalid_result,
)


def test_request_facts_prefer_validation_evidence():
    finding = SimpleNamespace(endpoint="GET https://fallback.test/a", param="q")
    evidence = SimpleNamespace(manifest={"transactions": [{"request": {
        "method": "GET", "url": "https://target.test/search.php",
        "params": [["q", "needle"]],
    }}]})
    assert _request_facts(finding, evidence) == {
        "method": "GET", "url": "https://target.test/search.php",
        "parameter": "q", "provenance": "validation evidence request",
        "path": "/search.php", "extension": ".php",
    }
    assert _markers(evidence) == ["needle"]


def test_retest_verdict_requires_active_disproof():
    assert _retest_verdict("false_positive") == ("remediated", False)
    assert _retest_verdict("validated") == ("still_vulnerable", True)
    assert _retest_verdict("inconclusive") == ("inconclusive", None)


def test_expired_session_retests_inconclusive_not_remediated():
    # An auth-only finding whose discovering session has expired must never be
    # reported as fixed just because an unauthenticated replay sees a login page.
    result = _session_invalid_result("authenticated")
    assert result["status"] == "inconclusive"
    assert result["retest_error"] is False
    assert result["manifest"]["session_invalid"] is True
    assert result["manifest"]["auth_context"] == "authenticated"
    # The verdict path must resolve to inconclusive, not remediated.
    verdict, reproducible = _retest_verdict(result["status"])
    assert verdict == "inconclusive"
    assert reproducible is None


def test_remediation_confidence_is_bounded_by_validated_evidence():
    score, basis = _grounded_confidence(1.0, [0.92, 0.95])
    assert score == 0.92
    assert basis["provider_self_reported"] == 1.0
    assert basis["validated_evidence_bound"] == 0.92
    assert basis["formula"] == "min(provider_self_reported, weakest_validated_evidence)"


def test_provider_can_lower_but_not_raise_evidence_confidence():
    assert _grounded_confidence(0.7, [0.9])[0] == 0.7
    assert _grounded_confidence(None, [0.9])[0] == 0.9
    assert _grounded_confidence(0.8, [])[0] == 0.8
