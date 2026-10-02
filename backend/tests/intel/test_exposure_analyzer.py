"""Deterministic tests for the Part 7 email exposure scanner (network mocked)."""
import app.engines.intel.exposure_analyzer as exposure
from app.engines.intel.exposure_analyzer import analyze_email_exposure

_ANALYTICS = {
    "ExposedBreaches": {"breaches_details": [
        {"breach": "Adobe", "domain": "adobe.com", "xposed_date": "2013",
         "xposed_records": "152445165", "password_risk": "plaintext", "verified": "Yes",
         "xposed_data": "Email addresses;Password hints;Passwords;Usernames"},
        {"breach": "LinkedIn", "domain": "linkedin.com", "xposed_date": "2012",
         "xposed_records": "164611595", "password_risk": "hashed", "verified": "Yes",
         "xposed_data": "Email addresses;Passwords"},
    ]},
    "ExposedPastes": {"pastes_details": [{"source": "Pastebin"}]},
}


def _stub(result, status, error):
    return lambda url, timeout: (result, status, error)


def test_invalid_email_never_calls_network(monkeypatch):
    monkeypatch.setattr(exposure, "_http_get_json", _stub(None, 500, "should not run"))
    r = analyze_email_exposure("nope")
    assert r.source == "invalid" and r.risk_score == 0 and r.error


def test_offline_skips_lookup():
    r = analyze_email_exposure("user@example.com", offline=True)
    assert r.source == "unavailable" and r.found is False


def test_email_is_masked_and_no_passwords_leak(monkeypatch):
    monkeypatch.setattr(exposure, "_http_get_json", _stub(_ANALYTICS, 200, None))
    r = analyze_email_exposure("alice@example.com")
    assert r.email == "a***@example.com"
    # categories are surfaced; raw password values never are.
    blob = " ".join(r.exposed_categories).lower()
    assert "passwords" in blob                      # category label is fine
    assert all("plaintext" not in b.name.lower() for b in r.breaches)


def test_breached_address_scores_high(monkeypatch):
    monkeypatch.setattr(exposure, "_http_get_json", _stub(_ANALYTICS, 200, None))
    r = analyze_email_exposure("alice@example.com")
    assert r.found and r.breach_count == 2
    assert r.risk_level in {"HIGH", "CRITICAL"}
    fired = {s.name for s in r.signals if s.triggered}
    assert {"appears_in_breach", "passwords_exposed", "plaintext_passwords"} <= fired


def test_clean_address_is_low_risk(monkeypatch):
    monkeypatch.setattr(exposure, "_http_get_json", _stub(None, 404, None))
    r = analyze_email_exposure("clean@example.com")
    assert r.found is False and r.breach_count == 0 and r.risk_level == "LOW"


def test_network_failure_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(exposure, "_http_get_json", _stub(None, None, "network unavailable: URLError"))
    r = analyze_email_exposure("alice@example.com")
    assert r.source == "unavailable" and r.error
