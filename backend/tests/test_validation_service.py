from __future__ import annotations

from app.engines.validation.http import Request, Response
from app.engines.validation.mock_target import MockSstiTarget

from app.engines.validation.service import (
    _validate_missing_headers,
    _validate_reflected_xss,
    _validate_slice5,
    endpoint_method,
    endpoint_url,
)


class HeaderTarget:
    def __init__(self, headers: tuple[tuple[str, str], ...]):
        self.headers = headers

    def __call__(self, _request: Request) -> Response:
        return Response(status=200, body="safe fixture", headers=self.headers, elapsed_ms=2.0)


class ReflectingHtmlTarget:
    def __call__(self, request: Request) -> Response:
        value = dict(request.params).get("q", "")
        return Response(status=200, body=f"<html><body>{value}</body></html>",
                        headers=(("content-type", "text/html"),), elapsed_ms=2.0)


def finding(**overrides):
    row = {
        "id": "41da261f-37b9-47a3-9d46-57fd25142038",
        "asset_id": "asset-1",
        "vuln_class": "misconfig_open_service",
        "endpoint": "GET http://example.test/",
        "param": None,
    }
    row.update(overrides)
    return row


def test_endpoint_url_removes_the_contract_method_prefix():
    assert endpoint_url("GET https://example.test/a?q=1") == "https://example.test/a?q=1"
    assert endpoint_url("javascript:alert(1)") is None
    assert endpoint_method("POST https://example.test/a") == "POST"


def test_missing_header_is_confirmed_three_times_with_replayable_evidence():
    result = _validate_missing_headers(
        finding(), HeaderTarget((("content-type", "text/html"),)),
        ["content-security-policy"],
    )
    assert result["status"] == "validated"
    assert result["confidence"] == 0.95
    assert result["manifest"]["generated_by"] == "tool"
    assert len(result["manifest"]["transactions"]) == 3
    assert result["manifest"]["outcomes"][0]["missing"] == ["content-security-policy"]


def test_hsts_is_not_applicable_to_plain_http_responses():
    result = _validate_missing_headers(
        finding(endpoint="GET http://example.test/"), HeaderTarget(()),
        ["strict-transport-security"],
    )
    assert result["status"] == "false_positive"
    assert result["manifest"]["transactions"] == []
    assert result["manifest"]["outcomes"][0]["not_applicable"] == [
        "strict-transport-security"
    ]


def test_hsts_remains_applicable_to_https_responses():
    result = _validate_missing_headers(
        finding(endpoint="GET https://example.test/"), HeaderTarget(()),
        ["strict-transport-security"],
    )
    assert result["status"] == "validated"
    assert result["manifest"]["outcomes"][0]["missing"] == [
        "strict-transport-security"
    ]


def test_http_header_validation_excludes_hsts_but_confirms_other_headers():
    result = _validate_missing_headers(
        finding(endpoint="GET http://example.test/"), HeaderTarget(()),
        ["strict-transport-security", "content-security-policy"],
    )
    assert result["status"] == "validated"
    assert result["manifest"]["outcomes"][0]["not_applicable"] == [
        "strict-transport-security"
    ]
    assert result["manifest"]["outcomes"][1]["missing"] == [
        "content-security-policy"
    ]


def test_present_header_disproves_the_original_scanner_observation():
    result = _validate_missing_headers(
        finding(), HeaderTarget((("Content-Security-Policy", "default-src 'self'"),)),
        ["content-security-policy"],
    )
    assert result["status"] == "false_positive"
    assert "now present" in result["reason"]


def test_secret_response_headers_are_redacted_in_persisted_manifest():
    result = _validate_missing_headers(
        finding(), HeaderTarget((("set-cookie", "session=secret"),)),
        ["content-security-policy"],
    )
    response_headers = result["manifest"]["transactions"][0]["response"]["headers"]
    assert ["set-cookie", "<redacted>"] in response_headers


def test_missing_matcher_is_inconclusive_not_a_guessed_validation():
    result = _validate_missing_headers(finding(), HeaderTarget(()), [])
    assert result["status"] == "inconclusive"
    assert result["manifest"]["transactions"] == []


def test_ssti_route_uses_the_expression_oracle_without_sqli_only_arguments():
    result = _validate_slice5(
        finding(
            vuln_class="ssti", endpoint="GET http://example.test/hello", param="name",
        ),
        MockSstiTarget("vulnerable"),
    )
    assert result["status"] == "validated"
    assert result["oracle"] == "differential.expression"


def test_reflected_xss_uses_two_inert_html_markers_without_script_execution():
    result = _validate_reflected_xss(
        finding(vuln_class="xss_reflected", endpoint="GET http://example.test/search", param="q"),
        ReflectingHtmlTarget(),
    )
    assert result["status"] == "validated"
    assert result["oracle"] == "reflection.html"
    assert len(result["manifest"]["transactions"]) == 3
    assert all("script" not in (tx["request"].get("body") or "")
               for tx in result["manifest"]["transactions"])
