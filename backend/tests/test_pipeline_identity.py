from app.engines.discovery.runner import _mapping_candidate, explicit_web_target, web_url_for_service
from app.engines.discovery.s4_crawl import normalize_discovered_endpoint
from app.engines.discovery.s4_crawl import (
    _dedupe_endpoints, _extract_js_routes, _openapi_operations, _same_authorized_root,
)
from app.engines.discovery.parameter_candidates import candidates_for_endpoints, dast_seed_urls
from app.engines.discovery.s7_persist import observation_source_ref


def test_nonstandard_web_ports_and_observed_scheme_are_preserved():
    assert web_url_for_service("api.example", {
        "port": 8080, "application_protocol": "http", "tunnel": None,
    }) == "http://api.example:8080"
    assert web_url_for_service("api.example", {
        "port": 8443, "application_protocol": "https", "tunnel": "ssl",
    }) == "https://api.example:8443"
    assert web_url_for_service("api.example", {
        "port": 6379, "application_protocol": "redis", "tunnel": None,
    }) is None


def test_explicit_url_becomes_one_constrained_web_service():
    origin, service = explicit_web_target("http://host.docker.internal:3000/")
    assert origin == "http://host.docker.internal:3000/"
    assert service["port"] == 3000
    assert service["application_protocol"] == "http"
    assert service["authorized_origin"] == origin
    assert explicit_web_target("example.test") is None


def test_endpoint_keeps_its_origin_and_removes_fragment():
    endpoint = normalize_discovered_endpoint(
        "https://api.example:8443", "/v1/users?id=7#profile"
    )
    assert endpoint == {
        "url": "https://api.example:8443/v1/users?id=7",
        "path": "/v1/users", "scheme": "https", "hostname": "api.example",
        "port": 8443, "source": "crawl",
    }


def test_malformed_scanner_url_is_dropped_without_crashing():
    assert normalize_discovered_endpoint("https://api.example", "https://api.example:bad/x") is None


def test_nuclei_mapping_is_deterministic_and_unknown_is_not_info_leak():
    finding = {"template-id": "x", "info": {"tags": ["xss", "sqli"]}}
    assert _mapping_candidate(finding) == "sqli"
    unknown = {"template-id": "vendor-new-check", "info": {"tags": ["vendor"]}}
    assert _mapping_candidate(unknown) == "nuclei:vendor-new-check"
    malformed = {"template-id": "broken-record", "info": ["not", "an", "object"]}
    assert _mapping_candidate(malformed) == "nuclei:broken-record"
    headers = {"template-id": "http-missing-security-headers", "info": {"tags": ["misconfig"]}}
    assert _mapping_candidate(headers) == "security_misconfig_headers"


def test_nuclei_matchers_have_distinct_retry_safe_observation_refs():
    csp = observation_source_ref(
        "nuclei", "http-missing-security-headers", {"matcher-name": "content-security-policy"}
    )
    referrer = observation_source_ref(
        "nuclei", "http-missing-security-headers", {"matcher-name": "referrer-policy"}
    )
    assert csp == "http-missing-security-headers:content-security-policy"
    assert referrer == "http-missing-security-headers:referrer-policy"
    assert csp != referrer


def test_openapi_operations_become_concrete_parameterized_endpoints():
    rows = _openapi_operations("http://example.test:3000/", {
        "paths": {"/api/users/{id}": {"get": {"parameters": [
            {"name": "q", "in": "query"}, {"name": "id", "in": "path"},
        ]}}}
    }, "none")
    assert len(rows) == 1
    assert rows[0]["url"] == "http://example.test:3000/api/users/1?q=1"
    assert rows[0]["param_names"] == ["q"]
    assert rows[0]["source"] == "openapi"


def test_crawl_root_rejects_cross_origin_and_path_escape():
    assert _same_authorized_root("https://example.test/app", "https://example.test/app/users")
    assert not _same_authorized_root("https://example.test/app", "https://example.test/admin")
    assert not _same_authorized_root("https://example.test/app", "https://evil.test/app")


def test_endpoint_merge_preserves_parameters_from_independent_channels():
    base = normalize_discovered_endpoint("https://example.test", "/search?q=1")
    rows = _dedupe_endpoints([
        {**base, "method": "GET", "param_names": ["q"], "auth_context": "none"},
        {**base, "method": "GET", "param_names": ["page"], "auth_context": "none",
         "source": "openapi"},
    ])
    assert len(rows) == 1
    assert rows[0]["param_names"] == ["page", "q"]


def test_spa_bundle_relative_api_literals_are_resolved_from_application_root():
    rows = _extract_js_routes(
        "http://example.test:3000/", "http://example.test:3000/assets/main.js",
        'const search="rest/products/search?q=apple";', "none",
    )
    assert rows[0]["url"] == "http://example.test:3000/rest/products/search?q=apple"
    assert rows[0]["param_names"] == ["q"]


class FakeEndpoint:
    id = "endpoint-1"
    url = "https://example.test/search"
    path = "/search"
    method = "GET"
    auth_context = "none"
    param_names = ["q", "csrf_token"]


def test_parameter_surface_feeds_validation_without_manufacturing_control_inputs():
    candidates = candidates_for_endpoints([FakeEndpoint()], 20)
    assert {(c.param, c.vuln_class) for c in candidates} == {
        ("q", "sqli"), ("q", "xss_reflected")
    }
    assert dast_seed_urls([FakeEndpoint()]) == ["https://example.test/search?q=1"]
