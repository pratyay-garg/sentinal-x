import json
from dataclasses import dataclass, field

import pytest

from app.engines.discovery import s4_crawl, s5_vuln_scan
from app.engines.discovery.parameter_candidates import (
    candidates_for_endpoints,
    dast_seed_urls,
    signature_scan_targets,
)
from app.core.subprocess_utils import ToolResult


@dataclass
class _Endpoint:
    url: str
    path: str
    method: str = "GET"
    auth_context: str = "none"
    id: str = "e"
    asset_id: str = "a"
    service_id: str = "s"
    source: str = "crawl"
    param_names: list[str] = field(default_factory=list)


def test_signature_targets_strip_queries_and_dedupe_paths():
    endpoints = [
        _Endpoint("http://t/product?id=1", "/product", param_names=["id"]),
        _Endpoint("http://t/product?id=2", "/product", param_names=["id"]),
        _Endpoint("http://t/about", "/about"),
    ]
    assert signature_scan_targets(endpoints) == ["http://t/about", "http://t/product"]


def test_dast_seeds_dedupe_by_parameter_shape_and_cap():
    endpoints = [_Endpoint(f"http://t/product?id={n}", "/product", param_names=["id"])
                 for n in range(50)]
    endpoints.append(_Endpoint("http://t/search?q=x", "/search", param_names=["q"]))
    seeds = dast_seed_urls(endpoints)
    assert len(seeds) == 2  # 50 ids of one shape collapse to a single seed
    assert dast_seed_urls(endpoints, limit=1) == seeds[:1]


def test_parameterless_urls_are_not_dast_seeded():
    assert dast_seed_urls([_Endpoint("http://t/about", "/about")]) == []


def test_candidates_collapse_on_path_shape():
    endpoints = [_Endpoint(f"http://t/product?id={n}", "/product", id=f"e{n}",
                           param_names=["id"]) for n in range(10)]
    rows = candidates_for_endpoints(endpoints, limit=100)
    assert len(rows) == 1
    assert rows[0].vuln_class == "sqli"


@pytest.mark.asyncio
async def test_deep_katana_uses_headless_without_incompatible_dit(monkeypatch):
    calls = []

    async def fake_run(argv, *, timeout, input_data=None):
        calls.append(argv)
        return ToolResult(0, b"", b"")

    async def fake_fallback(*args, **kwargs):
        return {"endpoints": [], "pages_fetched": 0}

    async def fake_specs(*args, **kwargs):
        return {"endpoints": [], "documents": 0, "operations": 0}

    async def fake_content(*args, **kwargs):
        return {"endpoints": [], "probed": 0}

    monkeypatch.setattr(s4_crawl, "run_tool", fake_run)
    monkeypatch.setattr(s4_crawl, "_fallback_crawl", fake_fallback)
    monkeypatch.setattr(s4_crawl, "_probe_spec_paths", fake_specs)
    monkeypatch.setattr(s4_crawl, "_probe_content_paths", fake_content)
    monkeypatch.setattr(s4_crawl.settings, "offline_mode", False)

    await s4_crawl.run_s4_crawl("http://example.test/", None, profile="deep")

    assert len(calls) == 1
    assert calls[0][0] == s4_crawl.settings.katana_bin
    assert "-kb" not in calls[0]
    assert "-kb-endpoints" not in calls[0]
    assert "-kb-secrets" not in calls[0]
    assert {"-headless", "-no-sandbox", "-xhr-extraction", "-system-chrome"} <= set(calls[0])
    assert "-cs" in calls[0]
    assert "-ns" not in calls[0]


@pytest.mark.asyncio
async def test_fast_katana_remains_standard_mode(monkeypatch):
    calls = []

    async def fake_run(argv, *, timeout, input_data=None):
        calls.append(argv)
        return ToolResult(0, b"", b"")

    async def fake_fallback(*args, **kwargs):
        return {"endpoints": [], "pages_fetched": 0}

    async def fake_specs(*args, **kwargs):
        return {"endpoints": [], "documents": 0, "operations": 0}

    async def fake_content(*args, **kwargs):
        return {"endpoints": [], "probed": 0}

    monkeypatch.setattr(s4_crawl, "run_tool", fake_run)
    monkeypatch.setattr(s4_crawl, "_fallback_crawl", fake_fallback)
    monkeypatch.setattr(s4_crawl, "_probe_spec_paths", fake_specs)
    monkeypatch.setattr(s4_crawl, "_probe_content_paths", fake_content)

    await s4_crawl.run_s4_crawl("http://example.test/", None, profile="fast")

    assert len(calls) == 1
    assert "-headless" not in calls[0]
    assert "-xhr-extraction" not in calls[0]
    assert "-kb" in calls[0]


def test_katana_endpoint_query_reaches_dast_seed_handoff():
    record = {
        "request": {
            "method": "GET",
            "endpoint": "http://example.test/rest/products/search?q=apple",
            "source": "xhr",
        },
        "response": {"status_code": 200, "body": "{}"},
    }
    parsed = s4_crawl._parse_katana(
        (json.dumps(record) + "\n").encode(), "http://example.test/", None, "none"
    )

    assert len(parsed) == 1
    assert parsed[0]["endpoint_class"] == "xhr"
    assert parsed[0]["param_names"] == ["q"]
    endpoint = _Endpoint(
        parsed[0]["url"], parsed[0]["path"], method=parsed[0]["method"],
        param_names=parsed[0]["param_names"], source=parsed[0]["source"],
    )
    assert dast_seed_urls([endpoint]) == [
        "http://example.test/rest/products/search?q=apple"
    ]


def test_katana_headless_json_api_is_xhr_when_source_marker_is_absent():
    """Katana 1.6.1 omits request.source on executed headless XHR records."""
    record = {
        "request": {
            "method": "GET",
            "endpoint": "http://example.test/rest/products/search?q=",
            "headers": {"Accept": "application/json, text/plain, */*"},
        },
        "response": {
            "status_code": 200,
            "headers": {"Content-Type": "application/json; charset=utf-8"},
            "body": '{"data":[]}',
        },
    }
    parsed = s4_crawl._parse_katana(
        (json.dumps(record) + "\n").encode(), "http://example.test/", None, "none"
    )

    assert parsed[0]["endpoint_class"] == "xhr"
    assert parsed[0]["param_names"] == ["q"]


def test_js_route_keeps_blank_query_parameter_and_stronger_classification():
    extracted = s4_crawl._extract_js_routes(
        "http://example.test/", "http://example.test/main.js",
        'const search = "/rest/products/search?q=";', "none",
    )
    merged = s4_crawl._dedupe_endpoints([
        {**extracted[0], "endpoint_class": "unknown"}, extracted[0],
    ])

    assert extracted[0]["param_names"] == ["q"]
    assert merged[0]["endpoint_class"] == "xhr"


class _FakeResponse:
    def __init__(self, status_code, headers, text=""):
        self.status_code = status_code
        self.headers = headers
        self.text = text


class _FakeClient:
    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        self.requested.append(url)
        return self.pages.get(url, _FakeResponse(404, {"content-type": "text/html"}, "nope"))


@pytest.mark.asyncio
async def test_fallback_crawl_follows_in_scope_redirect(monkeypatch):
    # A login-gated app answers `/` with `302 -> /login`; without following the
    # redirect the whole application stays invisible and no parameter is found.
    client = _FakeClient({
        "http://t/": _FakeResponse(302, {"content-type": "text/html",
                                         "location": "login.php"}),
        "http://t/login.php": _FakeResponse(
            200, {"content-type": "text/html"},
            '<html><form action="/login.php" method="POST">'
            '<input name="username"><input name="password"></form></html>'),
    })
    monkeypatch.setattr(s4_crawl.pyhttpx, "AsyncClient", lambda **kwargs: client)
    result = await s4_crawl._fallback_crawl("http://t/", None, {}, "none", 3, 50)
    assert "http://t/login.php" in client.requested
    assert any(sorted(ep["param_names"]) == ["password", "username"]
               for ep in result["endpoints"])


@pytest.mark.asyncio
async def test_fallback_crawl_refuses_out_of_scope_redirect(monkeypatch):
    client = _FakeClient({
        "http://t/": _FakeResponse(302, {"content-type": "text/html",
                                         "location": "http://evil.test/steal"}),
    })
    monkeypatch.setattr(s4_crawl.pyhttpx, "AsyncClient", lambda **kwargs: client)
    await s4_crawl._fallback_crawl("http://t/", None, {}, "none", 3, 50)
    assert client.requested == ["http://t/"]  # scope check still gates the hop


@pytest.mark.asyncio
async def test_spa_soft404_does_not_suppress_authorized_seed_scripts(monkeypatch):
    shell = '<html><script src="main.js"></script></html>'
    signature = {
        "status_code": 200,
        "content_length": len(shell),
        "content_hash": s4_crawl._quick_hash(shell),
    }
    client = _FakeClient({
        "http://t/": _FakeResponse(200, {"content-type": "text/html"}, shell),
        "http://t/main.js": _FakeResponse(
            200, {"content-type": "application/javascript"},
            'const search = "/rest/products/search?q=";',
        ),
    })
    monkeypatch.setattr(s4_crawl.pyhttpx, "AsyncClient", lambda **kwargs: client)

    result = await s4_crawl._fallback_crawl("http://t/", signature, {}, "none", 3, 50)

    assert "http://t/main.js" in client.requested
    assert any(ep["path"] == "/rest/products/search" and ep["param_names"] == ["q"]
               for ep in result["endpoints"])


def test_modern_spa_tags_fire_and_signature_pass_stays_bounded():
    tags = set(s5_vuln_scan.build_tag_allowlist([
        {"product": "Node.js"}, {"product": "Express"}, {"product": "Angular"},
    ]))
    assert {"nodejs", "express", "angular"} <= tags
    assert set(s5_vuln_scan.always_on_tags()) <= tags
    assert "exposure" in tags
    assert "exposures" not in tags
    # `-tags` is an OR filter: an injection tag here re-admits every CVE
    # template carrying it, which is what blew the signature-pass deadline.
    assert not ({"cve", "tech", "rce", "sqli", "xss"} & set(s5_vuln_scan.always_on_tags()))
    # Injection coverage lives in the DAST pass, which is scoped to the fuzzing
    # corpus directory rather than by tag — tags there admit non-fuzzing
    # templates that inflate the pass without ever mutating a parameter.
    assert (s5_vuln_scan.settings.nuclei_dast_templates_path
            != s5_vuln_scan.settings.nuclei_templates_path)
    assert "fuzz" not in s5_vuln_scan.excluded_tags()


def test_detected_stack_pulls_its_own_product_surface():
    tags = set(s5_vuln_scan.build_tag_allowlist([
        {"product": "Apache HTTP Server"}, {"product": "PHP"},
    ]))
    assert {"apache", "php"} <= tags


@pytest.mark.asyncio
async def test_signature_and_explicit_bounded_dast_passes_are_both_run(monkeypatch, tmp_path):
    calls = []
    finding = {"template-id": "test", "matched-at": "http://example.test/?q=1"}

    async def fake_run(argv, *, timeout, input_data):
        calls.append((argv, timeout, input_data))
        return ToolResult(0, (json.dumps(finding) + "\n").encode(), b"")

    monkeypatch.setattr(s5_vuln_scan, "run_tool", fake_run)
    monkeypatch.setattr(s5_vuln_scan.settings, "nuclei_dast_templates_path", str(tmp_path))
    result = await s5_vuln_scan.run_s5_vuln_scan(
        ["http://example.test/"], ["http://example.test/?q=1"], ["sqli", "xss"],
        False, profile="fast",
    )
    assert len(calls) == 2
    assert all(call[0][0] == s5_vuln_scan.settings.nuclei_bin for call in calls)
    assert "-dast" not in calls[0][0]
    assert "-dast" in calls[1][0]
    # Each pass is scoped to its own template set: full root for signatures,
    # fuzzing corpus only for DAST.
    assert calls[0][0][calls[0][0].index("-t") + 1] == s5_vuln_scan.settings.nuclei_templates_path
    assert calls[1][0][calls[1][0].index("-t") + 1] == str(tmp_path)
    assert "-tags" not in calls[1][0]
    assert calls[1][0][calls[1][0].index("-fuzz-aggression") + 1] == "low"
    assert "-ni" in calls[1][0]
    # The signature pass scans the bare path; only the DAST pass sees the query.
    assert calls[0][2] == b"http://example.test/"
    assert calls[1][2] == b"http://example.test/?q=1"
    # Two byte-identical records (one per pass) collapse to one finding.
    assert len(result["findings"]) == 1
    assert all(item["returncode"] == 0 for item in result["diagnostics"])


@pytest.mark.asyncio
async def test_pass_is_skipped_when_it_has_no_targets(monkeypatch):
    calls = []

    async def fake_run(argv, *, timeout, input_data):
        calls.append(argv)
        return ToolResult(0, b"", b"")

    monkeypatch.setattr(s5_vuln_scan, "run_tool", fake_run)
    result = await s5_vuln_scan.run_s5_vuln_scan(
        ["http://example.test/"], [], ["cve"], False
    )
    assert [c for c in calls if "-dast" in c] == []  # no DAST pass without seeds
    assert len(calls) == 1
    assert {item["pass"] for item in result["diagnostics"]} == {"signatures"}


@pytest.mark.asyncio
async def test_timed_out_pass_keeps_partial_findings(monkeypatch, tmp_path):
    partial = {"template-id": "partial", "matched-at": "http://example.test/?q=1"}

    async def fake_run(argv, *, timeout, input_data):
        return ToolResult(-1, (json.dumps(partial) + "\n").encode(), b"timeout",
                          timed_out=True)

    monkeypatch.setattr(s5_vuln_scan, "run_tool", fake_run)
    monkeypatch.setattr(s5_vuln_scan.settings, "nuclei_dast_templates_path", str(tmp_path))
    result = await s5_vuln_scan.run_s5_vuln_scan(
        ["http://example.test/"], ["http://example.test/?q=1"], ["sqli"], False
    )
    assert len(result["findings"]) == 1  # a deadline no longer discards results
    assert all(item["timed_out"] for item in result["diagnostics"])


@pytest.mark.asyncio
async def test_missing_dast_corpus_is_reported_rather_than_silent(monkeypatch, tmp_path):
    async def fake_run(argv, *, timeout, input_data):
        return ToolResult(0, b"", b"")

    monkeypatch.setattr(s5_vuln_scan, "run_tool", fake_run)
    monkeypatch.setattr(s5_vuln_scan.settings, "nuclei_dast_templates_path",
                        str(tmp_path / "absent"))
    result = await s5_vuln_scan.run_s5_vuln_scan(
        ["http://example.test/"], ["http://example.test/?q=1"], ["cve"], False
    )
    dast = [item for item in result["diagnostics"] if item["pass"] == "dast"]
    assert dast and "not found" in dast[0]["stderr"]


@pytest.mark.asyncio
async def test_tool_failure_and_secret_redaction_are_visible(monkeypatch):
    async def fake_run(argv, *, timeout, input_data):
        return ToolResult(2, b"", b"bad cookie session=supersecret")

    monkeypatch.setattr(s5_vuln_scan, "run_tool", fake_run)
    result = await s5_vuln_scan.run_s5_vuln_scan(
        ["http://example.test/"], [], ["cve"], False,
        headers={"Cookie": "session=supersecret"},
    )
    assert all(item["returncode"] == 2 for item in result["diagnostics"])
    assert all("supersecret" not in item["stderr"] for item in result["diagnostics"])
    assert all("<redacted>" in item["stderr"] for item in result["diagnostics"])
