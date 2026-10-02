"""
IMPLEMENTATION_SPEC_v4.md §10 risk #10: two genuinely different
vulnerabilities in the same parameter must NOT collapse into one finding.
"""
from __future__ import annotations

from app.engines.discovery.dedup import compute_dedup_key, normalize_path_for_dedup


def _key(
    vuln_class: str,
    url: str,
    template=None,
    tool="nuclei",
    matched_param=None,
    cve_id=None,
):
    return compute_dedup_key(
        asset_id="asset-abc",
        source_tool=tool,
        vuln_class_candidate=vuln_class,
        template_id_or_type=template,
        path_or_url=url,
        method="GET",
        matched_param=matched_param,
        cve_id=cve_id,
    )


def test_same_parameter_different_values_collapse_to_one_finding():
    key1 = _key("sqli", "/product?id=1", template="sqli-boolean-based")
    key2 = _key("sqli", "/product?id=2", template="sqli-boolean-based")
    key3 = _key("sqli", "/product?id=999", template="sqli-boolean-based")
    assert key1 == key2 == key3


def test_different_vuln_classes_in_the_same_parameter_stay_distinct():
    """This is the exact bug the prior design had: without vuln_class_candidate
    in the key, an XSS and a SQLi both hitting `id` (with no template_id, e.g.
    both sourced from httpx-header-based findings) would incorrectly collapse.
    """
    sqli_key = _key("sqli", "/product?id=1", template=None, tool="httpx")
    xss_key = _key("xss_reflected", "/product?id=1", template=None, tool="httpx")
    assert sqli_key != xss_key


def test_different_parameters_stay_distinct():
    key_id = _key("sqli", "/product?id=1", template="sqli-boolean-based", matched_param="id")
    key_name = _key("sqli", "/product?id=1", template="sqli-boolean-based", matched_param="name")
    assert key_id != key_name


def test_different_paths_stay_distinct():
    key_a = _key("sqli", "/product?id=1", template="sqli-boolean-based")
    key_b = _key("sqli", "/order?id=1", template="sqli-boolean-based")
    assert key_a != key_b


def test_normalize_path_strips_values_keeps_sorted_names():
    path, names = normalize_path_for_dedup("/search?q=hello&sort=asc&sort=desc")
    assert path == "/search"
    assert names == ("q", "sort")  # sorted, deduplicated by parse_qs's own key grouping


def test_same_security_identity_from_two_tools_correlates():
    nuclei = _key("sqli", "/product?id=1", template="nuclei-sqli", tool="nuclei", matched_param="id")
    custom = _key("sqli", "/product?id=2", template="custom-check", tool="custom", matched_param="id")
    assert nuclei == custom


def test_distinct_cves_on_the_same_sink_do_not_collapse():
    first = _key("rce", "/admin", cve_id="CVE-2025-0001")
    second = _key("rce", "/admin", cve_id="CVE-2025-0002")
    assert first != second
