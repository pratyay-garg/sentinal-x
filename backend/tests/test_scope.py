"""
IMPLEMENTATION_SPEC_v4.md §10 risk-review rule: "Give the scope engine real
human test coverage before demo day, specifically because those are the two
places where a subtle bug doesn't degrade the demo — it produces an
unauthorized scan." These cases are the ones that must never regress.
"""
from __future__ import annotations

from app.core.scope import canonical_root_hostname, is_in_scope, parse_allowlist


def test_empty_allowlist_is_fail_closed():
    rules = parse_allowlist("")
    assert is_in_scope(rules, "example.com") is False
    assert is_in_scope(rules, "anything.at.all") is False


def test_exact_host_match():
    rules = parse_allowlist("example.com")
    assert is_in_scope(rules, "example.com") is True
    assert is_in_scope(rules, "example.com:8443") is True
    assert is_in_scope(rules, "other.com") is False


def test_wildcard_matches_subdomains_but_not_unrelated_hosts():
    rules = parse_allowlist("*.staging.example.com")
    assert is_in_scope(rules, "api.staging.example.com") is True
    assert is_in_scope(rules, "staging.example.com") is False  # wildcard means subdomains only
    assert is_in_scope(rules, "example.com") is False  # parent domain is NOT auto-included
    assert is_in_scope(rules, "evilstaging.example.com") is False  # not a subdomain, just a similar prefix


def test_zero_cidr_entries_means_ip_restriction_not_in_effect():
    """The single most important, non-obvious rule in the whole scope engine.
    An allowlist with ONLY hostname entries (no CIDR at all) must authorize a
    hostname regardless of what IP it resolves to — IP-level restriction was
    simply never configured, which is different from "resolved IP must match
    an empty set of allowed ranges" (which would incorrectly reject
    everything).
    """
    rules = parse_allowlist("example.com")
    assert rules.has_cidrs is False
    assert is_in_scope(rules, "example.com", resolved_ip="203.0.113.50") is True
    assert is_in_scope(rules, "example.com", resolved_ip="10.0.0.1") is True


def test_cidr_present_can_veto_a_hostname_pointed_elsewhere():
    """When a CIDR IS configured, a hostname allow-listed by wildcard that
    resolves OUTSIDE every configured CIDR is rejected — this is the one case
    where IP-level scope can independently veto a name-based match, e.g. a
    subdomain that's been re-pointed (via DNS) at infrastructure nobody
    authorized.
    """
    rules = parse_allowlist("*.staging.example.com,10.20.30.0/24")
    assert is_in_scope(rules, "api.staging.example.com", resolved_ip="10.20.30.5") is True
    assert is_in_scope(rules, "api.staging.example.com", resolved_ip="198.51.100.9") is False


def test_asn_is_not_a_scope_primitive():
    """ASN strings must never be treated as valid allowlist entries — parsing
    one should simply drop it (fail closed), not silently authorize
    everything on that autonomous system.
    """
    rules = parse_allowlist("AS15169")
    assert is_in_scope(rules, "google.com") is False


def test_canonical_root_hostname_strips_scheme_port_path_www():
    assert canonical_root_hostname("https://www.example.com:8443/some/path?x=1") == "example.com"
    assert canonical_root_hostname("example.com") == "example.com"


def test_exact_host_and_port_does_not_authorize_other_ports():
    rules = parse_allowlist("example.com:8443")
    assert is_in_scope(rules, "https://example.com:8443/api")
    assert not is_in_scope(rules, "https://example.com:443/api")


def test_url_rule_enforces_scheme_port_and_path_boundary():
    rules = parse_allowlist("https://example.com:9443/allowed")
    assert is_in_scope(rules, "https://example.com:9443/allowed/child")
    assert not is_in_scope(rules, "http://example.com:9443/allowed")
    assert not is_in_scope(rules, "https://example.com:9443/allowed-evil")


def test_ipv6_cidr_and_literal_are_parsed_without_colon_confusion():
    rules = parse_allowlist("2001:db8::/32")
    assert is_in_scope(rules, "https://[2001:db8::1]:8443/")
    assert not is_in_scope(rules, "https://[2001:db9::1]:8443/")


def test_idn_is_normalized_to_punycode():
    rules = parse_allowlist("https://bücher.example/path")
    assert is_in_scope(rules, "https://xn--bcher-kva.example/path/item")


def test_userinfo_and_alternate_integer_ip_are_rejected():
    rules = parse_allowlist("example.com,127.0.0.0/8")
    assert not is_in_scope(rules, "https://example.com@evil.test/")
    assert not is_in_scope(rules, "2130706433")
