"""Fail-closed normalization and authorization for every Discovery target."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True, order=True)
class UrlRule:
    scheme: str
    host: str
    port: int
    path_prefix: str


@dataclass(frozen=True)
class ScopeRules:
    exact_hosts: frozenset[str] = field(default_factory=frozenset)
    exact_hostports: frozenset[tuple[str, int]] = field(default_factory=frozenset)
    wildcard_domains: frozenset[str] = field(default_factory=frozenset)
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    urls: tuple[UrlRule, ...] = ()
    rejected_entries: tuple[str, ...] = ()

    @property
    def has_cidrs(self) -> bool:
        return bool(self.cidrs)


@dataclass(frozen=True)
class ParsedTarget:
    host: str
    port: int | None
    scheme: str | None
    path: str


def _normalise_host(value: str) -> str:
    value = value.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not value or value.isdigit() or any(c in value for c in "@/%\\\x00"):
        raise ValueError("invalid hostname")
    ascii_host = value.encode("idna").decode("ascii")
    labels = ascii_host.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("invalid hostname labels")
    if any(not all(ch.isalnum() or ch == "-" for ch in label) for label in labels):
        raise ValueError("invalid hostname characters")
    return ascii_host


def parse_target(value: str) -> ParsedTarget:
    raw = (value or "").strip()
    if not raw or any(ord(ch) < 32 for ch in raw) or "\\" in raw:
        raise ValueError("malformed target")
    has_scheme = "://" in raw
    split = urlsplit(raw if has_scheme else f"//{raw}")
    if split.username is not None or split.password is not None:
        raise ValueError("userinfo is prohibited")
    if has_scheme and split.scheme.lower() not in {"http", "https"}:
        raise ValueError("unsupported scheme")
    if not split.hostname:
        raise ValueError("hostname is required")
    try:
        port = split.port
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    if has_scheme and port is None:
        port = 443 if split.scheme.lower() == "https" else 80
    path = unquote(split.path or "/")
    if any(part == ".." for part in path.split("/")):
        raise ValueError("path traversal is prohibited")
    return ParsedTarget(_normalise_host(split.hostname), port, split.scheme.lower() or None, path)


def parse_allowlist(raw: str) -> ScopeRules:
    exact_hosts: set[str] = set()
    exact_hostports: set[tuple[str, int]] = set()
    wildcard_domains: set[str] = set()
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    urls: list[UrlRule] = []
    rejected: list[str] = []
    for raw_entry in (raw or "").split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        try:
            cidrs.append(ipaddress.ip_network(entry, strict=False))
            continue
        except ValueError:
            pass
        try:
            if entry.startswith("*."):
                wildcard_domains.add(_normalise_host(entry[2:]))
                continue
            parsed = parse_target(entry)
            if parsed.scheme:
                urls.append(UrlRule(parsed.scheme, parsed.host, parsed.port or 80, parsed.path))
            elif parsed.port is not None:
                exact_hostports.add((parsed.host, parsed.port))
            else:
                exact_hosts.add(parsed.host)
        except ValueError:
            rejected.append(entry)
    return ScopeRules(
        frozenset(exact_hosts), frozenset(exact_hostports), frozenset(wildcard_domains),
        tuple(cidrs), tuple(sorted(urls)), tuple(rejected),
    )


def is_in_scope(rules: ScopeRules, target: str, resolved_ip: str | None = None) -> bool:
    try:
        candidate = parse_target(target)
    except ValueError:
        return False

    try:
        candidate_ip = ipaddress.ip_address(candidate.host)
    except ValueError:
        candidate_ip = None

    name_matched = candidate.host in rules.exact_hosts
    if candidate.port is not None and (candidate.host, candidate.port) in rules.exact_hostports:
        name_matched = True
    if not name_matched:
        name_matched = any(candidate.host.endswith("." + suffix) for suffix in rules.wildcard_domains)
    if not name_matched and candidate.scheme and candidate.port is not None:
        name_matched = any(
            candidate.scheme == rule.scheme and candidate.host == rule.host
            and candidate.port == rule.port
            and (candidate.path == rule.path_prefix.rstrip("/") or
                 candidate.path.startswith(rule.path_prefix.rstrip("/") + "/"))
            for rule in rules.urls
        )

    if candidate_ip is not None:
        return any(candidate_ip in network for network in rules.cidrs) or name_matched
    if not name_matched:
        return False
    if resolved_ip is not None and rules.has_cidrs:
        try:
            resolved = ipaddress.ip_address(resolved_ip)
        except ValueError:
            return False
        return any(resolved in network for network in rules.cidrs)
    return True


def canonical_root_hostname(host_or_url: str) -> str:
    host = parse_target(host_or_url).host
    return host[4:] if host.startswith("www.") else host
