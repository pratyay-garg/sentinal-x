"""
The scope gate -- Layer 0 of validation, and the single most important safety
control in the whole module.

LAW 5 (safe by construction): every outbound request passes through ONE
deny-by-default chokepoint. There is exactly one public function that decides
whether a URL may be touched, so there is exactly one place to audit. An oracle
does not get to reach the network except through a Fetcher that has already
called `assert_in_scope`.

DESIGN NOTES
  * Deny by default. An empty scope permits nothing.
  * Only http/https. file://, gopher://, ftp://, data:, and schemeless targets
    are refused outright -- these are exactly the SSRF-adjacent schemes an
    attacker would smuggle, and a validator must never follow them.
  * IP literals are checked against allowed CIDRs; hostnames against an
    exact-or-suffix allowlist. We do NOT resolve DNS here: resolution is a
    network round trip (non-deterministic, and itself a scope decision). The
    production client may resolve-then-recheck the resulting IP as a hardening
    step; that is additive and never widens what this function allows.
  * Credentials embedded in the URL (user:pass@host) are refused -- they have no
    place in an authorised test and often indicate a copy-paste of a real
    secret.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http", "https")


class OutOfScopeError(Exception):
    """Raised by assert_in_scope. Never caught-and-ignored: an out-of-scope
    request is a safety violation, not a recoverable condition."""


@dataclass(frozen=True)
class Scope:
    """The authorised test perimeter. Build it once from the competition's
    explicit target list and thread it through every Fetcher."""
    cidrs: tuple[str, ...] = ()          # e.g. "10.0.0.0/24", "192.168.1.5/32"
    hosts: tuple[str, ...] = ()          # exact or suffix, e.g. "target.local"

    def _networks(self):
        for c in self.cidrs:
            yield ipaddress.ip_network(c, strict=False)

    def _host_ok(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        for allowed in (a.lower().rstrip(".") for a in self.hosts):
            if h == allowed or h.endswith("." + allowed):
                return True
        return False

    def _ip_ok(self, ip: ipaddress._BaseAddress) -> bool:
        return any(ip in net for net in self._networks())

    def permits(self, url: str) -> tuple[bool, str]:
        """(allowed, reason). Reason is always populated, for the audit log."""
        parts = urlsplit(url)
        if parts.scheme.lower() not in ALLOWED_SCHEMES:
            return False, f"scheme {parts.scheme!r} is not http/https"
        if parts.username or parts.password:
            return False, "credentials embedded in URL are not permitted"
        host = parts.hostname
        if not host:
            return False, "no host in URL"

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        if ip is not None:
            return (True, f"{ip} in an allowed CIDR") if self._ip_ok(ip) \
                else (False, f"{ip} is not in any allowed CIDR")

        if self._host_ok(host):
            return True, f"{host} matches an allowed host"
        return False, f"{host} is not in the allowed host list"


def assert_in_scope(scope: Scope, url: str) -> None:
    """The chokepoint. Raises OutOfScopeError unless `url` is explicitly
    permitted by `scope`. Call this before EVERY outbound request."""
    ok, reason = scope.permits(url)
    if not ok:
        raise OutOfScopeError(f"refused {url!r}: {reason}")


def in_scope(scope: Scope, url: str) -> bool:
    return scope.permits(url)[0]
