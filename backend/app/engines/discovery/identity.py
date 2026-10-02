"""
Stable asset identity and the merge rule from IMPLEMENTATION_SPEC_v4.md §6.

asset_id = SHA256(canonical_root_hostname) — deterministic, never re-derived
from IP / certificate SAN / favicon hash. Those are recorded as AssetAlias
rows: evidence ABOUT an asset, never inputs used to MERGE asset identity.

The one rule that matters most: never merge two hostnames into one asset
across different registrable (eTLD+1) domains, even if they share an IP, a
certificate SAN, or a favicon hash. On any CDN-fronted or shared-hosting
target, a naive Union-Find over those signals collapses the whole multi-asset
inventory into a single node and destroys the graph Validation/Correlation
build on top of it.
"""
from __future__ import annotations

import hashlib

from app.core.scope import canonical_root_hostname

try:
    import tldextract  # optional; falls back to a naive heuristic if absent
except ImportError:  # pragma: no cover
    tldextract = None


def stable_asset_id(host_or_url: str) -> str:
    hostname = canonical_root_hostname(host_or_url)
    return hashlib.sha256(hostname.encode("utf-8")).hexdigest()


def registrable_domain(hostname: str) -> str:
    """eTLD+1 for the merge-rule check below. Uses tldextract if installed
    (recommended — add it to requirements.txt if your targets include
    multi-level public suffixes like co.uk or github.io); otherwise falls
    back to a naive last-two-labels heuristic, which is WRONG for those
    suffixes and should be treated as a known limitation, not a silent
    correctness guarantee.
    """
    hostname = canonical_root_hostname(hostname)
    if tldextract is not None:
        ext = tldextract.extract(hostname)
        return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def may_merge_by_alias(hostname_a: str, hostname_b: str, alias_type: str, ip_is_dedicated: bool = False) -> bool:
    """The gate every alias-based merge decision must pass through. Returns
    False (never merge) the instant the two hostnames sit under different
    registrable domains, regardless of how strong the alias signal looks.

    alias_type: "ip" | "cert_san" | "favicon_hash"
    ip_is_dedicated: only relevant when alias_type == "ip" — True only if you
        have positively confirmed the IP is not shared/CDN-fronted hosting.
    """
    if registrable_domain(hostname_a) != registrable_domain(hostname_b):
        return False
    if alias_type == "ip":
        return ip_is_dedicated
    if alias_type in ("cert_san", "favicon_hash"):
        return True
    return False
