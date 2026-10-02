"""Evidence-based routing from observed request parameters to Validation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.models import Endpoint

_CONTROL_PARAMS = frozenset({
    "csrf", "csrf_token", "csrftoken", "_token", "authenticity_token", "submit",
    "action", "button", "captcha", "recaptcha", "nonce",
})
_SQL_NAMES = frozenset({
    "id", "uid", "user_id", "account_id", "product_id", "item_id", "category_id",
    "q", "query", "search", "filter", "where", "sort", "order", "category",
    "product", "item", "user", "username", "email", "page", "limit", "offset",
})
_XSS_NAMES = frozenset({
    "q", "query", "search", "keyword", "name", "message", "comment", "text",
    "input", "title", "description", "url", "redirect", "return", "next",
})
_SSTI_NAMES = frozenset({"template", "view", "format", "greeting", "name", "message"})


@dataclass(frozen=True)
class ParameterCandidate:
    endpoint: Endpoint
    param: str
    vuln_class: str
    reason: str


def candidates_for_endpoints(endpoints: Sequence[Endpoint], limit: int) -> list[ParameterCandidate]:
    """Return bounded hypotheses, never claims of vulnerability.

    The endpoint and parameter were traffic/spec/form/JS observed. Class
    routing uses parameter and route semantics so Validation receives useful
    work without manufacturing every possible class for every input.

    Candidates collapse on (path, parameter, class, auth_context): a hundred
    `?/product?id=N` URLs share one data-store predicate to prove, so emitting
    one candidate for that shape — rather than one per crawled id — keeps
    Validation's queue proportional to the real attack surface.
    """
    rows: list[ParameterCandidate] = []
    seen: set[tuple[str, str, str, str]] = set()
    for endpoint in sorted(endpoints, key=lambda ep: (ep.path, ep.url, ep.method, ep.auth_context)):
        if endpoint.method.upper() not in {"GET", "HEAD"}:
            continue  # current unattended oracles intentionally reject state-capable methods
        path = endpoint.path.lower()
        for raw_param in sorted(set(endpoint.param_names or ())):
            param = str(raw_param).strip()
            name = param.lower()
            if not param or name in _CONTROL_PARAMS or name.startswith("csrf"):
                continue
            routes: list[tuple[str, str]] = []
            if name in _SQL_NAMES or any(token in path for token in ("sql", "search", "filter", "product", "user")):
                routes.append(("sqli", "identifier/query semantics can reach a data-store predicate"))
            if name in _XSS_NAMES or any(token in path for token in ("xss", "search", "comment", "message")):
                routes.append(("xss_reflected", "free-text/redirect semantics can reach an HTML response sink"))
            if name in _SSTI_NAMES and any(token in path for token in ("template", "render", "view", "hello", "greet", "ssti")):
                routes.append(("ssti", "template-like route and parameter semantics coincide"))
            for vuln_class, reason in routes:
                key = (endpoint.path, param, vuln_class, endpoint.auth_context)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(ParameterCandidate(endpoint, param, vuln_class, reason))
                if len(rows) >= max(0, limit):
                    return rows
    return rows


def _param_shape(endpoint: Endpoint) -> tuple[str, ...]:
    query_names = {name for name, _ in parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True)}
    names = query_names | {str(n) for n in (endpoint.param_names or ())}
    return tuple(sorted(n for n in names if n.lower() not in _CONTROL_PARAMS))


def dast_seed_urls(endpoints: Sequence[Endpoint], limit: int | None = None) -> list[str]:
    """Concrete GET query points for Nuclei DAST, deduped by parameter shape.

    Fuzzing `/product?id=1`, `/product?id=2`, … exercises the identical code
    path, so one representative per (path, parameter-name-set) is enough. The
    optional cap protects the stage from a crawl that discovered thousands of
    distinct query strings.
    """
    by_shape: dict[tuple[str, tuple[str, ...]], str] = {}
    for endpoint in sorted(endpoints, key=lambda ep: (ep.path, ep.url)):
        if endpoint.method.upper() not in {"GET", "HEAD"}:
            continue
        split = urlsplit(endpoint.url)
        pairs = list(parse_qsl(split.query, keep_blank_values=True))
        existing = {name for name, _ in pairs}
        for name in endpoint.param_names or ():
            if str(name).lower() not in _CONTROL_PARAMS and name not in existing:
                pairs.append((str(name), "1"))
        if not pairs:
            continue  # nothing to fuzz on a parameterless URL
        seed = urlunsplit((split.scheme, split.netloc, split.path,
                           urlencode(pairs, doseq=True), ""))
        by_shape.setdefault((split.path, _param_shape(endpoint)), seed)
    seeds = sorted(by_shape.values())
    return seeds[:limit] if limit is not None else seeds


def signature_scan_targets(endpoints: Sequence[Endpoint], limit: int | None = None) -> list[str]:
    """Distinct scheme/host/port/path URLs for host- and path-level templates.

    Signature templates (CVEs, exposures, misconfigurations) match on path and
    response, never on query values, so query strings are stripped and repeated
    paths collapse to one target. This keeps the signature pass from re-running
    the whole template set against every parameter permutation of one path.
    """
    targets: set[str] = set()
    for endpoint in endpoints:
        split = urlsplit(endpoint.url)
        targets.add(urlunsplit((split.scheme, split.netloc, split.path, "", "")))
    ordered = sorted(targets)
    return ordered[:limit] if limit is not None else ordered
