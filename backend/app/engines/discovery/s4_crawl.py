"""S4: bounded SPA, form, JavaScript, OpenAPI and GraphQL surface discovery."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import deque
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

import httpx as pyhttpx

from app.core.config import settings
from app.core.subprocess_utils import ToolNotFoundError, run_tool
from .s3_fingerprint import matches_soft_404

logger = logging.getLogger(__name__)

SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/api-docs", "/api/openapi.json",
    "/v1/openapi.json", "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/graphql/console")
# Common sensitive/config/backup/operational paths that a link crawl never
# reaches because nothing links to them. Every probe is a single GET and is
# scope-checked, so this stays inside the non-destructive, allow-listed
# contract; reachability of these paths is itself the finding (an exposed
# metrics endpoint, a published policy file, a world-readable backup or
# operational log directory).
CONTENT_PATHS = (
    "/robots.txt", "/sitemap.xml", "/humans.txt", "/crossdomain.xml",
    "/.well-known/security.txt", "/security.txt", "/metrics",
    "/server-status", "/actuator", "/actuator/health", "/actuator/env",
    "/.git/config", "/.env", "/.env.local", "/config.json", "/settings.json",
    "/package.json", "/composer.json", "/.DS_Store", "/phpinfo.php",
    "/backup.zip", "/backup.sql", "/dump.sql", "/db.sqlite",
    "/ftp", "/ftp/acquisitions.md", "/support/logs", "/support/logs/",
    "/assets/public/images/uploads", "/uploads", "/logs", "/log",
)
_HTTP_METHODS = frozenset({"get", "head", "post", "put", "patch", "delete", "options"})
_JS_ROUTE = re.compile(
    r'''["'`](?P<url>(?:https?://[^"'`\s]+|/?(?:api|rest|graphql|v\d+|users?|products?|admin|auth)/?[^"'`\s]*))["'`]''',
    re.I,
)
_STATIC_SUFFIXES = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".webm", ".pdf", ".zip",
)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Endpoints that change scanner-affecting SERVER state mid-crawl and so must
# never be fetched during discovery:
#   * logout/sign-out end the authenticated session and blind every later
#     authenticated request (the crawler following a menu's logout link once
#     reduced an authenticated scan to a handful of param-less pages);
#   * setup/install/reset re-initialise the application's database.
# A real assessment never needs to fetch these, authenticated or not. These are
# generic, name-based heuristics — no application-specific paths are hardcoded.
_CRAWL_EXCLUDE_PATTERN = (
    r"(?i)(?:log[-_]?out|sign[-_]?out|log[-_]?off|/exit(?:$|[/?])|destroy[-_]?session"
    r"|/setup\b|/install\b|/reset\b)"
)
_SESSION_DESTROYING = re.compile(_CRAWL_EXCLUDE_PATTERN)


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(k).lower(): str(v or "") for k, v in attrs}
        if tag in {"a", "link", "iframe"} and values.get("href"):
            self.links.add(values["href"])
        if tag in {"img", "iframe"} and values.get("src"):
            self.links.add(values["src"])
        if tag == "script" and values.get("src"):
            self.scripts.add(values["src"])
        if tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": values.get("method", "GET").upper(),
                "params": [],
            }
        elif tag in {"input", "select", "textarea", "button"} and self._form is not None:
            name = values.get("name")
            if name:
                self._form["params"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


async def run_s4_crawl(
    target: str,
    soft_404_signature: dict | None,
    *,
    headers: dict[str, str] | None = None,
    auth_context: str = "none",
    profile: str = "fast",
) -> dict:
    """Discover request shapes and return transparent tool diagnostics.

    Katana is primary. A deterministic HTTP/HTML/JS channel runs alongside it
    because one bad CLI flag or SPA bootstrap page must not reduce a scan to
    its seed URL.
    """
    depth = settings.crawl_depth_deep if profile == "deep" else settings.crawl_depth_fast
    max_pages = settings.crawl_max_pages_deep if profile == "deep" else settings.crawl_max_pages_fast
    argv = [
        settings.katana_bin, "-u", target, "-jc", "-jsl", "-d", str(depth),
        "-cs", _crawl_scope_regex(target), "-cos", _CRAWL_EXCLUDE_PATTERN,
        "-kf", "all", "-fx", "-td", "-mdp", str(max_pages), "-jsonl",
    ]
    if profile == "deep":
        # Angular and other SPAs construct API calls at runtime. Chromium-backed
        # crawling captures those requests, while the existing -cs expression
        # remains the authoritative crawl boundary. Never substitute -ns here:
        # Katana defines that flag as "no scope".
        argv += ["-headless", "-no-sandbox", "-xhr-extraction", "-system-chrome"]
    if not settings.offline_mode and profile != "deep":
        # Classification/extraction only; `-kb-validate-secrets` is forbidden
        # because it would contact a secret's provider outside scan scope.
        # Katana v1.6.1 exposes classification through the single `-kb` flag;
        # `-kb-endpoints` and `-kb-secrets` are not valid CLI options. DIT is
        # deliberately omitted from the Chromium pass: Katana 1.6.1 can hang
        # when DIT and headless mode are combined, while XHR extraction already
        # supplies the endpoint classification the deep pass needs.
        argv += ["-kb"]
    for name, value in sorted((headers or {}).items()):
        argv += ["-H", f"{name}: {value}"]

    diagnostics: dict[str, Any] = {
        "tool": "katana", "returncode": None, "timed_out": False, "stderr": ""
    }
    katana_records: list[dict] = []
    try:
        result = await run_tool(argv, timeout=(
            settings.katana_timeout_deep_seconds if profile == "deep"
            else settings.katana_timeout_fast_seconds))
        diagnostics.update(returncode=result.returncode, timed_out=result.timed_out,
                           stderr=_safe_stderr(result.stderr, headers))
        katana_records = _parse_katana(result.stdout, target, soft_404_signature, auth_context)
        if result.returncode != 0:
            logger.warning("S4 Katana exited %s: %s", result.returncode, diagnostics["stderr"])
    except ToolNotFoundError as exc:
        diagnostics.update(returncode=127, stderr=str(exc))
        logger.error("S4 Katana unavailable; using HTTP fallback")

    fallback = await _fallback_crawl(target, soft_404_signature, headers or {},
                                     auth_context, depth, max_pages)
    specs = await _probe_spec_paths(target, headers or {}, auth_context)
    content = await _probe_content_paths(target, soft_404_signature, headers or {}, auth_context)
    endpoints = _dedupe_endpoints([*_seed(target, auth_context), *katana_records,
                                   *fallback["endpoints"], *specs["endpoints"],
                                   *content["endpoints"]])
    diagnostics.update({
        "katana_endpoints": len(katana_records),
        "fallback_pages_fetched": fallback["pages_fetched"],
        "fallback_endpoints": len(fallback["endpoints"]),
        "openapi_documents": specs["documents"], "openapi_operations": specs["operations"],
        "content_paths_probed": content["probed"],
        "content_paths_found": len(content["endpoints"]),
        "total_endpoints": len(endpoints),
    })
    return {"endpoints": endpoints, "secrets": [], "auth_context": auth_context,
            "diagnostics": diagnostics}


def _seed(target: str, auth_context: str) -> list[dict]:
    normalized = normalize_discovered_endpoint(target, target)
    return ([{**normalized, "method": "GET", "param_names": [], "page_class": None,
              "endpoint_class": "unknown", "auth_context": auth_context}]
            if normalized else [])


def _parse_katana(output: bytes, target: str, soft_404_signature: dict | None,
                  auth_context: str) -> list[dict]:
    endpoints: list[dict] = []
    for line in output.decode(errors="ignore").splitlines():
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        request, response = record.get("request") or {}, record.get("response") or {}
        if matches_soft_404(soft_404_signature, response.get("status_code", 0),
                            len(response.get("body", "") or ""),
                            _quick_hash(response.get("body", ""))):
            continue
        normalized = normalize_discovered_endpoint(target,
                                                   request.get("endpoint") or request.get("url"))
        if normalized is None or not _same_authorized_root(target, normalized["url"]):
            continue
        kb = response.get("knowledgebase") or {}
        endpoints.append({
            **normalized, "method": str(request.get("method") or "GET").upper(),
            "param_names": _extract_param_names(request),
            "request_template": _request_template(request),
            "page_class": kb.get("PageType") if isinstance(kb, dict) else None,
            "endpoint_class": _katana_endpoint_class(request, response, normalized["path"]),
            "auth_context": auth_context,
        })
    return endpoints


async def _fallback_crawl(target: str, soft_404_signature: dict | None,
                          headers: dict[str, str], auth_context: str,
                          depth: int, max_pages: int) -> dict:
    seed = normalize_discovered_endpoint(target, target)
    seed_url = seed["url"] if seed else target
    queue = deque([(target, 0)])
    seen: set[str] = set()
    javascript: set[str] = set()
    endpoints: list[dict] = []
    client_headers = {"User-Agent": "SentinalX-Discovery/1.0", "Accept": "*/*", **headers}
    async with pyhttpx.AsyncClient(timeout=settings.crawl_request_timeout_seconds, verify=False,
                                   follow_redirects=False, trust_env=False,
                                   headers=client_headers) as client:
        while queue and len(seen) < max_pages:
            url, level = queue.popleft()
            normalized = normalize_discovered_endpoint(target, url)
            if normalized is None or normalized["url"] in seen:
                continue
            if not _same_authorized_root(target, normalized["url"]):
                continue
            if _SESSION_DESTROYING.search(normalized["url"]):
                continue  # never log the crawler's own session out
            seen.add(normalized["url"])
            try:
                response = await client.get(normalized["url"])
            except pyhttpx.HTTPError:
                continue
            body = response.text[: settings.validation_max_response_bytes]
            # SPA history fallbacks intentionally return the same bootstrap
            # HTML for every unknown path. The authorized seed is nevertheless
            # a real page and must be parsed for its scripts; only suppress
            # subsequently discovered catch-all aliases.
            if (normalized["url"] != seed_url and
                    matches_soft_404(soft_404_signature, response.status_code,
                                     len(body), _quick_hash(body))):
                continue
            content_type = response.headers.get("content-type", "").lower()
            params = sorted(parse_qs(urlsplit(normalized["url"]).query, keep_blank_values=True))
            endpoints.append({**normalized, "method": "GET", "param_names": params,
                              "request_template": None, "page_class": None,
                              "endpoint_class": "rest" if "json" in content_type else "unknown",
                              "auth_context": auth_context})
            if response.status_code in _REDIRECT_STATUSES:
                # A redirect body carries no surface, but its destination is the
                # real application root for anything that bounces `/` to a login
                # or dashboard page. The destination is queued rather than
                # followed by the client so that the authorized-root check still
                # runs on it — an off-scope Location is recorded and dropped.
                location = response.headers.get("location")
                if location:
                    redirect_url = urljoin(normalized["url"], location)
                    if _same_authorized_root(target, redirect_url) and level < depth:
                        queue.append((redirect_url, level + 1))
                continue
            if "javascript" in content_type or normalized["path"].lower().endswith((".js", ".mjs")):
                endpoints.extend(_extract_js_routes(target, normalized["url"], body, auth_context))
                continue
            if "html" not in content_type and "<html" not in body[:1000].lower():
                continue
            parser = _SurfaceParser()
            try:
                parser.feed(body)
            except Exception:
                pass
            for form in parser.forms:
                form_url = urljoin(normalized["url"], form["action"] or normalized["url"])
                form_ep = normalize_discovered_endpoint(target, form_url)
                if form_ep and _same_authorized_root(target, form_ep["url"]):
                    endpoints.append({**form_ep, "method": form["method"],
                                      "param_names": sorted(set(form["params"])),
                                      "request_template": {"encoding": "form", "fields": form["params"]},
                                      "page_class": "form", "endpoint_class": "rest",
                                      "auth_context": auth_context})
            for raw in sorted(parser.scripts):
                script_url = urljoin(normalized["url"], raw)
                if _same_authorized_root(target, script_url):
                    javascript.add(script_url)
            if level < depth:
                for raw in sorted(parser.links):
                    candidate = urljoin(normalized["url"], raw)
                    if (not urlsplit(candidate).path.lower().endswith(_STATIC_SUFFIXES)
                            and _same_authorized_root(target, candidate)
                            and not _SESSION_DESTROYING.search(candidate)):
                        queue.append((candidate, level + 1))

        for script_url in sorted(javascript)[: settings.crawl_max_javascript_files]:
            try:
                response = await client.get(script_url)
            except pyhttpx.HTTPError:
                continue
            endpoints.extend(_extract_js_routes(target, script_url,
                                                 response.text[: settings.validation_max_response_bytes],
                                                 auth_context))
    return {"endpoints": endpoints, "pages_fetched": len(seen)}


def _extract_js_routes(target: str, source_url: str, body: str,
                       auth_context: str) -> list[dict]:
    found: list[dict] = []
    for match in _JS_ROUTE.finditer(body):
        raw = match.group("url").replace("\\/", "/")
        # Root-relative and API-relative literals in compiled SPA bundles both
        # describe application routes, not paths below `/assets/main.js`.
        base = target if raw.startswith("/") or "://" not in raw else source_url
        normalized = normalize_discovered_endpoint(base, raw)
        if normalized is None or not _same_authorized_root(target, normalized["url"]):
            continue
        found.append({**normalized, "source": "js_extract", "method": "GET",
                      "param_names": sorted(parse_qs(
                          urlsplit(normalized["url"]).query, keep_blank_values=True
                      )),
                      "request_template": None, "page_class": None, "endpoint_class": "xhr",
                      "auth_context": auth_context})
    return found


async def _probe_spec_paths(target: str, headers: dict[str, str], auth_context: str) -> dict:
    found: list[dict] = []
    documents = operations = 0
    async with pyhttpx.AsyncClient(timeout=settings.crawl_request_timeout_seconds, verify=False,
                                   follow_redirects=False, trust_env=False,
                                   headers={"User-Agent": "SentinalX-Discovery/1.0", **headers}) as client:
        for path in SPEC_PATHS:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            if not _same_authorized_root(target, url):
                continue
            try:
                response = await client.get(url)
                document = response.json() if response.status_code == 200 else None
            except (pyhttpx.HTTPError, ValueError):
                continue
            if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
                continue
            documents += 1
            extracted = _openapi_operations(target, document, auth_context)
            operations += len(extracted)
            found.extend(extracted)
        for path in GRAPHQL_PATHS:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            if not _same_authorized_root(target, url):
                continue
            try:
                response = await client.post(url, json={"query": "{__typename}"})
            except pyhttpx.HTTPError:
                continue
            if response.status_code == 200 and "__typename" in response.text:
                normalized = normalize_discovered_endpoint(target, url)
                if normalized:
                    found.append({**normalized, "method": "POST", "param_names": ["query"],
                                  "request_template": {"encoding": "json", "body": {"query": "{__typename}"}},
                                  "endpoint_class": "graphql", "auth_context": auth_context})
    return {"endpoints": found, "documents": documents, "operations": operations}


_DIR_CHILD = re.compile(r'href=["\']([^"\':?#][^"\':?#]*)["\']', re.I)
# Bounded child fetches across all exposed directories; see settings.crawl_content_child_budget.


def _directory_children(body: str) -> list[str]:
    """Relative child names from an autoindex/dir-listing body (never absolute
    URLs, query strings, or the ``.``/``..`` self/parent entries)."""
    names: list[str] = []
    for href in _DIR_CHILD.findall(body):
        name = href.strip().rstrip("/")
        if not name or set(name) <= {".", "/"} or name.startswith((".", "http")):
            continue
        names.append(name)
    return names


async def _bounded_fetch(client: "pyhttpx.AsyncClient", url: str) -> tuple[int, str, str]:
    """GET, reading at most validation_max_response_bytes of the body. The full
    request still reaches the server (so exposure is genuinely observed) without
    pulling a multi-gigabyte log or backup into memory."""
    async with client.stream("GET", url) as response:
        chunks: list[bytes] = []
        size = 0
        cap = settings.validation_max_response_bytes
        async for chunk in response.aiter_bytes():
            room = cap - size
            if room <= 0:
                break
            chunks.append(chunk[:room])
            size += min(len(chunk), room)
        content_type = response.headers.get("content-type", "").lower()
        body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
        return response.status_code, content_type, body


async def _probe_content_paths(target: str, soft_404_signature: dict | None,
                               headers: dict[str, str], auth_context: str) -> dict:
    """GET a bounded list of common unlinked sensitive paths (see CONTENT_PATHS).

    Only paths whose response is a real distinct resource -- not the target's
    catch-all/soft-404 page -- are recorded, so a SPA that answers 200 for every
    URL does not inflate the surface. When a path returns a directory listing,
    its child files are fetched too (bounded), because an exposed log/backup
    directory's real finding is the files inside it. Every request is a
    scope-checked GET with a capped body read, keeping the pass non-destructive.
    """
    found: list[dict] = []
    probed = 0
    child_budget = settings.crawl_content_child_budget

    def _record(candidate_url: str) -> None:
        normalized = normalize_discovered_endpoint(target, candidate_url)
        if normalized and _same_authorized_root(target, normalized["url"]):
            found.append({**normalized, "method": "GET", "param_names": [],
                          "request_template": None, "page_class": None,
                          "endpoint_class": "content", "auth_context": auth_context})

    async with pyhttpx.AsyncClient(timeout=settings.crawl_request_timeout_seconds, verify=False,
                                   follow_redirects=False, trust_env=False,
                                   headers={"User-Agent": "SentinalX-Discovery/1.0", **headers}) as client:
        for path in CONTENT_PATHS:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            if not _same_authorized_root(target, url):
                continue
            try:
                status, content_type, body = await _bounded_fetch(client, url)
            except pyhttpx.HTTPError:
                continue
            probed += 1
            if status >= 400 or status in _REDIRECT_STATUSES:
                continue
            if matches_soft_404(soft_404_signature, status, len(body), _quick_hash(body)):
                continue
            _record(url)
            # An HTML autoindex is an exposed directory: fetch the files it
            # lists (bounded, same directory, GET only).
            if "html" not in content_type:
                continue
            for child in _directory_children(body):
                if child_budget <= 0:
                    break
                child_url = urljoin(url.rstrip("/") + "/", child)
                if not _same_authorized_root(target, child_url):
                    continue
                child_budget -= 1
                try:
                    c_status, _c_type, c_body = await _bounded_fetch(client, child_url)
                except pyhttpx.HTTPError:
                    continue
                probed += 1
                if c_status >= 400 or c_status in _REDIRECT_STATUSES:
                    continue
                if matches_soft_404(soft_404_signature, c_status, len(c_body), _quick_hash(c_body)):
                    continue
                _record(child_url)
    return {"endpoints": found, "probed": probed}


def _openapi_operations(target: str, document: dict, auth_context: str) -> list[dict]:
    endpoints: list[dict] = []
    for raw_path, path_item in sorted(document.get("paths", {}).items()):
        if not isinstance(path_item, dict):
            continue
        concrete_path = re.sub(r"\{[^{}]+}", "1", str(raw_path))
        for method, operation in sorted(path_item.items()):
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = [p for p in [*(path_item.get("parameters") or []),
                                      *(operation.get("parameters") or [])]
                          if isinstance(p, dict) and isinstance(p.get("name"), str)]
            query_names = sorted({p["name"] for p in parameters if p.get("in") == "query"})
            body_fields: list[str] = []
            request_body = operation.get("requestBody") or {}
            content = request_body.get("content") if isinstance(request_body, dict) else {}
            if isinstance(content, dict):
                for media in content.values():
                    schema = media.get("schema") if isinstance(media, dict) else None
                    if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
                        body_fields.extend(str(k) for k in schema["properties"])
            url = urljoin(target.rstrip("/") + "/", concrete_path.lstrip("/"))
            if query_names and method.lower() in {"get", "head"}:
                url += ("&" if "?" in url else "?") + urlencode({p: "1" for p in query_names})
            normalized = normalize_discovered_endpoint(target, url)
            if normalized is None or not _same_authorized_root(target, normalized["url"]):
                continue
            params = sorted(set(query_names) | set(body_fields))
            endpoints.append({**normalized, "source": "openapi", "method": method.upper(),
                              "param_names": params,
                              "request_template": {"encoding": "json" if body_fields else "query",
                                                   "fields": params,
                                                   "operation_id": operation.get("operationId")},
                              "page_class": None, "endpoint_class": "rest",
                              "auth_context": auth_context})
    return endpoints


def _request_template(request: dict) -> dict | None:
    body = request.get("body")
    if body is None and not request.get("body_params"):
        return None
    return {"encoding": "observed", "body": str(body)[:4096] if body is not None else None,
            "fields": sorted((request.get("body_params") or {}).keys())}


def _extract_param_names(request: dict) -> list[str]:
    raw_url = request.get("endpoint") or request.get("url") or ""
    names = set(parse_qs(urlsplit(raw_url).query, keep_blank_values=True))
    body_params = request.get("body_params") or {}
    if isinstance(body_params, dict):
        names.update(str(key) for key in body_params)
    return sorted(names)


def _katana_endpoint_class(request: dict, response: dict, path: str) -> str:
    """Classify browser API traffic across Katana JSONL schema variants.

    Katana versions that support ``-xhr-extraction`` do not consistently emit
    the literal ``request.source = xhr`` on the executed request record.  In
    that case, a browser request explicitly accepting JSON and receiving JSON
    is reliable evidence of an API/XHR request.  The path check prevents a
    generic JSON document from being relabelled solely because of its content
    type.
    """
    if str(request.get("source") or "").lower() == "xhr":
        return "xhr"

    request_headers = request.get("headers") or {}
    response_headers = response.get("headers") or {}
    if not isinstance(request_headers, dict) or not isinstance(response_headers, dict):
        return "unknown"
    accept = str(_header_value(request_headers, "accept") or "").lower()
    content_type = str(_header_value(response_headers, "content-type") or "").lower()
    api_path = path == "/graphql" or path.startswith(("/api/", "/rest/", "/graphql/"))
    if api_path and "json" in accept and "json" in content_type:
        return "xhr"
    return "unknown"


def _header_value(headers: dict, name: str) -> Any:
    wanted = name.lower()
    return next((value for key, value in headers.items() if str(key).lower() == wanted), None)


def _dedupe_endpoints(endpoints: list[dict]) -> list[dict]:
    merged: dict[tuple[str, str, str], dict] = {}
    for ep in endpoints:
        key = (ep["path"], ep.get("method", "GET").upper(), ep.get("auth_context", "none"))
        if key not in merged:
            merged[key] = ep
            continue
        current = merged[key]
        current["param_names"] = sorted(set(current.get("param_names", [])) |
                                        set(ep.get("param_names", [])))
        if current.get("source") == "crawl" and ep.get("source") != "crawl":
            current["source"] = ep["source"]
        if (not current.get("endpoint_class") or current.get("endpoint_class") == "unknown") \
                and ep.get("endpoint_class") not in {None, "unknown"}:
            current["endpoint_class"] = ep["endpoint_class"]
        if not current.get("page_class") and ep.get("page_class"):
            current["page_class"] = ep["page_class"]
        if not current.get("request_template") and ep.get("request_template"):
            current["request_template"] = ep["request_template"]
    return sorted(merged.values(), key=lambda ep: (ep["url"], ep["method"], ep["auth_context"]))


def _quick_hash(body: str) -> str:
    return hashlib.sha256((body or "")[:4096].encode(errors="ignore")).hexdigest()


def _safe_stderr(stderr: bytes, headers: dict[str, str] | None) -> str:
    value = stderr.decode(errors="replace")[-2000:]
    for secret in (headers or {}).values():
        if secret:
            value = value.replace(secret, "<redacted>")
    return value


def _origin_parts(value: str) -> tuple[str, str, int, str] | None:
    split = urlsplit(value)
    if split.scheme not in {"http", "https"} or not split.hostname:
        return None
    try:
        port = split.port or (443 if split.scheme == "https" else 80)
    except ValueError:
        return None
    return split.scheme, split.hostname.lower(), port, split.path or "/"


def _same_authorized_root(base_url: str, candidate_url: str) -> bool:
    base, candidate = _origin_parts(base_url), _origin_parts(candidate_url)
    if base is None or candidate is None or base[:3] != candidate[:3]:
        return False
    prefix = base[3].rstrip("/")
    return not prefix or candidate[3] == prefix or candidate[3].startswith(prefix + "/")


def _crawl_scope_regex(target: str) -> str:
    split = urlsplit(target)
    origin = f"{split.scheme}://{split.netloc}"
    prefix = (split.path or "/").rstrip("/")
    return "^" + re.escape(origin + prefix) + r"(?:/|\?|$)"


def normalize_discovered_endpoint(base_url: str, raw_url: str | None) -> dict | None:
    """Return stable URL ownership fields without erasing query parameter names."""
    if not raw_url:
        return None
    absolute = urljoin(base_url.rstrip("/") + "/", raw_url)
    split = urlsplit(absolute)
    if split.scheme not in {"http", "https"} or not split.hostname:
        return None
    try:
        port = split.port or (443 if split.scheme == "https" else 80)
    except ValueError:
        return None
    host_display = f"[{split.hostname}]" if ":" in split.hostname else split.hostname
    default_port = (split.scheme == "http" and port == 80) or (split.scheme == "https" and port == 443)
    netloc = host_display if default_port else f"{host_display}:{port}"
    path = split.path or "/"
    canonical = urlunsplit((split.scheme, netloc, path, split.query, ""))
    return {"url": canonical, "path": path, "scheme": split.scheme,
            "hostname": split.hostname.lower(), "port": port, "source": "crawl"}
