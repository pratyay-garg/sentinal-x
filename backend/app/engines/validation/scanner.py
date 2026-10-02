"""
The scanner adapter -- Nuclei is a COMMODITY INPUT, not the clever part.

Nuclei finds *suspects* (fast, broad, noisy); our engine runs the *trial*. This
module turns cached Nuclei JSONL into Candidates the oracles can adjudicate.

  * CACHED, NEVER LIVE IN THE DEMO. A live scan is slow and flaky; we pre-run
    Nuclei once and replay its JSON, so the stage a judge watches is our
    adjudication, not a four-minute crawl.
  * vuln_class MAPPING IS ENUM-CONSTRAINED. Nuclei template ids
    ('apache-struts-cve-2017-5638') never match contract.VULN_CLASSES. The
    deterministic HeuristicMapper maps by tags/keywords into the frozen enum;
    an optional LLMMapper may propose a mapping but its output is CONSTRAINED to
    the enum and falls back to the heuristic (LAW 3: AI at the edges, verified,
    never deciding). An unmappable template returns None -- we surface the
    unknown-class diagnostic rather than force a wrong mapping.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Protocol
from urllib.parse import urlsplit

from app.graph.contract import VULN_CLASSES

from .writer import Candidate

# ordered (regex-free) keyword rules; first hit wins. Values are in VULN_CLASSES.
_TAG_RULES: list[tuple[tuple[str, ...], str]] = [
    (("sqli", "sql-injection", "sql_injection"), "sqli"),
    (("xss", "cross-site-scripting"), "xss_reflected"),
    (("ssti", "template-injection", "template_injection"), "ssti"),
    (("ssrf",), "ssrf"),
    (("xxe",), "xxe"),
    (("rce", "command-injection", "code-injection", "log4j", "struts"), "rce"),
    (("lfi", "path-traversal", "file-read", "traversal"), "lfi"),
    (("idor", "bola", "broken-object"), "idor"),
    (("auth-bypass", "default-login", "default-credential", "authbypass"), "auth_bypass"),
    (("open-redirect", "redirect"), "open_redirect"),
    (("csrf",), "csrf"),
    (("deserial",), "deserialization"),
    (("upload",), "file_upload_rce"),
    (("exposure", "config", "git", "env", "disclosure", "listing", "backup"), "info_leak"),
    (("misconfig", "open-port", "default-page"), "misconfig_open_service"),
]


class ClassMapper(Protocol):
    def map(self, finding: dict) -> str | None: ...


class HeuristicMapper:
    """Deterministic. Checks Nuclei tags first, then keywords in template-id and
    name. Returns a vuln_class in VULN_CLASSES, or None if nothing matches."""
    def map(self, finding: dict) -> str | None:
        info = finding.get("info", {})
        tags = {t.lower() for t in info.get("tags", [])}
        haystack = " ".join([
            str(finding.get("template-id", "")),
            str(info.get("name", "")),
            " ".join(tags),
        ]).lower()
        for needles, cls in _TAG_RULES:
            if any(n in tags for n in needles) or any(n in haystack for n in needles):
                assert cls in VULN_CLASSES        # rules can never leave the enum
                return cls
        return None


class LLMMapper:
    """AT THE EDGE, CONSTRAINED. An LLM proposes a class for a template the
    heuristic could not place; the proposal is accepted ONLY if it is in the
    frozen enum, else we fall back to the heuristic. The LLM never decides a
    verdict or a score -- it only suggests a label a deterministic check ratifies.
    Not invoked in the demo (no network); wired here for completeness."""
    def __init__(self, ask: Callable[[str], str], fallback: ClassMapper | None = None):
        self._ask = ask
        self._fallback = fallback or HeuristicMapper()

    def map(self, finding: dict) -> str | None:
        base = self._fallback.map(finding)
        if base is not None:
            return base
        prompt = ("Map this scanner finding to exactly one of "
                  f"{sorted(VULN_CLASSES)} or the word NONE.\n"
                  f"template: {finding.get('template-id')}\n"
                  f"name: {finding.get('info', {}).get('name')}")
        try:
            proposal = (self._ask(prompt) or "").strip().lower()
        except Exception:
            return None
        return proposal if proposal in VULN_CLASSES else None


# --------------------------------------------------------------- parsing

def parse_nuclei(jsonl: str) -> list[dict]:
    """Parse Nuclei JSONL (one JSON object per line). Blank/comment lines skipped."""
    out = []
    for line in jsonl.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(json.loads(line))
    return out


def _endpoint_and_param(finding: dict) -> tuple[str | None, str | None]:
    url = finding.get("matched-at") or finding.get("host") or ""
    if not url:
        return None, None
    parts = urlsplit(url if "://" in url else "http://" + url)
    param = None
    if parts.query:
        param = parts.query.split("=", 1)[0].split("&", 1)[0] or None
    return (parts.path or "/"), param


def _asset_id(finding: dict, asset_map: dict | None) -> str:
    url = finding.get("matched-at") or finding.get("host") or ""
    host = urlsplit(url if "://" in url else "http://" + url).hostname or "unknown"
    return (asset_map or {}).get(host, host)


@dataclass
class MappedFinding:
    candidate: Candidate | None
    raw: dict
    mapped_class: str | None

    @property
    def mappable(self) -> bool:
        return self.candidate is not None


def to_candidate(finding: dict, mapper: ClassMapper | None = None,
                 asset_map: dict | None = None) -> MappedFinding:
    mapper = mapper or HeuristicMapper()
    cls = mapper.map(finding)
    if cls is None:
        return MappedFinding(candidate=None, raw=finding, mapped_class=None)

    info = finding.get("info", {})
    classification = info.get("classification", {}) or {}
    cve_ids = classification.get("cve-id") or classification.get("cve_id") or []
    endpoint, param = _endpoint_and_param(finding)
    candidate = Candidate(
        asset_id=_asset_id(finding, asset_map),
        vuln_class=cls,
        endpoint=endpoint,
        param=param,
        cvss_vector=classification.get("cvss-metrics") or classification.get("cvss_metrics"),
        cve=cve_ids[0] if cve_ids else None,
    )
    return MappedFinding(candidate=candidate, raw=finding, mapped_class=cls)


def candidates_from_nuclei(jsonl: str, mapper: ClassMapper | None = None,
                           asset_map: dict | None = None) -> list[MappedFinding]:
    return [to_candidate(f, mapper, asset_map) for f in parse_nuclei(jsonl)]
