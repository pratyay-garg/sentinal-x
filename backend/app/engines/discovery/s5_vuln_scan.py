"""S5: bounded Nuclei signature and parameter-aware DAST scanning."""
from __future__ import annotations

import json
import logging
import os

from app.core.config import settings
from app.core.subprocess_utils import ToolNotFoundError, run_tool

logger = logging.getLogger(__name__)

TAG_TRIGGERS: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-content"], "apache": ["apache"],
    "nginx": ["nginx"], "php": ["php"], "jquery": ["jquery"],
    "django": ["django"], "spring": ["spring", "java"], "iis": ["iis", "microsoft-iis"],
    "tomcat": ["tomcat"], "elasticsearch": ["elasticsearch"], "redis": ["redis"],
    "mongodb": ["mongodb", "mongo"], "jenkins": ["jenkins"], "gitlab": ["gitlab"],
    # Modern SPA/API stacks previously missing from the selector.
    "nodejs": ["node", "node.js", "nodejs"], "express": ["express"],
    "angular": ["angular"], "react": ["react"], "vue": ["vue"],
}

# Signature pass: bounded, high-signal classes only. `cve`/`tech` and the
# injection tags are deliberately absent. `-tags` is an OR filter, so listing
# `rce` or `xss` re-admits every per-product CVE template carrying that tag —
# tens of thousands of requests that cannot finish inside any sane deadline,
# which is exactly how this pass used to end with zero findings. Injection
# classes are covered by the DAST pass below and proven by Validation's
# oracles; per-stack CVEs arrive through the fingerprint-gated product tags.
# Tag policy is operator-tunable at runtime (ADR-0007 D6); these parse the
# comma-separated settings. EXCLUDED_TAGS applies to both passes and is what
# keeps destructive and brute-force templates out of a scan by default.
def _csv_tags(raw: str) -> list[str]:
    return [tag.strip() for tag in (raw or "").split(",") if tag.strip()]


def always_on_tags() -> list[str]:
    return _csv_tags(settings.nuclei_always_on_tags)


def excluded_tags() -> list[str]:
    return _csv_tags(settings.nuclei_excluded_tags)


def build_tag_allowlist(tech_fingerprints: list[dict]) -> list[str]:
    detected = {(fp.get("product") or "").lower() for fp in tech_fingerprints if fp.get("product")}
    tags = set(always_on_tags())
    for tag, keywords in TAG_TRIGGERS.items():
        if any(any(keyword in product for keyword in keywords) for product in detected):
            tags.add(tag)
    return sorted(tags)


async def run_s5_vuln_scan(
    signature_targets: list[str], dast_seeds: list[str], tag_allowlist: list[str],
    waf_detected: bool, *, profile: str = "fast", headers: dict[str, str] | None = None,
) -> dict:
    """Run independent signature and DAST passes and expose every failure.

    Signature templates match on path/response, so they run against distinct
    URLs; the DAST fuzzing pass runs against parameterized seeds only. Passing
    the two target sets separately keeps each pass proportional to what it can
    actually find. Interactsh/OAST is disabled because a project-controlled
    callback service has not been configured. Destructive, brute-force and
    intrusive templates remain excluded.
    """
    if not signature_targets and not dast_seeds:
        return {"findings": [], "diagnostics": []}
    rate, concurrency = (
        (str(settings.nuclei_waf_rate_limit), str(settings.nuclei_waf_concurrency)) if waf_detected
        else (str(settings.nuclei_rate_limit), str(settings.nuclei_concurrency))
    )
    common = [
        settings.nuclei_bin, "-jsonl", "-silent",
        "-disable-update-check", "-etags", ",".join(excluded_tags()),
        "-rate-limit", rate, "-concurrency", concurrency, "-ni", "-pt", "http",
    ]
    for name, value in sorted((headers or {}).items()):
        common += ["-H", f"{name}: {value}"]
    diagnostics: list[dict] = []
    passes: list[tuple[str, list[str], bytes]] = []
    if signature_targets:
        passes.append((
            "signatures",
            [*common, "-t", settings.nuclei_templates_path,
             "-tags", ",".join(sorted(set(tag_allowlist)))],
            "\n".join(sorted(set(signature_targets))).encode(),
        ))
    if dast_seeds:
        # Scope fuzzing to the DAST corpus by directory. Filtering the whole
        # template root by injection tags instead admits thousands of ordinary
        # signature templates that carry those tags but never mutate a
        # parameter — measured at 4207 templates versus the ~250 that actually
        # fuzz, and the reason this pass never finished.
        if os.path.isdir(settings.nuclei_dast_templates_path):
            passes.append((
                "dast",
                [*common, "-t", settings.nuclei_dast_templates_path, "-dast",
                 "-fuzz-aggression", "medium" if profile == "deep" else "low"],
                "\n".join(sorted(set(dast_seeds))).encode(),
            ))
        else:
            diagnostics.append({
                "pass": "dast", "returncode": None, "timed_out": False, "findings": 0,
                "stderr": (f"DAST corpus not found at {settings.nuclei_dast_templates_path}; "
                           "parameter fuzzing was skipped"),
            })
            logger.error("S5 DAST corpus missing at %s — fuzzing pass skipped",
                         settings.nuclei_dast_templates_path)
    timeout = (settings.nuclei_timeout_deep_seconds if profile == "deep"
               else settings.nuclei_timeout_fast_seconds)
    findings: list[dict] = []
    for pass_name, argv, payload in passes:
        diagnostic = {"pass": pass_name, "returncode": None, "timed_out": False,
                      "stderr": "", "findings": 0}
        try:
            result = await run_tool(argv, timeout=timeout, input_data=payload)
            records = _parse_jsonl(result.stdout)
            findings.extend(records)
            diagnostic.update(returncode=result.returncode, timed_out=result.timed_out,
                              stderr=_safe_stderr(result.stderr, headers), findings=len(records))
            if result.timed_out:
                logger.warning("S5 Nuclei %s pass hit the %ss deadline; kept %d partial findings",
                               pass_name, timeout, len(records))
            elif result.returncode != 0:
                logger.warning("S5 Nuclei %s pass exited %s: %s", pass_name,
                               result.returncode, diagnostic["stderr"])
        except ToolNotFoundError as exc:
            diagnostic.update(returncode=127, stderr=str(exc))
            logger.error("S5 Nuclei unavailable")
        diagnostics.append(diagnostic)
    # A template can be reached through both filters; preserve distinct
    # matchers but remove byte-identical duplicate result records.
    unique: dict[str, dict] = {}
    for finding in findings:
        key = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
        unique[key] = finding
    return {"findings": list(unique.values()), "diagnostics": diagnostics}


def _parse_jsonl(output: bytes) -> list[dict]:
    records: list[dict] = []
    for line in output.decode(errors="ignore").splitlines():
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _safe_stderr(stderr: bytes, headers: dict[str, str] | None) -> str:
    value = stderr.decode(errors="replace")[-2000:]
    for secret in (headers or {}).values():
        if secret:
            value = value.replace(secret, "<redacted>")
    return value
