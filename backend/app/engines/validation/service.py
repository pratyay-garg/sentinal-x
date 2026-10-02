"""Route persisted Discovery candidates through safe live Validation oracles."""
from __future__ import annotations

import re
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.engines.validation.adjudicate import adjudicate
from app.engines.validation.evidence import RecordingFetcher
from app.engines.validation.http import Request
from app.engines.validation.oracles.differential import (
    run_boolean_differential,
    run_error_differential,
    run_expression_differential,
)
from app.engines.validation.oracles.timing import run_timing_differential
from app.engines.validation.writer import observations

from .transport import LiveFetcher, ValidationHalted

_METHOD_PREFIX = re.compile(r"^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+", re.I)
_SAFE_UNSUPPORTED = {
    "xss_stored": "stored-XSS setup would mutate target state",
    "idor": "two explicitly provisioned test identities are required",
    "broken_access_control": "two explicitly provisioned test identities are required",
    "auth_bypass": "a non-production test account is required",
    "ssrf": "an authorized controlled callback endpoint is required",
    "rce": "an authorized harmless execution marker is not configured",
    "xxe": "an authorized controlled callback endpoint is required",
    "lfi": "a target-owned harmless marker file is required",
    "file_upload_rce": "file creation is disabled for unattended validation",
    "deserialization": "deserialization gadget execution is unsafe",
    "csrf": "state-changing validation is disabled",
    "open_redirect": "browser/user-interaction validation is not configured",
    "cred_reuse": "credential testing is prohibited without test identities",
    "phishing_credential": "phishing findings are not actively exercised",
    "info_leak": "the candidate lacks a class-specific non-destructive oracle",
}


def _validate_reflected_xss(finding: dict, fetch: LiveFetcher) -> dict:
    """Confirm repeatable unescaped HTML injection with inert custom elements."""
    param = finding.get("param")
    endpoint = _with_sibling_params(
        endpoint_url(finding.get("endpoint")), finding.get("endpoint_params"), param)
    if endpoint is None or not param:
        return _base_result(finding, status="unverifiable_safely", confidence=0.35,
                            oracle="reflection.html", reason="an endpoint and parameter are required")
    rec = RecordingFetcher(fetch)
    baseline_token = f"sxbase{uuid.uuid4().hex}"
    baseline = rec(Request.get(endpoint, **{param: baseline_token}))
    outcomes = []
    confirmed = 0
    for _ in range(2):
        token = f"sx{uuid.uuid4().hex}"
        payload = f'<sentinalx-probe data-token="{token}"></sentinalx-probe>'
        response = rec(Request.get(endpoint, **{param: payload}))
        content_type = dict(response.headers).get("content-type", "").lower()
        raw = payload in response.body and token not in baseline.body and "html" in content_type
        confirmed += int(raw)
        outcomes.append({"oracle": "reflection.html", "fired": raw,
                         "marker": token, "status": response.status})
    if confirmed == 2:
        result = _base_result(
            finding, status="validated", confidence=0.92, oracle="reflection.html",
            reason="two independent inert markers were reflected as unescaped HTML elements",
            transactions=_transaction_dicts(rec), outcomes=outcomes)
        result["observed_requires"] = ["network_reach"]
        # Must be a privilege the graph contract knows (app.graph model); reflected
        # XSS runs script in the victim's context, i.e. a user session.
        result["observed_grants"] = ["user_session"]
        return result
    status = "inconclusive" if confirmed == 1 else "false_positive"
    confidence = 0.45 if confirmed == 1 else 0.12
    return _base_result(
        finding, status=status, confidence=confidence, oracle="reflection.html",
        reason=("reflection was not repeatable" if confirmed == 1 else
                "the application encoded, removed, or did not reflect both inert HTML markers"),
        transactions=_transaction_dicts(rec), outcomes=outcomes)


def endpoint_url(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = _METHOD_PREFIX.sub("", value.strip(), count=1)
    parsed = urlsplit(cleaned)
    return cleaned if parsed.scheme in {"http", "https"} and parsed.hostname else None


def endpoint_method(value: str | None) -> str | None:
    if not value:
        return None
    match = _METHOD_PREFIX.match(value.strip())
    return match.group(1).upper() if match else "GET"


# Sibling parameters that are auth/anti-CSRF plumbing rather than form gates: a
# guessed value for these can only break the request, so they are not filled in.
_SIBLING_SKIP = frozenset({
    "csrf", "csrf_token", "csrftoken", "_token", "user_token",
    "authenticity_token", "nonce", "captcha", "recaptcha",
})


def _with_sibling_params(endpoint: str | None, all_params, implicated: str | None) -> str | None:
    """Add the endpoint's OTHER observed params, at a benign presence value, to
    the URL so the injected parameter actually reaches its handler.

    Many forms only execute when every field is present (a search form may run
    its query only when its ``Submit`` field is set). The oracle supplies the implicated parameter, so it
    is left out here; anti-CSRF/token fields are skipped because a guessed value
    would just be rejected. Any value the URL already carries is preserved.
    """
    if not endpoint:
        return endpoint
    split = urlsplit(endpoint)
    existing = dict(parse_qsl(split.query, keep_blank_values=True))
    for name in all_params or []:
        key = str(name).strip()
        if (not key or key == implicated or key in existing
                or key.lower() in _SIBLING_SKIP or key.lower().startswith("csrf")):
            continue
        existing[key] = "1"
    if not existing:
        return endpoint
    return urlunsplit((split.scheme, split.netloc, split.path,
                       urlencode(existing), split.fragment))


def _redact_headers(headers: list[list[str]]) -> list[list[str]]:
    secret = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
    return [[name, "<redacted>" if name.lower() in secret else value] for name, value in headers]


def _redact_manifest(manifest: dict) -> dict:
    for tx in manifest.get("transactions", []):
        request = tx.get("request", {})
        response = tx.get("response", {})
        request["headers"] = _redact_headers(request.get("headers", []))
        response["headers"] = _redact_headers(response.get("headers", []))
        # Bodies can contain personal data or session material. Keep a bounded
        # excerpt sufficient for replay inspection; full fetches are never DB blobs.
        if isinstance(response.get("body"), str):
            response["body"] = response["body"][:4096]
    return manifest


def _transaction_dicts(recorder: RecordingFetcher) -> list[dict]:
    return [tx.as_dict() for tx in recorder.transactions()]


def _base_result(finding: dict, *, status: str, confidence: float,
                 oracle: str, reason: str, transactions: list[dict] | None = None,
                 outcomes: list[dict] | None = None) -> dict:
    evidence_id = str(uuid.uuid4())
    manifest = _redact_manifest({
        "schema_version": 1,
        "evidence_id": evidence_id,
        "oracle": oracle,
        "expected_status": status,
        "seed": 1337,
        "generated_by": "tool",
        "finding_id": str(finding["id"]),
        "candidate": {
            "asset_id": finding["asset_id"], "vuln_class": finding["vuln_class"],
            "endpoint": endpoint_url(finding.get("endpoint")), "param": finding.get("param"),
        },
        "reason": reason,
        "outcomes": outcomes or [],
        "transactions": transactions or [],
    })
    return {
        "finding_id": str(finding["id"]), "status": status,
        "confidence": round(max(0.0, min(1.0, confidence)), 4),
        "oracle": oracle, "reason": reason, "evidence_id": evidence_id,
        "observed_requires": [], "observed_grants": [],
        "target_asset_id": None, "manifest": manifest,
    }


def _validate_missing_headers(finding: dict, fetch: LiveFetcher,
                              matcher_names: list[str]) -> dict:
    endpoint = endpoint_url(finding.get("endpoint"))
    if endpoint is None:
        return _base_result(
            finding, status="inconclusive", confidence=0.25,
            oracle="configuration.headers", reason="candidate has no absolute endpoint")
    names = sorted({name.strip().lower() for name in matcher_names if name.strip()})
    if not names:
        return _base_result(
            finding, status="inconclusive", confidence=0.25,
            oracle="configuration.headers",
            reason="the original scanner observation did not identify a header matcher")

    # Browsers only honor Strict-Transport-Security when it is delivered over
    # HTTPS. Its absence on an HTTP response is therefore not an applicable
    # security-header failure (RFC 6797, section 8.1). Preserve that decision in
    # the evidence instead of silently inflating the confirmed-header count.
    scheme = urlsplit(endpoint).scheme.lower()
    not_applicable = []
    if scheme == "http" and "strict-transport-security" in names:
        names.remove("strict-transport-security")
        not_applicable.append("strict-transport-security")
    applicability = ([{
        "oracle": "configuration.headers",
        "fired": False,
        "not_applicable": not_applicable,
        "reason": "HSTS is only applicable to HTTPS responses",
    }] if not_applicable else [])
    if not names:
        return _base_result(
            finding, status="false_positive", confidence=0.95,
            oracle="configuration.headers",
            reason="the only reported header was HSTS on a plain HTTP endpoint",
            outcomes=applicability)

    rec = RecordingFetcher(fetch)
    samples = [rec(Request.get(endpoint)) for _ in range(3)]
    successful = [r for r in samples if 200 <= r.status < 400]
    if len(successful) != len(samples):
        return _base_result(
            finding, status="inconclusive", confidence=0.35,
            oracle="configuration.headers",
            reason=f"only {len(successful)}/{len(samples)} repeat probes returned 2xx/3xx",
            transactions=_transaction_dicts(rec))
    missing = {
        name: all(name not in {h[0].lower() for h in response.headers}
                  for response in successful)
        for name in names
    }
    absent = sorted(name for name, is_missing in missing.items() if is_missing)
    if absent:
        reason = (
            f"repeatable direct observation: {absent} absent in "
            f"{len(successful)}/{len(samples)} scoped responses"
        )
        result = _base_result(
            finding, status="validated", confidence=0.95,
            oracle="configuration.headers", reason=reason,
            transactions=_transaction_dicts(rec),
            outcomes=applicability + [{"oracle": "configuration.headers", "fired": True,
                                       "missing": absent, "samples": len(samples)}])
        result["observed_requires"] = ["network_reach"]
        result["observed_grants"] = ["network_reach"]
        return result
    return _base_result(
        finding, status="false_positive", confidence=0.95,
        oracle="configuration.headers",
        reason=f"all originally reported headers are now present in {len(samples)} repeat probes",
        transactions=_transaction_dicts(rec), outcomes=applicability)


def _validate_slice5(finding: dict, fetch: LiveFetcher) -> dict:
    param = finding.get("param")
    endpoint = _with_sibling_params(
        endpoint_url(finding.get("endpoint")), finding.get("endpoint_params"), param)
    if endpoint is None or not param:
        return _base_result(
            finding, status="unverifiable_safely", confidence=0.35,
            oracle="policy", reason="the oracle requires an absolute endpoint and one implicated parameter")

    common = {
        "asset_id": finding["asset_id"], "endpoint": endpoint, "param": param,
        "cvss_vector": finding.get("cvss_vector"),
    }
    rec = RecordingFetcher(fetch)
    vuln_class = finding["vuln_class"]
    if vuln_class == "sqli":
        kwargs = {**common, "cve": finding.get("cve_id")}
        content = run_boolean_differential(rec, **kwargs)
        timing = run_timing_differential(rec, **kwargs)
        adjudicated = adjudicate([content, timing])
        verdict = adjudicated.verdict
        contributions = list(adjudicated.contributions)
        oracle = "differential.boolean+timing"
        # The calibrated boolean+timing pair is a two-family INFERENTIAL proof.
        # It cannot reach every context: a parenthesised LIKE clause turns the
        # boolean payload into a syntax error, and a database without a SLEEP
        # primitive (e.g. SQLite) gives the timing channel nothing to scale, so
        # both abstain and the pair adjudicates to inconclusive. Only then fall
        # back to the DIRECT error-based channel, whose doubled-quote negative
        # control keeps it sound on its own; adopt its verdict when it fires so a
        # genuinely injectable endpoint is confirmed rather than left uncertain.
        if verdict.status != "validated":
            # The error channel carries its own three-point control (benign
            # clean, unbalanced quote errors, balanced quote clean), which is
            # robust to the catch-all/blocking conditions the shared sanity
            # canary guards against -- a 200-for-everything JSON search API (the
            # very shape that trips the canary) never emits a SQL parser error.
            # So skip that gate here; gating on it would silence the one oracle
            # that still works on such a target.
            error = run_error_differential(rec, check_sanity=False, **kwargs)
            if error.verdict.status == "validated":
                verdict = error.verdict
                contributions = []
                oracle = "differential.error-based"
    elif vuln_class == "ssti":
        expression_result = run_expression_differential(
            rec, **common)
        verdict = expression_result.verdict
        contributions = []
        oracle = "differential.expression"
    else:
        raise AssertionError(f"no Slice 5 route for {vuln_class}")

    requires, grant = observations(verdict)
    outcome_rows = [{
        "oracle": o.oracle, "fired": o.fired, "effect": o.effect,
        "detail": o.detail, "artifacts": list(o.artifacts),
    } for o in verdict.outcomes]
    reason = "; ".join(o.detail for o in verdict.outcomes) or verdict.status
    output = _base_result(
        finding, status=verdict.status, confidence=verdict.confidence,
        oracle=oracle, reason=reason, transactions=_transaction_dicts(rec),
        outcomes=outcome_rows)
    output["manifest"]["calibration_contributions"] = contributions
    output["observed_requires"] = list(requires)
    output["observed_grants"] = [grant] if grant else []
    output["target_asset_id"] = verdict.discovered_target
    return output


def validate_finding(finding: dict, matcher_names: list[str], *,
                     should_stop=None, headers: dict[str, str] | None = None) -> dict:
    """Validate one DB projection. All exceptions become honest terminal output."""
    endpoint = endpoint_url(finding.get("endpoint"))
    method = endpoint_method(finding.get("endpoint"))
    vuln_class = finding.get("vuln_class")
    if finding.get("auth_context_expired"):
        return _base_result(
            finding, status="unverifiable_safely", confidence=0.35,
            oracle="policy", reason="the authenticated scan credential expired before validation")
    if vuln_class in _SAFE_UNSUPPORTED:
        return _base_result(
            finding, status="unverifiable_safely", confidence=0.35,
            oracle="policy", reason=_SAFE_UNSUPPORTED[vuln_class])
    if endpoint is None:
        return _base_result(
            finding, status="inconclusive", confidence=0.25,
            oracle="preflight", reason="candidate has no absolute HTTP(S) endpoint")
    if method != "GET":
        return _base_result(
            finding, status="unverifiable_safely", confidence=0.35,
            oracle="policy",
            reason=f"unattended Validation refuses state-capable endpoint method {method}")
    try:
        with LiveFetcher(endpoint, should_stop=should_stop, headers=headers) as fetch:
            if finding.get("template_id") == "http-missing-security-headers":
                return _validate_missing_headers(finding, fetch, matcher_names)
            if vuln_class in {"sqli", "ssti"}:
                return _validate_slice5(finding, fetch)
            if vuln_class == "xss_reflected":
                return _validate_reflected_xss(finding, fetch)
            return _base_result(
                finding, status="unverifiable_safely", confidence=0.35,
                oracle="policy", reason="no non-destructive oracle is registered for this class")
    except ValidationHalted:
        raise
    except Exception as exc:  # transport failure is uncertainty, never evidence of absence
        return _base_result(
            finding, status="inconclusive", confidence=0.25,
            oracle="preflight", reason=f"validation could not complete: {type(exc).__name__}: {exc}")
