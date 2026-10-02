"""
The differential oracle -- the two-sided rule, on top of the Phase 1 learned
volatility threshold.

WHAT MAKES IT SOUND. A naive detector fires whenever a payload changes the page.
That is one-sided and it fires on any dynamic page or any server that 500s on a
quote. The two-sided rule instead requires the response to TRACK the injected
logic:

    TRUE  payload ( ' AND 1=1 -- )  ->  response ~= baseline   (the row is still returned)
    FALSE payload ( ' AND 1=2 -- )  ->  response != baseline   (the row disappears)

Random variation cannot fake that, and a server that merely errors on a quote
fails it (its TRUE response is an error page, not the baseline).

THE NEGATIVE CONTROL -- why single quotes matter. The two-sided pattern could
still be produced by something that reacts to the *tokens* rather than to SQL
evaluation (a WAF signature on "1=2", say). So we also send the SAME boolean
WITHOUT the quote that breaks out of the string:

    control TRUE  ( AND 1=1 )   ->  }  must agree with each other: with no
    control FALSE ( AND 1=2 )   ->  }  break-out the boolean cannot execute

If the with-quote pair diverges but the no-quote pair does NOT, the difference
is caused by breaking the query -- a real injection. If the no-quote pair ALSO
diverges, the difference is not SQL evaluation and we return `inconclusive`
(confounded) rather than a false positive.

EXPRESSION MODE (SSTI). Boolean same/different is replaced by a computed-marker
check: {{7*7}} must render "49" and {{6*6}} must render "36" (values that were
not on the baseline page), while a literal control "7*7" must NOT produce "49"
-- proving template *evaluation*, not echo. Marker presence needs no volatility
threshold, so it works even on dynamic pages.

HONESTY (LAW / contract). The differential channel proves INJECTION, not
extraction, so the oracle claims no observed privilege (`proves=None`); the
writer derives grants from the CVSS vector instead. A differential-only verdict
is therefore single-family and NOT self-corroborating -- the writer will attach
a corroboration warning, correctly, and the timing oracle (Phase 4) supplies the
disjoint second family that clears it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..control import sample_baseline, similarity
from ..http import Fetcher, Request
from ..sanity import sanity_canary
from ..writer import Candidate, OracleOutcome, Verdict, fingerprint


def _req(endpoint: str, param: str, value: str) -> Request:
    return Request(method="GET", url=endpoint, params=((param, value),))


@dataclass
class ProbeRecord:
    label: str
    value: str
    status: int
    detail: str = ""

    def as_dict(self) -> dict:
        return {"label": self.label, "value": self.value, "status": self.status,
                "detail": self.detail}


@dataclass
class DifferentialResult:
    verdict: Verdict
    probes: list[ProbeRecord] = field(default_factory=list)
    reason: str = ""


def _build(candidate: Candidate, status: str, conf: float, fired: bool,
           effect: float, reason: str, probes: list[ProbeRecord],
           artifacts: tuple[str, ...]) -> DifferentialResult:
    outcome = OracleOutcome(oracle="differential", fired=fired, effect=effect,
                            detail=reason, artifacts=artifacts)
    ev = "diff::" + fingerprint(candidate)
    v = Verdict(candidate=candidate, status=status, confidence=conf,
                outcomes=(outcome,), evidence_id=ev)
    return DifferentialResult(verdict=v, probes=probes, reason=reason)


# --------------------------------------------------------------- boolean (SQLi)

def run_boolean_differential(
        fetch: Fetcher, *, asset_id: str, endpoint: str, param: str,
        base_value: str = "test", vuln_class: str = "sqli",
        cvss_vector: str | None = None, cve: str | None = None,
        target_asset_id: str | None = None,
        true_suffix: str = "' AND 1=1 -- ", false_suffix: str = "' AND 1=2 -- ",
        control_true: str = " AND 1=1", control_false: str = " AND 1=2",
        check_sanity: bool = True) -> DifferentialResult:

    candidate = Candidate(asset_id=asset_id, vuln_class=vuln_class,
                          endpoint=endpoint, param=param, method="GET",
                          cvss_vector=cvss_vector, cve=cve,
                          target_asset_id=target_asset_id,
                          root_cause="unparameterised_query")
    ev = "diff::" + fingerprint(candidate)
    art = (f"{ev}#baseline", f"{ev}#true", f"{ev}#false",
           f"{ev}#ctrl_true", f"{ev}#ctrl_false")

    if check_sanity:
        sc = sanity_canary(fetch)
        if not sc.trustworthy:
            return _build(candidate, "inconclusive", 0.40, False, 0.0,
                          f"sanity canary failed: {sc.reason}", [], art)

    baseline = sample_baseline(fetch, _req(endpoint, param, base_value), k=5)
    if not baseline.content_usable:
        return _build(candidate, "inconclusive", 0.40, False, 0.0,
                      f"content channel unusable: {baseline.reason}", [], art)

    r_true = fetch(_req(endpoint, param, base_value + true_suffix))
    r_false = fetch(_req(endpoint, param, base_value + false_suffix))
    n_true = fetch(_req(endpoint, param, base_value + control_true))
    n_false = fetch(_req(endpoint, param, base_value + control_false))

    true_sim = baseline.similarity_to_baseline(r_true)
    false_sim = baseline.similarity_to_baseline(r_false)
    true_same = true_sim >= baseline.content_threshold
    false_diff = false_sim < baseline.content_threshold
    control_agree = similarity(n_true.body, n_false.body) >= baseline.content_threshold

    probes = [
        ProbeRecord("true", base_value + true_suffix, r_true.status,
                    f"sim={true_sim:.2f} same={true_same}"),
        ProbeRecord("false", base_value + false_suffix, r_false.status,
                    f"sim={false_sim:.2f} different={false_diff}"),
        ProbeRecord("control_true", base_value + control_true, n_true.status),
        ProbeRecord("control_false", base_value + control_false, n_false.status,
                    f"control_pair_agree={control_agree}"),
    ]

    tracks = true_same and false_diff
    if tracks and control_agree:
        sep = max(0.0, true_sim - false_sim)
        conf = round(min(0.90, 0.60 + 0.30 * sep), 4)   # single-channel cap
        return _build(candidate, "validated", conf, True, round(sep, 4),
                      f"response tracks the injected boolean (TRUE~baseline, "
                      f"FALSE diverges, separation {sep:.2f}) and the no-quote "
                      f"control pair agrees, so the effect is SQL evaluation, "
                      f"not token matching", probes, art)
    if tracks and not control_agree:
        return _build(candidate, "inconclusive", 0.40, False, 0.0,
                      "the difference reproduces WITHOUT breaking the query "
                      "(control pair diverged): confounded by a WAF/token "
                      "signature, not proven SQL evaluation", probes, art)
    return _build(candidate, "false_positive", 0.10, False, 0.0,
                  f"response does not track the boolean (TRUE same={true_same}, "
                  f"FALSE different={false_diff}); the scanner's finding is "
                  f"disproved", probes, art)


# ----------------------------------------------------------- error-based (SQLi)

#: Database parser errors, not ordinary application text. Each string is one a
#: real engine emits when a query fails to parse; none plausibly appears in a
#: benign product/JSON response, which is what lets their presence stand as
#: direct evidence rather than a noisy content diff.
_SQL_ERROR_SIGNATURES = (
    "sqlite_error", "sqlite3.", "syntax error", "unterminated",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlstate", "psqlexception", "org.postgresql.util", "pg::syntaxerror",
    "you have an error in your sql syntax", "ora-00933", "ora-01756",
    "odbc sql", "sql command not properly ended",
)


def _sql_error(body: str) -> bool:
    low = body.lower()
    return any(sig in low for sig in _SQL_ERROR_SIGNATURES)


def run_error_differential(
        fetch: Fetcher, *, asset_id: str, endpoint: str, param: str,
        base_value: str = "test", vuln_class: str = "sqli",
        cvss_vector: str | None = None, cve: str | None = None,
        target_asset_id: str | None = None,
        check_sanity: bool = True) -> DifferentialResult:
    """Error-based, two-sided proof of a string-context SQL injection.

    This channel is DIRECT, not inferential. A single unbalanced quote makes the
    database parser raise an error; the SAME input with the quote DOUBLED (a
    balanced, valid string literal) does not; and a benign value does not either.
    Only the quote reaching the SQL grammar explains that pattern -- an endpoint
    that errors on all input fails the benign/balanced controls and is reported
    ``inconclusive``, never a false positive, so the two-sided discipline of the
    boolean oracle is preserved.

    It exists because the boolean-tracking channel cannot reach every context: a
    parenthesised LIKE clause such as
    ``((name LIKE '%q%' OR description LIKE '%q%') AND deletedAt IS NULL)`` turns
    the ``' AND 1=1`` payload into a syntax error rather than a baseline-tracking
    row, and SQLite has no ``SLEEP`` for the timing channel to corroborate with.
    The doubled-quote negative control is what keeps this sound without a second
    statistical family.
    """
    candidate = Candidate(asset_id=asset_id, vuln_class=vuln_class,
                          endpoint=endpoint, param=param, method="GET",
                          cvss_vector=cvss_vector, cve=cve,
                          target_asset_id=target_asset_id,
                          root_cause="unparameterised_query")
    ev = "error::" + fingerprint(candidate)
    art = (f"{ev}#benign", f"{ev}#broken", f"{ev}#balanced")

    if check_sanity:
        sc = sanity_canary(fetch)
        if not sc.trustworthy:
            return _build(candidate, "inconclusive", 0.40, False, 0.0,
                          f"sanity canary failed: {sc.reason}", [], art)

    benign = fetch(_req(endpoint, param, base_value))
    broken = fetch(_req(endpoint, param, base_value + "'"))
    balanced = fetch(_req(endpoint, param, base_value + "''"))

    benign_err = _sql_error(benign.body)
    broken_err = _sql_error(broken.body)
    balanced_err = _sql_error(balanced.body)

    probes = [
        ProbeRecord("benign", base_value, benign.status,
                    f"sql_error={benign_err}"),
        ProbeRecord("broken_quote", base_value + "'", broken.status,
                    f"sql_error={broken_err}"),
        ProbeRecord("balanced_quote", base_value + "''", balanced.status,
                    f"sql_error={balanced_err}"),
    ]

    if broken_err and not balanced_err and not benign_err:
        return _build(candidate, "validated", 0.90, True, 1.0,
                      "an unbalanced single quote raises a database parser error "
                      "that the same input with a balanced (doubled) quote does "
                      "not, and a benign value does not either: the quote reaches "
                      "the SQL grammar, proving string-context injection", probes,
                      art)
    if broken_err and (balanced_err or benign_err):
        return _build(candidate, "inconclusive", 0.40, False, 0.0,
                      "a database error appears even for balanced or benign input, "
                      "so the endpoint errors independently of query break-out; "
                      "injection is not proven", probes, art)
    return _build(candidate, "false_positive", 0.10, False, 0.0,
                  "an unbalanced quote produced no database parser error; "
                  "error-based string-context injection disproved", probes, art)


# --------------------------------------------------------------- expression (SSTI)

def run_expression_differential(
        fetch: Fetcher, *, asset_id: str, endpoint: str, param: str,
        base_value: str = "guest", vuln_class: str = "ssti",
        cvss_vector: str | None = None,
        exprs=((7, 7, "49"), (6, 6, "36")),
        check_sanity: bool = True) -> DifferentialResult:

    candidate = Candidate(asset_id=asset_id, vuln_class=vuln_class,
                          endpoint=endpoint, param=param, method="GET",
                          cvss_vector=cvss_vector,
                          root_cause="template_injection")
    ev = "diff::" + fingerprint(candidate)
    art = tuple(f"{ev}#expr{i}" for i in range(len(exprs))) + (f"{ev}#literal",)

    if check_sanity:
        sc = sanity_canary(fetch)
        if not sc.trustworthy:
            return _build(candidate, "inconclusive", 0.40, False, 0.0,
                          f"sanity canary failed: {sc.reason}", [], art)

    baseline = fetch(_req(endpoint, param, base_value)).body
    probes: list[ProbeRecord] = []
    all_present = True
    for a, b, marker in exprs:
        payload = f"{base_value}{{{{{a}*{b}}}}}"
        r = fetch(_req(endpoint, param, payload))
        present = (marker in r.body) and (marker not in baseline)
        all_present = all_present and present
        probes.append(ProbeRecord(f"expr {a}*{b}", payload, r.status,
                                   f"marker {marker!r} present={present}"))

    # literal control: same arithmetic WITHOUT template braces must NOT compute
    a0, b0, m0 = exprs[0]
    r_lit = fetch(_req(endpoint, param, f"{base_value}{a0}*{b0}"))
    control_clean = (m0 not in r_lit.body) or (m0 in baseline)
    probes.append(ProbeRecord("literal_control", f"{base_value}{a0}*{b0}",
                              r_lit.status, f"marker_absent={control_clean}"))

    if all_present and control_clean:
        return _build(candidate, "validated", 0.88, True, float(len(exprs)),
                      f"template evaluation confirmed: {len(exprs)} distinct "
                      f"computed markers rendered and a literal control did not "
                      f"-- so the server evaluates, it does not echo", probes, art)
    if all_present and not control_clean:
        return _build(candidate, "false_positive", 0.15, False, 0.0,
                      "the marker also appeared for a non-template literal; the "
                      "value is echoed, not evaluated", probes, art)
    return _build(candidate, "false_positive", 0.10, False, 0.0,
                  "computed markers did not render; template injection disproved",
                  probes, art)
