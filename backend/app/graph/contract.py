"""
THE MODULE 2 <-> MODULE 3 SEAM. Both modules import this file and nothing else
from each other.

Module 3 already refuses to call another module: it reads rows and writes rows.
The failure mode that leaves is *silent semantic drift* -- Module 2 writes a
`vuln_class` Module 3 has never heard of, or omits a `patch_group`, and the
graph still builds, still renders, and still reports a number. It is just a
worse number, derived from `DEFAULT_SEMANTICS` at `ASSUMED` provenance.

`diagnostics.py` already catches all of that at RUNTIME. This module moves the
same checks to WRITE time, where the team can act on them, and pins the shared
vocabulary in one importable place so the two tracks cannot drift apart between
Day 2 and Day 11.

    VULN_CLASSES        derived from SEMANTICS -- it can never fall out of date
    M2_EMITTED_CLASSES  what Module 2's oracles actually produce
    VERDICTS            the five statuses, including unverifiable_safely
    ORACLE_PROVES       which oracle proves which privilege transition
    DEFAULT_PATCH_HOURS so A6's budget plan is not uniformly 1.0
    patch_group_for()   the deterministic grouping rule the ILP depends on
    validate_finding_row() / normalise_finding_row()

`tests/graph/test_contract.py` asserts M2_EMITTED_CLASSES is a subset of
VULN_CLASSES, so adding an oracle without adding its semantics is a red build
rather than a quiet downgrade.
"""
from __future__ import annotations

from .model import (
    ADMIN_SESSION, CODE_EXEC, DATA_READ, NETWORK_REACH, SEMANTICS, USER_SESSION,
)

# --------------------------------------------------------------- vocabulary

#: Single source of truth. Derived, never hand-maintained.
VULN_CLASSES: frozenset[str] = frozenset(SEMANTICS)

#: What Module 2's oracle suite can emit. Must stay a subset of VULN_CLASSES.
M2_EMITTED_CLASSES: frozenset[str] = frozenset({
    # differential oracle
    "sqli", "ssti", "auth_bypass", "lfi", "broken_access_control",
    # timing oracle
    # (blind sqli reports as "sqli")
    # execution oracle
    "xss_reflected", "xss_stored",
    # authorization oracle
    "idor", "cred_reuse",
    # out-of-band oracle
    "ssrf", "rce", "xxe",
    # redirect / protocol oracle
    "open_redirect",
    # state-changing classes (proved by precondition, never fully exploited)
    "csrf", "file_upload_rce", "deserialization",
    # passive
    "misconfig_open_service", "info_leak",
})

#: Terminal verdicts Module 2 may write, plus the two Module 3 lifecycle states.
VERDICTS: frozenset[str] = frozenset({
    "unvalidated",           # candidate from the scanner, not yet adjudicated
    "validated",             # oracles fired, corroborated, controls clean
    "false_positive",        # we actively DISPROVED the scanner
    "inconclusive",          # WAF / instability / sanity canary failed
    "unverifiable_safely",   # real class, no non-destructive oracle exists
    "remediated",            # retest flipped it; Module 3 removes it
})

#: Statuses that still produce an edge in the graph.
LIVE_VERDICTS: frozenset[str] = VERDICTS - {"false_positive", "remediated"}


# --------------------------------------------------------------- oracles

#: oracle -> (observed_requires, observed_grants)
#:
#: Only oracles whose SUCCESS *is* the privilege transition appear here. A
#: boolean-differential or timing oracle proves INJECTION, not extraction, so it
#: deliberately does not override the CVSS/class semantics -- claiming an
#: observed `data_read` from a two-sided boolean test would be over-claiming, and
#: over-claiming is the one thing that loses a contention round.
ORACLE_PROVES: dict[str, tuple[tuple[str, ...], str]] = {
    "authorization": ((USER_SESSION,), DATA_READ),      # A read B's object
    "execution":     ((NETWORK_REACH,), USER_SESSION),  # marker ran in the DOM
    "oob_rce":       ((NETWORK_REACH,), CODE_EXEC),     # canary command executed
    "oob_ssrf":      ((NETWORK_REACH,), NETWORK_REACH),  # server fetched our URL
    "oob_xxe":       ((NETWORK_REACH,), DATA_READ),     # external entity resolved
    "priv_esc":      ((USER_SESSION,), ADMIN_SESSION),  # low-priv hit admin route
}

#: Oracles that prove a step without proving a specific new privilege.
NON_OVERRIDING_ORACLES: frozenset[str] = frozenset({
    "differential", "timing", "redirect",
})


def observations_for(oracle: str) -> tuple[tuple[str, ...], str | None]:
    """What Module 2 should write into observed_requires / observed_grants.

    Returns ((), None) for oracles that do not themselves establish a privilege
    transition -- the caller then leaves both fields empty and Module 3 falls
    back to the CVSS vector, which is the correct, honest precedence.
    """
    if oracle in ORACLE_PROVES:
        req, grants = ORACLE_PROVES[oracle]
        return req, grants
    return (), None


# --------------------------------------------------------------- patch effort

#: Rough remediation effort in hours. Uniform 1.0 makes A6's budget plan and the
#: cut's "cost in hours" decorative, so even coarse values are a large upgrade.
#: These are engineering estimates, not measurements -- say so in the report.
DEFAULT_PATCH_HOURS: dict[str, float] = {
    "sqli": 4.0,
    "ssti": 3.0,
    "lfi": 2.0,
    "xxe": 2.0,
    "rce": 2.0,
    "file_upload_rce": 3.0,
    "deserialization": 4.0,
    "ssrf": 3.0,
    "idor": 3.0,
    "broken_access_control": 3.0,
    "auth_bypass": 1.5,
    "xss_stored": 2.0,
    "xss_reflected": 1.5,
    "csrf": 2.0,
    "open_redirect": 1.0,
    "cred_reuse": 1.0,
    "misconfig_open_service": 0.5,
    "info_leak": 0.5,
    "phishing_credential": 2.0,
}

DEFAULT_PATCH_HOURS_FALLBACK = 1.0


def patch_hours_for(vuln_class: str) -> float:
    return DEFAULT_PATCH_HOURS.get(vuln_class, DEFAULT_PATCH_HOURS_FALLBACK)


def patch_group_for(vuln_class: str, *, cve: str | None = None,
                    component: str | None = None,
                    root_cause: str | None = None) -> str | None:
    """The grouping rule A3's ILP depends on. One ACTION, charged once.

    Precedence mirrors how a real fix is applied:
        CVE          one upgrade closes the same CVE on every host
        component    one base image / library bump closes a version family
        root_cause   one code change closes a sink family (an ORM call, a
                     template render, a shared auth decorator)

    Returns None when no grouping signal exists rather than inventing one.
    Over-grouping is worse than not grouping: it would let the ILP claim a
    single action fixes findings that in reality need separate work, which is a
    FALSE minimality claim -- exactly what breakchain.py is careful never to make.
    A None here surfaces as the `no_patch_groups` diagnostic.
    """
    if cve:
        return cve.strip().upper()
    if component:
        return f"component::{component.strip().lower()}"
    if root_cause:
        return f"{vuln_class}::{root_cause.strip().lower()}"
    return None


# --------------------------------------------------------------- validation

_REQUIRED = ("id", "asset_id", "vuln_class")
_KNOWN_KEYS = frozenset({
    "id", "finding_id", "asset_id", "vuln_class", "status", "confidence",
    "cvss_vector", "epss", "epss_snapshot_date", "patch_hours", "patch_group",
    "evidence_id", "endpoint", "param", "observed_grants", "observed_requires",
    "target_asset_id",
    "generated_by",
})


def _problem(code: str, severity: str, message: str, fix: str) -> dict:
    return {"code": code, "severity": severity, "message": message, "fix": fix}


def validate_finding_row(row: dict) -> list[dict]:
    """Check one Module 2 row BEFORE it is written. Returns problems, never raises.

    Same codes diagnostics.py uses at runtime, so a row that passes here cannot
    produce a surprise at analysis time.
    """
    problems: list[dict] = []
    fid = row.get("id") or row.get("finding_id") or "<no id>"

    for key in _REQUIRED:
        if key == "id" and (row.get("id") or row.get("finding_id")):
            continue
        if not row.get(key):
            problems.append(_problem(
                "missing_required_field", "error",
                f"{fid}: '{key}' is required", "Module 2 must always emit it"))

    vc = row.get("vuln_class")
    if vc and vc not in VULN_CLASSES:
        problems.append(_problem(
            "unknown_vuln_classes", "error",
            f"{fid}: vuln_class '{vc}' is not in SEMANTICS; the graph would fall "
            f"back to DEFAULT_SEMANTICS (grants info_disclosure) at ASSUMED "
            f"provenance",
            "add it to model.SEMANTICS, or map it to an existing class"))

    status = row.get("status", "unvalidated")
    if status not in VERDICTS:
        problems.append(_problem(
            "unknown_status", "error",
            f"{fid}: status '{status}' is not a recognised verdict",
            f"use one of {sorted(VERDICTS)}"))

    conf = row.get("confidence")
    if conf is not None and not (0.0 <= float(conf) <= 1.0):
        problems.append(_problem(
            "confidence_out_of_range", "error",
            f"{fid}: confidence {conf} is outside [0, 1]",
            "Module 2's calibrated posterior is a probability"))

    generated_by = row.get("generated_by", "tool")
    if generated_by not in {"tool", "ai", "human"}:
        problems.append(_problem(
            "unknown_provenance", "error",
            f"{fid}: generated_by '{generated_by}' is not recognised",
            "use tool, ai, or human and preserve the distinction"))

    if status == "validated" and not row.get("evidence_id"):
        problems.append(_problem(
            "validated_without_evidence", "warning",
            f"{fid}: validated but carries no evidence_id",
            "every validated edge must resolve to a replayable manifest"))

    if not row.get("patch_group"):
        problems.append(_problem(
            "no_patch_groups", "warning",
            f"{fid}: no patch_group; the ILP degenerates to min-cut for this row",
            "set it with contract.patch_group_for(cve=/component=/root_cause=)"))

    if row.get("observed_grants") and not row.get("observed_requires"):
        problems.append(_problem(
            "partial_observation", "warning",
            f"{fid}: observed_grants without observed_requires",
            "emit both, or Module 3 keeps the class-table preconditions"))

    stray = sorted(set(row) - _KNOWN_KEYS)
    if stray:
        problems.append(_problem(
            "unrecognised_input_keys", "warning",
            f"{fid}: keys not read by Module 3: {stray}",
            "use the documented column names or the values are dropped"))

    return problems


def normalise_finding_row(row: dict) -> dict:
    """Fill the fields Module 3 can use but Module 2 often forgets.

    Only ever ADDS defaults; never overwrites a value Module 2 supplied.
    """
    out = dict(row)
    out.setdefault("status", "unvalidated")
    vc = out.get("vuln_class")
    if out.get("patch_hours") in (None, ""):
        out["patch_hours"] = patch_hours_for(vc) if vc else DEFAULT_PATCH_HOURS_FALLBACK
    if out.get("confidence") in (None, ""):
        out["confidence"] = 0.25 if out["status"] == "unvalidated" else 0.5
    return out


def validate_batch(rows) -> dict:
    """Validate a whole Module 2 write. Used by POST /graph/load."""
    problems: list[dict] = []
    for r in rows:
        problems.extend(validate_finding_row(r))
    errors = [p for p in problems if p["severity"] == "error"]
    return {
        "rows": len(list(rows)) if not hasattr(rows, "__len__") else len(rows),
        "ok": not errors,
        "errors": len(errors),
        "warnings": len(problems) - len(errors),
        "problems": problems,
    }
