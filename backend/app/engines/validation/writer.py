"""
Module 2's OUTPUT ADAPTER -- the last step of validation, not a bridge.

Module 3 never imports this file. Data flows one way:

    oracle fires -> Verdict -> writer -> rows -> Postgres -> Module 3 reads

The only shared thing is `app.graph.contract`, which both sides import as a
rulebook. If importing it is unwelcome coupling, `GET /graph/contract` serves the
same vocabulary over HTTP and this module can be pointed at that instead.

WHAT THIS FILE IS FOR
    The graph is only as good as the rows it is fed. Three fields decide whether
    Module 3 performs on live data the way it performs on its fixture, and all
    three are Module 2's responsibility:

    observed_grants / observed_requires
        cvss.semantics_from_finding gives these TOP precedence and stamps
        Provenance.EVIDENCE -- the strongest tier -- so emitting them RAISES the
        derived_fraction Module 3 prints on screen. Our proofs are what make the
        graph evidence-derived.

    patch_group
        A3's ILP only beats the min-cut when findings share a group. Without
        this, every finding is its own group and the ILP silently degenerates to
        min-cut on the real target while still beating it on the fixture.

    finding_id (a stable fingerprint)
        Retest upserts by id. A fresh uuid per scan makes the before/after
        comparison -- the demo climax -- meaningless.

WHAT THIS FILE DELIBERATELY DOES NOT DO
    It does not adjudicate. `Verdict.status` arrives already decided by the
    oracle engine; the writer only translates. It does add one guard
    (`corroboration_warnings`) that flags a `validated` verdict resting on a
    single non-self-corroborating oracle, because over-claiming is the failure
    mode that costs a contention round.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.graph import contract
from app.graph.model import (
    ADMIN_SESSION, CODE_EXEC, DATA_READ, INFO_DISCLOSURE, NETWORK_REACH,
    USER_SESSION,
)

# Strongest grant wins when several oracles prove different transitions.
_GRANT_RANK = {
    CODE_EXEC: 5, DATA_READ: 4, ADMIN_SESSION: 3,
    USER_SESSION: 2, INFO_DISCLOSURE: 1, NETWORK_REACH: 0,
}

#: Oracles grouped by FAILURE MODE. Corroboration only means something when the
#: two oracles cannot fail for the same underlying reason -- content diffing and
#: timing are disjoint (a cache breaks one, load breaks the other); two content
#: signals are the same evidence counted twice.
FAILURE_FAMILY = {
    "differential": "content",
    "timing": "time",
    "oob_rce": "out_of_band",
    "oob_ssrf": "out_of_band",
    "oob_xxe": "out_of_band",
    "execution": "browser",
    "authorization": "identity",
    "priv_esc": "identity",
    "redirect": "protocol",
}

#: Oracles that carry their own control, so a single firing is already
#: corroborated. The dividing line is DIRECT ATTRIBUTABLE EVIDENCE versus
#: STATISTICAL INFERENCE:
#:
#:   direct    a unique nonce executed in the DOM; a unique canary token arrived
#:             at our listener from the target; the 2x2 matrix proved its own
#:             harness on the diagonal before reading the off-diagonal. There is
#:             no plausible alternative explanation for any of these.
#:   inferred  a content diff or a response-time shift. Both are comparisons
#:             against a noisy baseline and both have well-known confounders, so
#:             each needs a second family with a disjoint failure mode.
#:
#: Note this set is exactly contract.ORACLE_PROVES, and that is not a
#: coincidence: an oracle can name the specific privilege it granted precisely
#: when it produced direct evidence rather than an inference.
SELF_CORROBORATING = frozenset(contract.ORACLE_PROVES)


# --------------------------------------------------------------- inputs

@dataclass(frozen=True)
class OracleOutcome:
    """One oracle's result against one candidate."""
    oracle: str
    fired: bool
    effect: float = 0.0             # z-score, similarity delta, whatever is natural
    detail: str = ""
    artifacts: tuple[str, ...] = ()  # screenshot / request-response ids
    #: Explicit override: a privilege this oracle DEMONSTRATED, not inferred.
    #: A boolean-differential SQLi normally proves injection only, so it claims
    #: nothing -- but if the same probe actually returned a row from the target
    #: table, extraction was demonstrated and the oracle may say `proves=
    #: "data_read"`. Default None keeps the honest behaviour: infer nothing.
    proves: str | None = None
    #: Preconditions demonstrated alongside `proves`.
    proves_requires: tuple[str, ...] = ()

    @property
    def family(self) -> str:
        return FAILURE_FAMILY.get(self.oracle, self.oracle)


@dataclass(frozen=True)
class Candidate:
    """What the scanner -- or assist mode -- handed the validator."""
    asset_id: str
    vuln_class: str
    endpoint: str | None = None
    param: str | None = None
    method: str = "GET"
    cvss_vector: str | None = None
    cve: str | None = None            # -> patch_group, highest precedence
    component: str | None = None      # e.g. "django@4.1" -> patch_group
    root_cause: str | None = None     # e.g. "orm_raw" -> patch_group
    epss: float | None = None
    epss_snapshot_date: str | None = None
    target_asset_id: str | None = None


@dataclass(frozen=True)
class Verdict:
    """The oracle engine's decision. Already adjudicated; the writer translates."""
    candidate: Candidate
    status: str                                  # contract.VERDICTS
    confidence: float                            # calibrated posterior
    outcomes: tuple[OracleOutcome, ...] = ()
    evidence_id: str | None = None
    #: SSRF canary callback proved this reachability, (src_asset, dst_asset).
    proven_route: tuple[str, str] | None = None
    #: Asset the grant landed on, when an oracle discovered it (SSRF/SQLi).
    discovered_target: str | None = None
    seed: int = 1337

    @property
    def fired(self) -> tuple[OracleOutcome, ...]:
        return tuple(o for o in self.outcomes if o.fired)


# --------------------------------------------------------------- fingerprint

def fingerprint(c: Candidate) -> str:
    """Stable id across re-scans. Retest upserts by this, so it must not move.

    Canonicalises the endpoint (drop scheme/host/fragment, keep the path) so the
    same finding reached over http vs https, or via two hostnames for one asset,
    does not fork into two findings.
    """
    path = ""
    if c.endpoint:
        parts = urlsplit(c.endpoint)
        path = (parts.path or c.endpoint).rstrip("/") or "/"
    raw = "|".join([c.asset_id, c.vuln_class, path, c.param or "", c.method.upper()])
    return "V" + hashlib.sha256(raw.encode()).hexdigest()[:12]


# --------------------------------------------------------------- observations

def observations(v: Verdict) -> tuple[tuple[str, ...], str | None]:
    """The privilege transition our oracles actually PROVED.

    Only `validated` verdicts may claim an observation, and only from oracles in
    contract.ORACLE_PROVES. A differential or timing oracle proves injection but
    not extraction, so it returns nothing and the CVSS vector decides -- which is
    the correct, honest precedence. When several proving oracles fired, the
    strongest grant wins.
    """
    if v.status != "validated":
        return (), None
    best: tuple[str, ...] = ()
    best_grant: str | None = None
    for o in v.fired:
        req: tuple[str, ...]
        grants: str | None
        if o.proves:                      # explicit demonstration wins
            req, grants = o.proves_requires, o.proves
        else:
            req, grants = contract.observations_for(o.oracle)
        if grants is None:
            continue
        if best_grant is None or _GRANT_RANK.get(grants, -1) > _GRANT_RANK.get(best_grant, -1):
            best, best_grant = req, grants
    return best, best_grant


def corroboration_warnings(v: Verdict) -> list[str]:
    """Guard against over-claiming. Not adjudication -- the verdict already
    happened; this just refuses to let a weak one through quietly."""
    out: list[str] = []
    if v.status != "validated":
        return out
    fired = v.fired
    if not fired:
        return [f"{v.status} with no oracle fired"]
    families = {o.family for o in fired}
    self_corr = any(o.oracle in SELF_CORROBORATING for o in fired)
    if len(families) < 2 and not self_corr:
        out.append(
            f"validated on a single failure-mode family ({sorted(families)[0]}) "
            f"with no self-corroborating oracle; two disjoint families are the bar")
    return out


# --------------------------------------------------------------- row builders

def to_finding_row(v: Verdict) -> dict:
    """One Verdict -> one contract-valid Finding row."""
    c = v.candidate
    req, grants = observations(v)
    group = contract.patch_group_for(
        c.vuln_class, cve=c.cve, component=c.component, root_cause=c.root_cause)

    row = {
        "id": fingerprint(c),
        "asset_id": c.asset_id,
        "vuln_class": c.vuln_class,
        "status": v.status,
        "confidence": round(float(v.confidence), 4),
        "cvss_vector": c.cvss_vector,
        "epss": c.epss,
        "epss_snapshot_date": c.epss_snapshot_date,
        "patch_hours": contract.patch_hours_for(c.vuln_class),
        "patch_group": group,
        "evidence_id": v.evidence_id,
        "endpoint": c.endpoint,
        "param": c.param,
        "target_asset_id": v.discovered_target or c.target_asset_id,
        "observed_requires": tuple(req),
        "observed_grants": (grants,) if grants else (),
    }
    return contract.normalise_finding_row(row)


def to_route_rows(v: Verdict) -> list[dict]:
    """An SSRF canary callback is a route PROVEN by experiment.

    No scanner can produce this, and Module 3's README calls it the strongest
    route provenance there is. Note the SSRF itself grants only network_reach --
    a second finding still has to convert reach into read.
    """
    if not v.proven_route or v.status != "validated":
        return []
    src, dst = v.proven_route
    return [{
        "src": src, "dst": dst, "provenance": "observed",
        "reason": f"SSRF canary callback from {src} reached {dst} "
                  f"(evidence {v.evidence_id})",
    }]


@dataclass
class WriteResult:
    findings: list[dict] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)
    validation: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.validation.get("ok", True))

    def as_payload(self, assets, entries, facts=()) -> dict:
        """Body for POST /graph/load."""
        return {"assets": list(assets), "findings": self.findings,
                "routes": self.routes, "facts": list(facts),
                "entries": list(entries)}


def write(verdicts) -> WriteResult:
    """Translate a batch of verdicts, validate them, and report.

    Rows are returned even when validation finds errors: a partially valid graph
    is more useful than a rejected one, and Module 3 reports the same codes at
    analysis time. `ok` tells you whether anything needs fixing first.
    """
    res = WriteResult()
    seen: dict[str, dict] = {}
    for v in verdicts:
        row = to_finding_row(v)
        res.warnings.extend(f"{row['id']}: {w}" for w in corroboration_warnings(v))
        # Idempotent upsert by fingerprint: re-running the pipeline must
        # converge, not accumulate. Later verdicts win.
        seen[row["id"]] = row
        res.routes.extend(to_route_rows(v))
    res.findings = [seen[k] for k in sorted(seen)]
    # de-duplicate proven routes
    res.routes = [dict(t) for t in
                  sorted({tuple(sorted(r.items())) for r in res.routes})]
    res.validation = contract.validate_batch(res.findings)
    return res
