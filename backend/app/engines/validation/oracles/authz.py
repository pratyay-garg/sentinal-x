"""
The authorization oracle -- the 2x2 matrix. The most convincing oracle in the
module: it needs no payload, is trivially non-destructive (read-only GETs on
licensed test accounts), and a judge understands it in one sentence.

THE MATRIX. Two low-privilege test accounts A and B, each owning one object:

              A's object        B's object
    actor A   [aa] control      [ab] cross-read
    actor B   [ba] cross-read   [bb] control

  * The DIAGONAL (aa, bb) is the POSITIVE CONTROL. A must be able to read A's
    own object. If it cannot, the session or the harness is broken and a 403 on
    the off-diagonal proves nothing -- so the oracle returns `inconclusive`
    rather than a false clean bill. This self-check is why a single firing is
    already corroborated (contract.SELF_CORROBORATING).
  * The OFF-DIAGONAL (ab, ba) is the finding. A reading B's object is a leak,
    but STATUS 200 ALONE IS NOT ENOUGH -- a server can 200 an empty or generic
    page. The strong signal is a CROSS-ACCOUNT CONTENT MATCH: A's view of B's
    object equals B's own view of it. We compare with shingle Jaccard.
  * If the two owners' objects are indistinguishable to begin with, a match
    cannot be told from a coincidence, so the oracle abstains.

Honesty (LAW): the oracle sets no explicit `proves`; the writer maps the
authorization channel to (requires user_session, grants data_read) via
contract.ORACLE_PROVES, and only for a `validated` verdict. We do not claim an
observation we did not make.

Adjudication here is minimal and specific to this self-corroborating oracle;
Phase 5 introduces the calibrated cross-oracle scorecard. That is why the
confidence below is derived transparently from the matrix rather than fitted.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..control import similarity
from ..http import Fetcher, Request, Response
from ..writer import Candidate, OracleOutcome, Verdict, fingerprint

LEAK_SIMILARITY = 0.90         # A's view of B's object ~ B's view => leak
DISTINCT_SIMILARITY = 0.90     # owners' objects must differ by more than this


@dataclass(frozen=True)
class Account:
    id: str
    owns: str                              # object ref this account legitimately owns
    token: str | None = None               # bearer value; defaults to id

    def headers(self) -> tuple[tuple[str, str], ...]:
        return (("Authorization", f"Bearer {self.token or self.id}"),)


@dataclass
class Cell:
    actor: str
    object_ref: str
    object_owner: str
    is_control: bool
    status: int = 0
    leaked: bool = False
    match: float = 0.0

    def as_dict(self) -> dict:
        return {"actor": self.actor, "object": self.object_ref,
                "owner": self.object_owner, "control": self.is_control,
                "status": self.status, "leaked": self.leaked,
                "content_match": round(self.match, 3)}


@dataclass
class AuthzResult:
    verdict: Verdict
    cells: list[Cell] = field(default_factory=list)
    reason: str = ""

    def matrix(self) -> list[dict]:
        return [c.as_dict() for c in self.cells]


def _url(template: str, object_ref: str) -> str:
    return template.format(id=object_ref) if "{id}" in template \
        else template.rstrip("/") + "/" + object_ref


def _fetch_get(fetch: Fetcher, template: str, account: Account,
               object_ref: str) -> Response:
    # Read-only by construction. Every cell is a GET -- there is no state change.
    return fetch(Request(method="GET", url=_url(template, object_ref),
                         headers=account.headers()))


def run_authorization(fetch: Fetcher, *, asset_id: str, endpoint: str,
                      account_a: Account, account_b: Account,
                      vuln_class: str = "idor") -> AuthzResult:
    aa = _fetch_get(fetch, endpoint, account_a, account_a.owns)   # control
    ab = _fetch_get(fetch, endpoint, account_a, account_b.owns)   # cross-read
    bb = _fetch_get(fetch, endpoint, account_b, account_b.owns)   # control
    ba = _fetch_get(fetch, endpoint, account_b, account_a.owns)   # cross-read

    c_aa = Cell(account_a.id, account_a.owns, account_a.id, True, aa.status)
    c_bb = Cell(account_b.id, account_b.owns, account_b.id, True, bb.status)
    c_ab = Cell(account_a.id, account_b.owns, account_b.id, False, ab.status)
    c_ba = Cell(account_b.id, account_a.owns, account_a.id, False, ba.status)

    # off-diagonal leak = 2xx AND content matches the true owner's view
    c_ab.match = similarity(ab.body, bb.body)
    c_ab.leaked = ab.is_2xx and c_ab.match >= LEAK_SIMILARITY
    c_ba.match = similarity(ba.body, aa.body)
    c_ba.leaked = ba.is_2xx and c_ba.match >= LEAK_SIMILARITY

    cells = [c_aa, c_ab, c_ba, c_bb]

    candidate = Candidate(
        asset_id=asset_id, vuln_class=vuln_class, endpoint=endpoint,
        method="GET", root_cause="missing_object_authorization",
    )
    evidence_id = "authz::" + fingerprint(candidate)

    def verdict(status: str, conf: float, fired: bool, effect: float,
                reason: str) -> AuthzResult:
        outcome = OracleOutcome(
            oracle="authorization", fired=fired, effect=effect,
            detail=reason,
            artifacts=(f"{evidence_id}#aa", f"{evidence_id}#ab",
                       f"{evidence_id}#ba", f"{evidence_id}#bb"),
        )
        v = Verdict(candidate=candidate, status=status, confidence=conf,
                    outcomes=(outcome,), evidence_id=evidence_id)
        return AuthzResult(verdict=v, cells=cells, reason=reason)

    # 1. positive control must hold
    if not (aa.is_2xx and bb.is_2xx):
        return verdict(
            "inconclusive", 0.40, False, 0.0,
            f"positive control failed: an account could not read its own object "
            f"(A->A={aa.status}, B->B={bb.status}); session or harness is broken")

    # 2. the two owners' objects must be distinguishable
    if similarity(aa.body, bb.body) >= DISTINCT_SIMILARITY:
        return verdict(
            "inconclusive", 0.40, False, 0.0,
            "test objects are indistinguishable; a cross-read cannot be told "
            "from a legitimate content match")

    # 3. adjudicate the off-diagonal
    leaks = [c for c in (c_ab, c_ba) if c.leaked]
    if leaks:
        strength = max(c.match for c in leaks)
        conf = round(min(0.99, 0.80 + 0.19 * strength), 4)
        return verdict(
            "validated", conf, True, float(len(leaks)),
            f"broken object-level authorization: {len(leaks)} off-diagonal "
            f"cross-read(s) returned another account's object "
            f"(content match up to {strength:.0%}); controls clean")

    return verdict(
        "false_positive", 0.05, False, 0.0,
        "authorization enforced: every off-diagonal cross-read was denied or "
        "returned unrelated content; the scanner's finding is disproved")
