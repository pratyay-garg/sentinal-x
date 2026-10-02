"""
CVSS v3.1 vectors are already a formal statement of attack prerequisites and
impact. We parse them instead of hard-coding what each vulnerability class
grants, which removes the single largest modelling assumption in the graph.

    Exploitability metrics -> PRECONDITIONS
        AV:N  reachable over the network
        AV:A  reachable within the same zone
        AV:L  needs local access (user_session or code_exec on the host)
        AV:P  physical -- we treat as unreachable in a remote attack model
        PR:N  no privilege required
        PR:L  needs user_session
        PR:H  needs admin_session
        UI:R  needs a Fact(user_interaction)  <- this is where phishing attaches

    Impact metrics -> POSTCONDITIONS
        C:H   grants data_read
        C:L   grants info_disclosure
        I:H   grants code_exec
        I:L   grants user_session
        S:C   the grant lands on a DIFFERENT asset (formal lateral movement)

Exploitability subscore = 8.22 * AV * AC * PR * UI, max 3.887 (~3.9).
That subscore -- not the Base score -- is the right severity input for an edge,
because an edge asks "can they take this step", not "how bad is the outcome".
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import (
    ADMIN_SESSION, CODE_EXEC, DATA_READ, INFO_DISCLOSURE, NETWORK_REACH,
    USER_SESSION, Provenance, Semantics,
)

AV_W = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_W = {"L": 0.77, "H": 0.44}
PR_W_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_W_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_W = {"N": 0.85, "R": 0.62}

MAX_EXPLOITABILITY = 3.887  # 8.22 * 0.85 * 0.77 * 0.85 * 0.85

_TOKEN = re.compile(r"([A-Z]+):([A-Z])")


@dataclass(frozen=True)
class CVSSVector:
    raw: str
    metrics: dict[str, str]

    @property
    def scope_changed(self) -> bool:
        return self.metrics.get("S") == "C"

    def exploitability(self) -> float:
        m = self.metrics
        av = AV_W[m["AV"]]
        ac = AC_W[m["AC"]]
        pr = (PR_W_CHANGED if self.scope_changed else PR_W_UNCHANGED)[m["PR"]]
        ui = UI_W[m["UI"]]
        return 8.22 * av * ac * pr * ui

    def exploitability_norm(self) -> float:
        """Exploitability subscore normalised to [0, 1]."""
        return min(1.0, self.exploitability() / MAX_EXPLOITABILITY)


REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse(vector: str | None) -> CVSSVector | None:
    """Parse a CVSS v3.x vector. Returns None if absent or incomplete -- callers
    fall back to the class table rather than guessing."""
    if not vector:
        return None
    metrics = {k: v for k, v in _TOKEN.findall(vector.upper()) if k != "CVSS"}
    if not all(k in metrics for k in REQUIRED):
        return None
    try:
        AV_W[metrics["AV"]], AC_W[metrics["AC"]], UI_W[metrics["UI"]]
        (PR_W_CHANGED if metrics.get("S") == "C" else PR_W_UNCHANGED)[metrics["PR"]]
    except KeyError:
        return None
    return CVSSVector(raw=vector, metrics=metrics)


def derive_semantics(vec: CVSSVector, mitre: tuple[str, ...] = ()) -> Semantics:
    """Turn a parsed vector into graph preconditions and a postcondition."""
    m = vec.metrics

    # --- preconditions from the exploitability metrics
    requires: list[str] = []
    av = m["AV"]
    if av in ("N", "A"):
        requires.append(NETWORK_REACH)
    elif av == "L":
        requires.append(USER_SESSION)
    else:  # AV:P -- not reachable in a remote attack model
        requires.append(CODE_EXEC)

    pr = m["PR"]
    if pr == "L":
        requires.append(USER_SESSION)
    elif pr == "H":
        requires.append(ADMIN_SESSION)

    facts: list[str] = []
    if m["UI"] == "R":
        facts.append("user_interaction")

    # --- postcondition from the impact metrics, strongest wins
    conf, integ = m["C"], m["I"]
    if integ == "H":
        grants = CODE_EXEC
    elif conf == "H":
        grants = DATA_READ
    elif integ == "L":
        grants = USER_SESSION
    elif conf == "L":
        grants = INFO_DISCLOSURE
    else:
        grants = NETWORK_REACH  # availability-only: no new access, still a step

    # Two or more distinct preconditions is a genuine conjunction.
    uniq = tuple(dict.fromkeys(requires))
    join = "AND" if (len(uniq) + len(facts)) > 1 else "OR"

    return Semantics(
        requires=uniq,
        grants=grants,
        join=join,
        requires_facts=tuple(facts),
        mitre=mitre,
        scope_changed=vec.scope_changed,
    )


def semantics_from_finding(finding) -> tuple[Semantics, Provenance]:
    """Precedence: observed evidence > CVSS vector > class table.

    This is the same precedence rule used for edge probability in scoring.py --
    evidence we generated on the real target outranks any published prior.
    """
    from .model import PRIVILEGES, semantics_for

    base, prov = semantics_for(finding.vuln_class)

    vec = parse(finding.cvss_vector)
    if vec is not None:
        base = derive_semantics(vec, mitre=base.mitre)
        prov = Provenance.CVSS_VECTOR

    # Only privileges the contract defines may enter the graph; an oracle that
    # reports an out-of-vocabulary privilege (e.g. a legacy "session_access")
    # falls back to the class/CVSS default rather than crashing the whole build.
    observed_requires = tuple(p for p in finding.observed_requires if p in PRIVILEGES)
    observed_grants = tuple(p for p in finding.observed_grants if p in PRIVILEGES)

    # Validator actually observed the transition -> strongest source.
    if observed_grants or observed_requires:
        base = Semantics(
            requires=observed_requires or base.requires,
            grants=observed_grants[0] if observed_grants else base.grants,
            join=base.join,
            requires_facts=base.requires_facts,
            mitre=base.mitre,
            scope_changed=base.scope_changed or finding.target_asset_id is not None,
        )
        prov = Provenance.EVIDENCE

    return base, prov
