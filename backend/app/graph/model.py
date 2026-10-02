"""
Typed attacker-state graph: the data model everything else operates on.

This is a simplified MulVAL-style logical attack graph. The key property is that
a *vulnerability is its own node*, so "patch this finding" == "delete this node".
Remediation therefore maps one-to-one onto graph operations with no interpretation
layer, which is what makes the min-cut in breakchain.py an actual patch list.

Node roles
    state  ("state", asset_id, privilege)  what the attacker holds
    vuln   ("vuln",  finding_id)           a specific patchable finding
    fact   ("fact",  kind, ref)            a non-patchable enabler
    source SUPER_SOURCE / SUPER_SINK       synthetic entry / jewel aggregators

Edge kinds
    pre      state|fact -> vuln    precondition
    post     vuln -> state         postcondition (this is the ONLY probabilistic edge)
    implies  state -> state        privilege implication, same asset, downward
    route    state -> state        network reachability, network_reach only
    entry    SUPER_SOURCE -> state
    jewel    state -> SUPER_SINK
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

# ---------------------------------------------------------------- privileges

# Deliberately a PARTIAL order, not a chain.
#
#   code_exec -> admin_session -> user_session -> network_reach -> none
#   info_disclosure -> network_reach
#   data_read       -> network_reach
#
# code_exec does NOT imply data_read: owning the web server is not owning the
# database, and modelling it as a chain invents lateral movement that does not
# exist. data_read is granted only by an explicit Vuln or Fact.

NONE = "none"
NETWORK_REACH = "network_reach"
INFO_DISCLOSURE = "info_disclosure"
USER_SESSION = "user_session"
ADMIN_SESSION = "admin_session"
CODE_EXEC = "code_exec"
DATA_READ = "data_read"

PRIVILEGES: tuple[str, ...] = (
    NONE,
    NETWORK_REACH,
    INFO_DISCLOSURE,
    USER_SESSION,
    ADMIN_SESSION,
    CODE_EXEC,
    DATA_READ,
)

# Transitive reduction of the implication DAG. (hi, lo) means "holding hi
# implies holding lo on the same asset".
PRIVILEGE_IMPLICATIONS: tuple[tuple[str, str], ...] = (
    (CODE_EXEC, ADMIN_SESSION),
    (ADMIN_SESSION, USER_SESSION),
    (USER_SESSION, NETWORK_REACH),
    (INFO_DISCLOSURE, NETWORK_REACH),
    (DATA_READ, NETWORK_REACH),
    (NETWORK_REACH, NONE),
)


def implies(hi: str, lo: str) -> bool:
    """True iff holding `hi` on an asset entails holding `lo` on that asset."""
    if hi == lo:
        return True
    seen, stack = {hi}, [hi]
    while stack:
        cur = stack.pop()
        for a, b in PRIVILEGE_IMPLICATIONS:
            if a == cur and b not in seen:
                if b == lo:
                    return True
                seen.add(b)
                stack.append(b)
    return False


# ---------------------------------------------------------------- provenance

class Provenance(str, Enum):
    """Where a graph element's semantics came from.

    Ordered strongest -> weakest. The pipeline reports the distribution, which
    is the honest answer to "how much of this graph did you hard-code?".
    """
    EVIDENCE = "evidence"        # our validator observed the transition
    CVSS_VECTOR = "cvss_vector"  # parsed from a published CVSS v3.1 vector
    OBSERVED = "observed"        # discovery saw it (open port, DNS, redirect)
    CLASS_TABLE = "class_table"  # fallback mapping for app-layer findings
    ASSUMED = "assumed"          # modelled by us, no supporting observation

    @property
    def is_derived(self) -> bool:
        """Counted in the 'not hard-coded' share of the provenance report."""
        return self in (Provenance.EVIDENCE, Provenance.CVSS_VECTOR, Provenance.OBSERVED)


PROVENANCE_RANK = {
    Provenance.EVIDENCE: 0,
    Provenance.CVSS_VECTOR: 1,
    Provenance.OBSERVED: 2,
    Provenance.CLASS_TABLE: 3,
    Provenance.ASSUMED: 4,
}

# ---------------------------------------------------------------- node ids

SUPER_SOURCE = ("meta", "SUPER_SOURCE")
SUPER_SINK = ("meta", "SUPER_SINK")


def state(asset_id: str, privilege: str) -> tuple:
    if privilege not in PRIVILEGES:
        raise ValueError(f"unknown privilege {privilege!r}")
    return ("state", asset_id, privilege)


def vuln(finding_id: str) -> tuple:
    return ("vuln", finding_id)


def fact(kind: str, ref: str) -> tuple:
    return ("fact", kind, ref)


def nid(node: tuple) -> str:
    """Stable string id for JSON export / frontend. Stable across re-renders."""
    return "|".join(str(p) for p in node)


# ---------------------------------------------------------------- input DTOs

@dataclass(frozen=True)
class Asset:
    id: str
    zone: str = "default"
    is_crown_jewel: bool = False
    criticality: int = 1          # 1..5, adjustable live in the dashboard
    hostnames: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """Flat row from the Validation module. It deliberately carries NO graph
    semantics -- the graph layer owns that mapping, so a teammate's schema
    cannot break this module."""
    id: str
    asset_id: str
    vuln_class: str
    # unvalidated | validated | false_positive | inconclusive
    # | unverifiable_safely | remediated
    #
    # `unverifiable_safely` is Module 2's fourth terminal verdict: a real class
    # with no non-destructive oracle (a deserialization gadget we refuse to
    # fire). It is NOT the same as `unvalidated` -- we have a strong prior it is
    # real, we simply declined to prove it -- so scoring.py gives it its own
    # weight above unvalidated and below evidence. See contract.VERDICTS.
    status: str = "unvalidated"
    confidence: float = 0.25
    cvss_vector: str | None = None
    epss: float | None = None
    epss_snapshot_date: str | None = None
    patch_hours: float = 1.0
    patch_group: str | None = None     # same CVE / same base image -> same group
    evidence_id: str | None = None
    endpoint: str | None = None
    param: str | None = None
    # Optional: privileges the validator actually OBSERVED being granted.
    observed_grants: tuple[str, ...] = ()
    observed_requires: tuple[str, ...] = ()
    target_asset_id: str | None = None  # set when the grant lands elsewhere (CVSS S:C)


@dataclass(frozen=True)
class Fact:
    kind: str
    ref: str
    description: str = ""
    provenance: Provenance = Provenance.ASSUMED


@dataclass(frozen=True)
class Route:
    src: str
    dst: str
    provenance: Provenance = Provenance.ASSUMED
    reason: str = ""


@dataclass
class GraphInput:
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    entries: list[str] = field(default_factory=list)   # asset ids
    # Keys present in the caller's rows that this module does not read. Silently
    # ignoring them is how `epss_score` (vs `epss`) sailed through as a clean
    # `ok` diagnosis with the EPSS data quietly dropped.
    unknown_keys: dict = field(default_factory=dict)

    def jewels(self) -> list[Asset]:
        return [a for a in self.assets if a.is_crown_jewel]


# ---------------------------------------------------------------- semantics

@dataclass(frozen=True)
class Semantics:
    requires: tuple[str, ...]
    grants: str
    join: str = "OR"                       # OR | AND
    requires_facts: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    scope_changed: bool = False            # grant lands on a different asset


# Fallback only. Used when a finding has no parseable CVSS vector -- which is
# most app-layer findings (XSS, IDOR, broken access control). When a vector IS
# present, cvss.py derives these fields instead and provenance is CVSS_VECTOR.
SEMANTICS: dict[str, Semantics] = {
    "sqli": Semantics((NETWORK_REACH,), DATA_READ, "OR", mitre=("T1190",)),
    "xss_reflected": Semantics((NETWORK_REACH,), USER_SESSION, "OR",
                               requires_facts=("user_interaction",), mitre=("T1189",)),
    "xss_stored": Semantics((NETWORK_REACH,), USER_SESSION, "OR", mitre=("T1189",)),
    "idor": Semantics((USER_SESSION,), DATA_READ, "AND",
                      requires_facts=("sequential_object_ids",), mitre=("T1190",)),
    "broken_access_control": Semantics((USER_SESSION,), ADMIN_SESSION, "OR", mitre=("T1068",)),
    "auth_bypass": Semantics((NETWORK_REACH,), ADMIN_SESSION, "OR", mitre=("T1078",)),
    "ssrf": Semantics((NETWORK_REACH,), NETWORK_REACH, "OR",
                      mitre=("T1090",), scope_changed=True),
    "rce": Semantics((NETWORK_REACH,), CODE_EXEC, "OR", mitre=("T1190",)),
    "cred_reuse": Semantics((DATA_READ,), USER_SESSION, "AND",
                            requires_facts=("shared_credential",), mitre=("T1078",)),
    "misconfig_open_service": Semantics((NETWORK_REACH,), NETWORK_REACH, "OR", mitre=("T1046",)),
    "info_leak": Semantics((NETWORK_REACH,), INFO_DISCLOSURE, "OR", mitre=("T1592",)),
    "phishing_credential": Semantics((), USER_SESSION, "AND",
                                     requires_facts=("phished_credential",), mitre=("T1566",)),

    # ---- classes Module 2's oracle suite emits -------------------------------
    # Added so a validated SSTI is not silently downgraded to DEFAULT_SEMANTICS
    # (grants info_disclosure, provenance ASSUMED), which both breaks the attack
    # path and drags down the published derived_fraction. contract.py pins
    # M2_EMITTED_CLASSES as a subset of these keys, so adding an oracle without
    # adding its semantics is a red build.
    "ssti": Semantics((NETWORK_REACH,), CODE_EXEC, "OR", mitre=("T1190",)),
    "lfi": Semantics((NETWORK_REACH,), DATA_READ, "OR", mitre=("T1083",)),
    # XXE and SSRF are both server-side fetch primitives: the read can land on a
    # different asset, so scope_changed lets target_asset_id apply. With no
    # target_asset_id, build.py falls back to the finding's own asset.
    "xxe": Semantics((NETWORK_REACH,), DATA_READ, "OR", mitre=("T1190",),
                     scope_changed=True),
    "file_upload_rce": Semantics((NETWORK_REACH,), CODE_EXEC, "OR", mitre=("T1190",)),
    "deserialization": Semantics((NETWORK_REACH,), CODE_EXEC, "OR", mitre=("T1190",)),
    # Both need a victim to act, so the Fact is a genuine second precondition --
    # and it is the same Fact(user_interaction) that CVSS UI:R produces, which
    # is where the phishing module attaches.
    "open_redirect": Semantics((NETWORK_REACH,), NETWORK_REACH, "AND",
                               requires_facts=("user_interaction",), mitre=("T1204",)),
    "csrf": Semantics((NETWORK_REACH,), USER_SESSION, "AND",
                      requires_facts=("user_interaction",), mitre=("T1204",)),
}

DEFAULT_SEMANTICS = Semantics((NETWORK_REACH,), INFO_DISCLOSURE, "OR")


def semantics_for(vuln_class: str) -> tuple[Semantics, Provenance]:
    if vuln_class in SEMANTICS:
        return SEMANTICS[vuln_class], Provenance.CLASS_TABLE
    return DEFAULT_SEMANTICS, Provenance.ASSUMED


def node_type(node: tuple) -> str:
    return node[0]


def is_patchable(g, node: tuple) -> bool:
    """Only vuln nodes are patchable. State/Fact/meta get infinite cut cost."""
    return node_type(node) == "vuln"


def iter_vulns(g) -> Iterable[tuple]:
    return (n for n in g.nodes if node_type(n) == "vuln")
