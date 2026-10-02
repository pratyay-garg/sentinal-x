"""
The evidence store + replay -- "evidence is replayable or it is not evidence"
(LAW 6).

Two jobs, one artifact:

  * FOR A JUDGE / THE DASHBOARD. Every validated finding carries a MANIFEST: the
    exact ordered transaction array (request + captured response) that proved it,
    plus the oracle, its seed, and the expected verdict. `GET /evidence/{id}`
    returns it, so clicking an edge in the attack graph opens the proof. An
    attack graph whose every edge resolves to a reproducible artifact is a
    different object from one whose edges are asserted.

  * FOR RETEST. `replay(manifest, patched_fetch)` re-runs the IDENTICAL
    experiment against the (now patched) target and returns a fresh verdict. A
    finding is `remediated` only when the same experiment that produced
    `validated` now produces `false_positive` -- the fix is proven by
    construction, not asserted.

Capture is non-invasive: a RecordingFetcher wraps the fetch the oracle already
uses and logs every call in order, so no oracle needed changing. Replay re-
invokes the oracle (captured as a closure in-session; via ORACLE_REGISTRY +
serialised kwargs across processes).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from .http import Fetcher, Request, Response
from .writer import Verdict


# --------------------------------------------------------------- capture

@dataclass
class Transaction:
    seq: int
    request: Request
    response: Response
    role: str = "probe"           # setup | exploit | verify | probe

    def as_dict(self) -> dict:
        return {
            "seq": self.seq, "role": self.role,
            "request": {"method": self.request.method, "url": self.request.url,
                        "params": [list(p) for p in self.request.params],
                        "headers": [list(h) for h in self.request.headers],
                        "body": self.request.body},
            "response": {"status": self.response.status,
                         "elapsed_ms": self.response.elapsed_ms,
                         "body_len": len(self.response.body),
                         "headers": [list(h) for h in self.response.headers],
                         "body": self.response.body},
        }


class RecordingFetcher:
    """Wraps a Fetcher and records every (request, response) in order. This IS
    the transaction array -- stateful multi-step exploits (a POST that creates an
    object, a GET that triggers it) are captured in the order the oracle issued
    them."""
    def __init__(self, inner: Fetcher):
        self._inner = inner
        self._log: list[Transaction] = []

    def __call__(self, request: Request) -> Response:
        resp = self._inner(request)
        self._log.append(Transaction(len(self._log), request, resp))
        return resp

    def transactions(self, roles: list[str] | None = None) -> list[Transaction]:
        if roles:
            for tx, role in zip(self._log, roles):
                tx.role = role
        return list(self._log)


# --------------------------------------------------------------- manifest

@dataclass
class EvidenceManifest:
    evidence_id: str
    oracle: str
    expected_status: str
    transactions: list[Transaction] = field(default_factory=list)
    kwargs: dict = field(default_factory=dict)          # serialisable descriptor
    seed: int = 1337
    created: float = field(default_factory=time.time)
    _run_fn: Callable[[Fetcher], object] | None = None  # in-session replay closure

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id, "oracle": self.oracle,
            "expected_status": self.expected_status, "seed": self.seed,
            "generated_by": "tool",
            "transactions": [t.as_dict() for t in self.transactions],
            "replay_descriptor": {"oracle": self.oracle, "kwargs": self.kwargs},
        }

    def replay(self, fetch: Fetcher, **runtime) -> Verdict:
        """Re-run the identical experiment against `fetch`. Prefers the captured
        closure; falls back to the registry + stored kwargs across processes."""
        if self._run_fn is not None and not runtime:
            return _verdict(self._run_fn(fetch))
        fn = ORACLE_REGISTRY.get(self.oracle)
        if fn is None:
            raise KeyError(f"no registered oracle {self.oracle!r} for replay")
        return _verdict(fn(fetch, **{**self.kwargs, **runtime}))


class EvidenceStore:
    """In-session store. Production swaps this for Postgres/object storage; the
    manifest.to_dict() shape is what gets persisted."""
    def __init__(self):
        self._by_id: dict[str, EvidenceManifest] = {}

    def save(self, manifest: EvidenceManifest) -> None:
        self._by_id[manifest.evidence_id] = manifest

    def get(self, evidence_id: str) -> EvidenceManifest:
        return self._by_id[evidence_id]

    def exists(self, evidence_id: str) -> bool:
        return evidence_id in self._by_id

    def __len__(self) -> int:
        return len(self._by_id)


# --------------------------------------------------------------- run + record

def _verdict(result) -> Verdict:
    return result.verdict if hasattr(result, "verdict") else result


def record_run(store: EvidenceStore, run_fn: Callable[[Fetcher], object],
               fetch: Fetcher, *, oracle: str, kwargs: dict | None = None,
               seed: int = 1337, roles: list[str] | None = None):
    """Run an oracle while capturing its transactions into a saved manifest.

    `run_fn` is a closure `lambda f: some_oracle(f, **kw)` -- it captures the
    oracle and its parameters so replay needs only a fresh fetch.
    """
    rec = RecordingFetcher(fetch)
    result = run_fn(rec)
    verdict = _verdict(result)
    manifest = EvidenceManifest(
        evidence_id=verdict.evidence_id or f"ev::{oracle}",
        oracle=oracle, expected_status=verdict.status,
        transactions=rec.transactions(roles), kwargs=kwargs or {}, seed=seed,
        _run_fn=run_fn)
    store.save(manifest)
    return result, manifest


# --------------------------------------------------------------- replay + retest

@dataclass
class RetestResult:
    evidence_id: str
    before_status: str
    after_status: str
    remediated: bool
    reason: str
    after_confidence: float = 0.0

    def as_dict(self) -> dict:
        return {"evidence_id": self.evidence_id, "before": self.before_status,
                "after": self.after_status, "remediated": self.remediated,
                "reason": self.reason,
                "after_confidence": round(self.after_confidence, 4)}


def replay(manifest: EvidenceManifest, fetch: Fetcher, **runtime) -> Verdict:
    return manifest.replay(fetch, **runtime)


def retest(store: EvidenceStore, evidence_id: str, patched_fetch: Fetcher,
           **runtime) -> RetestResult:
    """Replay the finding against the patched target. `remediated` requires the
    verdict to FLIP validated -> false_positive: the fix made the same oracle
    actively fail. Anything else is honestly reported, never assumed fixed."""
    m = store.get(evidence_id)
    after = replay(m, patched_fetch, **runtime)

    if m.expected_status != "validated":
        remediated, reason = False, (
            f"original finding was {m.expected_status}, not validated; retest "
            f"is only meaningful for a validated finding")
    elif after.status == "false_positive":
        remediated, reason = True, (
            "the identical experiment now fails: the oracle that proved the "
            "vulnerability disproves it -- the fix is verified")
    elif after.status == "validated":
        remediated, reason = False, (
            "the exploit still succeeds against the patched target; the fix did "
            "not close it")
    else:
        remediated, reason = False, (
            f"retest is {after.status} (environment interfered); the fix is not "
            f"verified either way")

    return RetestResult(evidence_id=evidence_id, before_status=m.expected_status,
                        after_status=after.status, remediated=remediated,
                        reason=reason, after_confidence=after.confidence)


# --------------------------------------------------------------- registry

# Populated lazily to avoid an import cycle (oracles import writer, not this).
ORACLE_REGISTRY: dict[str, Callable] = {}


def register_default_oracles() -> None:
    from .oracles.authz import run_authorization
    from .oracles.differential import (
        run_boolean_differential, run_expression_differential,
    )
    from .oracles.execution import run_execution
    from .oracles.oob import run_oob
    from .oracles.timing import run_timing_differential
    ORACLE_REGISTRY.update({
        "differential.boolean": run_boolean_differential,
        "differential.expression": run_expression_differential,
        "timing": run_timing_differential,
        "execution": run_execution,
        "authz": run_authorization,
        "oob": run_oob,
    })
