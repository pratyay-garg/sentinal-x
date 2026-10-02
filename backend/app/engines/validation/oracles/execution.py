"""
The execution oracle -- XSS proven by execution, not reflection.

Reflection proves nothing: a payload can appear in the response encoded, in a
comment, or in an attribute where it never runs. EXECUTION proves exploitability.
We inject a benign marker that, IF it runs, sets a unique flag, then load the
response in a real browser and read the flag back:

    <script>window.__x_<nonce>=1</script>   -> is window.__x_<nonce> === 1 ?

The browser is abstracted behind the `Renderer` protocol. In production it is
Playwright (and the artifact is a screenshot); here it is a deterministic
`MockBrowser` that "executes" only a marker that lands in an executable context.
That keeps the oracle testable with no browser and lets Playwright drop in
unchanged later.

The negative control injects the nonce as PLAIN TEXT (no tags): it must NOT set
the flag, proving the detector fires on execution rather than on the mere
presence of the nonce string. The distinction between the `reflected_safe` case
(marker present, flag unset) and the vulnerable case (flag set) is the whole
point.

This oracle produces DIRECT attributable evidence -- a unique nonce ran in a
DOM, which has no other explanation -- so it is self-corroborating and observes
a real grant (user_session).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..http import Fetcher, Request
from ..writer import Candidate, OracleOutcome, Verdict, fingerprint


class Renderer(Protocol):
    def execute(self, body: str, nonce: str) -> bool:
        """True iff <script>window.__x_<nonce>=1</script> (or an equivalent
        handler) actually ran when `body` was loaded in a DOM."""
        ...


class MockBrowser:
    """Deterministic stand-in for Playwright. Executes a marker only when it
    appears in an executable context (a live script tag or an event handler),
    not when it is escaped or reflected as inert text."""
    def execute(self, body: str, nonce: str) -> bool:
        script = f"<script>window.__x_{nonce}=1</script>"
        handler = f"onerror=window.__x_{nonce}=1"
        return script in body or handler in body


def _req(endpoint, param, value):
    return Request(method="GET", url=endpoint, params=((param, value),))


@dataclass
class ExecutionResult:
    verdict: Verdict
    executed: bool = False
    reflected: bool = False
    reason: str = ""


def run_execution(fetch: Fetcher, *, asset_id: str, endpoint: str, param: str,
                  vuln_class: str = "xss_reflected",
                  renderer: Renderer | None = None,
                  nonce: str = "9f3ax") -> ExecutionResult:
    renderer = renderer or MockBrowser()
    candidate = Candidate(asset_id=asset_id, vuln_class=vuln_class,
                          endpoint=endpoint, param=param, method="GET",
                          root_cause="unescaped_output")
    ev = "exec::" + fingerprint(candidate)

    payload = f"<script>window.__x_{nonce}=1</script>"
    r = fetch(_req(endpoint, param, payload))
    executed = renderer.execute(r.body, nonce)
    reflected = f"__x_{nonce}" in r.body

    # negative control: the nonce as plain text must never execute
    ctrl = fetch(_req(endpoint, param, f"marker__x_{nonce}_plain"))
    control_clean = not renderer.execute(ctrl.body, nonce)

    def build(status, conf, fired, reason):
        outcome = OracleOutcome(oracle="execution", fired=fired,
                                effect=1.0 if executed else 0.0, detail=reason,
                                artifacts=(f"{ev}#screenshot", f"{ev}#dom"))
        v = Verdict(candidate=candidate, status=status, confidence=conf,
                    outcomes=(outcome,), evidence_id=ev)
        return ExecutionResult(verdict=v, executed=executed, reflected=reflected,
                               reason=reason)

    if not control_clean:
        return build("inconclusive", 0.40, False,
                     "the detector fired on a plain-text control; cannot trust "
                     "this endpoint's execution signal")
    if executed:
        return build("validated", 0.96, True,
                     "the injected marker executed in the DOM (window flag set); "
                     "this is exploitable XSS, not mere reflection")
    if reflected:
        return build("false_positive", 0.10, False,
                     "the marker is reflected but did NOT execute (non-executable "
                     "context); reflection is not exploitability")
    return build("false_positive", 0.08, False,
                 "the marker was neither reflected nor executed; disproved")
