"""
Scanner-independence -- the proof that this engine is an instrument, not a
rubber stamp over Nuclei. Two directions:

  1. REJECT HALLUCINATIONS. Route every scanner finding through the oracles and
     adjudicate. Count how many the engine DISPROVED. Scanners are tuned toward
     false positives; a 500 on a quote becomes "CRITICAL SQLi". We put the
     disproved count front and centre.
  2. CATCH MISSES (assist mode). Run oracles on endpoints the scanner never
     flagged. A validated finding there is one the engine discovered on its own
     -- Nuclei does not understand multi-user authorization, so an IDOR is the
     classic miss.

The scoreboard turns both into one line a judge remembers:
    "Nuclei flagged N; we disproved D with reproducible experiments, confirmed
     C, and found X it missed. We verify -- we do not repeat."
"""
from __future__ import annotations

from dataclasses import dataclass


def _status(x) -> str:
    v = x.verdict if hasattr(x, "verdict") else x
    return v.status


@dataclass
class Scoreboard:
    raw_findings: int = 0
    confirmed: int = 0            # validated among scanner findings
    disproved: int = 0           # false_positive among scanner findings
    inconclusive: int = 0
    unmappable: int = 0          # templates outside the vuln_class enum
    discovered: int = 0          # validated in assist mode (scanner missed these)

    def as_dict(self) -> dict:
        return {
            "scanner_raw_findings": self.raw_findings,
            "engine_confirmed": self.confirmed,
            "engine_disproved": self.disproved,
            "engine_inconclusive": self.inconclusive,
            "unmappable_templates": self.unmappable,
            "discovered_independently": self.discovered,
            "false_positive_rate": (round(self.disproved / self.raw_findings, 3)
                                    if self.raw_findings else 0.0),
        }

    def pitch(self) -> str:
        return (f"Nuclei flagged {self.raw_findings}; we independently disproved "
                f"{self.disproved} with reproducible experiments, confirmed "
                f"{self.confirmed}, and found {self.discovered} it missed. "
                f"We verify -- we do not repeat.")


def build_scoreboard(scanner_results, assist_results=(), *,
                     unmappable: int = 0) -> Scoreboard:
    """scanner_results / assist_results: adjudicated verdicts (or results)."""
    sb = Scoreboard(raw_findings=len(scanner_results) + unmappable,
                    unmappable=unmappable)
    for r in scanner_results:
        s = _status(r)
        if s == "validated":
            sb.confirmed += 1
        elif s == "false_positive":
            sb.disproved += 1
        else:
            sb.inconclusive += 1
    sb.discovered = sum(1 for r in assist_results if _status(r) == "validated")
    return sb
