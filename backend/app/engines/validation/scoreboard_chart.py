#!/usr/bin/env python3
"""Render the scanner-independence scoreboard for the report. Deterministic."""
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app.engines.validation.scenario import run_scenario

out = sys.argv[1] if len(sys.argv) > 1 else "scoreboard.png"
sb, _ = run_scenario()
d = sb.as_dict()

labels = ["Nuclei\nflagged", "Engine\nconfirmed", "Engine\ndisproved",
          "Inconclusive", "Found\n(assist)"]
vals = [d["scanner_raw_findings"], d["engine_confirmed"], d["engine_disproved"],
        d["engine_inconclusive"], d["discovered_independently"]]
colors = ["#5f6368", "#1a73e8", "#d93025", "#f9ab00", "#188038"]

fig, ax = plt.subplots(figsize=(6.4, 4.6))
bars = ax.bar(labels, vals, color=colors, edgecolor="white", zorder=3)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.08, str(v), ha="center",
            va="bottom", fontweight="bold")
ax.set_ylabel("Findings")
ax.set_title("Scanner Independence — verify, don't repeat", fontsize=12, weight="bold")
ax.set_ylim(0, max(vals) + 1.2)
ax.grid(True, axis="y", color="#f1f3f4", zorder=0)
ax.text(0.5, -0.22, sb.pitch(), transform=ax.transAxes, ha="center", fontsize=8,
        color="#3c4043", wrap=True)
fig.tight_layout()
fig.savefig(out, dpi=130, bbox_inches="tight")
print(f"wrote {out}  ({sb.pitch()})")
