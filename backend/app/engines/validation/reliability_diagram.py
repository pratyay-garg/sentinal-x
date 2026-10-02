#!/usr/bin/env python3
"""Render the calibration reliability diagram for the report.

Deterministic: same corpus + seeded oracles -> identical figure every run.
Usage: python scripts/reliability_diagram.py [out.png]
"""
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app.engines.validation.adjudicate import default_calibration
from app.engines.validation.calibration import reliability, score, separation
from app.engines.validation.corpus import evaluation_corpus

out = sys.argv[1] if len(sys.argv) > 1 else "reliability.png"
cal = default_calibration()
pairs = [(score(cal, s)[1], y) for y, s in evaluation_corpus(replicas=6)]
bins, ece = reliability(pairs, n_bins=10)
sep = separation(pairs)

fig, ax = plt.subplots(figsize=(6.0, 5.4))
ax.plot([0, 1], [0, 1], "--", color="#9aa0a6", lw=1.2, label="perfect calibration")
xs = [b.mean_pred for b in bins]
ys = [b.obs_freq for b in bins]
sizes = [30 + 12 * b.count for b in bins]
ax.scatter(xs, ys, s=sizes, color="#1a73e8", alpha=0.85, edgecolor="white",
           zorder=3, label="observed (size = #findings)")
ax.axvline(0.5, color="#d93025", lw=1.0, ls=":", zorder=2)
ax.text(0.505, 0.05, "validate\nthreshold", fontsize=7, color="#d93025", va="bottom")

ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.set_xlabel("Predicted confidence")
ax.set_ylabel("Observed fraction truly vulnerable")
ax.set_title("Module 2 — Validation Confidence Reliability", fontsize=12, weight="bold")
ax.legend(loc="lower right", fontsize=8, framealpha=0.9)
ax.text(0.03, 0.97,
        f"AUC = {sep['auc']:.2f}   ECE = {ece:.2f}\n"
        f"mean(vuln) = {sep['mean_vuln']:.2f}   mean(safe) = {sep['mean_not']:.2f}\n"
        f"n = {len(pairs)} labeled findings",
        fontsize=8, va="top", ha="left",
        bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="#dadce0"))
ax.grid(True, color="#f1f3f4", zorder=0)
fig.tight_layout()
fig.savefig(out, dpi=130)
print(f"wrote {out}  (AUC={sep['auc']} ECE={ece:.3f} n={len(pairs)})")
