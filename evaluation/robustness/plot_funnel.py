#!/usr/bin/env python3
"""
Funnel plot for the TerraDS robustness evaluation pipeline.

Two-panel figure:
  Left  — population filtering funnel (all modules → in-scope)
  Right — analysis success rates from the in-scope population

Rates for estimated stages are derived by applying Phase 2 / Phase 3
sample success rates (n=100) to the full in-scope population (1,051 modules).

Usage:
    python3 evaluation/robustness/plot_funnel.py
    python3 evaluation/robustness/plot_funnel.py --out evaluation/robustness/results/plot_funnel.png
"""

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

RESULTS_DIR = Path(__file__).parent / "results"

# Phase 1 numbers (from SQLite analysis — fixed)
TOTAL_MODULES     = 279_344
CANDIDATE_MODULES = 5_514
IN_SCOPE_MODULES  = 1_051

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "figure.dpi": 150,
})


def load_success_rate(path: Path) -> float:
    with open(path) as f:
        data = json.load(f)
    outcomes = data.get("outcomes", {})
    total = sum(outcomes.values())
    return outcomes.get("success", 0) / total if total else 0.0


def plot_funnel(phase2_path: Path, phase3_random_path: Path,
                phase3_recent_path: Path, out_path: Path):

    parse_rate   = load_success_rate(phase2_path)
    alloy_rand   = load_success_rate(phase3_random_path)
    alloy_recent = load_success_rate(phase3_recent_path)

    parse_n  = round(IN_SCOPE_MODULES * parse_rate)
    rand_n   = round(IN_SCOPE_MODULES * alloy_rand)
    recent_n = round(IN_SCOPE_MODULES * alloy_recent)

    fig, (ax_left, ax_right) = plt.subplots(
        1, 2, figsize=(14, 6),
        gridspec_kw={"width_ratios": [1, 1]},
    )
    fig.suptitle("TerraDS Robustness Evaluation — Analysis Pipeline",
                 fontsize=13, y=1.02)

    # ── Left panel: population filtering (log bar chart) ─────────────────────
    left_labels = [
        "All TerraDS\nmodules",
        "S3 + IAM\ncandidates",
        "Fully\nin-scope",
    ]
    left_counts = [TOTAL_MODULES, CANDIDATE_MODULES, IN_SCOPE_MODULES]
    left_colors = ["#94a3b8", "#60a5fa", "#3b82f6"]
    left_pcts   = [None,
                   f"{CANDIDATE_MODULES/TOTAL_MODULES*100:.1f}% of all",
                   f"{IN_SCOPE_MODULES/CANDIDATE_MODULES*100:.1f}% of candidates"]

    ys = np.arange(len(left_labels))
    bars = ax_left.barh(ys, left_counts, color=left_colors,
                        height=0.55, zorder=3)

    ax_left.set_xscale("log")
    ax_left.set_xlim(500, 10**6.2)
    ax_left.set_yticks(ys)
    ax_left.set_yticklabels(left_labels, fontsize=10)
    ax_left.set_xlabel("Module count (log scale)")
    ax_left.set_title("Population filtering", fontsize=11)
    ax_left.grid(axis="x", which="both", alpha=0.3, zorder=0)
    ax_left.invert_yaxis()

    for bar, count, pct in zip(bars, left_counts, left_pcts):
        x_end = bar.get_width()
        ax_left.text(x_end * 1.08, bar.get_y() + bar.get_height() / 2,
                     f"{count:,}", va="center", fontsize=10, fontweight="bold")
        if pct:
            ax_left.text(x_end * 1.08, bar.get_y() + bar.get_height() / 2 + 0.22,
                         pct, va="center", fontsize=8, color="#6b7280")

    # ── Right panel: analysis success on in-scope population ─────────────────
    right_labels = [
        f"In-scope\n(baseline)",
        f"Alloy analyzed\nrandom ({alloy_rand:.0%})",
        f"Alloy analyzed\nrecent top-100 ({alloy_recent:.0%})",
    ]
    right_counts = [IN_SCOPE_MODULES, rand_n, recent_n]
    right_colors = ["#3b82f6", "#1d4ed8", "#1e3a8a"]
    right_pcts   = [None,
                    f"{rand_n/IN_SCOPE_MODULES*100:.0f}% of in-scope *",
                    f"{recent_n/IN_SCOPE_MODULES*100:.0f}% of in-scope *"]

    ys2 = np.arange(len(right_labels))
    bars2 = ax_right.barh(ys2, right_counts, color=right_colors,
                          height=0.55, zorder=3)

    ax_right.set_xlim(0, IN_SCOPE_MODULES * 1.35)
    ax_right.set_yticks(ys2)
    ax_right.set_yticklabels(right_labels, fontsize=10)
    ax_right.set_xlabel("Module count")
    ax_right.set_title("Analysis success (from in-scope population)", fontsize=11)
    ax_right.grid(axis="x", alpha=0.3, zorder=0)
    ax_right.invert_yaxis()

    for bar, count, pct in zip(bars2, right_counts, right_pcts):
        x_end = bar.get_width()
        ax_right.text(x_end + 12, bar.get_y() + bar.get_height() / 2,
                      f"{count:,}", va="center", fontsize=10, fontweight="bold")
        if pct:
            ax_right.text(x_end + 12, bar.get_y() + bar.get_height() / 2 + 0.22,
                          pct, va="center", fontsize=8, color="#6b7280")

    ax_right.axvline(IN_SCOPE_MODULES, color="#3b82f6",
                     linestyle="--", linewidth=1, alpha=0.6, zorder=2)

    fig.text(0.5, -0.04,
             "* Estimated: sample rate (n=100) applied to full in-scope population",
             ha="center", fontsize=8, color="#6b7280", style="italic")

    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight", dpi=150)
    plt.close(fig)
    print(f"Saved: {out_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(RESULTS_DIR / "plot_funnel.png"),
                        help="output PNG path")
    args = parser.parse_args()

    phase2        = RESULTS_DIR / "phase2_results.json"
    phase3_random = RESULTS_DIR / "phase3_final.json"
    phase3_recent = RESULTS_DIR / "phase3_recent100.json"

    for p in [phase2, phase3_random, phase3_recent]:
        if not p.exists():
            print(f"Missing result file: {p}")
            print("Run evaluate.py phases 2 and 3 first.")
            return

    plot_funnel(phase2, phase3_random, phase3_recent, Path(args.out))


if __name__ == "__main__":
    main()
