#!/usr/bin/env python3
"""
Funnel pipeline figure for the TerraDS robustness evaluation.

Usage:
    python3 evaluation/robustness/plot_pipeline.py
    python3 evaluation/robustness/plot_pipeline.py --out path/to/out.png
"""

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import Polygon

RESULTS_DIR = Path(__file__).parent / "results"

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "figure.dpi": 150,
})

C_GRAY  = "#94a3b8"
C_BLUE1 = "#60a5fa"
C_BLUE2 = "#3b82f6"
C_BLUE3 = "#1d4ed8"
C_BLUE4 = "#1e3a8a"
C_EDGE  = "#1e293b"
C_LABEL = "#64748b"
C_ARROW = "#334155"


def load_json(path):
    if path.exists():
        return json.loads(path.read_text())
    return None


def success_count(data):
    outcomes = data.get("outcomes", {})
    total    = sum(outcomes.values())
    return outcomes.get("success", 0), total


def fw(y, y_top, y_bot, w_top, w_bot):
    """Width of the funnel at height y (linear interpolation)."""
    t = (y - y_bot) / (y_top - y_bot)
    return w_bot + t * (w_top - w_bot)


def funnel_section(ax, cx, y_top, y_bot, w_top, w_bot, color, lines, fs=10):
    verts = [
        (cx - w_top / 2, y_top), (cx + w_top / 2, y_top),
        (cx + w_bot / 2, y_bot), (cx - w_bot / 2, y_bot),
    ]
    ax.add_patch(Polygon(verts, closed=True,
                         facecolor=color, edgecolor="none", zorder=3))
    # top & bottom edges only — sides are shared with neighbours
    ax.plot([cx - w_top / 2, cx + w_top / 2], [y_top, y_top],
            color=C_EDGE, lw=1.0, zorder=4)
    ax.plot([cx - w_bot / 2, cx + w_bot / 2], [y_bot, y_bot],
            color=C_EDGE, lw=1.0, zorder=4)
    ax.text(cx, (y_top + y_bot) / 2, "\n".join(lines),
            ha="center", va="center", color="white",
            fontsize=fs, linespacing=1.6, zorder=5)


def funnel_sides(ax, cx, y_top, y_bot, w_top, w_bot, ls="-"):
    ax.plot([cx - w_top / 2, cx - w_bot / 2], [y_top, y_bot],
            color=C_EDGE if ls == "-" else C_GRAY,
            lw=1.0, linestyle=ls, zorder=2)
    ax.plot([cx + w_top / 2, cx + w_bot / 2], [y_top, y_bot],
            color=C_EDGE if ls == "-" else C_GRAY,
            lw=1.0, linestyle=ls, zorder=2)


def result_box(ax, cx, cy, w, h, color, lines, fs=9):
    ax.add_patch(mpatches.FancyBboxPatch(
        (cx - w / 2, cy - h / 2), w, h,
        boxstyle="round,pad=0.015",
        facecolor=color, edgecolor=C_EDGE, lw=1.0, zorder=3,
    ))
    ax.text(cx, cy, "\n".join(lines),
            ha="center", va="center", color="white",
            fontsize=fs, linespacing=1.6, zorder=4)


def main(out_path):
    p1     = load_json(RESULTS_DIR / "phase1_results.json")
    p3rand = load_json(RESULTS_DIR / "phase3_final.json")
    p3rec  = load_json(RESULTS_DIR / "phase3_recent100.json")

    total      = p1["total_modules"]     if p1 else 279_344
    cands      = p1["candidate_modules"] if p1 else 5_514
    in_scope   = p1["in_scope_count"]   if p1 else 1_051
    cand_pct   = round(100 * cands    / total,  1)
    scope_pct  = round(100 * in_scope / cands,  1)

    rand_ok, rand_n = success_count(p3rand) if p3rand else (89, 100)
    rec_ok,  rec_n  = success_count(p3rec)  if p3rec  else (98, 100)
    rand_pct = round(100 * rand_ok / rand_n)
    rec_pct  = round(100 * rec_ok  / rec_n)

    fig, ax = plt.subplots(figsize=(7.5, 7.0))
    ax.set_xlim(0, 1)
    ax.set_ylim(0.32, 1)
    ax.axis("off")

    CX = 0.5

    # ── Funnel geometry ────────────────────────────────────────────────────────
    # All three funnel sections share the SAME two side lines →
    # gives a smooth narrowing funnel shape.
    #
    # Total funnel span (including gaps):
    FY_TOP = 0.93   # top of section 1
    FY_BOT = 0.38   # bottom of section 3
    FW_TOP = 0.82
    FW_BOT = 0.26

    def W(y):
        return fw(y, FY_TOP, FY_BOT, FW_TOP, FW_BOT)

    # Section boundaries
    S1_TOP, S1_BOT = 0.93, 0.77
    S2_TOP, S2_BOT = 0.71, 0.57
    S3_TOP, S3_BOT = 0.51, 0.38

    # Gaps between sections (dashed sides visible here)
    funnel_sides(ax, CX, S1_BOT, S2_TOP, W(S1_BOT), W(S2_TOP), ls="--")
    funnel_sides(ax, CX, S2_BOT, S3_TOP, W(S2_BOT), W(S3_TOP), ls="--")

    # Section 1 — all modules
    funnel_section(ax, CX, S1_TOP, S1_BOT, W(S1_TOP), W(S1_BOT),
                   C_GRAY,
                   ["All TerraDS modules", f"{total:,}"],
                   fs=10)
    funnel_sides(ax, CX, S1_TOP, S1_BOT, W(S1_TOP), W(S1_BOT))

    # Section 2 — S3 + IAM candidates
    funnel_section(ax, CX, S2_TOP, S2_BOT, W(S2_TOP), W(S2_BOT),
                   C_BLUE1,
                   ["S3 + IAM candidates",
                    f"{cands:,}   ({cand_pct}% of all modules)"],
                   fs=10)
    funnel_sides(ax, CX, S2_TOP, S2_BOT, W(S2_TOP), W(S2_BOT))

    # Section 3 — in-scope
    funnel_section(ax, CX, S3_TOP, S3_BOT, W(S3_TOP), W(S3_BOT),
                   C_BLUE2,
                   ["In-scope modules",
                    f"{in_scope:,}   ({scope_pct}% of candidates)"],
                   fs=10)
    funnel_sides(ax, CX, S3_TOP, S3_BOT, W(S3_TOP), W(S3_BOT))

    # ── Filter labels in gaps ─────────────────────────────────────────────────
    for y_mid, txt in [
        ((S1_BOT + S2_TOP) / 2, "filter: S3 bucket + IAM principal"),
        ((S2_BOT + S3_TOP) / 2, "filter: only supported resource types"),
    ]:
        ax.text(CX, y_mid, txt,
                ha="center", va="center",
                fontsize=8.5, color=C_LABEL, style="italic", zorder=6,
                bbox=dict(facecolor="white", edgecolor="none", pad=3))


    # ── Title & footnote ──────────────────────────────────────────────────────
    ax.text(0.5, 0.995,
            "TerraDS Robustness Evaluation — Analysis Pipeline",
            ha="center", va="top",
            fontsize=11, fontweight="bold",
            transform=ax.transAxes)
    ax.text(0.5, 0.005,
            "Filters applied to TerraDS metadata (SQLite) — "
            "no Terraform files extracted at the filtering stage.",
            ha="center", va="bottom",
            fontsize=7.5, color=C_LABEL, style="italic",
            transform=ax.transAxes)

    fig.tight_layout(pad=0)
    fig.savefig(out_path, bbox_inches="tight", dpi=150)
    plt.close(fig)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(RESULTS_DIR / "plot_pipeline.png"))
    args = parser.parse_args()
    main(Path(args.out))
