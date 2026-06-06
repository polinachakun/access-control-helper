#!/usr/bin/env python3
"""
Scalability plots for the access-control-helper Alloy pipeline.

Usage:
    python3 plot.py results/triples_<ts>.csv results/dimensions_<ts>.csv
    python3 plot.py --latest          # auto-picks newest files in results/
"""

import argparse
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np
import pandas as pd
from scipy import stats

RESULTS_DIR = Path(__file__).parent / "results"
OUT_DIR = Path(__file__).parent / "results"

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "figure.dpi": 150,
})


# ── Data loading ──────────────────────────────────────────────────────────────

def load(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df[df["status"] == "ok"].copy()
    df["elapsed_s"] = df["elapsed_ms"] / 1000
    return df


def latest_file(prefix: str) -> Path:
    files = sorted(RESULTS_DIR.glob(f"{prefix}_*.csv"))
    if not files:
        sys.exit(f"No {prefix}_*.csv found in {RESULTS_DIR}")
    return files[-1]


# ── Plot 1: Triple count vs. time (main result) ───────────────────────────────

def plot_triples(df: pd.DataFrame, out: Path):
    ok = df[df["status"] == "ok"].copy()
    ok = ok.sort_values("triples")

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Left: linear scale
    ax = axes[0]
    ax.scatter(ok["triples"], ok["elapsed_s"], color="#2563eb", zorder=3, s=60)

    if len(ok) >= 3:
        z = np.polyfit(ok["triples"], ok["elapsed_s"], 2)
        xs = np.linspace(ok["triples"].min(), ok["triples"].max(), 200)
        ax.plot(xs, np.polyval(z, xs), color="#dc2626", linewidth=1.5,
                linestyle="--", label="quadratic fit")
        ax.legend()

    ax.set_xlabel("Number of triples (P × B × A)")
    ax.set_ylabel("Execution time (s)")
    ax.set_title("Alloy execution time vs. triple count")
    ax.grid(True, alpha=0.3)

    # Right: log–log scale (reveals scaling exponent)
    ax = axes[1]
    log_x = np.log10(ok["triples"])
    log_y = np.log10(ok["elapsed_s"])
    ax.scatter(ok["triples"], ok["elapsed_s"], color="#2563eb", zorder=3, s=60)
    ax.set_xscale("log")
    ax.set_yscale("log")

    if len(ok) >= 3:
        slope, intercept, r, _, _ = stats.linregress(log_x, log_y)
        xs = np.logspace(log_x.min(), log_x.max(), 200)
        ax.plot(xs, 10**intercept * xs**slope, color="#dc2626", linewidth=1.5,
                linestyle="--", label=f"slope ≈ {slope:.2f}  (R²={r**2:.2f})")
        ax.legend()
        ax.set_title(f"Log–log scale  |  scaling exponent ≈ {slope:.2f}")
    else:
        ax.set_title("Log–log scale")

    ax.set_xlabel("Number of triples (log scale)")
    ax.set_ylabel("Execution time (s, log scale)")
    ax.grid(True, which="both", alpha=0.3)

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out}")


# ── Plot 2: Dimension isolation ───────────────────────────────────────────────

def plot_dimensions(df: pd.DataFrame, out: Path):
    fig, axes = plt.subplots(1, 3, figsize=(14, 5))

    dim_map = {
        "vary_principals": ("principals", "Principals (P)", "#7c3aed"),
        "vary_buckets":    ("buckets",    "Buckets (B)",    "#0891b2"),
        "vary_actions":    ("actions",    "Actions (A)",    "#059669"),
    }

    for ax, (exp, (col, xlabel, color)) in zip(axes, dim_map.items()):
        sub = df[df["experiment"] == exp].sort_values(col)
        if sub.empty:
            ax.set_title(f"{xlabel}\n(no data)")
            continue

        ax.plot(sub[col], sub["elapsed_s"], "o-", color=color,
                linewidth=2, markersize=7)
        ax.set_xlabel(xlabel)
        ax.set_ylabel("Execution time (s)")
        ax.set_title(f"Scaling by {xlabel}")
        ax.set_xticks(sorted(sub[col].unique()))
        ax.grid(True, alpha=0.3)

        # Annotate triple count on each point
        for _, row in sub.iterrows():
            ax.annotate(f"{int(row['triples'])}t",
                        (row[col], row["elapsed_s"]),
                        textcoords="offset points", xytext=(4, 4),
                        fontsize=8, color="#6b7280")

    fig.suptitle("Execution time scaled by individual dimension\n"
                 "(other two dimensions fixed at 1)", y=1.02)
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out}")


# ── Plot 3: Heatmap P × B at fixed A ─────────────────────────────────────────

def plot_heatmap(df: pd.DataFrame, out: Path, heatmap_df: pd.DataFrame = None):
    # Prefer dedicated heatmap CSV (full grid); fall back to triples data.
    if heatmap_df is not None and not heatmap_df.empty:
        sub = heatmap_df.copy()
        fixed_a = int(sub["actions"].iloc[0])
    else:
        sub = df[df["experiment"] == "triples"].copy()
        if sub.empty:
            print("Not enough data for heatmap, skipping.")
            return
        fixed_a = int(sub["actions"].value_counts().idxmax())
        sub = sub[sub["actions"] == fixed_a]

    pivot = sub.pivot_table(index="principals", columns="buckets",
                            values="elapsed_s", aggfunc="mean")
    if pivot.empty:
        print("Heatmap pivot is empty, skipping.")
        return

    fig, ax = plt.subplots(figsize=(9, 7))
    im = ax.imshow(pivot.values, aspect="auto", cmap="YlOrRd", origin="lower")
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)
    ax.set_xlabel("Buckets (B)")
    ax.set_ylabel("Principals (P)")
    ax.set_title(f"Execution time (s) — P × B heatmap  [A={fixed_a}]")
    fig.colorbar(im, ax=ax, label="Time (s)")

    for i in range(len(pivot.index)):
        for j in range(len(pivot.columns)):
            val = pivot.values[i, j]
            if not np.isnan(val):
                color = "white" if val > pivot.values.max() * 0.6 else "black"
                ax.text(j, i, f"{val:.1f}s", ha="center", va="center",
                        fontsize=9, color=color)

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out}")


# ── Plot 4: All experiments combined overview ─────────────────────────────────

def plot_overview(triples_df: pd.DataFrame, dim_df: pd.DataFrame, out: Path):
    fig = plt.figure(figsize=(14, 10))
    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

    # Top-left: triples vs time
    ax0 = fig.add_subplot(gs[0, :2])
    ok = triples_df[triples_df["status"] == "ok"].sort_values("triples")
    ax0.scatter(ok["triples"], ok["elapsed_s"], color="#2563eb", zorder=3, s=55)
    if len(ok) >= 3:
        z = np.polyfit(ok["triples"], ok["elapsed_s"], 2)
        xs = np.linspace(ok["triples"].min(), ok["triples"].max(), 200)
        ax0.plot(xs, np.polyval(z, xs), "--", color="#dc2626", linewidth=1.5)
    ax0.set_xlabel("Triples (P × B × A)")
    ax0.set_ylabel("Time (s)")
    ax0.set_title("Execution time vs. triple count")
    ax0.grid(True, alpha=0.3)

    # Top-right: log-log
    ax1 = fig.add_subplot(gs[0, 2])
    ax1.scatter(ok["triples"], ok["elapsed_s"], color="#2563eb", zorder=3, s=45)
    ax1.set_xscale("log")
    ax1.set_yscale("log")
    if len(ok) >= 3:
        log_x = np.log10(ok["triples"])
        log_y = np.log10(ok["elapsed_s"])
        slope, intercept, r, _, _ = stats.linregress(log_x, log_y)
        xs = np.logspace(log_x.min(), log_x.max(), 200)
        ax1.plot(xs, 10**intercept * xs**slope, "--", color="#dc2626", linewidth=1.5,
                 label=f"k≈{slope:.1f}")
        ax1.legend(fontsize=9)
    ax1.set_xlabel("Triples (log)")
    ax1.set_ylabel("Time (log)")
    ax1.set_title("Log–log")
    ax1.grid(True, which="both", alpha=0.3)

    # Bottom: dimension plots
    dim_configs = [
        ("vary_principals", "principals", "Principals (P)", "#7c3aed"),
        ("vary_buckets",    "buckets",    "Buckets (B)",    "#0891b2"),
        ("vary_actions",    "actions",    "Actions (A)",    "#059669"),
    ]
    for i, (exp, col, xlabel, color) in enumerate(dim_configs):
        ax = fig.add_subplot(gs[1, i])
        sub = dim_df[dim_df["experiment"] == exp].sort_values(col)
        if sub.empty:
            continue
        ax.plot(sub[col], sub["elapsed_s"], "o-", color=color,
                linewidth=2, markersize=6)
        ax.set_xlabel(xlabel)
        ax.set_ylabel("Time (s)")
        ax.set_title(f"Vary {xlabel}")
        ax.grid(True, alpha=0.3)
        ax.set_xticks(sorted(sub[col].unique()))

    fig.suptitle("Alloy Scalability Analysis — access-control-helper",
                 fontsize=14, y=1.01)
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--latest", action="store_true",
                        help="auto-pick newest CSV files in results/")
    parser.add_argument("triples_csv", nargs="?")
    parser.add_argument("dimensions_csv", nargs="?")
    args = parser.parse_args()

    if args.latest:
        triples_path = latest_file("triples")
        dim_path = latest_file("dimensions")
    elif args.triples_csv and args.dimensions_csv:
        triples_path = Path(args.triples_csv)
        dim_path = Path(args.dimensions_csv)
    else:
        parser.print_help()
        sys.exit(1)

    print(f"Loading triples:    {triples_path}")
    print(f"Loading dimensions: {dim_path}")

    triples_df = load(triples_path)
    dim_df = load(dim_path)

    # Load dedicated heatmap CSV if available.
    heatmap_files = sorted(RESULTS_DIR.glob("heatmap_*.csv"))
    heatmap_df = load(heatmap_files[-1]) if heatmap_files else None
    if heatmap_df is not None:
        print(f"Loading heatmap:    {heatmap_files[-1]}")

    plot_triples(triples_df, OUT_DIR / "plot_triples.png")
    plot_dimensions(dim_df, OUT_DIR / "plot_dimensions.png")
    plot_heatmap(triples_df, OUT_DIR / "plot_heatmap.png", heatmap_df)
    plot_overview(triples_df, dim_df, OUT_DIR / "plot_overview.png")

    print("\nDone. Plots saved to", OUT_DIR)


if __name__ == "__main__":
    main()
