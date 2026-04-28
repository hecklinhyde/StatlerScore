# Generates PNG image for StatlerScore.

import warnings
warnings.filterwarnings("ignore")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patheffects as pe
import numpy as np
from matplotlib.patches import FancyBboxPatch
from matplotlib.gridspec import GridSpec
from datetime import datetime

#Palette 
TEXT    = "#FFFFFF"
MUTED   = "#CCCCCC"
PANEL   = "#111827"
BORDER  = "#374151"
GREEN   = "#22C55E"
YELLOW  = "#EAB308"
ORANGE  = "#F97316"
RED     = "#EF4444"
BLUE    = "#3B82F6"
LIME    = "#84CC16"
PURPLE  = "#A855F7"

TIER_COLORS = {
    "Resilient Posture":             GREEN,
    "Strong Posture":                LIME,
    "Stable Posture":                YELLOW,
    "Accumulating Technical Risk":   ORANGE,
    "Critical Remediation Required": RED,
}

SHADOW = [pe.withStroke(linewidth=3, foreground="#000000")]


def _overallLabel(score):
    if score >= 800: return "Resilient Posture"
    if score >= 740: return "Strong Posture"
    if score >= 670: return "Stable Posture"
    if score >= 580: return "Accumulating Technical Risk"
    return "Critical Remediation Required"


def _bandColor(score):
    """Return the gauge band color for the given score."""
    if score >= 800: return GREEN
    if score >= 740: return LIME
    if score >= 670: return YELLOW
    if score >= 580: return ORANGE
    return RED


def _gaugeAngle(score, lo=300, hi=850):
    frac = (score - lo) / (hi - lo)
    return 180 - frac * 180


def _panel(ax, x, y, w, h, alpha=0.72, radius=0.04):
    """Draw a rounded dark panel in axes-fraction coordinates."""
    rect = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0,rounding_size={radius}",
        transform=ax.transAxes,
        facecolor=PANEL, edgecolor=BORDER, linewidth=1,
        alpha=alpha, zorder=4, clip_on=False,
    )
    ax.add_patch(rect)


def _drawGauge(ax, score):
    ax.set_xlim(-1.45, 1.45)
    ax.set_ylim(-0.75, 1.3)
    ax.set_aspect("equal")
    ax.axis("off")

    # color bands
    bands = [
        (300, 579, RED),
        (580, 669, ORANGE),
        (670, 739, YELLOW),
        (740, 799, LIME),
        (800, 850, GREEN),
    ]
    r_outer, r_inner = 1.0, 0.62
    for lo, hi, color in bands:
        a_start = 180 - (hi - 300) / 550 * 180
        a_end   = 180 - (lo - 300) / 550 * 180
        theta   = np.linspace(np.radians(a_start), np.radians(a_end), 80)
        x_outer = r_outer * np.cos(theta)
        y_outer = r_outer * np.sin(theta)
        x_inner = r_inner * np.cos(theta[::-1])
        y_inner = r_inner * np.sin(theta[::-1])
        ax.fill(np.concatenate([x_outer, x_inner]),
                np.concatenate([y_outer, y_inner]),
                color=color, alpha=0.9, zorder=2)


    # tick marks & labels
    for ts, tl in zip([300, 580, 670, 740, 800, 850],
                      ["300", "580", "670", "740", "800", "850"]):
        ang = np.radians(180 - (ts - 300) / 550 * 180)
        ax.plot([1.03 * np.cos(ang), 1.10 * np.cos(ang)],
                [1.03 * np.sin(ang), 1.10 * np.sin(ang)],
                color="#555555", lw=1.5, zorder=3)
        ax.text(1.22 * np.cos(ang), 1.22 * np.sin(ang), tl,
                ha="center", va="center", fontsize=9,
                fontweight="bold", color="#333333", zorder=5)

    #needle 
       needle_ang = np.radians(_gaugeAngle(score))
    nx, ny = 0.80 * np.cos(needle_ang), 0.80 * np.sin(needle_ang)
    ax.annotate("", xy=(nx, ny), xytext=(0, 0),
                arrowprops=dict(arrowstyle="->, head_width=0.08, head_length=0.08",
                                color="#222222", lw=2.5),
                zorder=6)
    ax.add_patch(plt.Circle((0, 0), 0.06, color="#222222", zorder=7))
    ax.add_patch(plt.Circle((0, 0), 0.03, color="white",   zorder=8))

    #score display
    label = _overallLabel(score)
    color = _bandColor(score)

    ax.text(0, -0.30, str(score), ha="center", va="center",
            fontsize=52, fontweight="bold", color=color, zorder=7)

    ax.plot([-0.18, 0.18], [-0.48, -0.48], color=color, lw=2, alpha=0.6, zorder=7)

    ax.text(0, -0.58, label, ha="center", va="center",
            fontsize=10, fontweight="bold", color="#333333", zorder=7)


# ── Public API ─────────────────────────────────────────────────────────────────

def generateScoreImage(result, previousScore,
                       outPath="statler_score.png"):
    """Gauge-only image — transparent background."""
    score = result["score"]
    diff  = score - previousScore
    trend = "↑" if diff > 0 else "↓" if diff < 0 else "→"
    label = _overallLabel(score)

    fig, ax = plt.subplots(figsize=(6, 5.4))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    # leave equal padding top and bottom; text sits in the top pad
    fig.subplots_adjust(left=0.05, right=0.95, top=0.78, bottom=0.05)

    fig.text(0.5, 0.870, "Statler Score",
             ha="center", fontsize=16, fontweight="bold", color="#111111")
    fig.text(0.5, 0.835,
             f"Score: {score}  {trend} ({diff:+d} pts)   |   {label}",
             ha="center", fontsize=11, color="#555555")

    _drawGauge(ax, score)

    plt.savefig(outPath, dpi=150, bbox_inches="tight",
                facecolor="white")
    plt.close(fig)
    return outPath
