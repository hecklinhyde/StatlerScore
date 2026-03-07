"""
Generates PNG images for a Cloud Credit Score attestation.

Produces two separate transparent-background files:
  - cloud_credit_score.png   : gauge + score + tier label
  - cloud_credit_pillars.png : pillar breakdown bars + key factors
"""

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

# ── Palette ────────────────────────────────────────────────────────────────────
TEXT    = "#FFFFFF"
MUTED   = "#CCCCCC"
PANEL   = "#111827"      # dark background for text panels
BORDER  = "#374151"
GREEN   = "#22C55E"
YELLOW  = "#EAB308"
ORANGE  = "#F97316"
RED     = "#EF4444"
BLUE    = "#3B82F6"
PURPLE  = "#A855F7"

TIER_COLORS = {
    "Exceptional": GREEN,
    "Very Good":   BLUE,
    "Good":        BLUE,
    "Fair":        YELLOW,
    "Poor":        RED,
}

PILLAR_COLORS = [BLUE, PURPLE, GREEN, ORANGE]

# Shadow effect applied to all labels for readability on any background
SHADOW = [pe.withStroke(linewidth=3, foreground="#000000")]


def _overallLabel(score):
    if score >= 800: return "Exceptional"
    if score >= 740: return "Very Good"
    if score >= 670: return "Good"
    if score >= 580: return "Fair"
    return "Poor"


def _bandColor(score):
    """Return the gauge band color for the given score."""
    if score >= 800: return GREEN
    if score >= 740: return BLUE
    if score >= 670: return YELLOW
    if score >= 580: return ORANGE
    return RED


def _pillarLabel(pct):
    if pct >= 80: return ("Strong",   GREEN)
    if pct >= 60: return ("Fair",     YELLOW)
    if pct >= 40: return ("At Risk",  ORANGE)
    return              ("Critical",  RED)


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

    # ── colour bands ─────────────────────────────────────────────────────────
    bands = [
        (300, 579, RED),
        (580, 669, ORANGE),
        (670, 739, YELLOW),
        (740, 799, BLUE),
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

    # ── tick marks & labels (dark for white background) ──────────────────────
    for ts, tl in zip([300, 580, 670, 740, 800, 850],
                      ["300", "580", "670", "740", "800", "850"]):
        ang = np.radians(180 - (ts - 300) / 550 * 180)
        ax.plot([1.03 * np.cos(ang), 1.10 * np.cos(ang)],
                [1.03 * np.sin(ang), 1.10 * np.sin(ang)],
                color="#555555", lw=1.5, zorder=3)
        ax.text(1.22 * np.cos(ang), 1.22 * np.sin(ang), tl,
                ha="center", va="center", fontsize=9,
                fontweight="bold", color="#333333", zorder=5)

    # ── needle ───────────────────────────────────────────────────────────────
    needle_ang = np.radians(_gaugeAngle(score))
    nx, ny = 0.80 * np.cos(needle_ang), 0.80 * np.sin(needle_ang)
    ax.annotate("", xy=(nx, ny), xytext=(0, 0),
                arrowprops=dict(arrowstyle="->, head_width=0.08, head_length=0.08",
                                color="#222222", lw=2.5),
                zorder=6)
    ax.add_patch(plt.Circle((0, 0), 0.06, color="#222222", zorder=7))
    ax.add_patch(plt.Circle((0, 0), 0.03, color="white",   zorder=8))

    # ── score display — below the arc, clear of the needle ───────────────────
    label = _overallLabel(score)
    color = _bandColor(score)

    ax.text(0, -0.30, str(score), ha="center", va="center",
            fontsize=52, fontweight="bold", color=color, zorder=7)

    ax.plot([-0.18, 0.18], [-0.48, -0.48], color=color, lw=2, alpha=0.6, zorder=7)

    ax.text(0, -0.58, label, ha="center", va="center",
            fontsize=13, fontweight="bold", color="#333333", zorder=7)


def _drawPillars(ax, pillars):
    ax.patch.set_alpha(0)
    for spine in ax.spines.values():
        spine.set_edgecolor(BORDER)
        spine.set_linewidth(1.2)
    ax.tick_params(colors=TEXT, labelsize=11)

    # Separate rated vs N/A pillars; sort rated ascending (lowest bar at bottom)
    rated = {k: v for k, v in pillars.items() if v is not None}
    na    = [k for k, v in pillars.items() if v is None]

    names = list(rated.keys())
    pcts  = list(rated.values())
    order  = sorted(range(len(pcts)), key=lambda i: pcts[i])
    names  = [names[i]  for i in order]
    pcts   = [pcts[i]   for i in order]
    colors = [PILLAR_COLORS[i % len(PILLAR_COLORS)] for i in order]

    y    = np.arange(len(names))
    ax.barh(y, [100] * len(names), color="#1F2937", height=0.6, zorder=1)
    bars = ax.barh(y, pcts,        color=colors,    height=0.6, alpha=0.9, zorder=2)

    ax.set_xlim(0, 128)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=12, color=TEXT, fontweight="bold")
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"], fontsize=9, color=MUTED)
    ax.axvline(50, color=MUTED,  lw=1,   ls="--", alpha=0.5, zorder=3)
    ax.axvline(80, color=GREEN,  lw=1,   ls="--", alpha=0.5, zorder=3)

    title = ax.set_title("Pillar Breakdown", color=TEXT, fontsize=13,
                         fontweight="bold", pad=10)
    title.set_path_effects(SHADOW)

    for lbl in ax.get_yticklabels():
        lbl.set_path_effects(SHADOW)

    for bar, pct in zip(bars, pcts):
        lbl, lcolor = _pillarLabel(pct)
        t = ax.text(pct + 1.5, bar.get_y() + bar.get_height() / 2,
                    f"{pct}%  {lbl}", va="center", fontsize=11,
                    color=lcolor, fontweight="bold")
        t.set_path_effects(SHADOW)

    if na:
        note = ax.text(0.5, -0.18, f"Not rated (no services in use): {', '.join(na)}",
                       transform=ax.transAxes, ha="center", fontsize=9, color=MUTED)
        note.set_path_effects(SHADOW)


def _drawFactors(ax, factors, title, color, icon):
    ax.axis("off")
    ax.patch.set_alpha(0)

    items = factors[:8]
    row_h = 0.108
    panel_top    = 0.98
    panel_bottom = panel_top - row_h * (len(items) + 1.4)

    # dark panel behind the whole section
    _panel(ax, -0.02, panel_bottom, 1.04, panel_top - panel_bottom, alpha=0.75)

    # section title
    t = ax.text(0.02, panel_top - 0.04, f"{icon}  {title}",
                transform=ax.transAxes,
                fontsize=11, fontweight="bold", color=color, va="top", zorder=5)
    t.set_path_effects(SHADOW)

    for i, f in enumerate(items):
        y = panel_top - 0.14 - i * row_h

        # alternating row tint
        if i % 2 == 0:
            ax.add_patch(FancyBboxPatch(
                (-0.02, y - 0.03), 1.04, row_h,
                boxstyle="square,pad=0",
                transform=ax.transAxes,
                facecolor="#1F2937", alpha=0.5,
                zorder=4, clip_on=False,
            ))

        t1 = ax.text(0.02, y, f["check"], transform=ax.transAxes,
                     fontsize=9.5, color=TEXT, va="center", zorder=5)
        t2 = ax.text(0.68, y, f"[{f['pillar']}]", transform=ax.transAxes,
                     fontsize=8.5, color=MUTED, va="center", ha="left", zorder=5)
        t3 = ax.text(0.99, y, f"{f['score']:.0%}", transform=ax.transAxes,
                     fontsize=10, color=color, va="center", ha="right",
                     fontweight="bold", zorder=5)
        for t in (t1, t2, t3):
            t.set_path_effects(SHADOW)


# ── Public API ─────────────────────────────────────────────────────────────────

def generateScoreImage(result, previousScore,
                       outPath="cloud_credit_score.png"):
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


def generatePillarImage(result, previousScore,
                        outPath="cloud_credit_pillars.png"):
    """Pillar breakdown + key factors — transparent background."""
    pillars = result["pillars"]
    factors = result.get("factors", {})
    ts      = result.get("timestamp", datetime.utcnow().isoformat())[:19].replace("T", "  ")

    fig = plt.figure(figsize=(14, 9))
    fig.patch.set_alpha(0)
    fig.subplots_adjust(left=0.16, right=0.97, top=0.89, bottom=0.05,
                        hspace=0.55, wspace=0.38)

    gs = GridSpec(2, 2, figure=fig, height_ratios=[1, 1.1])

    t1 = fig.text(0.5, 0.955, "AWS Cloud Security Posture  —  Pillar Detail",
                  ha="center", fontsize=14, fontweight="bold", color="white")
    t2 = fig.text(0.5, 0.928, f"{ts} UTC",
                  ha="center", fontsize=10, color=MUTED)
    for t in (t1, t2):
        t.set_path_effects(SHADOW)

    ax_pillars = fig.add_subplot(gs[0, :])
    ax_pillars.set_facecolor("none")
    _drawPillars(ax_pillars, pillars)

    ax_hurt = fig.add_subplot(gs[1, 0])
    ax_hurt.set_facecolor("none")
    _drawFactors(ax_hurt, factors.get("hurting", []),
                 "Issues Hurting Your Score", RED, "▼")

    ax_help = fig.add_subplot(gs[1, 1])
    ax_help.set_facecolor("none")
    _drawFactors(ax_help, factors.get("helping", []),
                 "Strengths", GREEN, "▲")

    if "attestation_id" in result:
        t3 = fig.text(0.03, 0.01,
                      f"Attestation: {result['attestation_id']}   |   "
                      f"Verdict: {result['verdict']}",
                      fontsize=8, color=MUTED)
        t3.set_path_effects(SHADOW)

    plt.savefig(outPath, dpi=150, bbox_inches="tight",
                transparent=True, facecolor="none")
    plt.close(fig)
    return outPath
