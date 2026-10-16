"""Architecture and attack figure for the conference paper (one 7.5 cm column, 7 pt text).

Reads results/numbers.json, so the bars show measured shares of each band's airtime (FCFS, one compliant SF7
attacker, mean over the paired seeds of E10). Writes figures/conf_architecture.png (600 dpi) and .pdf.

    python diagrams/make_conf_architecture.py
"""
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = json.load(open(os.path.join(ROOT, "results", "numbers.json"), encoding="utf8"))
E = N["E10"]["summary"]["fcfs"]["7"]
C = N["const"]

hon1, atk1 = E["hon_rx1"]["mean"], E["atk_rx1"]["mean"]
hon2, atk2 = E["hon_rx2"]["mean"], E["atk_air"]["mean"] - E["atk_rx1"]["mean"]
share1, share2 = atk1 / (hon1 + atk1), atk2 / (hon2 + atk2)
rate7 = N["E10"]["measured_ul_per_h"]["7"]["mean"]

INK, GREY, LIGHT = "#2b2b2b", "#8c8c8c", "#f3f3f1"
RED, REDF = "#b5472a", "#fbe3dc"
BLUE = "#e6eef8"
GREEN, GREENF = "#1b7f5b", "#dff2ea"
FS = 6.6

plt.rcParams.update({"font.size": FS, "font.family": ["Liberation Sans", "DejaVu Sans"]})
W_IN, H_IN = 2.9, 2.5
fig = plt.figure(figsize=(W_IN, H_IN))
ax = fig.add_axes([0, 0, 1, 1])
X1, Y1 = 100.0, 100.0 * H_IN / W_IN
ax.set_xlim(0, X1)
ax.set_ylim(0, Y1)
ax.axis("off")


def box(x0, y0, x1, y1, fc=LIGHT, ec=INK, lw=0.6, ls="-", r=1.6):
    ax.add_patch(FancyBboxPatch((x0, y0), x1 - x0, y1 - y0, boxstyle=f"round,pad=0,rounding_size={r}",
                                fc=fc, ec=ec, lw=lw, ls=ls))


def text(x, y, s, ha="center", va="center", **kw):
    ax.text(x, y, s, ha=ha, va=va, color=kw.pop("color", INK), linespacing=1.15, **kw)


def arrow(x0, y0, x1, y1, color=INK, lw=0.7):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle="-|>", color=color, lw=lw, mutation_scale=6, shrinkA=0, shrinkB=0))


# devices
top = Y1 - 0.8
box(0.6, top - 14.5, 48.4, top)
text(24.5, top - 3.4, "Honest Class A devices", weight="bold", fontsize=7)
text(24.5, top - 9.6, "critical: streetlights, water\nother: parking, waste bins")
box(51.6, top - 14.5, 99.4, top, fc=REDF, ec=RED, lw=0.9)
text(75.5, top - 3.4, "Compromised device", weight="bold", color=RED, fontsize=7)
text(75.5, top - 9.6, f"valid keys, obeys the 1% rule\n{rate7:.0f} confirmed uplinks/h at SF7")

# gateway with measured airtime shares
gt, gb = top - 21.0, top - 48.5
arrow(24.5, top - 14.5, 24.5, gt)
arrow(75.5, top - 14.5, 75.5, gt, color=RED, lw=0.9)
text(27.0, top - 17.8, "uplinks", ha="left", fontsize=6.3)
text(73.0, top - 17.8, "each asks for an ACK", ha="right", fontsize=6.3, color=RED)
box(0.6, gb, 99.4, gt, fc=BLUE)
text(50, gt - 3.3, "Shared gateway: half-duplex, deaf while sending", weight="bold", fontsize=7)
text(50, gt - 8.2, f"empty ACK: {1000 * C['ack_sf7']:.0f} ms in RX1 at SF7, {C['ack_sf12']:.2f} s in RX2 at SF12",
     fontsize=6.3)
bx0, bx1 = 33.0, 97.6
for i, (lab, sh) in enumerate([(f"RX1, 1% = {C['budget_rx1_s_per_h']:.0f} s/h", share1),
                               (f"RX2, 10% = {C['budget_rx2_s_per_h']:.0f} s/h", share2)]):
    y = gt - 14.3 - i * 7.3
    text(2.4, y, lab, ha="left")
    xa = bx0 + (bx1 - bx0) * (1 - sh)
    ax.add_patch(plt.Rectangle((bx0, y - 2.2), xa - bx0, 4.4, fc="#c9c9c6", ec="none"))
    ax.add_patch(plt.Rectangle((xa, y - 2.2), bx1 - xa, 4.4, fc=RED, ec="none"))
    ax.add_patch(plt.Rectangle((bx0, y - 2.2), bx1 - bx0, 4.4, fc="none", ec=INK, lw=0.5))
    text((bx0 + xa) / 2, y, "honest", fontsize=6.3)
    text((xa + bx1) / 2, y, f"attacker {100 * sh:.0f}%", fontsize=6.3, color="white", weight="bold")

# network server pipeline
st, sb = gb - 7.0, 0.6
arrow(14.0, gb, 14.0, st)
arrow(86.0, st, 86.0, gb)
text(16.0, gb - 3.5, "reply request", ha="left", fontsize=6.3)
text(84.0, gb - 3.5, "reply in RX1, RX2 or none", ha="right", fontsize=6.3)
box(0.6, sb, 99.4, st, fc="white", ec=GREY, ls=(0, (3, 1.5)))
text(50, st - 3.2, "Network server", weight="bold", fontsize=7)
py0, py1 = sb + 2.0, st - 6.6


def ttl(col, t, color=INK):
    text((col[0] + col[1]) / 2, py1 - 3.0, t, weight="bold", color=color, fontsize=6.6)

cols = [(2.4, 32.4), (35.0, 65.0), (67.6, 97.6)]
box(cols[0][0], py0, cols[0][1], py1, fc=GREENF, ec=GREEN, lw=0.9)
ttl(cols[0], "Per-tenant budget", GREEN)
text((cols[0][0] + cols[0][1]) / 2, (py0 + py1) / 2 - 2.0, "token bucket per\ndevice, rate h·λ$_i$\nfrom the tenant's\ndeclared profile")
box(cols[1][0], py0, cols[1][1], py1)
ttl(cols[1], "Regulatory check")
text((cols[1][0] + cols[1][1]) / 2, (py0 + py1) / 2 - 2.0, "airtime left in\nthe band over the\nlast hour, radio\nnot transmitting")
box(cols[2][0], py0, cols[2][1], py1)
ttl(cols[2], "Window")
text((cols[2][0] + cols[2][1]) / 2, (py0 + py1) / 2 - 2.0, "answer in RX1,\nelse in RX2,\nelse deny")
ym = (py0 + py1) / 2 - 2.0
arrow(cols[0][1], ym, cols[1][0], ym)
arrow(cols[1][1], ym, cols[2][0], ym)

out = os.path.join(ROOT, "figures", "conf_architecture")
fig.savefig(out + ".png", dpi=600)
fig.savefig(out + ".pdf")
print("wrote", out + ".png/.pdf", "| attacker share RX1 %.3f RX2 %.3f" % (share1, share2))
