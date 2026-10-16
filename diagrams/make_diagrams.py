"""Architecture, attack timeline and DLGuard flowchart for the paper."""
import os
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, Rectangle  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(ROOT, "figures")
HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(FIG, exist_ok=True)

ARCH = r'''
digraph G {
  graph [rankdir=TB, fontname="Times-Roman", fontsize=8, nodesep=0.12, ranksep=0.22, pad=0.02, dpi=300];
  node  [fontname="Times-Roman", fontsize=8, shape=box, style="rounded,filled", fillcolor="#f4f4f2", color="#4a4a46", penwidth=0.7, margin="0.05,0.02"];
  edge  [fontname="Times-Roman", fontsize=7, color="#4a4a46", arrowsize=0.45, penwidth=0.7];

  hon [label="Honest Class A devices\ncritical: streetlights, water sensors\nother: parking, waste bins"];
  atk [label="Compromised device\n(valid keys of a tenant)", fillcolor="#fbe1d6", color="#b3471d", penwidth=1.2];
  gw  [label="Shared gateway (half-duplex)\nRX1 band 1% = 36 s/h\nRX2 band 10% = 360 s/h", fillcolor="#e6eef9"];
  subgraph cluster_ns {
    label="Network server"; fontsize=8; color="#9a9a94"; style="rounded,dashed"; margin=6;
    mac [label="MAC layer:\nACKs, MAC answers"];
    dlg [label="DLGuard\nbucket | share | detector", fillcolor="#dff3ea", color="#14805a", penwidth=1.1];
  }
  js  [label="Join\nserver"];
  as  [label="Tenant app\nservers"];
  soc [label="City SOC"];

  hon -> gw [label=" uplinks"];
  atk -> gw [color="#b3471d", penwidth=1.1, fontcolor="#b3471d", label=" downlink-\n forcing frames"];
  gw -> mac [dir=both, label=" backhaul"];
  mac -> dlg [label=" request"];
  dlg -> gw [label="grant RX1/RX2\nor deny", style=dashed, constraint=false];
  mac -> js [dir=both];
  mac -> as [dir=both];
  dlg -> soc [label=" alert", style=dashed];
  {rank=same; hon; atk;}
  {rank=same; js; as; soc;}
}
'''

FLOW = r'''
digraph F {
  graph [rankdir=TB, fontname="Times-Roman", fontsize=8, nodesep=0.15, ranksep=0.13, pad=0.02, dpi=300];
  node  [fontname="Times-Roman", fontsize=8, shape=box, style="rounded,filled", fillcolor="#f4f4f2", color="#4a4a46", penwidth=0.7, margin="0.05,0.02"];
  edge  [fontname="Times-Roman", fontsize=7, color="#4a4a46", arrowsize=0.45, penwidth=0.7];

  s   [label="Uplink needs a downlink\n(ACK, MAC answer, command)", fillcolor="#e6eef9"];
  obs [label="Count request for device d"];
  q   [label="d quarantined and request\nis MAC-only or a join?", style="filled,bold", fillcolor="#ffffff"];
  b   [label="Bucket of d has a token?", style="filled,bold", fillcolor="#ffffff"];
  r   [label="Window W = RX1, then RX2:\nregulatory budget left\nand gateway idle?", style="filled,bold", fillcolor="#ffffff"];
  sh  [label="Tenant under its share, or\nborrowing allowed for its class?", style="filled,bold", fillcolor="#ffffff"];
  g   [label="Grant in W\nspend 1 token", fillcolor="#dff3ea", color="#14805a"];
  n   [label="Deny", fillcolor="#fbe1d6", color="#b3471d"];
  win [label="Every 10 min: count > max(mu_k + theta sigma_k, 1)\nin 2 windows in a row -> quarantine, alert SOC", fillcolor="#fff4d6", color="#a07000"];

  s -> obs -> q;
  q -> b [label=" no"];
  b -> r [label=" yes"];
  r -> sh [label=" yes"];
  sh -> g [label=" yes"];
  q -> n [label="yes"];
  b -> n [label="no"];
  r -> n [label="no, for both\nwindows"];
  sh -> r [label="no: try RX2", style=dashed, constraint=false];
  g -> win [style=invis];
  {rank=same; sh; n;}
}
'''


def dot(src, name):
    path = os.path.join(HERE, name + ".dot")
    with open(path, "w") as f:
        f.write(src)
    subprocess.run(["dot", "-Tpng", path, "-o", os.path.join(FIG, name + ".png")], check=True)


def timeline():
    """Class A exchanges: the attacker's downlink makes the gateway deaf and uses up its budget."""
    plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Liberation Serif"],
                         "font.size": 7})
    fig, ax = plt.subplots(figsize=(3.45, 1.95))
    lanes = {"Attacker": 2.0, "Gateway": 1.0, "Honest": 0.0}
    for lab, y in lanes.items():
        ax.hlines(y, 0, 12, color="#c9c9c4", lw=0.6)
        ax.text(-0.2, y, lab, ha="right", va="center", fontsize=7)
    h = 0.34

    def box(x0, x1, y, fc, ec, txt="", tc="black"):
        ax.add_patch(Rectangle((x0, y - h / 2), x1 - x0, h, fc=fc, ec=ec, lw=0.7))
        if txt:
            ax.text((x0 + x1) / 2, y, txt, ha="center", va="center", fontsize=6.5, color=tc)

    red, redf = "#b3471d", "#fbe1d6"
    grn, grnf = "#14805a", "#dff3ea"
    blu, blud = "#2a78d6", "#1c5cab"
    # round 1
    box(0.3, 1.8, 2.0, redf, red, "UL")
    ax.text(1.05, 2.33, "confirmed", ha="center", fontsize=6)
    box(2.8, 4.1, 2.0, "#f4f4f2", "#4a4a46", "RX1")
    box(2.8, 4.1, 1.0, blu, blud, "ACK", "white")
    ax.annotate("", xy=(2.8, 1.55), xytext=(1.8, 1.55), arrowprops=dict(arrowstyle="<->", lw=0.6, color="#4a4a46"))
    ax.text(2.3, 1.62, "1 s", ha="center", va="bottom", fontsize=6)
    box(2.3, 3.6, 0.0, grnf, grn, "UL")
    ax.plot([2.95], [0.0], marker="x", color=red, ms=8, mew=1.5)
    ax.text(2.95, -0.42, "lost: gateway transmitting", ha="center", fontsize=6, color=red)
    # round 2
    box(5.2, 6.7, 2.0, redf, red, "UL")
    ax.text(5.95, 2.33, "confirmed", ha="center", fontsize=6)
    box(7.7, 9.0, 1.0, blu, blud, "ACK", "white")
    ax.text(8.35, 1.3, "budget now spent", ha="center", va="bottom", fontsize=6, color="#4a4a46")
    box(5.5, 7.0, 0.0, grnf, grn, "UL")
    ax.text(6.25, 0.33, "confirmed", ha="center", fontsize=6)
    box(8.0, 8.9, 0.0, "#f4f4f2", "#4a4a46", "RX1")
    box(9.0, 9.9, 0.0, "#f4f4f2", "#4a4a46", "RX2")
    ax.text(9.0, -0.42, "no ACK, device retransmits", ha="center", fontsize=6, color=red)
    ax.annotate("", xy=(11.6, 0.0), xytext=(10.1, 0.0), arrowprops=dict(arrowstyle="->", lw=0.8, color="#4a4a46"))
    ax.text(12.0, 2.0, "time", ha="right", va="bottom", fontsize=6, color="#4a4a46")
    ax.set_xlim(-1.6, 12.1)
    ax.set_ylim(-0.65, 2.55)
    ax.axis("off")
    fig.savefig(os.path.join(FIG, "fig_timeline.png"), dpi=300, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


if __name__ == "__main__":
    dot(ARCH, "fig_architecture")
    dot(FLOW, "fig_flowchart")
    timeline()
    print("diagrams written")
