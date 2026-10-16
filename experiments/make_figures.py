"""Builds every result figure and results/numbers.json (every number quoted in the paper) from results/*.json.

Statistics: means with 95% t-intervals over seeds. Because runs with the same seed share
honest traffic, differences between two configurations are computed per seed (paired) and
reported as mean difference with a 95% t-interval; "sig" is False when that interval contains 0.
"""
import json
import math
import os
import statistics as st
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from scipy import stats  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys  # noqa: E402
sys.path.insert(0, ROOT)
RES = os.path.join(ROOT, "results")
FIG = os.path.join(ROOT, "figures")
os.makedirs(FIG, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "font.size": 8, "axes.labelsize": 8, "legend.fontsize": 6.5, "xtick.labelsize": 7, "ytick.labelsize": 7,
    "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.6,
    "axes.grid": True, "grid.color": "#e3e3e0", "grid.linewidth": 0.5, "lines.linewidth": 1.3,
    "savefig.dpi": 300, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})
# categorical slots in fixed order, validated for CVD separation; markers and line styles carry identity too
COL = {"fcfs": "#2a78d6", "ratelimit": "#eb6834", "tenantcap": "#eda100", "dccheck": "#e87ba4", "dlguard": "#1baf7a"}
MK = {"fcfs": "o", "ratelimit": "s", "tenantcap": "D", "dccheck": "v", "dlguard": "^"}
LS = {"fcfs": "-", "ratelimit": "--", "tenantcap": ":", "dccheck": (0, (5, 1, 1, 1)), "dlguard": "-."}
NAME = {"fcfs": "FCFS", "ratelimit": "Uniform rate limit", "tenantcap": "Tenant cap", "dccheck": "DC check",
        "dlguard": "DLGuard"}
W1 = 3.4
NUM = {}


# ------------------------------------------------------------------ helpers
def load(n):
    with open(os.path.join(RES, f"{n}.json")) as f:
        return json.load(f)


def clean(x):
    if isinstance(x, float):
        return None if math.isnan(x) else round(x, 6)
    if isinstance(x, dict):
        return {str(k): clean(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [clean(v) for v in x]
    return x


def metric(r, m):
    g = r["gw_airtime"]
    if m == "atk_air":
        return g.get("attacker_rx1", 0) + g.get("attacker_rx2", 0)
    if m == "atk_rx1":
        return g.get("attacker_rx1", 0)
    if m == "hon_rx1":
        return g.get("honest_rx1", 0)
    if m == "hon_rx2":
        return g.get("honest_rx2", 0)
    if m == "rx1_util":
        return (g.get("honest_rx1", 0) + g.get("attacker_rx1", 0)) / 36.0
    if m == "hon_rx1_util":
        return g.get("honest_rx1", 0) / 36.0
    if m.startswith("pt:"):                      # per-tenant metric, "pt:water:pdr"
        _, tn, k = m.split(":")
        return r["per_tenant"][tn][k]
    if m == "detect_delay_min":
        dd = r.get("detect_delay") or []
        return st.mean(dd) / 60 if dd else None
    v = r.get(m)
    return v


def valid(v):
    return isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v))


def mci(xs):
    xs = [x for x in xs if valid(x)]
    n = len(xs)
    if n == 0:
        return {"mean": None, "ci": None, "n": 0}
    mu = st.mean(xs)
    ci = stats.t.ppf(0.975, n - 1) * st.stdev(xs) / math.sqrt(n) if n > 1 else 0.0
    return {"mean": mu, "ci": ci, "n": n}


def by(rows, keyf):
    g = defaultdict(dict)
    for r in rows:
        k = keyf(r["key"])
        g[k][r["key"][0]] = r          # seed -> run
    return g


def summarize(group, metrics):
    return {m: mci([metric(r, m) for r in group.values()]) for m in metrics}


def paired(ga, gb, m):
    """mean of (a - b) over seeds present in both, with 95% CI and a significance flag."""
    seeds = sorted(set(ga) & set(gb))
    d = [metric(ga[s], m) - metric(gb[s], m) for s in seeds if valid(metric(ga[s], m)) and valid(metric(gb[s], m))]
    out = mci(d)
    out["sig"] = bool(out["n"] > 1 and out["ci"] is not None and abs(out["mean"]) > out["ci"])
    return out


MAIN = ["ack_within_60s", "ack_ratio_critical", "ul_pdr_honest", "deaf_loss_frac", "ul_coll_frac", "dl_grant_honest",
        "atk_air", "atk_rx1", "hon_rx1", "hon_rx2", "rx1_util", "hon_rx1_util", "cmd_latency_median",
        "conf_latency_mean", "tx_per_conf_msg", "ul_tx_atk_per_h", "dl_req_atk_per_h", "dl_sent_atk_per_h",
        "detected", "false_quarantine", "false_quarantine_critical", "detect_delay_min", "crit_conf_dropped_busy",
        "dc_flagged_attackers", "dc_flagged_honest", "pt:water:charge_mas_per_delivered", "pt:streetlight:pdr",
        "pt:water:pdr", "pt:parking:pdr", "pt:waste:pdr", "pt:streetlight:dl_req_per_dev_h",
        "pt:water:dl_req_per_dev_h", "pt:parking:dl_req_per_dev_h", "pt:waste:dl_req_per_dev_h"]


def err(ax, xs, s, sc, m, scale=1.0, label=None):
    ys = [s[x][m]["mean"] * scale if s[x][m]["mean"] is not None else float("nan") for x in xs]
    es = [s[x][m]["ci"] * scale if s[x][m]["ci"] is not None else 0 for x in xs]
    ax.errorbar(range(len(xs)), ys, yerr=es, color=COL[sc], marker=MK[sc], ls=LS[sc], ms=3.5, capsize=2,
                elinewidth=0.6, label=label or NAME[sc])


def finish(fig, name):
    fig.savefig(os.path.join(FIG, name + ".png"))
    plt.close(fig)


SCHEMES = ["fcfs", "ratelimit", "tenantcap", "dccheck", "dlguard"]


# ------------------------------------------------------------------ E1 compliant swarm
def e1():
    rows = load("E1_attackers")
    g = by(rows, lambda k: (k[1], k[2]))
    ks = [0, 1, 2, 4, 8, 16, 32]
    S = {sc: {k: summarize(g[(sc, k)], MAIN) for k in ks} for sc in SCHEMES}
    D = {sc: {k: {m: paired(g[(sc, k)], g[(sc, 0)], m) for m in ["ack_within_60s", "ul_pdr_honest", "dl_grant_honest",
                                                                  "deaf_loss_frac", "hon_rx1", "pt:water:charge_mas_per_delivered"]}
              for k in ks[1:]} for sc in SCHEMES}
    V = {k: {m: paired(g[("dlguard", k)], g[("tenantcap", k)], m) for m in ["ack_within_60s", "ul_pdr_honest", "atk_air",
                                                                              "dl_grant_honest"]} for k in ks}
    NUM["E1"] = {"summary": S, "vs_noattack": D, "dlguard_minus_tenantcap": V}
    fig, axs = plt.subplots(2, 1, figsize=(W1, 3.5), sharex=True)
    for sc in ["fcfs", "ratelimit", "tenantcap", "dlguard"]:
        err(axs[0], ks, S[sc], sc, "hon_rx1")
        err(axs[1], ks, S[sc], sc, "ack_within_60s", 100)
    axs[0].axhline(36, color="#6b6b66", lw=0.8, ls=":")
    axs[0].text(0.0, 36.6, "RX1 band budget, 36 s/h", fontsize=6.3, color="#4a4a46")
    axs[0].set_ylim(0, 40)
    axs[0].set_ylabel("Honest RX1 airtime (s/h)")
    axs[1].set_ylabel("Critical ACKs within 60 s (%)")
    axs[1].set_xticks(range(len(ks)), [str(k) for k in ks])
    axs[1].set_xlabel("Compromised parking sensors (duty-cycle compliant, SF12)")
    axs[1].legend(frameon=False, loc="lower left", ncol=2)
    finish(fig, "fig_swarm")


# ------------------------------------------------------------------ E2 one non-compliant device
def e2():
    rows = load("E2_intensity")
    g = by(rows, lambda k: (k[1], k[2]))
    ivs = [0, 120, 60, 30, 15, 10, 5]
    S = {sc: {iv: summarize(g[(sc, iv)], MAIN) for iv in ivs} for sc in SCHEMES}
    rate = {iv: mci([r["ul_tx_atk_per_h"] for sc in SCHEMES for r in g[(sc, iv)].values()]) for iv in ivs[1:]}
    req = {iv: mci([r["dl_req_atk_per_h"] for r in g[("fcfs", iv)].values()]) for iv in ivs[1:]}
    D = {sc: {iv: {m: paired(g[(sc, iv)], g[(sc, 0)], m) for m in ["ack_within_60s", "ul_pdr_honest", "dl_grant_honest",
                                                                     "deaf_loss_frac", "pt:water:charge_mas_per_delivered"]}
              for iv in ivs[1:]} for sc in SCHEMES}
    NUM["E2"] = {"summary": S, "measured_ul_per_h": rate, "measured_dl_req_per_h_fcfs": req, "vs_noattack": D,
                 "dlguard_minus_tenantcap": {iv: {m: paired(g[("dlguard", iv)], g[("tenantcap", iv)], m)
                                                  for m in ["ack_within_60s", "ul_pdr_honest"]} for iv in ivs[1:]}}
    xs = ivs[1:]
    labels = [f"{rate[iv]['mean']:.0f}" for iv in xs]
    fig, axs = plt.subplots(2, 1, figsize=(W1, 3.6), sharex=True)
    for ax, m, yl in [(axs[0], "ack_within_60s", "Critical ACKs within 60 s (%)"),
                      (axs[1], "ul_pdr_honest", "Honest uplink PDR (%)")]:
        for sc in SCHEMES:
            err(ax, xs, S[sc], sc, m, 100)
        b = S["fcfs"][0][m]["mean"] * 100
        ax.axhline(b, color="#6b6b66", lw=0.8, ls=":", label="No attack")
        ax.set_ylabel(yl)
    axs[1].set_xticks(range(len(xs)), labels)
    axs[1].set_xlabel("Measured attacker uplinks per hour (one non-compliant device)")
    axs[0].legend(ncol=2, frameon=False, loc="lower left")
    finish(fig, "fig_intensity")


# ------------------------------------------------------------------ E3 network size
def e3():
    rows = load("E3_size")
    g = by(rows, lambda k: (k[1], k[2], k[3]))
    ns = [250, 500, 1000, 1500, 2000, 3000]
    sch = ["fcfs", "ratelimit", "tenantcap", "dlguard"]
    S = {sc: {n: {k: summarize(g[(sc, n, k)], MAIN) for k in [0, 1]} for n in ns} for sc in sch}
    D = {sc: {n: {m: paired(g[(sc, n, 1)], g[(sc, n, 0)], m) for m in ["ack_within_60s", "deaf_loss_frac",
                                                                        "dl_grant_honest"]} for n in ns} for sc in sch}
    NUM["E3"] = {"summary": S, "vs_noattack": D}
    fig, axs = plt.subplots(2, 1, figsize=(W1, 3.5), sharex=True)
    for ax, m, yl in [(axs[0], "deaf_loss_frac", "Honest uplinks lost while\ngateway transmits (%)"),
                      (axs[1], "dl_grant_honest", "Honest downlink requests\ngranted (%)")]:
        ys = [S["fcfs"][n][0][m]["mean"] * 100 for n in ns]
        ax.plot(range(len(ns)), ys, color="#6b6b66", ls=":", marker="x", ms=4, label="No attack (FCFS)")
        for sc in sch:
            mu = [S[sc][n][1][m]["mean"] * 100 for n in ns]
            ci = [S[sc][n][1][m]["ci"] * 100 for n in ns]
            ax.errorbar(range(len(ns)), mu, yerr=ci, color=COL[sc], marker=MK[sc], ls=LS[sc], ms=3.5, capsize=2,
                        elinewidth=0.6, label=NAME[sc])
        ax.set_ylabel(yl)
    axs[1].set_xticks(range(len(ns)), [str(n) for n in ns])
    axs[1].set_xlabel("Devices in the cell (one non-compliant attacker, 10 s target gap)")
    axs[1].legend(frameon=False, fontsize=6.3, loc="lower left")
    finish(fig, "fig_size")


# ------------------------------------------------------------------ E5 time series, mean over seeds
def e5():
    rows = load("E5_timeseries")
    fig, axs = plt.subplots(2, 1, figsize=(W1, 3.3), sharex=True)
    out = {}
    for sc in ["fcfs", "tenantcap", "dlguard"]:
        runs = [r for r in rows if r["key"][1] == sc]
        bins = sorted({int(b) for r in runs for b in r["timeseries"]["ul_tx_hon"]})
        x = [(b + 0.5) * 10 / 60 for b in bins]
        atk = [[r["timeseries"].get("gw_attacker", {}).get(str(b), 0) / 600 * 100 for r in runs] for b in bins]
        pdr = [[100 * r["timeseries"]["ul_rx_hon"].get(str(b), 0) / max(1, r["timeseries"]["ul_tx_hon"][str(b)])
                for r in runs] for b in bins]
        for ax, data in [(axs[0], atk), (axs[1], pdr)]:
            m = [mci(v) for v in data]
            mu = [v["mean"] for v in m]
            lo = [v["mean"] - v["ci"] for v in m]
            hi = [v["mean"] + v["ci"] for v in m]
            ax.plot(x, mu, color=COL[sc], ls=LS[sc], label=NAME[sc])
            ax.fill_between(x, lo, hi, color=COL[sc], alpha=0.18, lw=0)
        out[sc] = {"n_runs": len(runs)}
    for ax in axs:
        ax.axvline(1.5, color="#6b6b66", lw=0.8, ls=":")
    axs[0].set_ylabel("Gateway time on\nattacker downlinks (%)")
    axs[1].set_ylabel("Honest uplink PDR (%)")
    axs[1].set_xlabel("Time (h); attack starts at 1.5 h")
    axs[0].legend(frameon=False, loc="upper left")
    NUM["E5"] = out
    finish(fig, "fig_timeseries")


# ------------------------------------------------------------------ E6 detector on unmitigated traces
def detector_eval(r, theta=4.0, consecutive=2, min_count=1.0, sigma_floor=0.25, t_attack=5400.0,
                  t_train=(900.0, 5400.0)):
    tenant_of = {int(k): v for k, v in r["tenant_of"].items()}
    atk = set(r["attackers"])
    trace = [(t, {int(k): v for k, v in c.items()}) for t, c in r["trace"]]
    train = defaultdict(list)
    for t, c in trace:
        if t_train[0] < t <= t_train[1] + 1e-6:
            for d, tn in tenant_of.items():
                train[tn].append(c.get(d, 0.0))
    fit = {}
    for tn, xs in train.items():
        mu = sum(xs) / len(xs)
        sd = math.sqrt(sum((x - mu) ** 2 for x in xs) / (len(xs) - 1))
        fit[tn] = (mu, max(sd, sigma_floor))
    over = defaultdict(int)
    flagged = {}
    for t, c in trace:
        if t <= t_train[1]:
            continue
        for d, tn in tenant_of.items():
            if d in flagged:
                continue
            mu, sd = fit[tn]
            if c.get(d, 0.0) > max(mu + theta * sd, min_count):
                over[d] += 1
                if over[d] >= consecutive:
                    flagged[d] = t - t_attack
            else:
                over[d] = 0
    tp = [d for d in flagged if d in atk]
    fp = [d for d in flagged if d not in atk]
    return len(tp) / len(atk), len(fp) / (len(tenant_of) - len(atk)), [flagged[d] for d in tp]


def e6():
    rows = load("E6_detector")
    out = {}
    for lab in ["compliant SF12", "1 frame / 2 min", "1 frame / 5 min", "1 frame / 10 min"]:
        tp, fp, dl, rate = [], [], [], []
        for r in rows:
            if r["key"][1] != lab:
                continue
            a, b, d = detector_eval(r)
            tp.append(a)
            fp.append(b)
            dl += d
            rate.append(r["dl_req_atk_per_h"])
        out[lab] = {"tpr_pct": 100 * st.mean(tp), "fpr_pct": 100 * st.mean(fp), "n_attackers": 4 * len(tp),
                    "delay_mean_min": st.mean(dl) / 60 if dl else None, "delay_min_min": min(dl) / 60 if dl else None,
                    "delay_max_min": max(dl) / 60 if dl else None, "atk_dl_req_per_h": st.mean(rate)}
    NUM["E6"] = out


# ------------------------------------------------------------------ E7 strategies
def e7():
    rows = load("E7_strategy")
    g = by(rows, lambda k: (k[1], k[2]))
    names = sorted({k[1] for k in g})
    S = {name: {sc: summarize(g[(sc, name)], MAIN) for sc in SCHEMES} for name in names}
    NUM["E7"] = S


# ------------------------------------------------------------------ E10 one compliant attacker at each SF
def e10():
    rows = load("E10_compliant_sf")
    g = by(rows, lambda k: (k[1], k[2]))
    sfs = [7, 8, 9, 10, 11, 12]
    base = by(load("E1_attackers"), lambda k: (k[1], k[2]))
    S = {sc: {sf: summarize(g[(sc, sf)], MAIN) for sf in sfs} for sc in SCHEMES}
    D = {sc: {sf: {m: paired(g[(sc, sf)], base[(sc, 0)], m) for m in ["ack_within_60s", "ul_pdr_honest",
                                                                       "dl_grant_honest", "deaf_loss_frac",
                                                                       "pt:water:charge_mas_per_delivered"]}
              for sf in sfs} for sc in SCHEMES}
    rate = {sf: mci([r["ul_tx_atk_per_h"] for r in g[("fcfs", sf)].values()]) for sf in sfs}
    req = {sf: mci([r["dl_req_atk_per_h"] for r in g[("fcfs", sf)].values()]) for sf in sfs}
    NUM["E10"] = {"summary": S, "vs_noattack": D, "measured_ul_per_h": rate, "measured_dl_req_per_h_fcfs": req}
    fig, axs = plt.subplots(2, 1, figsize=(W1, 3.5), sharex=True)
    for ax, m, yl in [(axs[0], "ack_within_60s", "Critical ACKs within 60 s (%)"),
                      (axs[1], "dl_grant_honest", "Honest downlink requests\ngranted (%)")]:
        for sc in ["fcfs", "ratelimit", "tenantcap", "dccheck", "dlguard"]:
            err(ax, sfs, S[sc], sc, m, 100)
        b = base[("fcfs", 0)]
        ax.axhline(mci([metric(r, m) for r in b.values()])["mean"] * 100, color="#6b6b66", lw=0.8, ls=":",
                   label="No attack")
        ax.set_ylabel(yl)
    axs[1].set_xticks(range(len(sfs)), [f"SF{sf}\n{rate[sf]['mean']:.0f}/h" for sf in sfs])
    axs[1].set_xlabel("Spreading factor and measured uplinks per hour of one compliant attacker")
    axs[0].legend(ncol=2, frameon=False, loc="lower right")
    finish(fig, "fig_compliant_sf")


# ------------------------------------------------------------------ E8 ablation (paired)
def e8():
    rows = load("E8_ablation")
    g = by(rows, lambda k: k[1])
    names = ["FCFS", "Bucket only", "Reserve only", "Detector only", "Full DLGuard"]
    ms = ["ack_within_60s", "ul_pdr_honest", "deaf_loss_frac", "atk_air", "hon_rx1", "detected", "false_quarantine",
          "dl_grant_honest"]
    S = {n: summarize(g[n], ms) for n in names}
    vs_full = {n: {m: paired(g[n], g["Full DLGuard"], m) for m in ms[:5]} for n in names if n != "Full DLGuard"}
    NUM["E8"] = {"summary": S, "minus_full": vs_full}


# ------------------------------------------------------------------ E9 low-and-slow critical insiders
def e9():
    rows = load("E9_lowslow")
    g = by(rows, lambda k: (k[1], k[2]))
    ivs = [3600, 1800, 900, 600, 300, 120]
    sch = ["fcfs", "ratelimit", "tenantcap", "dlguard"]
    S = {sc: {iv: summarize(g[(sc, iv)], MAIN) for iv in ivs} for sc in sch}
    req = {iv: mci([r["dl_req_atk_per_h"] for r in g[("fcfs", iv)].values()]) for iv in ivs}
    ul = {iv: mci([r["ul_tx_atk_per_h"] for r in g[("fcfs", iv)].values()]) for iv in ivs}
    NUM["E9"] = {"summary": S, "atk_dl_req_per_h_fcfs": req, "atk_ul_per_h_fcfs": ul}
    fig, ax = plt.subplots(figsize=(W1, 2.1))
    for sc in sch:
        err(ax, ivs, S[sc], sc, "atk_air")
    ax.set_xticks(range(len(ivs)), [f"{ul[iv]['mean']:.1f}" for iv in ivs])
    ax.set_xlabel("Measured uplinks per hour per insider (8 compromised streetlight controllers)")
    ax.set_ylabel("Attacker downlink\nairtime (s/h)")
    ax.legend(frameon=False, loc="upper left")
    finish(fig, "fig_lowslow")


# ------------------------------------------------------------------ X1 poisoning
def x1():
    rows = load("X1_poisoning")
    g = by(rows, lambda k: (k[1], k[2]))
    out = {}
    for (k, start), grp in sorted(g.items()):
        det = [r["detected"] / k for r in grp.values()]
        thr = defaultdict(list)
        for r in grp.values():
            for tn, v in r["detector_thresholds"].items():
                thr[tn].append(v["threshold"])
        out[f"{k}|{int(start)}"] = {"detected_frac": mci(det), "detect_delay_min": mci([metric(r, "detect_delay_min")
                                                                                       for r in grp.values()]),
                                    "false_quarantine": mci([r["false_quarantine"] for r in grp.values()]),
                                    "false_quarantine_critical": mci([r["false_quarantine_critical"] for r in grp.values()]),
                                    "ack_within_60s": mci([r["ack_within_60s"] for r in grp.values()]),
                                    "atk_air": mci([metric(r, "atk_air") for r in grp.values()]),
                                    "threshold_parking": mci(thr["parking"]),
                                    "frac_runs_any_detected": sum(1 for r in grp.values() if r["detected"] > 0) / len(grp)}
    NUM["X1"] = out


# ------------------------------------------------------------------ X2 collateral quarantine of honest critical devices
def x2():
    out = {}

    def add(label, rows, sel):
        v = [r["false_quarantine_critical"] for r in rows if sel(r["key"]) and "false_quarantine_critical" in r]
        a = [r["false_quarantine"] for r in rows if sel(r["key"]) and "false_quarantine" in r]
        if v:
            out[label] = {"critical_mean": st.mean(v), "critical_max": max(v), "all_mean": st.mean(a),
                          "runs_with_any_critical": sum(1 for x in v if x > 0), "runs": len(v)}
    e1r = load("E1_attackers")
    for k in [0, 1, 4, 16, 32]:
        add(f"E1 k={k}", e1r, lambda key, k=k: key[1] == "dlguard" and key[2] == k)
    e2r = load("E2_intensity")
    for iv in [10, 5]:
        add(f"E2 gap={iv}s", e2r, lambda key, iv=iv: key[1] == "dlguard" and key[2] == iv)
    e3r = load("E3_size")
    for n in [1000, 2000, 3000]:
        for k in [0, 1]:
            add(f"E3 n={n} k={k}", e3r, lambda key, n=n, k=k: key[1] == "dlguard" and key[2] == n and key[3] == k)
    e7r = load("E7_strategy")
    add("E7 critical insider", e7r, lambda key: key[1] == "dlguard" and key[2] == "Critical insider")
    e9r = load("E9_lowslow")
    for iv in [3600, 600, 120]:
        add(f"E9 gap={iv}s", e9r, lambda key, iv=iv: key[1] == "dlguard" and key[2] == iv)
    x1r = load("X1_poisoning")
    for k in [16, 32]:
        add(f"X1 k={k} start=0", x1r, lambda key, k=k: key[1] == k and key[2] == 0.0)
    NUM["X2"] = out


# ------------------------------------------------------------------ X3 sensitivity
def x3():
    rows = load("X3_sensitivity")
    g = by(rows, lambda k: (k[1], k[2], k[3]))
    variants = ["base", "rx2_sf9", "low_load", "small_cell"]
    points = ["no attack", "2 compliant", "8 compliant", "32 compliant", "1 at 10 s", "1 at 5 s"]
    ms = ["ack_within_60s", "ul_pdr_honest", "dl_grant_honest", "atk_air", "hon_rx1", "hon_rx1_util", "deaf_loss_frac"]
    S = {v: {p: {sc: summarize(g[(v, p, sc)], ms) for sc in SCHEMES} for p in points} for v in variants}
    D = {v: {p: {sc: {m: paired(g[(v, p, sc)], g[(v, "no attack", sc)], m) for m in ["ack_within_60s", "ul_pdr_honest"]}
                 for sc in SCHEMES} for p in points[1:]} for v in variants}
    sfmix = {v: {sf: st.mean(r["sf_mix"][sf] for r in g[(v, "no attack", "fcfs")].values()) for sf in
                 ["7", "8", "9", "10", "11", "12"]} for v in variants}
    NUM["X3"] = {"summary": S, "vs_noattack": D, "sf_mix": sfmix}


def x3b():
    rows = load("X3b_compliant_sf")
    g = by(rows, lambda k: (k[1], k[2], k[3]))
    out = {}
    for v in ["base", "rx2_sf9", "low_load", "small_cell"]:
        out[v] = {}
        for sf in [7, 9]:
            out[v][sf] = {sc: {m: paired(g[(v, sf, sc)], g[(v, 0, sc)], m) for m in ["ack_within_60s", "ul_pdr_honest",
                                                                                     "dl_grant_honest"]}
                          for sc in SCHEMES}
            out[v][sf]["ul_per_h"] = mci([r["ul_tx_atk_per_h"] for r in g[(v, sf, "fcfs")].values()])
    NUM["X3b"] = out


# ------------------------------------------------------------------ E11 RX2 policy and uplink-rate baselines
E11_SC = ["fcfs", "ratelimit", "dccheck", "norx2spill", "rx1only", "uplinkrate", "tenantcap", "dlguard"]
SCN = ["none", "sf7", "k16", "k32"]
BASE_MS = ["ack_within_60s", "ack_ratio_critical", "ul_pdr_honest", "dl_grant_honest", "atk_air", "hon_rx1", "hon_rx2",
           "dl_sent_atk_per_h", "dc_flagged_attackers", "dc_flagged_honest", "false_quarantine",
           "false_quarantine_critical", "cmd_delivered_frac", "rx1_util"]


def e11():
    g = by(load("E11_baselines"), lambda k: (k[1], k[2]))
    S = {sc: {n: summarize(g[(sc, n)], BASE_MS) for n in SCN} for sc in E11_SC}
    vs_none = {sc: {n: {m: paired(g[(sc, n)], g[(sc, "none")], m) for m in ["ack_within_60s", "dl_grant_honest"]}
                    for n in SCN[1:]} for sc in E11_SC}
    # every scheme against FCFS without attack: the cost of the policy itself plus the attack
    vs_fcfs0 = {sc: {n: {m: paired(g[(sc, n)], g[("fcfs", "none")], m) for m in ["ack_within_60s", "dl_grant_honest",
                                                                               "cmd_delivered_frac"]}
                     for n in SCN} for sc in E11_SC}
    # uplink-rate check: share of attackers flagged and honest devices flagged per run
    n_atk = {"none": 0, "sf7": 1, "k16": 16, "k32": 32}
    det = {}
    for n in SCN:
        rs = list(g[("uplinkrate", n)].values())
        det[n] = {"attackers_flagged_frac": mci([r["dc_flagged_attackers"] / n_atk[n] for r in rs]) if n_atk[n] else None,
                  "honest_flagged": mci([r["dc_flagged_honest"] for r in rs]),
                  "honest_flagged_frac": mci([r["dc_flagged_honest"] / (1000 - n_atk[n]) for r in rs]),
                  "runs_with_honest_flagged": sum(1 for r in rs if r["dc_flagged_honest"] > 0), "runs": len(rs)}
    # share of attacker uplinks the server received (each received confirmed uplink is one downlink request)
    rx = {n: mci([r["raw"]["dl_req_atk"] / r["raw"]["ul_tx_atk"] for r in g[("fcfs", n)].values()]) for n in SCN[1:]}
    NUM["E11"] = {"atk_ul_received_frac_fcfs": rx, "summary": S, "vs_noattack": vs_none, "vs_fcfs_noattack": vs_fcfs0, "uplinkrate_detection": det}


# ------------------------------------------------------------------ E12 SF7 attacker placed near the gateway
def e12():
    g = by(load("E12_placement"), lambda k: (k[1], k[2]))
    base = by(load("E11_baselines"), lambda k: (k[1], k[2]))
    scs = SCHEMES + ["norx2spill", "uplinkrate"]
    S = {sc: summarize(g[(sc, 50.0)], BASE_MS + ["ul_tx_atk_per_h", "dl_req_atk_per_h"]) for sc in scs}
    D = {sc: {m: paired(g[(sc, 50.0)], base[(sc, "none")], m) for m in ["ack_within_60s", "dl_grant_honest"]}
         for sc in scs if (sc, "none") in base}
    D["ratelimit"] = {m: paired(g[("ratelimit", 50.0)], by(load("E1_attackers"), lambda k: (k[1], k[2]))[("ratelimit", 0)], m)
                      for m in ["ack_within_60s", "dl_grant_honest"]}
    D["dccheck"] = {m: paired(g[("dccheck", 50.0)], by(load("E1_attackers"), lambda k: (k[1], k[2]))[("dccheck", 0)], m)
                    for m in ["ack_within_60s", "dl_grant_honest"]}
    # compare with the attacker drawn from devices that already reach SF7 (E10, FCFS)
    e10 = by(load("E10_compliant_sf"), lambda k: (k[1], k[2]))
    vs_sampled = {m: paired(g[("fcfs", 50.0)], e10[("fcfs", 7)], m) for m in ["ack_within_60s", "dl_grant_honest"]}
    NUM["E12"] = {"distance_m": 50.0, "summary": S, "vs_noattack": D, "fcfs_placed_minus_sampled": vs_sampled}


# ------------------------------------------------------------------ E13 bucket headroom x burst sweep
def e13():
    g = by(load("E13_bucket"), lambda k: (k[1], k[2], k[3], k[4]))
    out = {}
    for sc in ["tenantcap", "dlguard"]:
        out[sc] = {}
        for h in [2, 4, 8]:
            for b in [1, 3, 5]:
                cell = {}
                for n in SCN:
                    rs = g[(sc, h, b, n)]
                    cell[n] = {"atk_air": mci([metric(r, "atk_air") for r in rs.values()]),
                               "ack_within_60s": mci([metric(r, "ack_within_60s") for r in rs.values()]),
                               "honest_denied": mci([1 - r["dl_grant_honest"] for r in rs.values()]),
                               "false_quarantine": mci([r.get("false_quarantine", 0) or 0 for r in rs.values()]),
                               "false_quarantine_critical": mci([r.get("false_quarantine_critical", 0) or 0
                                                                 for r in rs.values()])}
                    if n != "none":
                        cell[n]["ack60_minus_noattack"] = paired(rs, g[(sc, h, b, "none")], "ack_within_60s")
                out[sc][f"h{h}_b{b}"] = cell
    NUM["E13"] = out


# ------------------------------------------------------------------ E14 uplink-rate threshold, E15 RX2 preference
def e14():
    g = by(load("E14_uplink_k"), lambda k: (k[1], k[2]))
    base = by(load("E11_baselines"), lambda k: (k[1], k[2]))
    n_atk = {"none": 0, "sf7": 1, "k32": 32}
    out = {}
    for k in [2, 3, 4]:
        out[k] = {}
        for n in ["none", "sf7", "k32"]:
            rs = list(g[(k, n)].values())
            out[k][n] = {"ack_within_60s": mci([r["ack_within_60s"] for r in rs]),
                         "dl_grant_honest": mci([r["dl_grant_honest"] for r in rs]),
                         "attackers_flagged": mci([r["dc_flagged_attackers"] for r in rs]) if n_atk[n] else None,
                         "honest_flagged": mci([r["dc_flagged_honest"] for r in rs]),
                         "runs_with_honest_flagged": sum(1 for r in rs if r["dc_flagged_honest"] > 0), "runs": len(rs),
                         "ack60_minus_tenantcap": paired(g[(k, n)], base[("tenantcap", n)], "ack_within_60s")}
    NUM["E14"] = out
    g = by(load("E15_rx2prefer"), lambda k: (k[1], k[2]))
    NUM["E15"] = {n: {m: mci([metric(r, m) for r in g[("rx2prefer", n)].values()])
                      for m in ["ack_within_60s", "dl_grant_honest", "atk_air"]} | {
                      "minus_fcfs": paired(g[("rx2prefer", n)], base[("fcfs", n)], "ack_within_60s"),
                      "minus_own_noattack": paired(g[("rx2prefer", n)], g[("rx2prefer", "none")], "ack_within_60s")}
                  for n in ["none", "sf7", "k32"]}


# ------------------------------------------------------------------ E16 several SF7 attackers vs single-knob settings
E16_SC = ["fcfs", "dccheck", "rx2prefer", "uplinkrate", "ratelimit", "tenantcap", "dlguard"]


def e16():
    g = by(load("E16_multi_sf7"), lambda k: (k[1], k[2]))
    out = {}
    for sc in E16_SC:
        out[sc] = {}
        for n in [0, 1, 2, 3, 4]:
            rs = g[(sc, n)]
            out[sc][n] = {m: mci([metric(r, m) for r in rs.values()])
                          for m in ["ack_within_60s", "dl_grant_honest", "atk_air", "hon_rx1"]}
            out[sc][n]["minus_noattack"] = paired(rs, g[(sc, 0)], "ack_within_60s")
            out[sc][n]["minus_tenantcap"] = paired(rs, g[("tenantcap", n)], "ack_within_60s")
            if sc == "uplinkrate":
                out[sc][n]["attackers_flagged"] = mci([r["dc_flagged_attackers"] for r in rs.values()]) if n else None
                out[sc][n]["honest_flagged"] = mci([r["dc_flagged_honest"] for r in rs.values()])
    NUM["E16"] = {"uplink_k": 3.0, **out}



def e17():
    """Several gateways (Oct. 16): G1, G2, G3 and G3dense, four schedulers, four scenarios, 20 paired seeds."""
    g = by(load("E17_multigw"), lambda k: (k[1], k[2], k[3]))
    out = {}
    for gw in ["G1", "G2", "G3", "G3dense"]:
        out[gw] = {"heard_mean": mci([r.get("n_gateways_heard_mean", 1.0) for r in g[("fcfs", gw, "none")].values()])}
        for sc in ["fcfs", "uplinkrate", "ratelimit", "tenantcap"]:
            out[gw][sc] = {}
            for n in ["none", "sf7", "sf7x2", "k32"]:
                rs = g[(sc, gw, n)]
                o = {"ack_within_60s": mci([r["ack_within_60s"] for r in rs.values()]),
                     "minus_noattack": paired(rs, g[(sc, gw, "none")], "ack_within_60s"),
                     "minus_tenantcap": paired(rs, g[("tenantcap", gw, n)], "ack_within_60s")}
                if gw != "G1":
                    o["ack60_attacker_cells"] = mci([r.get("ack60_attacker_cells", float("nan")) for r in rs.values()])
                    o["ack60_other_cells"] = mci([r.get("ack60_other_cells", float("nan")) for r in rs.values()])
                out[gw][sc][n] = o
    NUM["E17"] = out

def e18():
    """Whose credentials (Oct. 16): the headline attacks with the keys of each tenant, five schedulers, 20 paired seeds."""
    g = by(load("E18_credentials"), lambda k: (k[1], k[2]))
    out = {}
    names = sorted({k[1] for k in g})
    for sc in ["fcfs", "uplinkrate", "ratelimit", "tenantcap", "dlguard"]:
        out[sc] = {}
        for n in names:
            rs = g[(sc, n)]
            o = {"ack_within_60s": mci([r["ack_within_60s"] for r in rs.values()]),
                 "minus_noattack": paired(rs, g[(sc, "none")], "ack_within_60s"),
                 "minus_tenantcap": paired(rs, g[("tenantcap", n)], "ack_within_60s"),
                 "dl_sent_atk_per_h": mci([r.get("dl_sent_atk_per_h", float("nan")) for r in rs.values()])}
            out[sc][n] = o
    NUM["E18"] = out


def e19():
    """8-channel EU868 plan (Oct. 16): two 1% sub-bands for devices and for RX1 replies; Figure 1 schedulers and attacks."""
    g = by(load("E19_8ch"), lambda k: (k[1], k[2]))
    out = {}
    for sc in E16_SC:
        out[sc] = {}
        for n in ["none", "sf7", "sf7x2", "k32"]:
            rs = g[(sc, n)]
            o = {"ack_within_60s": mci([r["ack_within_60s"] for r in rs.values()]),
                 "minus_noattack": paired(rs, g[(sc, "none")], "ack_within_60s"),
                 "minus_tenantcap": paired(rs, g[("tenantcap", n)], "ack_within_60s"),
                 "ul_tx_atk_per_h": mci([r.get("ul_tx_atk_per_h", float("nan")) for r in rs.values()]),
                 "hon_rx1_util": mci([metric(r, "hon_rx1") / 72.0 for r in rs.values()]),
                 "ul_pdr_honest": mci([r["ul_pdr_honest"] for r in rs.values()])}
            if sc in ("uplinkrate", "dccheck"):
                o["attackers_flagged"] = mci([r.get("dc_flagged_attackers", float("nan")) for r in rs.values()]) if n != "none" else None
                o["honest_flagged"] = mci([r.get("dc_flagged_honest", float("nan")) for r in rs.values()])
            out[sc][n] = o
    NUM["E19"] = out


def x6():
    """Downlink link budget (Oct. 16): RX2 at SF9 loss-free and with decodability checked at 27 dBm and 14 dBm."""
    g = by(load("X6_dl_link"), lambda k: (k[1], k[2], k[3]))
    out = {}
    for v in ["sf9_lossfree", "sf9_27dBm", "sf9_14dBm", "sf12_14dBm"]:
        out[v] = {}
        for sc in ["fcfs", "tenantcap"]:
            out[v][sc] = {}
            for n in ["none", "sf7"]:
                rs = g[(v, sc, n)]
                out[v][sc][n] = {
                    "ack_within_60s": mci([r["ack_within_60s"] for r in rs.values()]),
                    "minus_noattack": paired(rs, g[(v, sc, "none")], "ack_within_60s"),
                    "undecodable_frac_honest": mci([r["raw"].get("dl_undecodable_hon", 0) / max(1, r["raw"].get("dl_sent_hon", 0))
                                                    for r in rs.values()])}
    NUM["X6"] = out


# ------------------------------------------------------------------ conference figures (printed at 100%, 8 pt text)
CONF_RC = {"font.size": 8, "axes.labelsize": 8, "legend.fontsize": 8, "xtick.labelsize": 8, "ytick.labelsize": 8,
           "savefig.bbox": None}
CONF_W = 2.9       # inches; SCITEPRESS columns are 7.5 cm (2.95 in), so the figure is placed at 100% scale
CCOL = {**COL, "norx2spill": "#8f6bbf", "uplinkrate": "#5c5c58", "rx2prefer": "#8f6bbf"}
CNAME = {**NAME, "ratelimit": "Unif. rate limit", "norx2spill": "No RX2 spill", "uplinkrate": "Uplink-rate (k=3)",
         "rx2prefer": "ChirpStack RX2-pref."}
HATCH = {"fcfs": "", "rx2prefer": "xxxx", "dccheck": "////", "ratelimit": "....", "norx2spill": "xxxx", "uplinkrate": "\\\\",
         "tenantcap": "", "dlguard": "----"}


def conf_figs():
    with plt.rc_context(CONF_RC):
        # Fig. A: defenses compared. Same configurations and seeds in every source, so values are paired:
        # E11 (no attack, 1 SF7, 32 SF12), E14 (uplink-rate k=3), E15 (ChirpStack RX2 preference), E16 (2 SF7)
        scs = ["fcfs", "dccheck", "rx2prefer", "uplinkrate", "ratelimit", "tenantcap", "dlguard"]
        scen = [("none", "No attack"), ("sf7", "1 SF7"), ("sf7x2", "2 SF7"), ("k32", "32 SF12")]

        def val(sc, n):
            if n == "sf7x2":
                return NUM["E16"][sc][2]["ack_within_60s"]
            if sc == "uplinkrate":
                return NUM["E14"][3][n]["ack_within_60s"]
            if sc == "rx2prefer":
                return NUM["E15"][n]["ack_within_60s"]
            return NUM["E11"]["summary"][sc][n]["ack_within_60s"]
        NUM["fig_defenses"] = {sc: {n: val(sc, n) for n, _ in scen} for sc in scs}
        fig = plt.figure(figsize=(CONF_W, 2.55))
        ax = fig.add_axes([0.15, 0.10, 0.84, 0.60])
        bw = 0.84 / len(scs)
        for j, sc in enumerate(scs):
            xs = [i - 0.42 + bw * (j + 0.5) for i in range(len(scen))]
            ys = [100 * val(sc, n)["mean"] for n, _ in scen]
            es = [100 * val(sc, n)["ci"] for n, _ in scen]
            ax.bar(xs, ys, bw * 0.92, yerr=es, color=CCOL[sc], hatch=HATCH[sc], edgecolor="white", linewidth=0.3,
                   error_kw=dict(elinewidth=0.5, capsize=0.8), label=CNAME[sc])
        ax.set_xticks(range(len(scen)), [lab for _, lab in scen])
        ax.set_ylabel("ACK60 (%)")
        # y-axis starts at 20% (author request, Oct. 16) so differences near the top are visible;
        # the lowest bar minus its CI is about 31%, so no bar is cut off
        lowest = min(100 * (val(sc, n)["mean"] - val(sc, n)["ci"]) for sc in scs for n, _ in scen)
        assert lowest > 20, lowest
        ax.set_ylim(20, 100)
        ax.set_yticks(range(20, 101, 20))
        ax.grid(axis="x", visible=False)
        fig.legend(*ax.get_legend_handles_labels(), loc="upper center", ncol=2, frameon=False,
                   bbox_to_anchor=(0.55, 1.0), columnspacing=0.8, handlelength=1.4, handletextpad=0.4,
                   labelspacing=0.25)
        fig.savefig(os.path.join(FIG, "conf_defenses.pdf"))
        fig.savefig(os.path.join(FIG, "conf_defenses.png"), dpi=600)  # for the SCITEPRESS Word template (>= 300 dpi)
        plt.close(fig)
        # Fig. B: one compliant attacker by SF (E10)
        S10 = NUM["E10"]["summary"]
        rate = NUM["E10"]["measured_ul_per_h"]
        sfs = [7, 8, 9, 10, 11, 12]
        fig = plt.figure(figsize=(CONF_W, 2.0))
        ax = fig.add_axes([0.15, 0.25, 0.84, 0.72])
        for sc in ["fcfs", "dccheck", "ratelimit", "tenantcap", "dlguard"]:
            err(ax, sfs, S10[sc], sc, "ack_within_60s", 100, label=CNAME[sc])
        ax.axhline(100 * NUM["E1"]["summary"]["fcfs"][0]["ack_within_60s"]["mean"], color="#6b6b66", lw=0.8, ls=":")
        ax.set_xticks(range(len(sfs)), [f"SF{sf}\n{rate[sf]['mean']:.0f}/h" for sf in sfs])
        ax.set_ylabel("ACK60 (%)")
        ax.set_ylim(35, 95)
        ax.legend(ncol=2, frameon=False, loc="lower right", handlelength=2.2)
        fig.savefig(os.path.join(FIG, "conf_sf.pdf"))
        fig.savefig(os.path.join(FIG, "conf_sf.png"), dpi=600)  # for the SCITEPRESS Word template (>= 300 dpi)
        plt.close(fig)
        # Fig. C: compliant SF12 swarm (E1)
        S1 = NUM["E1"]["summary"]
        ks = [0, 1, 2, 4, 8, 16, 32]
        fig = plt.figure(figsize=(CONF_W, 1.9))
        ax = fig.add_axes([0.15, 0.22, 0.84, 0.75])
        for sc in ["fcfs", "ratelimit", "tenantcap", "dlguard"]:
            err(ax, ks, S1[sc], sc, "ack_within_60s", 100, label=CNAME[sc])
        ax.set_xticks(range(len(ks)), [str(k) for k in ks])
        ax.set_xlabel("Compliant SF12 attackers")
        ax.set_ylabel("ACK60 (%)")
        ax.set_ylim(55, 95)
        ax.legend(ncol=2, frameon=False, loc="lower left", handlelength=2.2)
        fig.savefig(os.path.join(FIG, "conf_swarm.pdf"))
        fig.savefig(os.path.join(FIG, "conf_swarm.png"), dpi=600)  # for the SCITEPRESS Word template (>= 300 dpi)
        plt.close(fig)


# ------------------------------------------------------------------ X5 validation against pure ALOHA
def x5():
    from lorawan_sim import phy
    rows = load("X5_validation")
    g = defaultdict(list)
    for r in rows:
        g[r["key"][1]].append(r["ul_pdr_honest"])
    toa = phy.airtime(7, 23, crc=True)
    pts = []
    for n in sorted(g):
        G = n * toa / 30.0
        m = mci(g[n])
        pts.append({"n": n, "G": G, "sim": m["mean"], "ci": m["ci"], "aloha": math.exp(-2 * G)})
    NUM["X5"] = {"points": pts, "max_abs_diff": max(abs(p["sim"] - p["aloha"]) for p in pts), "toa_s": toa}
    fig, ax = plt.subplots(figsize=(W1, 1.9))
    Gs = [p["G"] for p in pts]
    fine = [i / 100 for i in range(0, 131)]
    ax.plot(fine, [100 * math.exp(-2 * x) for x in fine], color="#6b6b66", lw=1.0, label=r"Pure ALOHA, $e^{-2G}$")
    ax.errorbar(Gs, [100 * p["sim"] for p in pts], yerr=[100 * p["ci"] for p in pts], color=COL["fcfs"], marker="o",
                ls="none", ms=3.5, capsize=2, elinewidth=0.6, label="Simulator")
    ax.set_xlabel("Offered load G (frames per frame time)")
    ax.set_ylabel("PDR (%)")
    ax.legend(frameon=False)
    finish(fig, "fig_validation")


# ------------------------------------------------------------------ constants and configuration used in the text
def constants():
    from dataclasses import asdict
    from lorawan_sim import phy, SimConfig
    c = SimConfig()
    budget1, budget2 = c.dc_rx1_band * 3600, c.dc_rx2_band * 3600
    per_sf = {}
    for sf in phy.SF_RANGE:
        t_ul = phy.airtime(sf, 14, crc=True)
        t_dl1 = phy.airtime(sf, 12, crc=False)
        t_dl2 = phy.airtime(c.rx2_sf, 12, crc=False)
        rc = 3600 * c.dc_device / t_ul
        per_sf[sf] = {"t_ul_14B": t_ul, "t_dl_ack_rx1": t_dl1, "compliant_frames_per_h": rc,
                      "rx1_demand_s_per_h": rc * t_dl1, "rx2_demand_if_all_overflow_s_per_h": rc * t_dl2,
                      "devices_to_fill_rx1": math.ceil(budget1 / (rc * t_dl1)),
                      "devices_to_fill_rx2_if_overflow": math.ceil(budget2 / (rc * t_dl2))}
    t12 = per_sf[12]
    nc_cycle = t12["t_ul_14B"] + c.rx2_delay_s + phy.airtime(12, 12, crc=False)
    tenants = {}
    for t in c.tenants:
        lam = (3600.0 / t.period_s) * (t.conf_frac + t.mac_prob) + t.cmd_rate_per_h
        tenants[t.name] = {**asdict(t), "lambda_per_h": lam, "bucket_rate_per_h": c.scheduler.headroom * lam,
                           "bucket_rate_per_day": 24 * c.scheduler.headroom * lam, "hours_per_expected_downlink":
                           (1 / lam) if lam else None}
    rows = load("E1_attackers")
    thr = defaultdict(list)
    for r in rows:
        if r["key"][1] == "dlguard" and r["key"][2] == 0:
            for tn, v in r["detector_thresholds"].items():
                thr[tn].append(v)
    thresholds = {tn: {k: st.mean(x[k] for x in v) for k in ["mu", "sigma", "threshold"]} for tn, v in thr.items()}
    sfmix = {sf: mci([r["sf_mix"][sf] for r in rows if r["key"][1] == "fcfs" and r["key"][2] == 0])
             for sf in ["7", "8", "9", "10", "11", "12"]}
    NUM["const"] = {
        "budget_rx1_s_per_h": budget1, "budget_rx2_s_per_h": budget2,
        "per_sf": per_sf,
        "ack_sf12": phy.airtime(12, 12, crc=False), "ack_sf7": phy.airtime(7, 12, crc=False),
        "mac_reply_sf12": phy.airtime(12, 21, crc=False),
        "join_accept_sf12": phy.airtime(12, c.join_accept_bytes, crc=False),
        "join_request_sf12": phy.airtime(12, 23, crc=True),
        "nc_cycle_s": nc_cycle, "nc_max_frames_per_h": 3600 / nc_cycle,
        "nc_max_demand_s_per_h": 3600 / nc_cycle * phy.airtime(12, 12, crc=False),
        "gateway_max_tx_frac": (budget1 + budget2) / 3600,
        "tenants": tenants, "detector_thresholds": thresholds, "sf_mix_mean": sfmix,
        "config": {k: v for k, v in asdict(c).items() if k not in ("tenants", "attack", "scheduler")},
        "scheduler": asdict(c.scheduler), "attack_defaults": asdict(c.attack),
        "seeds_main": 20, "seeds_aux": 10,
    }


# ------------------------------------------------------------------ worst-case ACK60 deficit at the default load
def worst():
    """Largest drop in ACK60 (no attack minus attack, means over seeds) for each scheduler, over every
    attack scenario run at the default 1000-device load."""
    base = {sc: NUM["E1"]["summary"][sc][0]["ack_within_60s"]["mean"] for sc in SCHEMES}
    cand = defaultdict(list)
    for k in [1, 2, 4, 8, 16, 32]:
        for sc in SCHEMES:
            cand[sc].append((f"E1 k={k}", base[sc] - NUM["E1"]["summary"][sc][k]["ack_within_60s"]["mean"]))
    for iv in [120, 60, 30, 15, 10, 5]:
        for sc in SCHEMES:
            cand[sc].append((f"E2 gap={iv}", base[sc] - NUM["E2"]["summary"][sc][iv]["ack_within_60s"]["mean"]))
    for sf in [7, 8, 9, 10, 11, 12]:
        for sc in SCHEMES:
            cand[sc].append((f"E10 SF{sf}", base[sc] - NUM["E10"]["summary"][sc][sf]["ack_within_60s"]["mean"]))
    for name, v in NUM["E7"].items():
        for sc in SCHEMES:
            cand[sc].append((f"E7 {name}", base[sc] - v[sc]["ack_within_60s"]["mean"]))
    for iv in [3600, 1800, 900, 600, 300, 120]:
        for sc in ["fcfs", "ratelimit", "tenantcap", "dlguard"]:
            cand[sc].append((f"E9 gap={iv}", base[sc] - NUM["E9"]["summary"][sc][iv]["ack_within_60s"]["mean"]))
    NUM["worst_ack60_drop"] = {sc: dict(zip(["scenario", "drop"], max(v, key=lambda x: x[1]))) for sc, v in cand.items()}


# ------------------------------------------------------------------ runtime
def runtime():
    out = {}
    for f in sorted(os.listdir(RES)):
        if f.endswith(".json") and f != "numbers.json":
            rows = load(f[:-5])
            if not isinstance(rows, list):
                continue
            out[f[:-5]] = {"runs": len(rows), "cpu_s": sum(r.get("runtime_s", 0) for r in rows),
                           "seeds": len({r["key"][0] for r in rows})}
    NUM["runtime"] = out


if __name__ == "__main__":
    for fn in [e1, e2, e3, e5, e6, e7, e10, e8, e9, x1, x2, x3, x3b, e11, e12, e13, e14, e16, e17, e18, e19, x6, conf_figs, x5, constants, worst, runtime]:
        fn()
    with open(os.path.join(RES, "numbers.json"), "w") as f:
        json.dump(clean(NUM), f, indent=1, sort_keys=True)
    print("figures written to", FIG)
