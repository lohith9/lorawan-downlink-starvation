"""Runs every experiment reported in the paper and writes JSON files to results/.

Usage:
  python experiments/run_experiments.py                    # everything
  python experiments/run_experiments.py --only E1,E2       # selected experiments
  python experiments/run_experiments.py --only E1 --shard 0/3   # one third of E1 (merge with --merge E1)

Every run of the same seed shares honest traffic (see lorawan_sim/sim.py), so
differences between schedulers or between attack and no attack are paired.
"""
import argparse
import glob
import json
import os
import sys
import time
from dataclasses import replace
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from lorawan_sim import SimConfig, AttackConfig, SchedulerConfig, run  # noqa: E402

OUT = os.path.join(ROOT, "results")
ALL = ["fcfs", "ratelimit", "tenantcap", "dccheck", "dlguard"]
SEEDS_MAIN = 20      # headline experiments
SEEDS_AUX = 10       # sweeps that are expensive or secondary

KEEP = ["ack_ratio_critical", "ack_within_60s", "tx_per_conf_msg", "conf_latency_mean", "crit_conf_msgs",
        "crit_conf_dropped_busy", "ul_pdr_honest", "deaf_loss_frac", "ul_coll_frac", "dl_grant_honest",
        "dl_grant_attacker", "cmd_delivered_frac", "cmd_latency_median", "cmd_latency_p95", "gw_airtime", "raw",
        "per_tenant", "ul_tx_atk_per_h", "dl_req_atk_per_h", "dl_sent_atk_per_h", "detected", "false_quarantine",
        "false_quarantine_critical", "detect_delay", "detector_thresholds", "dc_flagged_attackers",
        "dc_flagged_honest", "sf_mix", "ack60_attacker_cells", "ack60_other_cells", "n_gateways_heard_mean", "trace", "tenant_of", "attackers", "timeseries"]


def job(args):
    tag, cfg = args
    t = time.time()
    r = run(cfg)
    keep = {k: r[k] for k in KEEP if k in r}
    keep["runtime_s"] = time.time() - t
    return tag, keep


def cfg(seed, scheme, n=1000, sched=None, **atk):
    over = atk.pop("sim", {})
    sc = SchedulerConfig(kind=scheme, **(sched or {}))
    return SimConfig(seed=seed, n_devices=n, attack=AttackConfig(**atk), scheduler=sc, **over)


def experiments():
    S = list(range(1, SEEDS_MAIN + 1))
    A = list(range(1, SEEDS_AUX + 1))
    E = {}
    # E1: k duty-cycle compliant attackers at SF12
    E["E1_attackers"] = [((s, sc, k), cfg(s, sc, n_attackers=k, compliant=True))
                         for s in S for sc in ALL for k in [0, 1, 2, 4, 8, 16, 32]]
    # E2: one non-compliant attacker, target gap between frames (measured rates are saved)
    E["E2_intensity"] = [((s, sc, iv), cfg(s, sc, n_attackers=iv and 1, compliant=False, interval_s=iv or 10))
                         for s in S for sc in ALL for iv in [0, 120, 60, 30, 15, 10, 5]]
    # E3: network size, one non-compliant attacker at 10 s, and no attack
    E["E3_size"] = [((s, sc, n, k), cfg(s, sc, n=n, n_attackers=k, compliant=False, interval_s=10))
                    for s in A for sc in ["fcfs", "ratelimit", "tenantcap", "dlguard"]
                    for n in [250, 500, 1000, 1500, 2000, 3000] for k in [0, 1]]
    # E5: time series, mean over seeds
    ts = []
    for s in S:
        for sc in ["fcfs", "tenantcap", "dlguard"]:
            c = cfg(s, sc, n_attackers=1, compliant=False, interval_s=10)
            c.record_timeseries = True
            ts.append(((s, sc), c))
    E["E5_timeseries"] = ts
    # E6: detector traces on FCFS (attack unmitigated), four parking attackers at fixed rates
    tr = []
    for s in A:
        for label, kw in [("compliant SF12", dict(compliant=True)),
                          ("1 frame / 2 min", dict(compliant=False, interval_s=120)),
                          ("1 frame / 5 min", dict(compliant=False, interval_s=300)),
                          ("1 frame / 10 min", dict(compliant=False, interval_s=600))]:
            c = cfg(s, "fcfs", n_attackers=4, **kw)
            c.record_detector_trace = True
            tr.append(((s, label), c))
    E["E6_detector"] = tr
    # E7: attack strategies
    strategies = {
        "Confirmed, SF12": dict(mode="confirmed", sf=12, compliant=False, interval_s=10),
        "MAC commands, SF12": dict(mode="mac", sf=12, compliant=False, interval_s=10),
        "Confirmed, own SF": dict(mode="confirmed", sf=None, compliant=False, interval_s=10),
        "Critical insider": dict(mode="confirmed", sf=12, tenant="streetlight", compliant=False, interval_s=10),
        "Join flood, SF12": dict(mode="join", sf=12, compliant=False, interval_s=10),
        "Join flood, SF12, compliant": dict(mode="join", sf=12, compliant=True),
        "Confirmed, SF12, compliant": dict(mode="confirmed", sf=12, compliant=True),
    }
    E["E7_strategy"] = [((s, sc, name), cfg(s, sc, n_attackers=1, **kw))
                        for s in S for sc in ALL for name, kw in strategies.items()]
    # E10: one duty-cycle compliant attacker at each SF its link supports
    E["E10_compliant_sf"] = [((s, sc, sf), cfg(s, sc, n_attackers=1, compliant=True, sf=sf, reachable_sf_only=True))
                             for s in S for sc in ALL for sf in [7, 8, 9, 10, 11, 12]]
    # scenarios shared by E11-E13
    SCN = {"none": dict(n_attackers=0),
           "sf7": dict(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True),
           "k16": dict(n_attackers=16, compliant=True),
           "k32": dict(n_attackers=32, compliant=True)}
    # E11: RX2 policy and uplink-rate baselines (follow-up review, steps 2 and 3)
    E["E11_baselines"] = [((s, sc, name), cfg(s, sc, **kw))
                          for s in S for sc in ["fcfs", "ratelimit", "dccheck", "norx2spill", "rx1only", "uplinkrate", "tenantcap", "dlguard"]
                          for name, kw in SCN.items()]
    # E12: SF7 attacker moved close to the gateway instead of drawn from devices that already reach SF7
    E["E12_placement"] = [((s, sc, d), cfg(s, sc, n_attackers=1, compliant=True, sf=7, place_at_m=d))
                          for s in S for sc in ALL + ["norx2spill", "uplinkrate"] for d in [50.0]]
    # E13: bucket headroom and burst sweep
    E["E13_bucket"] = [((s, sc, h, b, name), cfg(s, sc, sched=dict(headroom=h, burst_frames=b), **kw))
                       for s in S for sc in ["tenantcap", "dlguard"] for h in [2, 4, 8] for b in [1, 3, 5]
                       for name, kw in SCN.items()]
    # E14: uplink-rate check threshold sweep (reviewer audit, issue 1)
    E["E14_uplink_k"] = [((s, k, name), cfg(s, "uplinkrate", sched=dict(uplink_k=float(k)), **SCN[name]))
                         for s in S for k in [2, 3, 4] for name in ["none", "sf7", "k32"]]
    # E15: ChirpStack-style RX2 preference for slow devices (reviewer audit, issue 2)
    E["E15_rx2prefer"] = [((s, "rx2prefer", name), cfg(s, "rx2prefer", **SCN[name]))
                          for s in S for name in ["none", "sf7", "k32"]]
    # E16: several compliant SF7 attackers against single-knob server settings (reviewer, round 3)
    E16_SC = [("fcfs", {}), ("dccheck", {}), ("rx2prefer", {}), ("uplinkrate", dict(uplink_k=3.0)), ("ratelimit", {}),
              ("tenantcap", {}), ("dlguard", {})]
    E["E16_multi_sf7"] = [((s, sc, n), cfg(s, sc, sched=kw, **(dict(n_attackers=n, compliant=True, sf=7,
                                                                     reachable_sf_only=True) if n else dict(n_attackers=0))))
                          for s in S for sc, kw in E16_SC for n in [0, 1, 2, 3, 4]]
    # E17: several gateways (Oct. 16). G gateways, 1000 x G devices so density per gateway is unchanged.
    # "G3dense" puts three gateways closer together (gw_ring_frac 0.2) so more uplinks reach two gateways.
    GW = {"G1": dict(n_gateways=1), "G2": dict(n_gateways=2), "G3": dict(n_gateways=3),
          "G3dense": dict(n_gateways=3, gw_ring_frac=0.2)}
    SC17 = {"none": dict(n_attackers=0), "sf7": dict(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True),
            "sf7x2": dict(n_attackers=2, compliant=True, sf=7, reachable_sf_only=True),
            "k32": dict(n_attackers=32, compliant=True)}
    E["E17_multigw"] = [((s, sc, g, name), cfg(s, sc, n=1000 * gw["n_gateways"], sched=kw, sim=gw, **SC17[name]))
                        for s in S for g, gw in GW.items()
                        for sc, kw in [("fcfs", {}), ("uplinkrate", dict(uplink_k=3.0)), ("ratelimit", {}), ("tenantcap", {})]
                        for name in SC17]
    # E18: whose credentials? The headline attacks (1 compliant SF7 device, 32 compliant SF12 devices) with the keys
    # of each tenant, including the two critical ones, which the per-tenant budget sizes more generously.
    E18_SC = [("fcfs", {}), ("uplinkrate", dict(uplink_k=3.0)), ("ratelimit", {}), ("tenantcap", {}), ("dlguard", {})]
    SC18 = {"none": dict(n_attackers=0)}
    for tn in ["parking", "waste", "water", "streetlight"]:
        SC18[f"sf7|{tn}"] = dict(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True, tenant=tn)
        SC18[f"k32|{tn}"] = dict(n_attackers=32, compliant=True, tenant=tn)
    E["E18_credentials"] = [((s, sc, name), cfg(s, sc, sched=kw, **SC18[name]))
                            for s in S for sc, kw in E18_SC for name in SC18]
    # E19: the common 8-channel EU868 plan (868.1-868.5 MHz and 867.1-867.9 MHz, two 1% sub-bands for devices and for
    # the gateway's RX1 replies) instead of the three default channels. Same schedulers and attacks as Figure 1.
    SC19 = {"none": dict(n_attackers=0), "sf7": dict(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True),
            "sf7x2": dict(n_attackers=2, compliant=True, sf=7, reachable_sf_only=True),
            "k32": dict(n_attackers=32, compliant=True)}
    E["E19_8ch"] = [((s, sc, name), cfg(s, sc, sched=kw, sim=dict(channel_plan="8ch"), **SC19[name]))
                    for s in S for sc, kw in E16_SC for name in SC19]
    # X6: downlink link budget. RX2 at SF9 only helps if far devices can decode it: loss-free (as in X3b), and with
    # decodability checked for a gateway sending at 27 dBm (the RX2 sub-band limit) or 14 dBm in RX2.
    X6V = {"sf9_lossfree": dict(rx2_sf=9), "sf9_27dBm": dict(rx2_sf=9, dl_link_check=True, gw_tx_dbm_rx2=27.0),
           "sf9_14dBm": dict(rx2_sf=9, dl_link_check=True, gw_tx_dbm_rx2=14.0),
           "sf12_14dBm": dict(rx2_sf=12, dl_link_check=True, gw_tx_dbm_rx2=14.0)}
    E["X6_dl_link"] = [((s, v, sc, name), cfg(s, sc, sim=over, **SC19[name]))
                       for s in S for v, over in X6V.items() for sc in ["fcfs", "tenantcap"] for name in ["none", "sf7"]]
    # E8: DLGuard ablation, 16 compliant attackers
    variants = {
        "FCFS": ("fcfs", {}),
        "Bucket only": ("dlguard", dict(use_bucket=True, use_reserve=False, use_detector=False)),
        "Reserve only": ("dlguard", dict(use_bucket=False, use_reserve=True, use_detector=False)),
        "Detector only": ("dlguard", dict(use_bucket=False, use_reserve=False, use_detector=True)),
        "Full DLGuard": ("dlguard", {}),
    }
    E["E8_ablation"] = [((s, name), cfg(s, kind, sched=kw, n_attackers=16, compliant=True))
                        for s in S for name, (kind, kw) in variants.items()]
    # E9: eight low-and-slow insiders in the streetlight tenant
    E["E9_lowslow"] = [((s, sc, iv), cfg(s, sc, n_attackers=8, compliant=False, interval_s=iv, tenant="streetlight"))
                       for s in S for sc in ["fcfs", "ratelimit", "tenantcap", "dlguard"]
                       for iv in [3600, 1800, 900, 600, 300, 120]]
    # X1: detector poisoning, compliant attackers active from t = 0 or 0.5 h; training fixed at 0.25-1.5 h
    E["X1_poisoning"] = [((s, k, start), cfg(s, "dlguard", n_attackers=k, compliant=True,
                                              sim=dict(t_attack_s=start)))
                         for s in S for k in [1, 4, 16, 32] for start in [0.0, 1800.0, 5400.0]]
    # X3: sensitivity of the main attack to RX2 data rate, load and SF mix
    sens = {"base": {}, "rx2_sf9": dict(rx2_sf=9), "low_load": dict(n_devices=200),
            "small_cell": dict(radius_m=250.0)}
    points = {"no attack": dict(n_attackers=0),
              "2 compliant": dict(n_attackers=2, compliant=True),
              "8 compliant": dict(n_attackers=8, compliant=True),
              "32 compliant": dict(n_attackers=32, compliant=True),
              "1 at 10 s": dict(n_attackers=1, compliant=False, interval_s=10),
              "1 at 5 s": dict(n_attackers=1, compliant=False, interval_s=5)}
    x3 = []
    for s in A:
        for vname, over in sens.items():
            n = over.get("n_devices", 1000)
            simo = {k: v for k, v in over.items() if k != "n_devices"}
            for pname, kw in points.items():
                for sc in ALL:
                    x3.append(((s, vname, pname, sc), cfg(s, sc, n=n, sim=simo, **kw)))
    E["X3_sensitivity"] = x3
    # X3b: the headline compliant low-SF attacker under the same alternative settings
    x3b = []
    for s in A:
        for vname, over in sens.items():
            n = over.get("n_devices", 1000)
            simo = {k: v for k, v in over.items() if k != "n_devices"}
            for sf in [0, 7, 9]:
                for sc in ALL:
                    kw = dict(n_attackers=1, compliant=True, sf=sf, reachable_sf_only=True) if sf else dict(n_attackers=0)
                    x3b.append(((s, vname, sf, sc), cfg(s, sc, n=n, sim=simo, **kw)))
    E["X3b_compliant_sf"] = x3b
    # X5: simulator validation against pure ALOHA (one channel, one SF, no capture, no downlinks)
    from lorawan_sim.config import Tenant
    x5 = []
    for s in A[:5]:
        for n in [25, 50, 100, 150, 200, 300, 400, 500, 600]:
            # Poisson traffic, 30 s mean period; receive windows shrunk so a device is busy only while sending
            t = Tenant("aloha", False, True, 1.0, 1.0, 30, True, 0.0, 0.0, 10)
            c = SimConfig(seed=s, n_devices=n, radius_m=100.0, tenants=[t], n_channels=1, force_sf=7,
                          capture_db=1e9, n_demodulators=10 ** 6, dc_device=1.0, duration_s=2 * 3600,
                          t_measure_s=1800.0, t_attack_s=1e9, t_train_end_s=1e9,
                          rx1_delay_s=0.0005, rx2_delay_s=0.001, rx_timeout_symbols=0)
            x5.append(((s, n), c))
    E["X5_validation"] = x5
    return E


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--procs", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--shard", default="", help="i/n: run only the i-th of n slices of each selected experiment")
    ap.add_argument("--merge", default="", help="merge shard files of these experiments")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if a.merge:
        for name in a.merge.split(","):
            parts = sorted(glob.glob(os.path.join(OUT, f"{name}*.shard*.json")))
            name_full = os.path.basename(parts[0]).split(".shard")[0]
            rows = []
            for p in parts:
                with open(p) as f:
                    rows += json.load(f)
            rows.sort(key=lambda r: r["order"])
            with open(os.path.join(OUT, f"{name_full}.json"), "w") as f:
                json.dump(rows, f)
            for p in parts:
                os.remove(p)
            print(f"merged {len(parts)} shards into {name_full}.json ({len(rows)} runs)")
        return
    E = experiments()
    only = [x for x in a.only.split(",") if x]
    with Pool(a.procs) as pool:
        for name, jobs in E.items():
            if only and not any(name.startswith(o) for o in only):
                continue
            jobs = [(i, k, c) for i, (k, c) in enumerate(jobs)]
            suffix = ""
            if a.shard:
                i, n = map(int, a.shard.split("/"))
                jobs = jobs[i::n]
                suffix = f".shard{i}of{n}"
            t = time.time()
            res = pool.map(job, [((i, k), c) for i, k, c in jobs], chunksize=1)
            out = [{"order": i, "key": list(k), **v} for (i, k), v in res]
            with open(os.path.join(OUT, f"{name}{suffix}.json"), "w") as f:
                json.dump(out, f)
            print(f"{name}{suffix}: {len(jobs)} runs in {time.time() - t:.0f}s, "
                  f"sum of run times {sum(v['runtime_s'] for _, v in res):.0f}s", flush=True)


if __name__ == "__main__":
    main()
