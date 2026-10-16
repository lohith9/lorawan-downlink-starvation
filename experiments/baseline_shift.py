"""Explains why the no-attack ACK60 moved between v1 and v2 (review step 1).

Runs the v2 simulator without attack under FCFS in three configurations and
compares with the v1 value stored in the original results:
  A: v2 code, 3 dB margin NOT enforced (v1 SF choice), seeds 1-8
  B: v2 code, margin enforced, seeds 1-8
  C: v2 code, margin enforced, seeds 1-20 (the value in the paper)
Writes results/baseline_shift.json.
"""
import json
import math
import os
import statistics as st
import sys
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from lorawan_sim import SimConfig, run  # noqa: E402
from scipy import stats  # noqa: E402



def one(args):
    seed, fallback = args
    r = run(SimConfig(seed=seed, sf_margin_fallback=fallback))
    sf12 = r["sf_mix"]["12"]
    return seed, fallback, r["ack_within_60s"], r["ul_pdr_honest"], r["dl_grant_honest"], sf12


def mci(xs):
    n = len(xs)
    return {"mean": st.mean(xs), "ci": stats.t.ppf(0.975, n - 1) * st.stdev(xs) / math.sqrt(n), "n": n}


if __name__ == "__main__":
    v1_path = os.path.join(ROOT, "results", "v1_E1_noattack_fcfs.json")
    with open(v1_path) as f:
        v1 = json.load(f)
    jobs = [(s, True) for s in range(1, 9)] + [(s, False) for s in range(1, 21)]
    with Pool(os.cpu_count() or 2) as p:
        res = p.map(one, jobs)
    A = [r for r in res if r[1] and r[0] <= 8]
    B = [r for r in res if not r[1] and r[0] <= 8]
    C = [r for r in res if not r[1]]
    out = {
        "v1_seeds1_8": {"ack60": mci(v1["ack60"]), "sf12_share": None},
        "A_v2_nomargin_seeds1_8": {"ack60": mci([r[2] for r in A]), "sf12_share": mci([r[5] for r in A])},
        "B_v2_margin_seeds1_8": {"ack60": mci([r[2] for r in B]), "sf12_share": mci([r[5] for r in B])},
        "C_v2_margin_seeds1_20": {"ack60": mci([r[2] for r in C]), "sf12_share": mci([r[5] for r in C])},
    }
    # paired effect of the margin alone (same seeds, same v2 random streams)
    d = [b[2] - a[2] for a, b in zip(sorted(A), sorted(B))]
    out["margin_effect_paired_seeds1_8"] = mci(d)
    with open(os.path.join(ROOT, "results", "baseline_shift.json"), "w") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))
