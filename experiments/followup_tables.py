"""Prints the markdown tables for follow-up steps 2-5 from results/numbers.json (used in the revision record)."""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = json.load(open(os.path.join(ROOT, "results", "numbers.json")))


def pc(x, d=1):
    return f"{100 * x['mean']:.{d}f} ± {100 * x['ci']:.{d}f}"


def f1(x):
    return f"{x['mean']:.1f}"


def e11():
    S = N["E11"]["summary"]
    names = {"fcfs": "FCFS", "norx2spill": "No RX2 spill (RX2 only for SF10-12)", "rx1only": "RX1 only",
             "uplinkrate": "Uplink-rate check (k = 4)", "tenantcap": "Tenant cap", "dlguard": "DLGuard"}
    print("| Scheduler | No attack | 1 SF7 compliant | 16 SF12 compliant | 32 SF12 compliant |")
    print("|---|---|---|---|---|")
    for sc, nm in names.items():
        print(f"| {nm} | " + " | ".join(f"{pc(S[sc][n]['ack_within_60s'])} ({pc(S[sc][n]['dl_grant_honest'], 0)})"
                                       for n in ["none", "sf7", "k16", "k32"]) + " |")
    print()
    D = N["E11"]["uplinkrate_detection"]
    print("| Uplink-rate check | No attack | 1 SF7 | 16 SF12 | 32 SF12 |")
    print("|---|---|---|---|---|")
    print("| Attackers flagged (%) | n/a | " + " | ".join(pc(D[n]["attackers_flagged_frac"], 0) for n in ["sf7", "k16", "k32"]) + " |")
    print("| Honest devices flagged per run | " + " | ".join(f"{D[n]['honest_flagged']['mean']:.2f}" for n in ["none", "sf7", "k16", "k32"]) + " |")
    print("| Runs with at least one honest device flagged | " + " | ".join(f"{D[n]['runs_with_honest_flagged']} of {D[n]['runs']}" for n in ["none", "sf7", "k16", "k32"]) + " |")


def e12():
    S = N["E12"]["summary"]
    print("| Scheduler | ACK60 (%) | Honest DL granted (%) | Attacker airtime (s/h) |")
    print("|---|---|---|---|")
    for sc in ["fcfs", "ratelimit", "dccheck", "norx2spill", "uplinkrate", "tenantcap", "dlguard"]:
        print(f"| {sc} | {pc(S[sc]['ack_within_60s'])} | {pc(S[sc]['dl_grant_honest'])} | {f1(S[sc]['atk_air'])} |")
    v = N["E12"]["fcfs_placed_minus_sampled"]["ack_within_60s"]
    print(f"\nFCFS, placed at 50 m minus drawn from SF7 devices (paired): {100 * v['mean']:+.2f} ± {100 * v['ci']:.2f} points ACK60.")


def e13():
    print("| Scheme | h | b | ACK60, no attack (%) | ACK60, SF7 / k16 / k32 (%) | Attacker airtime k32 (s/h) | Honest DL not served, no attack (%) | False quarantines, no attack / k32 |")
    print("|---|---|---|---|---|---|---|---|")
    for sc in ["tenantcap", "dlguard"]:
        for h in [2, 4, 8]:
            for b in [1, 3, 5]:
                c = N["E13"][sc][f"h{h}_b{b}"]
                print(f"| {sc} | {h} | {b} | {pc(c['none']['ack_within_60s'])} | "
                      + " / ".join(f"{100 * c[n]['ack_within_60s']['mean']:.1f}" for n in ["sf7", "k16", "k32"])
                      + f" | {f1(c['k32']['atk_air'])} | {pc(c['none']['honest_denied'])} | "
                      f"{c['none']['false_quarantine']['mean']:.2f} / {c['k32']['false_quarantine']['mean']:.2f} |")


if __name__ == "__main__":
    for fn in [e11, e12, e13]:
        print(f"\n### {fn.__name__}\n")
        fn()
