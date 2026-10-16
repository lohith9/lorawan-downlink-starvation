"""Command-line tool: how exposed is a shared LoRaWAN cell to downlink starvation, and what does each server
policy buy?

    python -m lorawan_sim assess --scenario examples/paper_default.json --seeds 5
    python -m lorawan_sim assess --scenario examples/city_8ch.json --attacks none,sf7,swarm32 \\
        --schedulers fcfs,uplinkrate,tenantcap --attacker-tenant streetlight --json out.json
    python -m lorawan_sim list

For every attack and scheduler it reports ACK60 (share of critical confirmed messages acknowledged within 60 s)
as the mean over seeds with a 95% interval, and the paired difference to the same scheduler without attack.
Runs with the same seed share honest traffic, so the differences are paired.
"""
import argparse
import json
import math
import os
import statistics as st
import sys
from dataclasses import replace
from multiprocessing import Pool

from . import scenario as scn
from .config import AttackConfig, SchedulerConfig, SimConfig
from .schedulers import SCHEDULERS
from .sim import run

# two-sided 95% Student t quantiles, so the tool needs nothing beyond the standard library
_T975 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131,
         2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042]


def _ci(xs):
    xs = [x for x in xs if isinstance(x, (int, float)) and not math.isnan(x)]
    if len(xs) < 2:
        return (xs[0] if xs else float("nan")), 0.0
    t = _T975[len(xs) - 2] if len(xs) - 1 <= len(_T975) else 1.96
    return st.mean(xs), t * st.stdev(xs) / math.sqrt(len(xs))


ATTACKS = {
    "none": dict(n_attackers=0),
    "sf7": dict(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True),
    "sf7x2": dict(n_attackers=2, compliant=True, sf=7, reachable_sf_only=True),
    "swarm32": dict(n_attackers=32, compliant=True, sf=12),
    "fast10s": dict(n_attackers=1, compliant=False, sf=12, interval_s=10.0),
    "join": dict(n_attackers=1, compliant=False, sf=12, interval_s=10.0, mode="join"),
}
ATTACK_HELP = {
    "none": "no attack (baseline)",
    "sf7": "1 device that obeys the 1% duty cycle, confirmed uplinks at SF7",
    "sf7x2": "2 such devices",
    "swarm32": "32 duty-cycle compliant devices at SF12",
    "fast10s": "1 device ignoring the duty cycle, one confirmed uplink every 10 s at SF12",
    "join": "1 device sending a JoinRequest every 10 s at SF12",
}


def _job(args):
    seed, sched, atk, cfg = args
    r = run(replace(cfg, seed=seed))
    return seed, sched, atk, r["ack_within_60s"], r["ul_pdr_honest"], r.get("dl_sent_atk_per_h")


def assess(cfg: SimConfig, attacks, schedulers, seeds, attacker_tenant, procs=1, progress=True):
    names = {t.name for t in cfg.tenants}
    if attacker_tenant not in names:
        raise SystemExit(f"--attacker-tenant {attacker_tenant!r} is not a tenant of the scenario ({', '.join(sorted(names))})")
    jobs = []
    for a in attacks:
        akw = dict(ATTACKS[a], tenant=attacker_tenant) if a != "none" else ATTACKS[a]
        for sc in schedulers:
            sk = replace(cfg.scheduler, kind=sc)
            if sc == "uplinkrate" and sk.uplink_k is None:
                sk = replace(sk, uplink_k=3.0)       # the threshold the paper uses
            c = replace(cfg, attack=AttackConfig(**akw), scheduler=sk)
            jobs += [(s, sc, a, c) for s in seeds]
    if progress:
        print(f"{len(jobs)} runs ({len(seeds)} seeds x {len(schedulers)} schedulers x {len(attacks)} attacks) on {procs} "
              f"process(es)...", file=sys.stderr, flush=True)
    if procs > 1:
        with Pool(procs) as p:
            rows = p.map(_job, jobs, chunksize=1)
    else:
        rows = [_job(j) for j in jobs]
    res = {}
    for seed, sc, a, ack, pdr, dl in rows:
        res.setdefault((sc, a), {})[seed] = (ack, pdr, dl)
    out = []
    for a in attacks:
        for sc in schedulers:
            g = res[(sc, a)]
            m, ci = _ci([v[0] for v in g.values()])
            o = {"attack": a, "scheduler": sc, "ack60_mean": m, "ack60_ci95": ci,
                 "uplink_pdr_mean": _ci([v[1] for v in g.values()])[0], "seeds": len(g)}
            if "none" in attacks:
                base = res[(sc, "none")]
                d = [g[s][0] - base[s][0] for s in g if s in base]
                o["minus_noattack_mean"], o["minus_noattack_ci95"] = _ci(d)
            if a != "none":
                o["attacker_downlinks_per_h"] = _ci([v[2] for v in g.values() if v[2] is not None])[0]
            out.append(o)
    return out


def _print_table(out, attacks, schedulers):
    w = max(12, max(len(s) for s in schedulers) + 2)
    print("ACK60 (%): share of critical confirmed messages acknowledged within 60 s, mean ± 95% interval")
    print("attack".ljust(10) + "".join(s.rjust(w + 6) for s in schedulers))
    idx = {(o["attack"], o["scheduler"]): o for o in out}
    for a in attacks:
        line = a.ljust(10)
        for sc in schedulers:
            o = idx[(a, sc)]
            cell = f"{100 * o['ack60_mean']:.1f} ± {100 * o['ack60_ci95']:.1f}"
            line += cell.rjust(w + 6)
        print(line)
    if "none" in attacks and len(attacks) > 1:
        print("\nPaired change against the same scheduler without attack (points):")
        for a in attacks:
            if a == "none":
                continue
            line = a.ljust(10)
            for sc in schedulers:
                o = idx[(a, sc)]
                line += f"{100 * o['minus_noattack_mean']:+.1f} ± {100 * o['minus_noattack_ci95']:.1f}".rjust(w + 6)
            print(line)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m lorawan_sim", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="run attacks against schedulers on a scenario and print ACK60")
    a.add_argument("--scenario", help="JSON scenario file (default: the paper's default cell)")
    a.add_argument("--attacks", default="none,sf7,swarm32", help="comma-separated, see 'list'")
    a.add_argument("--schedulers", default="fcfs,uplinkrate,ratelimit,tenantcap", help="comma-separated, see 'list'")
    a.add_argument("--attacker-tenant", default=None, help="tenant whose keys the attacker holds (default: first non-critical)")
    a.add_argument("--seeds", type=int, default=5, help="number of paired seeds (the paper uses 20)")
    a.add_argument("--hours", type=float, default=None, help="override run length in hours (attack starts at 30%%)")
    a.add_argument("--procs", type=int, default=os.cpu_count() or 1)
    a.add_argument("--json", help="also write the results to this JSON file")
    sub.add_parser("list", help="list attacks and schedulers")
    args = ap.parse_args(argv)

    if args.cmd == "list":
        print("attacks:")
        for k, v in ATTACK_HELP.items():
            print(f"  {k:9s} {v}")
        print("schedulers:")
        for k, cls in sorted(SCHEDULERS.items()):
            doc = (cls.__doc__ or "").strip().split("\n")[0]
            print(f"  {k:11s} {doc}")
        return 0

    cfg = scn.load(args.scenario) if args.scenario else SimConfig()
    if args.hours:
        d = args.hours * 3600.0
        cfg = replace(cfg, duration_s=d, t_attack_s=0.3 * d, t_measure_s=0.3 * d, t_train_end_s=0.3 * d,
                      t_train_start_s=min(cfg.t_train_start_s, 0.1 * d))
    attacks = [x for x in args.attacks.split(",") if x]
    schedulers = [x for x in args.schedulers.split(",") if x]
    for x in attacks:
        if x not in ATTACKS:
            raise SystemExit(f"unknown attack {x!r}; see 'python -m lorawan_sim list'")
    for x in schedulers:
        if x not in SCHEDULERS:
            raise SystemExit(f"unknown scheduler {x!r}; see 'python -m lorawan_sim list'")
    tenant = args.attacker_tenant or next((t.name for t in cfg.tenants if not t.critical), cfg.tenants[0].name)
    out = assess(cfg, attacks, schedulers, list(range(1, args.seeds + 1)), tenant, procs=max(1, args.procs))
    print(f"\nscenario: {args.scenario or 'paper default'} | {cfg.n_devices} devices | {cfg.n_gateways} gateway(s) | "
          f"plan {cfg.channel_plan} | RX2 SF{cfg.rx2_sf} | attacker keys: {tenant}\n")
    _print_table(out, attacks, schedulers)
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"scenario": args.scenario, "attacker_tenant": tenant, "results": out}, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
