"""Drive the two scenarios against the live ChirpStack server and write integration/results.json.

Scenario NATIVE   : honest devices plus one duty-cycle-compliant SF7 attacker send authenticated confirmed
                    uplinks; we record every downlink (ACK) ChirpStack schedules, per device, with its RX
                    window. This shows the server replies to each authenticated confirmed uplink with no
                    per-device downlink limit.
Scenario GATED    : the same recorded downlinks are passed, in the order and simulated times they were
                    requested, through the paper's per-tenant budget (lorawan_sim/budget.py) at the server's
                    downlink egress. This shows the budget caps the attacker to about its tenant's rate while
                    honest devices keep their replies.

The budget is rate-based, so each uplink is given a time on a simulated one-hour clock; sending is paced only
enough to let the server respond. Airtime and the RX2-at-SF12 cost remain simulator and analytical results
(see the paper); this test checks the server's scheduling and the policy's enforcement, not the radio.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from integration.lorawan_frame import Device  # noqa: E402
from integration.udp_gateway import VirtualGateway  # noqa: E402
from integration.budget_gate import BudgetGate  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SIM_HOUR = 3600.0
ATTACKER_UPLINKS_PER_HOUR = 773      # a compliant SF7 device under the 1% duty cycle (paper, Section 4)
# honest confirmed-uplink rate per hour by tenant (profile reporting rate x confirmed fraction)
HONEST_CONF_PER_HOUR = {"streetlight": 4 * 0.10, "water": 2 * 0.10, "parking": 6 * 1.0 * 0.0, "waste": 1 * 0.05}
# parking honest sends MAC requests rarely; keep a small confirmed rate so it has downlinks to protect
HONEST_CONF_PER_HOUR["parking"] = 0.5
SF_BY_TENANT = {"streetlight": 9, "water": 10, "parking": 9, "waste": 10}


def load_devices():
    with open(os.path.join(HERE, "devices.json")) as f:
        return json.load(f)["devices"]


def build_schedule(devs):
    """Return a list of (sim_time_s, record, sf, confirmed) uplink events over one simulated hour."""
    events = []
    for d in devs:
        if d["attacker"]:
            n = ATTACKER_UPLINKS_PER_HOUR
            sf = 7
        else:
            n = max(1, round(HONEST_CONF_PER_HOUR.get(d["tenant"], 0.5)))
            sf = SF_BY_TENANT.get(d["tenant"], 9)
        for i in range(n):
            t = (i + 0.5) * SIM_HOUR / n
            events.append((t, d, sf, True))
    events.sort(key=lambda e: e[0])
    return events


def run_native(devs, events, pace_s=0.004, drain_s=5.0):
    gw = VirtualGateway()
    gw.start()
    time.sleep(1.0)  # let PULL_DATA register the gateway route
    frames = {d["name"]: Device(d["name"], d["tenant"], d["devaddr"],
                                bytes.fromhex(d["nwkskey"]), bytes.fromhex(d["appskey"])) for d in devs}
    for (_, d, sf, conf) in events:
        phy = frames[d["name"]].build_uplink(b"\x01", fport=1, confirmed=conf)
        gw.send_uplink(phy, sf=sf, freq=868.1)
        time.sleep(pace_s)
    time.sleep(drain_s)
    gw.stop()
    return gw


def apply_gate(devs, events, observed_by_devaddr):
    """Replay the per-tenant budget over the uplink schedule; a device's k-th uplink yields a downlink only
    if the server actually returned at least k downlinks for it (confirmed uplinks map 1:1 to ACKs in order)."""
    gate = BudgetGate()
    for d in devs:
        gate.register(d["devaddr"], d["tenant"])
    seen = {}
    delivered = {}
    for (t, d, _sf, _c) in events:
        k = seen.get(d["devaddr"], 0) + 1
        seen[d["devaddr"]] = k
        if k > observed_by_devaddr.get(d["devaddr"], 0):
            continue  # the server did not schedule a downlink for this uplink
        if gate.allow(d["devaddr"], now=t):
            delivered[d["devaddr"]] = delivered.get(d["devaddr"], 0) + 1
    return delivered


def main():
    devs = load_devices()
    events = build_schedule(devs)
    print("scenario NATIVE: sending %d authenticated confirmed uplinks to ChirpStack ..." % len(events))
    gw = run_native(devs, events)
    per_dev = gw.per_device()                       # devaddr -> {delivered, rx1, rx2, dropped}
    observed = {a: v["delivered"] for a, v in per_dev.items()}
    summ = gw.summary()
    print("  server scheduled %d downlinks (%d RX1, %d RX2)"
          % (summ["downlinks_total"], summ["rx1"], summ["rx2"]))

    gated = apply_gate(devs, events, observed)

    rows = []
    name_by_addr = {d["devaddr"]: (d["name"], d["tenant"], d["attacker"]) for d in devs}
    for d in devs:
        a = d["devaddr"]
        name, tenant, atk = name_by_addr[a]
        rows.append({"device": name, "tenant": tenant, "attacker": atk,
                     "uplinks": sum(1 for e in events if e[1]["devaddr"] == a),
                     "downlinks_native": observed.get(a, 0),
                     "downlinks_gated": gated.get(a, 0)})
    out = {"server": "ChirpStack 4.19.2 (live, Semtech UDP)",
           "native_summary": summ, "rows": rows,
           "note": "downlinks_native = ACKs ChirpStack scheduled (no per-device limit); "
                   "downlinks_gated = after the per-tenant budget at egress."}
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(out, f, indent=1)

    print("\n%-22s %-11s %7s %9s %8s" % ("device", "tenant", "uplinks", "native", "gated"))
    for r in rows:
        tag = "  <-- attacker" if r["attacker"] else ""
        print("%-22s %-11s %7d %9d %8d%s"
              % (r["device"], r["tenant"], r["uplinks"], r["downlinks_native"], r["downlinks_gated"], tag))
    print("\nwrote integration/results.json")


if __name__ == "__main__":
    main()
