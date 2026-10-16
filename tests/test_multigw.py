"""Multi-gateway model (Oct. 16): one gateway must be unchanged, and the extra gateways must behave as stated."""
import json
import math
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from lorawan_sim import SimConfig, AttackConfig, SchedulerConfig, run  # noqa: E402
from lorawan_sim.sim import Simulation, RX1, RX2  # noqa: E402
from lorawan_sim.schedulers import DownlinkRequest  # noqa: E402


def test_single_gateway_bit_identical_to_stored_results():
    rows = json.load(open(os.path.join(ROOT, "results", "E16_multi_sf7.json")))
    stored = {tuple(r["key"]): r for r in rows}
    for key in [(1, "fcfs", 1), (2, "tenantcap", 2)]:
        s, sc, n = key
        r = run(SimConfig(seed=s, attack=AttackConfig(n_attackers=n, compliant=True, sf=7, reachable_sf_only=True),
                          scheduler=SchedulerConfig(kind=sc)))
        for k in ("ack_within_60s", "ul_pdr_honest", "dl_grant_honest", "raw"):
            assert r[k] == stored[key][k], (key, k)


def _req(t=100.0):
    return DownlinkRequest(dev=None, tenant=None, critical=False, t_rx1=t + 1.0, t_rx2=t + 2.0, toa1=0.05, toa2=1.0,
                           has_ack=True, has_mac=False, has_cmd=False, has_join=False, fcnt=1, retx=False, sf=7)


def test_reply_goes_through_gateway_with_most_remaining_budget():
    sim = Simulation(SimConfig(seed=1, n_devices=20, n_gateways=2))
    g0, g1 = sim.gws
    g0.send(RX1, 10.0, 20.0, "parking", False)        # g0 has spent 20 s of its 36 s RX1 budget
    assert sim.pick_gateway([g0, g1], _req()) is g1
    g1.send(RX1, 40.0, 30.0, "parking", False)        # now g1 has less left than g0
    assert sim.pick_gateway([g0, g1], _req()) is g0
    assert sim.pick_gateway([g1], _req()) is g1       # only gateways that heard the uplink are candidates


def test_half_duplex_is_per_gateway():
    sim = Simulation(SimConfig(seed=1, n_devices=20, n_gateways=2))
    g0, g1 = sim.gws
    g0.send(RX2, 50.0, 1.0, "parking", True)
    assert g0.overlaps_tx(50.2, 50.4)
    assert not g1.overlaps_tx(50.2, 50.4)


def test_density_per_gateway_and_layout():
    sim = Simulation(SimConfig(seed=3, n_devices=2000, n_gateways=2))
    R = sim.cfg.radius_m * math.sqrt(2)
    ring = sim.cfg.gw_ring_frac * R
    assert all(abs(math.hypot(g.x, g.y) - ring) < 1e-9 for g in sim.gws)
    assert all(len(d.rssi_g) == 2 and d.rssi == max(d.rssi_g) for d in sim.devices)
    homes = [d.home_gw for d in sim.devices]
    assert 0.4 < homes.count(0) / len(homes) < 0.6   # symmetric layout: about half the devices per gateway


def test_uplinks_can_be_heard_by_several_gateways():
    r = run(SimConfig(seed=2, n_devices=1500, n_gateways=3, gw_ring_frac=0.2, duration_s=2400.0, t_measure_s=0.0,
                      t_attack_s=0.0, t_train_end_s=1800.0))
    assert r["n_gateways_heard_mean"] > 1.0


import unittest  # noqa: E402


class MultiGatewayTest(unittest.TestCase):
    """unittest wrapper, so the file runs with `python -m unittest` like the other tests."""
    def test_single_gateway_bit_identical_to_stored_results(self):
        test_single_gateway_bit_identical_to_stored_results()

    def test_reply_goes_through_gateway_with_most_remaining_budget(self):
        test_reply_goes_through_gateway_with_most_remaining_budget()

    def test_half_duplex_is_per_gateway(self):
        test_half_duplex_is_per_gateway()

    def test_density_per_gateway_and_layout(self):
        test_density_per_gateway_and_layout()

    def test_uplinks_can_be_heard_by_several_gateways(self):
        test_uplinks_can_be_heard_by_several_gateways()
