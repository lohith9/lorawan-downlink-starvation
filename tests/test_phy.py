"""Airtime and duty-cycle checks against hand-computed values (Semtech AN1200.13 formula)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lorawan_sim import phy, SimConfig  # noqa: E402
from lorawan_sim.sim import Simulation, Msg  # noqa: E402


class AirtimeTest(unittest.TestCase):
    def test_uplink_14B_sf12(self):
        self.assertAlmostEqual(phy.airtime(12, 14, crc=True), 1.155072, places=6)

    def test_downlink_12B_sf12_no_crc(self):
        self.assertAlmostEqual(phy.airtime(12, 12, crc=False), 0.991232, places=6)

    def test_downlink_12B_sf7_no_crc(self):
        self.assertAlmostEqual(phy.airtime(7, 12, crc=False), 0.041216, places=6)

    def test_downlink_21B_sf12_no_crc(self):
        self.assertAlmostEqual(phy.airtime(12, 21, crc=False), 1.318912, places=6)


class DutyCycleTest(unittest.TestCase):
    def test_offtime_after_uplink(self):
        sim = Simulation(SimConfig(n_devices=20, seed=1))
        d = sim.devices[0]
        d.cur = Msg(0.0, False, False, 1)
        sim.now = 100.0
        sim.tx_start(d)
        toa = sim.ul_toa(d.sf, 13 + d.tenant.payload)
        self.assertAlmostEqual(d.dc_ready, 100.0 + toa + toa * 99.0, places=9)


class MarginTest(unittest.TestCase):
    def test_every_device_has_margin(self):
        sim = Simulation(SimConfig(n_devices=500, seed=2))
        for d in sim.devices:
            self.assertGreaterEqual(d.rssi, phy.SENSITIVITY_DBM[d.sf] + 3.0)


if __name__ == "__main__":
    unittest.main()
