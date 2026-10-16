"""C2: attack and no-attack runs with the same seed must share honest traffic until the attack starts."""
import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lorawan_sim import SimConfig, AttackConfig, SchedulerConfig, run, schedulers  # noqa: E402


def honest_uplinks(k, kind="fcfs", seed=3, t_attack=3600.0):
    cfg = SimConfig(n_devices=300, seed=seed, duration_s=2 * 3600, t_attack_s=t_attack,
                    attack=AttackConfig(n_attackers=k, compliant=False, interval_s=10),
                    scheduler=SchedulerConfig(kind=kind), record_uplinks=True)
    return [u for u in run(cfg)["uplink_log"] if u[1] < t_attack]


class PairingTest(unittest.TestCase):
    def test_same_honest_traffic_before_attack(self):
        base = honest_uplinks(0)
        self.assertGreater(len(base), 500)
        for k in (1, 4, 16):
            self.assertEqual(base, honest_uplinks(k), f"honest uplinks differ with {k} attackers")

    def test_pairing_holds_for_dlguard(self):
        self.assertEqual(honest_uplinks(0, "dlguard"), honest_uplinks(4, "dlguard"))


class DetectorIndependenceTest(unittest.TestCase):
    def test_detector_never_reads_attack_start(self):
        self.assertNotIn("t_attack_s", inspect.getsource(schedulers))


if __name__ == "__main__":
    unittest.main()
