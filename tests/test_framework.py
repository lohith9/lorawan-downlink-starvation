"""Framework tests: the reference budget, the scheduler registry, scenario files, the 8-channel plan,
the command line, and a small regression guard for the default model."""
import doctest
import json
import os
import sys
import tempfile
import unittest
from dataclasses import asdict, replace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from lorawan_sim import (AttackConfig, FCFS, SchedulerConfig, SimConfig, register_scheduler, run,  # noqa: E402
                         scenario, budget, schedulers, cli)

SMALL = dict(n_devices=300, duration_s=2 * 3600, t_attack_s=3600.0, t_measure_s=3600.0, t_train_end_s=3600.0)


def small(seed=1, kind="fcfs", **atk):
    return SimConfig(seed=seed, attack=AttackConfig(**atk), scheduler=SchedulerConfig(kind=kind), **SMALL)


class RegressionTest(unittest.TestCase):
    """If one of these numbers changes, the simulator's behavior changed: rerun the experiments before publishing."""

    def test_default_model_unchanged(self):
        r = run(small(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True))
        self.assertEqual(r["ack_within_60s"], 0.8571428571428571)
        self.assertEqual(r["raw"]["ul_tx_hon"], 1057.0)
        self.assertEqual(r["raw"]["dl_sent_hon"], 56.0)
        self.assertEqual(r["ul_tx_atk_per_h"], 770.0)


class BudgetTest(unittest.TestCase):
    def test_doctest(self):
        self.assertEqual(doctest.testmod(budget).failed, 0)

    def test_expected_rate(self):
        p = budget.TenantProfile("streetlight", period_s=900, confirmed_fraction=0.1, commands_per_hour=1 / 6)
        self.assertAlmostEqual(p.expected_downlinks_per_hour(), 4 * 0.1 + 1 / 6)

    def test_refill(self):
        b = budget.DownlinkBudget([budget.TenantProfile("t", period_s=3600, confirmed_fraction=1.0)], headroom=1, burst=1)
        self.assertTrue(b.try_acquire("d", "t", 0.0))
        self.assertFalse(b.try_acquire("d", "t", 1800.0))
        self.assertTrue(b.try_acquire("d", "t", 3600.0))

    def test_reference_matches_tenant_cap(self):
        for atk in (dict(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True), dict(n_attackers=8, compliant=True)):
            a = run(small(kind="tenantcap", **atk))
            b = run(small(kind="budget", **atk))
            self.assertEqual(a["ack_within_60s"], b["ack_within_60s"])
            self.assertEqual(a["raw"], b["raw"])


class RegistryTest(unittest.TestCase):
    def test_custom_scheduler(self):
        @register_scheduler("test_deny_all")
        class DenyAll(FCFS):
            """Never answers."""
            def decide(self, req, now):
                return None
        try:
            r = run(small(kind="test_deny_all"))
            self.assertEqual(r["raw"].get("dl_sent_hon", 0), 0)
            self.assertEqual(r["ack_within_60s"], 0.0)
        finally:
            schedulers.SCHEDULERS.pop("test_deny_all", None)

    def test_unknown_scheduler(self):
        with self.assertRaises(ValueError):
            run(small(kind="no_such_policy"))


class ScenarioTest(unittest.TestCase):
    def test_paper_default_file_is_the_default_config(self):
        c = scenario.load(os.path.join(ROOT, "examples", "paper_default.json"))
        self.assertEqual(asdict(c), asdict(SimConfig()))

    def test_city_template_loads(self):
        c = scenario.load(os.path.join(ROOT, "examples", "city_8ch.json"))
        self.assertEqual(c.channel_plan, "8ch")
        self.assertAlmostEqual(sum(t.fraction for t in c.tenants), 1.0)

    def test_rejects_typos(self):
        with self.assertRaises(ValueError):
            scenario.from_dict({"n_device": 10})
        with self.assertRaises(ValueError):
            scenario.from_dict({"attack": {"n_attacker": 1}})
        with self.assertRaises(ValueError):
            scenario.from_dict({"tenants": [{"name": "a", "critical": True, "fraction": 0.5, "period_s": 60}]})

    def test_roundtrip(self):
        c = replace(SimConfig(), channel_plan="8ch", n_gateways=2)
        self.assertEqual(asdict(scenario.from_dict(scenario.to_dict(c))), asdict(c))


class EightChannelTest(unittest.TestCase):
    def test_compliant_attacker_uses_both_sub_bands(self):
        three = run(small(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True))["ul_tx_atk_per_h"]
        eight = run(replace(small(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True), channel_plan="8ch"))["ul_tx_atk_per_h"]
        self.assertGreater(eight, 1.9 * three)       # 1% in each of two sub-bands
        self.assertLess(eight, 2.05 * three)

    def test_dc_check_never_flags_honest_devices(self):
        r = run(replace(small(kind="dccheck"), channel_plan="8ch"))
        self.assertEqual(r["dc_flagged_honest"], 0)

    def test_bad_plan(self):
        with self.assertRaises(ValueError):
            run(replace(small(), channel_plan="16ch"))


class LinkBudgetTest(unittest.TestCase):
    def test_default_rx2_unchanged_by_check(self):
        base = run(small(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True))
        chk = run(replace(small(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True), dl_link_check=True,
                          gw_tx_dbm_rx2=14.0))
        self.assertEqual(base["ack_within_60s"], chk["ack_within_60s"])
        self.assertEqual(chk["raw"].get("dl_undecodable_hon", 0), 0)

    def test_weak_rx2_at_sf9_loses_replies(self):
        r = run(replace(small(), rx2_sf=9, dl_link_check=True, gw_tx_dbm_rx2=14.0))
        self.assertGreater(r["raw"].get("dl_undecodable_hon", 0), 0)
        strong = run(replace(small(), rx2_sf=9, dl_link_check=True, gw_tx_dbm_rx2=27.0))
        self.assertEqual(strong["raw"].get("dl_undecodable_hon", 0), 0)


class CliTest(unittest.TestCase):
    def test_list(self):
        self.assertEqual(cli.main(["list"]), 0)

    def test_assess_json(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.json")
            cli.main(["assess", "--seeds", "2", "--hours", "1", "--procs", "1", "--attacks", "none,sf7",
                      "--schedulers", "fcfs,tenantcap", "--json", out])
            rows = json.load(open(out))["results"]
            self.assertEqual(len(rows), 4)
            fc = next(r for r in rows if r["attack"] == "sf7" and r["scheduler"] == "fcfs")
            self.assertLess(fc["minus_noattack_mean"], 0)


if __name__ == "__main__":
    unittest.main()
