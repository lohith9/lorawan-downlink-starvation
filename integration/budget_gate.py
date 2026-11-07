"""Downlink-egress budget gate: the paper's per-tenant policy applied to ChirpStack's scheduled downlinks.

This reuses the reference implementation in ``lorawan_sim/budget.py`` unchanged. The gate sits between the
server's scheduling decision and the (virtual) gateway: for each downlink ChirpStack decides to send, it
looks up the destination device's tenant by DevAddr and asks the token bucket whether the device may receive
one more downlink now. Over-budget downlinks are dropped at the server's egress. Honest devices within their
declared profile keep their replies.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lorawan_sim.budget import DownlinkBudget, TenantProfile  # noqa: E402

# The four tenant profiles from the paper (examples/paper_default.json). Rates are per device.
PROFILES = [
    TenantProfile("streetlight", period_s=900, confirmed_fraction=0.10, commands_per_hour=1 / 6, critical=True),
    TenantProfile("water", period_s=1800, confirmed_fraction=0.10, critical=True),
    TenantProfile("parking", period_s=600, mac_fraction=0.005),
    TenantProfile("waste", period_s=3600, confirmed_fraction=0.05),
]


class BudgetGate:
    def __init__(self, headroom: float = 4.0, burst: float = 3.0):
        self.budget = DownlinkBudget(PROFILES, headroom=headroom, burst=burst)
        self.tenant_of: dict[int, str] = {}   # DevAddr -> tenant name
        self.granted: dict[int, int] = {}
        self.denied: dict[int, int] = {}

    def register(self, devaddr: int, tenant: str) -> None:
        self.tenant_of[devaddr] = tenant

    def allow(self, devaddr: int, now: float) -> bool:
        tenant = self.tenant_of.get(devaddr)
        if tenant is None:
            return True  # unknown device: do not gate (fail open), matches "honest until profiled"
        ok = self.budget.try_acquire(devaddr, tenant, now)
        (self.granted if ok else self.denied)[devaddr] = (self.granted if ok else self.denied).get(devaddr, 0) + 1
        return ok
