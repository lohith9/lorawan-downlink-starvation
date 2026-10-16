"""Discrete-event simulator of shared EU868 LoRaWAN cells under downlink-starvation attacks.

Quick start:
    from lorawan_sim import SimConfig, AttackConfig, SchedulerConfig, run
    r = run(SimConfig(seed=1, attack=AttackConfig(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True),
                      scheduler=SchedulerConfig(kind="tenantcap")))
    print(r["ack_within_60s"])

Command line: python -m lorawan_sim --help
"""
from .config import SimConfig, AttackConfig, SchedulerConfig, Tenant, default_tenants
from .sim import Simulation, run
from .schedulers import SCHEDULERS, register_scheduler, FCFS
from .budget import DownlinkBudget, TenantProfile
from . import scenario

__version__ = "1.1.1"
