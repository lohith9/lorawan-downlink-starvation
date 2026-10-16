"""Describe a deployment in JSON and turn it into a SimConfig.

A scenario file lets an operator model its own city: the tenants that share a gateway, their reporting periods
and confirmed-message shares, the channel plan, the RX2 data rate and the number of gateways. Any scalar field of
``SimConfig`` may be given at the top level; ``tenants``, ``attack`` and ``scheduler`` are nested objects whose
fields are those of ``Tenant``, ``AttackConfig`` and ``SchedulerConfig``. Unknown fields are rejected so that a
typo cannot silently fall back to a default. See ``examples/`` for complete files.
"""
import json
from dataclasses import fields, asdict
from typing import Union

from .config import SimConfig, Tenant, AttackConfig, SchedulerConfig

_TENANT_DEFAULTS = {"battery": True, "share": 0.25, "poisson": False, "conf_frac": 0.0, "mac_prob": 0.0,
                    "payload": 10, "cmd_rate_per_h": 0.0, "cmd_payload": 0}


def _check(obj, cls, where):
    known = {f.name for f in fields(cls)}
    unknown = set(obj) - known
    if unknown:
        raise ValueError(f"{where}: unknown field(s) {sorted(unknown)}; allowed: {sorted(known)}")


def _tenant(d, i):
    d = {**_TENANT_DEFAULTS, **d}
    _check(d, Tenant, f"tenants[{i}]")
    for req in ("name", "critical", "fraction", "period_s"):
        if req not in d:
            raise ValueError(f"tenants[{i}]: missing required field {req!r}")
    return Tenant(**d)


def from_dict(d: dict) -> SimConfig:
    d = dict(d)
    d.pop("description", None)
    kw = {}
    if "tenants" in d:
        ts = [_tenant(t, i) for i, t in enumerate(d.pop("tenants"))]
        total = sum(t.fraction for t in ts)
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"tenant fractions must sum to 1 (they sum to {total:g})")
        kw["tenants"] = ts
    if "attack" in d:
        a = d.pop("attack")
        _check(a, AttackConfig, "attack")
        kw["attack"] = AttackConfig(**a)
    if "scheduler" in d:
        s = d.pop("scheduler")
        _check(s, SchedulerConfig, "scheduler")
        kw["scheduler"] = SchedulerConfig(**s)
    _check(d, SimConfig, "scenario")
    cfg = SimConfig(**d, **kw)
    if cfg.channel_plan not in ("3ch", "8ch"):
        raise ValueError("channel_plan must be '3ch' or '8ch'")
    return cfg


def load(path_or_dict: Union[str, dict]) -> SimConfig:
    """Load a scenario from a JSON file path or an already parsed dict."""
    if isinstance(path_or_dict, dict):
        return from_dict(path_or_dict)
    with open(path_or_dict, encoding="utf8") as f:
        return from_dict(json.load(f))


def to_dict(cfg: SimConfig) -> dict:
    """The inverse of ``from_dict`` (every field written out)."""
    return asdict(cfg)
