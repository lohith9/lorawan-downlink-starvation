"""Per-tenant downlink budget: a reference implementation for network servers.

This module has no dependency on the simulator. It is the policy the paper calls the *tenant cap*, written so
that it can be copied into, or ported to, a network server (ChirpStack, The Things Stack or an in-house server).

Idea
----
Every device belongs to a tenant (a service such as streetlights or parking sensors), and every tenant
declares a traffic profile when it is onboarded: how often its devices report, which share of uplinks are
confirmed, how often they send MAC requests, and how many commands the application sends per hour. From the
profile the server knows how many downlinks a device of that tenant should need per hour:

    lambda = (3600 / period_s) * (confirmed_fraction + mac_fraction) + commands_per_hour

Each device gets a token bucket counted in downlink frames, with rate ``headroom * lambda`` per hour and depth
``burst``. Before the server spends gateway airtime on a downlink that a device asked for (an ACK, a MAC answer,
a JoinAccept or a queued command), it checks the device's bucket. A compromised device can still send as many
uplinks as the duty cycle allows, but it can no longer turn them into more than about ``headroom`` times its
tenant's normal downlink use. Honest devices are not affected as long as they stay within their own profile.

Usage
-----
>>> from lorawan_sim.budget import TenantProfile, DownlinkBudget
>>> parking = TenantProfile("parking", period_s=600, mac_fraction=0.005)
>>> budget = DownlinkBudget([parking], headroom=4.0, burst=3.0)
>>> granted = [budget.try_acquire("dev-1", "parking", now=t) for t in range(0, 100, 10)]
>>> granted.count(True)        # the burst, then about 0.12 downlinks per hour
3

If the server only learns whether it *can* send after asking the gateway (RX1, then RX2), use
:meth:`DownlinkBudget.has_token` before scheduling and :meth:`DownlinkBudget.consume` once a window was found.
"""
from dataclasses import dataclass
from typing import Dict, Iterable, Optional


@dataclass(frozen=True)
class TenantProfile:
    """Traffic profile a tenant declares for its devices."""
    name: str
    period_s: float                    # mean reporting period of one device
    confirmed_fraction: float = 0.0    # share of uplinks sent as confirmed (each needs an ACK)
    mac_fraction: float = 0.0          # share of uplinks carrying a MAC request that needs an answer
    commands_per_hour: float = 0.0     # application downlinks per device per hour
    critical: bool = False             # informational; the bucket itself treats all tenants alike

    def expected_downlinks_per_hour(self) -> float:
        if self.period_s <= 0:
            raise ValueError(f"tenant {self.name!r}: period_s must be positive")
        return (3600.0 / self.period_s) * (self.confirmed_fraction + self.mac_fraction) + self.commands_per_hour

    @classmethod
    def from_tenant(cls, t) -> "TenantProfile":
        """Build a profile from a simulator ``config.Tenant``."""
        return cls(t.name, t.period_s, t.conf_frac, t.mac_prob, t.cmd_rate_per_h, t.critical)


class DownlinkBudget:
    """Per-device token buckets, sized from the device's tenant profile.

    Parameters
    ----------
    profiles: the tenants' declared profiles.
    headroom: bucket rate as a multiple of the expected downlink rate (the paper uses 4).
    burst: bucket depth in frames (the paper uses 3). A device seen for the first time starts with a full bucket.
    """

    def __init__(self, profiles: Iterable[TenantProfile], headroom: float = 4.0, burst: float = 3.0):
        if headroom <= 0 or burst < 1:
            raise ValueError("headroom must be positive and burst at least 1")
        self.profiles: Dict[str, TenantProfile] = {p.name: p for p in profiles}
        self.headroom = float(headroom)
        self.burst = float(burst)
        self._rate = {n: self.headroom * p.expected_downlinks_per_hour() / 3600.0 for n, p in self.profiles.items()}
        self._tokens: Dict[object, float] = {}
        self._last: Dict[object, float] = {}

    def rate_per_hour(self, tenant: str) -> float:
        return self._rate[tenant] * 3600.0

    def _refill(self, device_id, tenant: str, now: float) -> float:
        if tenant not in self._rate:
            raise KeyError(f"unknown tenant {tenant!r}; declare its profile first")
        if device_id not in self._tokens:
            self._tokens[device_id] = self.burst
            self._last[device_id] = now
        tok = self._tokens[device_id] + (now - self._last[device_id]) * self._rate[tenant]
        tok = min(self.burst, tok)
        self._tokens[device_id] = tok
        self._last[device_id] = now
        return tok

    def has_token(self, device_id, tenant: str, now: float) -> bool:
        """True if the device may receive one more downlink now (does not consume it)."""
        return self._refill(device_id, tenant, now) >= 1.0

    def consume(self, device_id) -> None:
        """Take one token after the downlink was scheduled."""
        self._tokens[device_id] -= 1.0

    def try_acquire(self, device_id, tenant: str, now: float) -> bool:
        """Check and consume in one step."""
        if self.has_token(device_id, tenant, now):
            self.consume(device_id)
            return True
        return False

    def tokens(self, device_id) -> Optional[float]:
        return self._tokens.get(device_id)
