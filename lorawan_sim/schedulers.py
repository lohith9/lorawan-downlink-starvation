"""Network-server downlink schedulers.

Every scheduler sees one DownlinkRequest per received uplink that needs an answer
and returns "rx1", "rx2" or None. The regulatory duty-cycle check and the
half-duplex check are done by the gateway object for all schedulers, so the
baselines are never allowed to break the rules either.
"""
import math
from collections import defaultdict
from dataclasses import replace


class DownlinkRequest:
    __slots__ = ("dev", "tenant", "critical", "t_rx1", "t_rx2", "toa1", "toa2",
                 "has_ack", "has_mac", "has_cmd", "has_join", "fcnt", "retx", "sf")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class FCFS:
    """Grant whatever the regulatory budget allows, RX1 first then RX2."""
    name = "FCFS"

    def __init__(self, sim):
        self.sim = sim

    def observe(self, req, now):
        pass

    def on_uplink(self, p):
        pass

    def decide(self, req, now):
        gw = self.sim.gw
        if gw.can_send("rx1", req.t_rx1, req.toa1):
            return "rx1"
        if gw.can_send("rx2", req.t_rx2, req.toa2):
            return "rx2"
        return None

    def on_window(self, now):
        pass


class RateLimit(FCFS):
    """Uniform per-device token bucket on the number of downlinks, then FCFS."""
    name = "Rate limit"

    def __init__(self, sim):
        super().__init__(sim)
        c = sim.cfg.scheduler
        self.rate = c.rl_rate_per_h / 3600.0
        self.burst = c.rl_burst
        self.tokens = {}
        self.last = {}

    def decide(self, req, now):
        d = req.dev.id
        tok = self.tokens.get(d, self.burst)
        tok = min(self.burst, tok + (now - self.last.get(d, now)) * self.rate)
        self.last[d] = now
        if tok < 1.0:
            self.tokens[d] = tok
            return None
        w = super().decide(req, now)
        if w is not None:
            tok -= 1.0
        self.tokens[d] = tok
        return w


class DLGuard:
    """Tenant-aware downlink admission control.

    1. Per-device token bucket, counted in downlink frames, with a rate sized from
       the tenant's declared profile.
    2. Per-tenant share of each band's rolling budget, with borrowing.
       Non-critical tenants may only borrow while a reserve stays free for
       critical tenants.
    3. A per-tenant statistical detector on downlink-request counts. A device
       above threshold for several consecutive windows is quarantined.
    """
    name = "DLGuard"

    def __init__(self, sim):
        self.sim = sim
        self.c = sim.cfg.scheduler
        self.tokens = {}
        self.last = {}
        self.rate = {}
        self.burst = {}
        self.quarantined = {}
        self.window_counts = defaultdict(float)
        self.over = defaultdict(int)
        self.train = defaultdict(list)
        self.stats = {}
        self.trace = []           # per window: {dev_id: count}
        self.thresholds = {}
        for dev in sim.devices:
            self._init_bucket(dev)

    def _init_bucket(self, dev):
        """Bucket in frames: rate = headroom x the tenant's declared downlink demand."""
        t = dev.tenant
        lam = (3600.0 / t.period_s) * (t.conf_frac + t.mac_prob) + t.cmd_rate_per_h
        self.rate[dev.id] = self.c.headroom * lam / 3600.0
        self.burst[dev.id] = self.c.burst_frames
        self.tokens[dev.id] = self.c.burst_frames
        self.last[dev.id] = 0.0

    def observe(self, req, now):
        self.window_counts[req.dev.id] += 1.0

    def on_uplink(self, p):
        pass

    def _refill(self, d, now):
        tok = self.tokens[d] + (now - self.last[d]) * self.rate[d]
        self.tokens[d] = min(self.burst[d], tok)
        self.last[d] = now

    def _band_ok(self, band, req, t, toa):
        gw = self.sim.gw
        if not gw.can_send(band, t, toa):
            return False
        if not self.c.use_reserve:
            return True
        budget = gw.band_budget(band)
        total = gw.usage(band, t)
        mine = gw.tenant_usage(band, req.tenant.name, t)
        share = req.tenant.share * budget
        if mine + toa <= share:
            return True
        # borrowing
        limit = budget if req.critical else (1.0 - self.c.reserve) * budget
        return total + toa <= limit

    def decide(self, req, now):
        d = req.dev.id
        if d in self.quarantined and (req.has_mac or req.has_join) and not req.has_ack:
            return None
        metered = self.c.use_bucket or d in self.quarantined
        if metered:
            self._refill(d, now)
            if self.tokens[d] < 1.0:
                return None
        for band, t, toa in (("rx1", req.t_rx1, req.toa1), ("rx2", req.t_rx2, req.toa2)):
            if self._band_ok(band, req, t, toa):
                if metered:
                    self.tokens[d] -= 1.0
                return band
        return None

    def on_window(self, now):
        """Called at the end of every detector window."""
        counts = self.window_counts
        sim = self.sim
        if sim.cfg.record_detector_trace:
            self.trace.append((now, dict(counts)))
        # training uses its own window; the detector never reads the attack start time
        if sim.cfg.t_train_start_s < now <= sim.cfg.t_train_end_s + 1e-6:
            for dev in sim.devices:
                self.train[dev.tenant.name].append(counts.get(dev.id, 0.0))
        elif now > sim.cfg.t_train_end_s and self.c.use_detector:
            if not self.stats:
                self._fit()
            for dev in sim.devices:
                if dev.id in self.quarantined:
                    continue
                mu, sd = self.stats[dev.tenant.name]
                thr = max(mu + self.c.theta * sd, self.c.min_count)
                if counts.get(dev.id, 0.0) > thr:
                    self.over[dev.id] += 1
                    if self.over[dev.id] >= self.c.consecutive:
                        self.quarantined[dev.id] = now
                        self.rate[dev.id] = min(self.rate[dev.id], self.c.quarantine_rate_per_h / 3600.0)
                        self.tokens[dev.id] = min(self.tokens[dev.id], 1.0)
                        self.burst[dev.id] = 1.0
                else:
                    self.over[dev.id] = 0
        self.window_counts = defaultdict(float)

    def _fit(self):
        for name, xs in self.train.items():
            n = len(xs)
            mu = sum(xs) / n if n else 0.0
            var = sum((x - mu) ** 2 for x in xs) / max(n - 1, 1)
            self.stats[name] = (mu, max(math.sqrt(var), self.c.sigma_floor))
        for t in self.sim.cfg.tenants:
            self.stats.setdefault(t.name, (0.0, self.c.sigma_floor))
        for name, (mu, sd) in self.stats.items():
            self.thresholds[name] = {"mu": mu, "sigma": sd,
                                     "threshold": max(mu + self.c.theta * sd, self.c.min_count)}


class TenantCap(DLGuard):
    """Fair rate-limit baseline: DLGuard's per-device, per-tenant bucket alone (no reserve, no detector)."""
    name = "Tenant cap"

    def __init__(self, sim):
        super().__init__(sim)
        self.c = replace(self.c, use_bucket=True, use_reserve=False, use_detector=False)


class DCCheck(FCFS):
    """FCFS, but ignore downlink requests from any device seen breaking the 1% duty cycle.

    The server only sees received uplinks. A device is flagged once the gap between
    the end of one received uplink and the start of the next is shorter than
    (1 - tolerance) x the off-time the first one requires. Lost uplinks only make
    observed gaps longer, so an honest device is never flagged by this rule.
    """
    name = "DC check"

    def __init__(self, sim):
        super().__init__(sim)
        self.tol = sim.cfg.scheduler.dc_tolerance
        self.dc = sim.cfg.dc_device
        self.last = {}
        self.violators = {}

    def on_uplink(self, p):
        # the duty cycle applies per sub-band, so gaps are checked between uplinks in the same sub-band
        d = p.dev.id
        key = (d, getattr(p, "band1", "rx1"))
        prev = self.last.get(key)
        if prev is not None:
            end, toa = prev
            need = toa * (1.0 / self.dc - 1.0)
            if p.t0 - end < (1.0 - self.tol) * need and d not in self.violators:
                self.violators[d] = p.t0
        self.last[key] = (p.t1, p.toa)

    def decide(self, req, now):
        if req.dev.id in self.violators:
            return None
        return super().decide(req, now)


class Recorder(FCFS):
    """FCFS that also records per-window request counts for offline detector analysis."""
    name = "FCFS"

    def __init__(self, sim):
        super().__init__(sim)
        self.window_counts = defaultdict(float)
        self.trace = []

    def observe(self, req, now):
        self.window_counts[req.dev.id] += 1.0

    def on_window(self, now):
        self.trace.append((now, dict(self.window_counts)))
        self.window_counts = defaultdict(float)


class UplinkRate(FCFS):
    """FCFS, but ignore downlink requests from any device whose received uplinks in the last hour
    exceed k times its tenant's declared uplink rate (k = the bucket headroom). Retransmissions count,
    because the server sees them as frames. A flagged device stays flagged."""
    name = "Uplink-rate check"

    def __init__(self, sim):
        super().__init__(sim)
        from collections import deque
        c = sim.cfg.scheduler
        self.k = c.uplink_k if c.uplink_k is not None else c.headroom
        self.window = 3600.0
        self.seen = defaultdict(deque)
        self.violators = {}

    def on_uplink(self, p):
        d = p.dev
        q = self.seen[d.id]
        q.append(p.t0)
        while q and q[0] < p.t0 - self.window:
            q.popleft()
        limit = self.k * 3600.0 / d.tenant.period_s
        if len(q) > limit and d.id not in self.violators:
            self.violators[d.id] = p.t0

    def decide(self, req, now):
        if req.dev.id in self.violators:
            return None
        return super().decide(req, now)


class NoRx2Spill(FCFS):
    """Hypothetical policy (not taken from any server): FCFS, but a downlink may only fall back to RX2
    when the device's uplink (and so RX1) used DR0-DR2 (SF12-SF10). Fast devices are answered in RX1 or
    not at all. Note that ChirpStack's rx2_prefer_on_rx1_dr_lt does something different: it tries RX2
    *first* for slow RX1 data rates (see Rx2Prefer)."""
    name = "No RX2 spill"
    MIN_SF_FOR_RX2 = 10

    def decide(self, req, now):
        gw = self.sim.gw
        if gw.can_send("rx1", req.t_rx1, req.toa1):
            return "rx1"
        if req.sf >= self.MIN_SF_FOR_RX2 and gw.can_send("rx2", req.t_rx2, req.toa2):
            return "rx2"
        return None


class Rx2Prefer(FCFS):
    """Mimics ChirpStack v4's rx2_prefer_on_rx1_dr_lt = 3: when the RX1 data rate is below DR3
    (SF10-SF12) try RX2 first, then RX1; otherwise RX1 first, then RX2."""
    name = "RX2 preferred for slow devices"
    MIN_SF_RX2_FIRST = 10

    def decide(self, req, now):
        gw = self.sim.gw
        order = (("rx2", req.t_rx2, req.toa2), ("rx1", req.t_rx1, req.toa1)) if req.sf >= self.MIN_SF_RX2_FIRST \
            else (("rx1", req.t_rx1, req.toa1), ("rx2", req.t_rx2, req.toa2))
        for band, t, toa in order:
            if gw.can_send(band, t, toa):
                return band
        return None


class Rx1Only(FCFS):
    """FCFS restricted to RX1, as with ChirpStack's rx_window = 1 ("RX1 only")."""
    name = "RX1 only"

    def decide(self, req, now):
        if self.sim.gw.can_send("rx1", req.t_rx1, req.toa1):
            return "rx1"
        return None


class BudgetScheduler(FCFS):
    """The tenant cap built on the standalone reference implementation in ``budget.py``.

    It makes the same decisions as ``TenantCap`` (tests/test_framework.py checks this run for run), and it is the
    shortest example of how a server policy plugs into the simulator: subclass FCFS, override ``decide``."""
    name = "Tenant cap (reference)"

    def __init__(self, sim):
        super().__init__(sim)
        from .budget import DownlinkBudget, TenantProfile
        c = sim.cfg.scheduler
        self.budget = DownlinkBudget([TenantProfile.from_tenant(t) for t in sim.cfg.tenants],
                                     headroom=c.headroom, burst=c.burst_frames)

    def decide(self, req, now):
        if not self.budget.has_token(req.dev.id, req.tenant.name, now):
            return None
        w = super().decide(req, now)
        if w is not None:
            self.budget.consume(req.dev.id)
        return w


# ---------------------------------------------------------------------- registry
# A scheduler is any class built from the simulation object that implements
#   observe(req, now), on_uplink(packet), decide(req, now) -> "rx1" | "rx2" | None, on_window(now).
# Subclass FCFS to inherit no-op hooks and the regulatory check. Register new policies with
#   @register_scheduler("mypolicy")
# and select them with SchedulerConfig(kind="mypolicy") or the command line (--schedulers mypolicy).
SCHEDULERS = {
    "fcfs": FCFS,
    "ratelimit": RateLimit,
    "dlguard": DLGuard,
    "tenantcap": TenantCap,
    "budget": BudgetScheduler,
    "dccheck": DCCheck,
    "uplinkrate": UplinkRate,
    "rx2prefer": Rx2Prefer,
    "norx2spill": NoRx2Spill,
    "rx1only": Rx1Only,
}


def register_scheduler(kind):
    """Class decorator that makes a scheduler available as SchedulerConfig(kind=kind)."""
    def deco(cls):
        if kind in SCHEDULERS and SCHEDULERS[kind] is not cls:
            raise ValueError(f"scheduler {kind!r} is already registered")
        SCHEDULERS[kind] = cls
        return cls
    return deco


def make_scheduler(sim):
    k = sim.cfg.scheduler.kind
    if k == "fcfs" and sim.cfg.record_detector_trace:
        return Recorder(sim)
    if k not in SCHEDULERS:
        raise ValueError(f"unknown scheduler {k!r}; known: {', '.join(sorted(SCHEDULERS))}")
    return SCHEDULERS[k](sim)
