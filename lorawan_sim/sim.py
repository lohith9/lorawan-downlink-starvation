"""Discrete-event simulator of a single-gateway, multi-tenant LoRaWAN cell (EU868, Class A).

Modeled:
  * Pure ALOHA uplinks on 3 channels, SF7-SF12, per-device 1% duty cycle.
  * Same-channel same-SF collisions with a 6 dB capture threshold, SFs treated as orthogonal.
  * 8 demodulator paths at the gateway.
  * Half-duplex gateway: an uplink overlapping any gateway transmission is lost.
  * Gateway duty cycle as a rolling one-hour airtime budget per sub-band
    (1% for the RX1 band, 10% for the RX2 band at 869.525 MHz).
  * Class A receive windows at +1 s (RX1, same SF) and +2 s (RX2, fixed SF);
    +5 s / +6 s for JoinAccept.
  * Confirmed uplinks retransmitted up to max_tx times with a 1-3 s ACK timeout.
  * Server-initiated commands queued at the network server until the next uplink.
  * Charge-based energy model for battery-powered devices.

Randomness is split into independent streams (placement, attacker selection, and
per-device streams for traffic, channel choice, backoff, commands and attacker
behavior), all derived from the run seed. Honest traffic is therefore identical
in runs that differ only in the attack, until the attack starts to change outcomes.
"""
import heapq
import math
import random
from collections import defaultdict, deque

from . import phy
from .config import SimConfig
from .schedulers import DownlinkRequest, make_scheduler

RX1, RX2 = "rx1", "rx2"
RX1B = "rx1b"   # RX1 replies to uplinks in the 865-868 MHz sub-band (8-channel plan only)
JOIN_REQUEST_BYTES = 23   # MHDR(1) JoinEUI(8) DevEUI(8) DevNonce(2) MIC(4)


class Packet:
    __slots__ = ("dev", "ch", "sf", "rssi", "t0", "t1", "toa", "lost", "locked",
                 "confirmed", "mac", "join", "msg", "attack", "lost_g", "rx_g", "heard", "band1")


class Msg:
    __slots__ = ("t_gen", "confirmed", "mac", "join", "fcnt", "tx_count", "delivered")

    def __init__(self, t_gen, confirmed, mac, fcnt, join=False):
        self.t_gen = t_gen
        self.confirmed = confirmed
        self.mac = mac
        self.join = join
        self.fcnt = fcnt
        self.tx_count = 0
        self.delivered = False


class Device:
    def __init__(self, idx, tenant):
        self.id = idx
        self.tenant = tenant
        self.attacker = False          # will turn malicious at t_attack
        self.active_attack = False
        self.busy = False
        self.cur = None
        self.queued = None
        self.dc_ready = 0.0
        self.fcnt = 0
        self.charge_mas = 0.0          # milliamp-seconds spent in TX/RX
        self.charge_at_measure = 0.0


class Gateway:
    def __init__(self, sim, idx=0, x=0.0, y=0.0):
        self.sim = sim
        self.idx, self.x, self.y = idx, x, y
        c = sim.cfg
        bands = [RX1, RX2] + ([RX1B] if c.channel_plan == "8ch" else [])
        self.budget = {b: (c.dc_rx2_band if b == RX2 else c.dc_rx1_band) * 3600.0 for b in bands}
        self.log = {b: deque() for b in bands}
        self.sum = {b: 0.0 for b in bands}
        self.tsum = {b: defaultdict(float) for b in bands}
        self.tx = []                   # list of (start, end)
        self.airtime_by = defaultdict(float)
        self.onair = defaultdict(list) # (ch, sf) -> packets
        self.locked = []

    def _k(self, band):
        """Budget key for a receive window: RX1 replies use the sub-band of the uplink being answered."""
        return self.sim.cur_rx1_band if band == RX1 else band

    def _prune(self, band, t):
        lg = self.log[band]
        while lg and lg[0][0] < t - 3600.0:
            _, toa, tenant = lg.popleft()
            self.sum[band] -= toa
            self.tsum[band][tenant] -= toa

    def usage(self, band, t):
        band = self._k(band)
        self._prune(band, t)
        return self.sum[band]

    def tenant_usage(self, band, tenant, t):
        band = self._k(band)
        self._prune(band, t)
        return self.tsum[band][tenant]

    def busy_at(self, t, toa):
        for s, e in self.tx:
            if s < t + toa and e > t:
                return True
        return False

    def remaining(self, band, t):
        return self.budget[self._k(band)] - self.usage(band, t)

    def band_budget(self, band):
        return self.budget[self._k(band)]

    def can_send(self, band, t, toa):
        if self.usage(band, t) + toa > self.budget[self._k(band)] + 1e-9:
            return False
        return not self.busy_at(t, toa)

    def send(self, band, t, toa, tenant, attacker):
        k = self._k(band)
        self.log[k].append((t, toa, tenant))
        self.sum[k] += toa
        self.tsum[k][tenant] += toa
        self.tx.append((t, t + toa))
        if t >= self.sim.cfg.t_measure_s:
            self.airtime_by[("attacker" if attacker else "honest", band)] += toa
        self.sim.ts_add("gw_attacker" if attacker else "gw_honest", t, toa)

    def overlaps_tx(self, t0, t1):
        for s, e in self.tx:
            if s < t1 and e > t0:
                return True
        return False

    def prune_tx(self, now):
        if len(self.tx) > 64:
            self.tx = [(s, e) for s, e in self.tx if e > now - 30.0]


class Simulation:
    def __init__(self, cfg: SimConfig):
        self.cfg = cfg
        self.now = 0.0
        self.q = []
        self.seq = 0
        self._toa_cache = {}
        self.devices = []
        self.gws = self._make_gateways()
        self.gw = self.gws[0]          # schedulers use sim.gw; ns_handle points it at the chosen gateway
        self.cmd_queue = defaultdict(deque)
        self.m = defaultdict(float)            # scalar counters
        self.conf_records = []                 # (tenant, success, tx_count, latency, dropped)
        self.cmd_latency = []
        self.cmd_generated = 0
        self.ts = defaultdict(lambda: defaultdict(float))
        self.uplink_log = [] if cfg.record_uplinks else None
        if cfg.channel_plan not in ("3ch", "8ch"):
            raise ValueError("channel_plan must be '3ch' or '8ch'")
        self.plan8 = cfg.channel_plan == "8ch"
        self.n_ch = 8 if self.plan8 else cfg.n_channels
        self.cur_rx1_band = RX1
        self._last_dl_ok = True
        self._place_devices()
        self.sched = make_scheduler(self)

    # ------------------------------------------------------------------ helpers
    def stream(self, *parts):
        """Independent random stream derived from the seed and a label."""
        return random.Random(":".join(str(x) for x in (self.cfg.seed,) + parts))

    def dl_toa(self, sf, pl):
        k = ("d", sf, pl)
        if k not in self._toa_cache:
            self._toa_cache[k] = phy.airtime(sf, pl, crc=False)
        return self._toa_cache[k]

    def ul_toa(self, sf, pl):
        k = ("u", sf, pl)
        if k not in self._toa_cache:
            self._toa_cache[k] = phy.airtime(sf, pl, crc=True)
        return self._toa_cache[k]

    def at(self, t, fn, *args):
        self.seq += 1
        heapq.heappush(self.q, (t, self.seq, fn, args))

    def ts_add(self, key, t, v):
        if self.cfg.record_timeseries:
            self.ts[key][int(t // self.cfg.ts_bin_s)] += v

    def in_window(self, t):
        return t >= self.cfg.t_measure_s

    # ------------------------------------------------------------------ setup
    def _make_gateways(self):
        c = self.cfg
        G = c.n_gateways
        if G == 1:
            return [Gateway(self)]
        ring = c.gw_ring_frac * c.radius_m * math.sqrt(G)
        return [Gateway(self, g, ring * math.cos(2 * math.pi * g / G), ring * math.sin(2 * math.pi * g / G))
                for g in range(G)]

    def _place_single(self, rng):
        """Original single-gateway placement (unchanged draw order)."""
        c = self.cfg
        while True:
            r = max(10.0, c.radius_m * math.sqrt(rng.random()))
            shadow = rng.gauss(0, phy.SHADOW_SIGMA)
            rssi = c.tx_power_dbm - phy.path_loss_db(r, shadow)
            if c.force_sf is not None:
                sf = c.force_sf if rssi >= phy.SENSITIVITY_DBM[c.force_sf] + c.sf_margin_db else None
            else:
                sf = phy.pick_sf(rssi, c.sf_margin_db)
                if sf is None and c.sf_margin_fallback and rssi >= phy.SENSITIVITY_DBM[12]:
                    sf = 12
            if sf is not None:
                return r, rssi, sf

    def _place_multi(self, d, rng, idx):
        """Multi-gateway placement: uniform in a disc of radius radius_m * sqrt(G), independent shadowing per
        device-gateway link, SF chosen for the strongest gateway (the one the device's ADR would settle on)."""
        c = self.cfg
        R = c.radius_m * math.sqrt(c.n_gateways)
        while True:
            r = max(10.0, R * math.sqrt(rng.random()))
            ang = 2 * math.pi * rng.random()
            x, y = r * math.cos(ang), r * math.sin(ang)
            rssi_g = []
            for g in self.gws:
                dist = max(10.0, math.hypot(x - g.x, y - g.y))
                rssi_g.append(c.tx_power_dbm - phy.path_loss_db(dist, rng.gauss(0, phy.SHADOW_SIGMA)))
            best = max(range(len(rssi_g)), key=lambda i: rssi_g[i])
            sf = phy.pick_sf(rssi_g[best], c.sf_margin_db)
            if sf is not None:
                break
        d.dist = math.hypot(x - self.gws[best].x, y - self.gws[best].y)
        d.rssi, d.sf, d.rssi_g, d.home_gw = rssi_g[best], sf, rssi_g, best

    def _place_devices(self):
        c = self.cfg
        rng = self.stream("place")
        tenants = c.tenants
        counts = [int(round(t.fraction * c.n_devices)) for t in tenants]
        counts[-1] = c.n_devices - sum(counts[:-1])
        idx = 0
        for t, n in zip(tenants, counts):
            for _ in range(n):
                d = Device(idx, t)
                if c.n_gateways > 1:
                    self._place_multi(d, rng, idx)
                else:
                    r, rssi, sf = self._place_single(rng)
                    d.dist, d.rssi, d.sf = r, rssi, sf
                    d.rssi_g = [rssi]
                    d.home_gw = 0
                d.own_sf = d.sf
                d.rng_traffic = self.stream("traffic", idx)
                d.rng_chan = self.stream("chan", idx)
                d.rng_backoff = self.stream("backoff", idx)
                d.rng_cmd = self.stream("cmd", idx)
                d.rng_atk = self.stream("atk", idx)
                if self.plan8:
                    d.dc_ready_b = {RX1: 0.0, RX1B: 0.0}   # per sub-band duty-cycle clocks
                self.devices.append(d)
                idx += 1
        a = c.attack
        if a.n_attackers > 0:
            pool = [d for d in self.devices if d.tenant.name == a.tenant]
            if a.reachable_sf_only and a.sf is not None:
                pool = [d for d in pool if d.own_sf <= a.sf]
            if len(pool) < a.n_attackers:
                raise ValueError(f"only {len(pool)} devices of tenant {a.tenant!r} can be attackers"
                                 + (f" at SF{a.sf}" if a.reachable_sf_only else "") + f", but n_attackers={a.n_attackers}")
            for d in self.stream("attackers").sample(pool, a.n_attackers):
                d.attacker = True

    # ------------------------------------------------------------------ run
    def run(self):
        c = self.cfg
        for d in self.devices:
            t = d.tenant
            self.at(d.rng_traffic.uniform(0, t.period_s), self.gen_msg, d)
            if t.cmd_rate_per_h > 0:
                self.at(d.rng_cmd.expovariate(t.cmd_rate_per_h / 3600.0), self.gen_cmd, d)
        if c.attack.n_attackers > 0:
            self.at(c.t_attack_s, self.start_attack)
        self.at(c.t_measure_s, self.snapshot_energy)
        w = c.scheduler.window_s
        t = w
        while t <= c.duration_s:
            self.at(t, self.sched.on_window, t)
            t += w
        while self.q:
            t, _, fn, args = heapq.heappop(self.q)
            if t > c.duration_s:
                break
            self.now = t
            fn(*args)
        return self.results()

    def snapshot_energy(self):
        for d in self.devices:
            d.charge_at_measure = d.charge_mas

    # ------------------------------------------------------------------ traffic
    def _counts_for_ack(self, d, msg):
        return (msg.confirmed and d.tenant.critical and not d.attacker and self.in_window(msg.t_gen)
                and msg.t_gen < self.cfg.duration_s - 1800)

    def gen_msg(self, d):
        t = d.tenant
        r = d.rng_traffic
        nxt = r.expovariate(1.0 / t.period_s) if t.poisson else t.period_s * r.uniform(0.95, 1.05)
        self.at(self.now + nxt, self.gen_msg, d)
        conf = r.random() < t.conf_frac
        mac = r.random() < t.mac_prob
        if d.active_attack:
            return
        d.fcnt += 1
        msg = Msg(self.now, conf, mac, d.fcnt)
        if self.in_window(self.now):
            self.m["msgs_generated"] += 1
            self.m[f"gen_{t.name}"] += 1
            if msg.confirmed:
                self.m["conf_generated"] += 1
        if d.busy:
            old = d.queued
            if old is not None:
                if self.in_window(self.now):
                    self.m["msgs_dropped_busy"] += 1
                if self._counts_for_ack(d, old):
                    # an overwritten critical confirmed message is a failure, not a missing sample
                    self.m["crit_conf_dropped_busy"] += 1
                    self.conf_records.append((d.tenant.name, False, 0, float("nan"), True, d.home_gw))
            d.queued = msg
            return
        self.begin_msg(d, msg)

    def gen_cmd(self, d):
        self.at(self.now + d.rng_cmd.expovariate(d.tenant.cmd_rate_per_h / 3600.0), self.gen_cmd, d)
        if d.active_attack:
            return
        self.cmd_queue[d.id].append(self.now)
        if self.in_window(self.now):
            self.cmd_generated += 1

    def begin_msg(self, d, msg):
        d.busy = True
        d.cur = msg
        self.request_tx(d, self.now)

    def request_tx(self, d, earliest):
        t = max(earliest, d.dc_ready)    # with "8ch", dc_ready is the earliest time any sub-band is free
        self.at(t, self.tx_start, d)

    # ------------------------------------------------------------------ attack
    def start_attack(self):
        a = self.cfg.attack
        for d in self.devices:
            if d.attacker:
                d.active_attack = True
                d.queued = None
                if a.place_at_m is not None:
                    assert self.cfg.n_gateways == 1, "place_at_m is only defined for one gateway"
                    # the attacker holds the keys and can move the device (or use its own radio) near the gateway
                    d.rssi = self.cfg.tx_power_dbm - phy.path_loss_db(a.place_at_m, 0.0)
                    d.dist = a.place_at_m
                    d.rssi_g = [d.rssi]
                if a.sf is not None:
                    d.sf = a.sf
                if not d.busy:
                    # attackers start at random offsets so they do not collide with each other
                    self.at(self.now + d.rng_atk.uniform(0, a.start_spread_s), self.attack_tx, d)

    def attack_tx(self, d):
        a = self.cfg.attack
        d.busy = True
        d.fcnt += 1
        join = False
        if a.mode == "confirmed":
            conf, mac = True, False
        elif a.mode == "mac":
            conf, mac = False, True
        elif a.mode == "join":
            conf, mac, join = False, False, True
        else:
            conf, mac = d.rng_atk.random() < 0.5, True
        earliest = self.now if not a.compliant else max(self.now, d.dc_ready)
        d.cur = Msg(earliest, conf, mac, d.fcnt, join=join)
        self.at(earliest, self.tx_start, d)

    # ------------------------------------------------------------------ uplink
    def tx_start(self, d):
        c = self.cfg
        msg = d.cur
        attack = d.active_attack
        if msg.join:
            pl = JOIN_REQUEST_BYTES
        else:
            payload = c.attack.payload if attack else d.tenant.payload
            fopts = (2 if (attack and msg.mac) else (1 if msg.mac else 0))
            pl = phy.LORAWAN_OVERHEAD + payload + fopts
        toa = self.ul_toa(d.sf, pl)
        p = Packet()
        if self.plan8:
            # pick uniformly among the channels whose sub-band is free now (channels 0-2: 868.x, 3-7: 867.x)
            free = [ch for ch in range(8) if d.dc_ready_b[RX1 if ch < 3 else RX1B] <= self.now + 1e-9]
            ch = free[d.rng_chan.randrange(len(free))]
            band1 = RX1 if ch < 3 else RX1B
        else:
            ch, band1 = d.rng_chan.randrange(c.n_channels), RX1
        p.dev, p.ch, p.sf, p.rssi = d, ch, d.sf, d.rssi
        p.band1 = band1
        p.t0, p.t1, p.toa = self.now, self.now + toa, toa
        p.lost, p.locked = False, True
        p.confirmed, p.mac, p.join, p.msg, p.attack = msg.confirmed, msg.mac, msg.join, msg, attack
        if self.uplink_log is not None and not attack:
            self.uplink_log.append((d.id, round(p.t0, 9)))
        if c.n_gateways == 1:
            gw = self.gws[0]
            # demodulator availability
            gw.locked = [x for x in gw.locked if x.t1 > p.t0]
            if len(gw.locked) >= c.n_demodulators:
                p.locked = False
                p.lost = True
            else:
                gw.locked.append(p)
            # collisions on the same channel and SF, with capture
            lst = [x for x in gw.onair[(p.ch, p.sf)] if x.t1 > p.t0]
            for o in lst:
                if o.rssi - p.rssi < c.capture_db:
                    p.lost = True
                if p.rssi - o.rssi < c.capture_db:
                    o.lost = True
            lst.append(p)
            gw.onair[(p.ch, p.sf)] = lst
        else:
            self._receive_multi(p, d)
        msg.tx_count += 1
        d.charge_mas += toa * c.i_tx_ma
        if self.plan8:
            d.dc_ready_b[p.band1] = p.t1 + toa * (1.0 / c.dc_device - 1.0)
            d.dc_ready = min(d.dc_ready_b.values())
        else:
            d.dc_ready = p.t1 + toa * (1.0 / c.dc_device - 1.0)
        if self.in_window(self.now):
            key = "atk" if attack else "hon"
            self.m[f"ul_tx_{key}"] += 1
            self.m[f"ul_airtime_{key}"] += toa
            if not attack:
                self.m[f"ul_tx_{d.tenant.name}"] += 1
        self.at(p.t1, self.tx_end, p)

    def _receive_multi(self, p, d):
        """Reception at every gateway: own demodulators, own collision list, rssi of this link.
        A frame below a gateway's sensitivity is neither received nor counted as interference there."""
        c = self.cfg
        p.rx_g = list(d.rssi_g)
        p.lost_g = []
        p.locked = True
        for g in self.gws:
            rs = p.rx_g[g.idx]
            if rs < phy.SENSITIVITY_DBM[p.sf]:
                p.lost_g.append(True)
                continue
            lost = False
            g.locked = [x for x in g.locked if x.t1 > p.t0]
            if len(g.locked) >= c.n_demodulators:
                lost = True
            else:
                g.locked.append(p)
            lst = [x for x in g.onair[(p.ch, p.sf)] if x.t1 > p.t0]
            for o in lst:
                ors = o.rx_g[g.idx]
                if ors - rs < c.capture_db:
                    lost = True
                if rs - ors < c.capture_db:
                    o.lost_g[g.idx] = True
            lst.append(p)
            g.onair[(p.ch, p.sf)] = lst
            p.lost_g.append(lost)
        p.lost = all(p.lost_g)

    def pick_gateway(self, gws, req):
        """Duty-cycle-based selection among the gateways that heard the uplink: prefer a gateway that can
        send in RX1 now, then the most remaining RX1 budget, then RX2 the same way."""
        return max(gws, key=lambda g: (g.can_send(RX1, req.t_rx1, req.toa1), g.remaining(RX1, req.t_rx1),
                                       g.can_send(RX2, req.t_rx2, req.toa2), g.remaining(RX2, req.t_rx2), -g.idx))

    def tx_end(self, p):
        c = self.cfg
        d = p.dev
        if c.n_gateways == 1:
            gw = self.gws[0]
            received = (not p.lost) and p.rssi >= phy.SENSITIVITY_DBM[p.sf] and not gw.overlaps_tx(p.t0, p.t1)
            deaf = (not p.lost) and gw.overlaps_tx(p.t0, p.t1)
            gw.prune_tx(self.now)
            p.heard = [0] if received else []
        else:
            p.heard = [g.idx for g in self.gws if not p.lost_g[g.idx] and not g.overlaps_tx(p.t0, p.t1)]
            received = bool(p.heard)
            deaf = (not received) and any(not p.lost_g[g.idx] and g.overlaps_tx(p.t0, p.t1) for g in self.gws)
            for g in self.gws:
                g.prune_tx(self.now)
        win = self.in_window(p.t0)
        if not p.attack:
            self.ts_add("ul_tx_hon", p.t0, 1)
            self.ts_add("ul_rx_hon", p.t0, received)
        if win and not p.attack and c.n_gateways > 1:
            self.m["heard_sum"] += len(p.heard)
            self.m["heard_n"] += 1
        if win and not p.attack:
            self.m["ul_rx_hon"] += received
            self.m[f"ul_rx_{d.tenant.name}"] += received
            self.m["ul_lost_deaf_hon"] += deaf
            self.m["ul_lost_coll_hon"] += p.lost
            if received and not p.msg.delivered:
                self.m[f"delivered_{d.tenant.name}"] += 1
        if received:
            p.msg.delivered = True
            self.sched.on_uplink(p)
        dl = None
        if received:
            dl = self.ns_handle(p)
            if dl is not None and not self._last_dl_ok:
                dl = None        # sent but too weak to decode: the device hears nothing in either window
        d1 = c.join_delay1_s if p.join else c.rx1_delay_s
        d2 = c.join_delay2_s if p.join else c.rx2_delay_s
        # Class A receive windows (energy and timing)
        if dl == RX1:
            rx_time = self._last_dl_toa
            rx_end = p.t1 + d1 + rx_time
        elif dl == RX2:
            rx_time = phy.symbol_time(p.sf) * c.rx_timeout_symbols + self._last_dl_toa
            rx_end = p.t1 + d2 + self._last_dl_toa
        else:
            rx_time = phy.symbol_time(p.sf) * c.rx_timeout_symbols + phy.symbol_time(c.rx2_sf) * c.rx_timeout_symbols
            rx_end = p.t1 + d2 + phy.symbol_time(c.rx2_sf) * c.rx_timeout_symbols
        d.charge_mas += rx_time * c.i_rx_ma
        self.at(rx_end, self.after_rx, d, p.msg, dl is not None)

    def after_rx(self, d, msg, got_dl):
        c = self.cfg
        if d.active_attack:
            a = c.attack
            d.busy = False
            if a.compliant:
                nxt = self.now                      # attack_tx then waits for the duty-cycle off-time
            else:
                # target gap between frame starts, with small symmetric jitter; never earlier than
                # the end of the current Class A cycle
                nxt = max(self.now, msg.t_gen + a.interval_s + d.rng_atk.uniform(-a.jitter_s, a.jitter_s))
            self.at(nxt, self.attack_tx, d)
            return
        if msg.confirmed and not got_dl and msg.tx_count < c.max_tx:
            self.request_tx(d, self.now + d.rng_backoff.uniform(1.0, 3.0))
            return
        # message finished
        if self._counts_for_ack(d, msg):
            self.conf_records.append((d.tenant.name, got_dl, msg.tx_count, self.now - msg.t_gen, False, d.home_gw))
        d.busy = False
        d.cur = None
        if d.queued is not None:
            m2 = d.queued
            d.queued = None
            self.begin_msg(d, m2)

    # ------------------------------------------------------------------ network server
    def ns_handle(self, p):
        c = self.cfg
        d = p.dev
        has_ack = p.confirmed
        has_mac = p.mac
        has_join = p.join
        cmdq = self.cmd_queue.get(d.id)
        has_cmd = bool(cmdq) and not has_join
        if not (has_ack or has_mac or has_cmd or has_join):
            return None
        if has_join:
            pl = c.join_accept_bytes
            d1, d2 = c.join_delay1_s, c.join_delay2_s
        else:
            pl = phy.LORAWAN_OVERHEAD_NOPORT
            if has_mac:
                pl += 9 if p.attack else 3          # LinkCheckAns (3) + DeviceTimeAns (6)
            if has_cmd:
                pl += 1 + d.tenant.cmd_payload
            d1, d2 = c.rx1_delay_s, c.rx2_delay_s
        # the server cannot tell an insider from its tenant, so it keeps the tenant's class
        req = DownlinkRequest(dev=d, tenant=d.tenant, critical=d.tenant.critical,
                              t_rx1=p.t1 + d1, t_rx2=p.t1 + d2,
                              toa1=self.dl_toa(p.sf, pl), toa2=self.dl_toa(c.rx2_sf, pl),
                              has_ack=has_ack, has_mac=has_mac, has_cmd=has_cmd, has_join=has_join,
                              fcnt=p.msg.fcnt, retx=p.msg.tx_count > 1, sf=p.sf)
        self.cur_rx1_band = p.band1
        self.gw = self.gws[0] if c.n_gateways == 1 else self.pick_gateway([self.gws[i] for i in p.heard], req)
        self.sched.observe(req, self.now)
        win = self.sched.decide(req, self.now)
        win_flag = self.in_window(p.t0)
        if win_flag:
            self.m["dl_req_atk" if p.attack else "dl_req_hon"] += 1
            if not p.attack:
                self.m[f"dl_req_{d.tenant.name}"] += 1
        if win is None:
            if win_flag:
                self.m["dl_denied_atk" if p.attack else "dl_denied_hon"] += 1
            return None
        t = req.t_rx1 if win == RX1 else req.t_rx2
        toa = req.toa1 if win == RX1 else req.toa2
        self.gw.send(win, t, toa, d.tenant.name, p.attack)
        self._last_dl_toa = toa
        if win_flag:
            self.m["dl_sent_atk" if p.attack else "dl_sent_hon"] += 1
        if c.dl_link_check:
            # path loss of this device-gateway link, from the uplink RSSI (links are reciprocal; shadowing is static)
            ul_rssi = d.rssi if c.n_gateways == 1 else d.rssi_g[self.gw.idx]
            pl = c.tx_power_dbm - ul_rssi
            gw_dbm = c.gw_tx_dbm_rx1 if win == RX1 else c.gw_tx_dbm_rx2
            dl_sf = p.sf if win == RX1 else c.rx2_sf
            self._last_dl_ok = gw_dbm - pl >= phy.SENSITIVITY_DBM[dl_sf]
            if not self._last_dl_ok:
                if win_flag:
                    self.m["dl_undecodable_atk" if p.attack else "dl_undecodable_hon"] += 1
                if has_cmd:
                    cmdq.popleft()           # the server considers the command sent; it is lost
                return win
        if has_cmd:
            tg = cmdq.popleft()
            if self.in_window(tg):
                self.cmd_latency.append(t - tg)
        return win

    # ------------------------------------------------------------------ results
    def _airtime_by(self):
        if len(self.gws) == 1:
            return self.gws[0].airtime_by
        tot = defaultdict(float)
        for g in self.gws:
            for k, v in g.airtime_by.items():
                tot[k] += v
        return tot

    def results(self):
        c = self.cfg
        m = dict(self.m)
        honest = [d for d in self.devices if not d.attacker]
        n_hon = {t.name: sum(1 for d in honest if d.tenant.name == t.name) for t in c.tenants}
        span_h = (c.duration_s - c.t_measure_s) / 3600.0
        crit = [r for r in self.conf_records if r[0] in {t.name for t in c.tenants if t.critical}]
        done = [r for r in crit if not r[4]]
        ok = [r for r in done if r[1]]
        n_att = c.attack.n_attackers
        res = {
            "ack_ratio_critical": (len(ok) / len(crit)) if crit else float("nan"),
            "tx_per_conf_msg": (sum(r[2] for r in done) / len(done)) if done else float("nan"),
            "conf_latency_mean": (sum(r[3] for r in ok) / len(ok)) if ok else float("nan"),
            "ack_within_60s": (sum(1 for r in ok if r[3] <= 60.0) / len(crit)) if crit else float("nan"),
            "crit_conf_msgs": len(crit),
            "crit_conf_dropped_busy": int(m.get("crit_conf_dropped_busy", 0)),
            "ul_coll_frac": m.get("ul_lost_coll_hon", 0) / max(1, m.get("ul_tx_hon", 0)),
            "ul_pdr_honest": m.get("ul_rx_hon", 0) / max(1, m.get("ul_tx_hon", 0)),
            "deaf_loss_frac": m.get("ul_lost_deaf_hon", 0) / max(1, m.get("ul_tx_hon", 0)),
            "dl_grant_honest": m.get("dl_sent_hon", 0) / max(1, m.get("dl_req_hon", 0)),
            "dl_grant_attacker": m.get("dl_sent_atk", 0) / m["dl_req_atk"] if m.get("dl_req_atk") else float("nan"),
            "cmd_delivered_frac": len(self.cmd_latency) / max(1, self.cmd_generated),
            "cmd_latency_median": sorted(self.cmd_latency)[len(self.cmd_latency) // 2] if self.cmd_latency else float("nan"),
            "cmd_latency_p95": sorted(self.cmd_latency)[int(0.95 * (len(self.cmd_latency) - 1))] if self.cmd_latency else float("nan"),
            "gw_airtime": {f"{k[0]}_{k[1]}": v / span_h for k, v in self._airtime_by().items()},
            "raw": m,
        }
        # measured attacker rates, per attacker per hour
        if n_att:
            for k in ("ul_tx_atk", "dl_req_atk", "dl_sent_atk"):
                res[f"{k}_per_h"] = m.get(k, 0) / span_h / n_att
        # per-tenant uplink PDR, downlink request rate per device, and energy per delivered message
        per = {}
        for t in c.tenants:
            name = t.name
            charge = sum(d.charge_mas - d.charge_at_measure for d in honest if d.tenant.name == name)
            dlv = m.get(f"delivered_{name}", 0)
            per[name] = {
                "pdr": m.get(f"ul_rx_{name}", 0) / max(1, m.get(f"ul_tx_{name}", 0)),
                "dl_req_per_dev_h": m.get(f"dl_req_{name}", 0) / max(1, n_hon[name]) / span_h,
                "charge_mas_per_delivered": (charge / dlv) if dlv else float("nan"),
                "delivered": dlv,
                "generated": m.get(f"gen_{name}", 0),
            }
        res["per_tenant"] = per
        if c.n_gateways > 1:
            # ACK60 for critical devices whose home gateway also serves an attacker, and for the rest
            atk_cells = {d.home_gw for d in self.devices if d.attacker}
            for label, keep in (("attacker_cells", lambda g: g in atk_cells), ("other_cells", lambda g: g not in atk_cells)):
                grp = [r for r in crit if keep(r[5])]
                okg = [r for r in grp if r[1] and not r[4] and r[3] <= 60.0]
                res[f"ack60_{label}"] = (len(okg) / len(grp)) if grp else float("nan")
            res["n_gateways_heard_mean"] = m.get("heard_sum", 0) / max(1, m.get("heard_n", 0))
        q = getattr(self.sched, "quarantined", None)
        if q is not None:
            atk = {d.id for d in self.devices if d.attacker}
            crit_ids = {d.id for d in self.devices if d.tenant.critical}
            res["detected"] = sum(1 for i in q if i in atk)
            res["false_quarantine"] = sum(1 for i in q if i not in atk)
            res["false_quarantine_critical"] = sum(1 for i in q if i not in atk and i in crit_ids)
            res["detect_delay"] = [q[i] - c.t_attack_s for i in q if i in atk]
            res["detector_thresholds"] = getattr(self.sched, "thresholds", {})
        if hasattr(self.sched, "violators"):
            atk = {d.id for d in self.devices if d.attacker}
            v = self.sched.violators
            res["dc_flagged_attackers"] = sum(1 for i in v if i in atk)
            res["dc_flagged_honest"] = sum(1 for i in v if i not in atk)
        if hasattr(self.sched, "trace") and c.record_detector_trace:
            res["trace"] = self.sched.trace
            res["tenant_of"] = {d.id: d.tenant.name for d in self.devices}
            res["attackers"] = [d.id for d in self.devices if d.attacker]
        if c.record_timeseries:
            res["timeseries"] = {k: dict(v) for k, v in self.ts.items()}
        if self.uplink_log is not None:
            res["uplink_log"] = self.uplink_log
        res["sf_mix"] = {str(sf): sum(1 for d in self.devices if d.own_sf == sf) / len(self.devices) for sf in phy.SF_RANGE}
        return res


def run(cfg: SimConfig):
    return Simulation(cfg).run()
