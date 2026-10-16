"""Scenario configuration. Every number used in the paper's parameter table lives here."""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Tenant:
    name: str
    critical: bool          # critical service class (gets reserved downlink capacity)
    battery: bool           # battery powered (lifetime is reported)
    share: float            # SLA share of gateway downlink budget (fair-share scheduler)
    fraction: float         # fraction of devices that belong to this tenant
    period_s: float         # mean reporting period
    poisson: bool           # event driven (exponential gaps) or periodic
    conf_frac: float        # probability a message is sent as confirmed
    mac_prob: float         # probability a message carries LinkCheckReq
    payload: int            # application payload bytes
    cmd_rate_per_h: float = 0.0   # server-initiated commands per device per hour
    cmd_payload: int = 0


def default_tenants():
    return [
        Tenant("streetlight", True, False, 0.35, 0.25, 900, False, 0.10, 0.0, 12,
               cmd_rate_per_h=1 / 6, cmd_payload=6),
        Tenant("water", True, True, 0.35, 0.25, 1800, False, 0.10, 0.0, 10),
        Tenant("parking", False, True, 0.15, 0.30, 600, True, 0.0, 0.005, 6),
        Tenant("waste", False, True, 0.15, 0.20, 3600, False, 0.05, 0.0, 8),
    ]


@dataclass
class AttackConfig:
    n_attackers: int = 0
    mode: str = "confirmed"      # "confirmed" | "mac" | "mixed" | "join"
    sf: Optional[int] = 12       # forced SF, None keeps the device's own SF
    compliant: bool = True       # respects the 1% device duty cycle
    interval_s: float = 10.0     # target gap between frame starts when not duty-cycle bound
    jitter_s: float = 0.5        # symmetric jitter on that gap, uniform(-j, +j)
    start_spread_s: float = 120.0  # attackers start at random offsets in [0, spread)
    tenant: str = "parking"      # tenant whose credentials are abused
    payload: int = 1
    reachable_sf_only: bool = False  # pick attackers only among devices whose link supports the forced SF
    place_at_m: Optional[float] = None  # move the attacker to this distance from the gateway (no shadowing) when the attack starts


@dataclass
class SchedulerConfig:
    kind: str = "fcfs"           # "fcfs" | "ratelimit" | "tenantcap" | "dccheck" | "dlguard"
    # rate limit baseline
    rl_rate_per_h: float = 6.0
    rl_burst: float = 3.0
    # DLGuard
    headroom: float = 4.0        # device bucket = headroom x expected demand
    burst_frames: float = 3.0
    reserve: float = 0.30        # fraction of each band kept for critical tenants
    window_s: float = 600.0      # detector window
    theta: float = 4.0           # detector threshold in standard deviations
    consecutive: int = 2         # windows above threshold before quarantine
    min_count: float = 1.0       # never flag at or below this many requests per window
    sigma_floor: float = 0.25
    quarantine_rate_per_h: float = 1.0
    use_detector: bool = True
    use_reserve: bool = True
    use_bucket: bool = True
    # duty-cycle check baseline
    dc_tolerance: float = 0.05   # a gap shorter than (1 - tol) x required off-time is a violation
    uplink_k: Optional[float] = None  # uplink-rate check threshold (x declared rate); None = headroom


@dataclass
class SimConfig:
    n_devices: int = 1000
    radius_m: float = 360.0
    seed: int = 1
    duration_s: float = 5 * 3600
    t_attack_s: float = 1.5 * 3600      # when compromised devices start misbehaving
    t_measure_s: float = 1.5 * 3600     # metrics are computed over [t_measure_s, duration_s]
    t_train_start_s: float = 900.0      # detector training window; independent of t_attack_s
    t_train_end_s: float = 1.5 * 3600
    tenants: List[Tenant] = field(default_factory=default_tenants)
    attack: AttackConfig = field(default_factory=AttackConfig)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    n_channels: int = 3
    # Channel plan. "3ch": the three default EU868 channels (868.1/868.3/868.5 MHz), all in the 868.0-868.6 MHz
    # sub-band, so devices and the gateway's RX1 replies share one 1% budget (the setting of the paper).
    # "8ch": the common 8-channel EU868 plan; channels 0-2 are the default ones and channels 3-7 are
    # 867.1-867.9 MHz in the 865-868 MHz sub-band, which has its own 1% budget for the device and for the gateway's
    # RX1 replies (RX1 uses the uplink frequency). n_channels is ignored with "8ch".
    channel_plan: str = "3ch"
    # Multi-gateway cells (Oct. 16). With n_gateways = 1 the simulator is unchanged, bit for bit.
    # With G > 1 devices are placed in a disc of radius radius_m * sqrt(G) (so device density per gateway
    # stays the same when n_devices is scaled by G), gateways sit at gw_ring_frac of that radius at equal
    # angles, every gateway has its own half-duplex radio, demodulators and per-sub-band budgets, and the
    # network server answers through the gateway, among those that received the uplink, with the most
    # remaining budget (duty-cycle-based selection in the spirit of Al Mojamed, 2023).
    n_gateways: int = 1
    gw_ring_frac: float = 0.5
    tx_power_dbm: float = 14.0
    dc_device: float = 0.01
    dc_rx1_band: float = 0.01     # 868.0-868.6 MHz sub-band
    dc_rx2_band: float = 0.10     # 869.4-869.65 MHz sub-band
    rx2_sf: int = 12              # EU868 default RX2 data rate (DR0)
    # Downlink link budget. Off by default (every downlink that is sent is received, as in the paper's main runs).
    # When on, a downlink is decoded only if gateway power minus the device's path loss reaches the receiver
    # sensitivity of the downlink's SF; airtime is spent either way. RX1 (868.0-868.6 MHz) allows 25 mW e.r.p.
    # (14 dBm) and the RX2 sub-band (869.4-869.65 MHz) 500 mW (27 dBm).
    dl_link_check: bool = False
    gw_tx_dbm_rx1: float = 14.0
    gw_tx_dbm_rx2: float = 27.0
    rx1_delay_s: float = 1.0
    rx2_delay_s: float = 2.0
    rx_timeout_symbols: int = 8
    max_tx: int = 8
    capture_db: float = 6.0
    n_demodulators: int = 8
    sf_margin_db: float = 3.0     # link margin required when choosing the SF (positions are redrawn otherwise)
    sf_margin_fallback: bool = False  # v1 behaviour, kept only to explain the baseline shift: SF12 without margin
    force_sf: Optional[int] = None  # validation runs only: put every device on one SF
    join_accept_bytes: int = 33   # JoinAccept with CFList (EU868)
    join_delay1_s: float = 5.0
    join_delay2_s: float = 6.0
    # energy model (mA, mAh)
    i_tx_ma: float = 44.0
    i_rx_ma: float = 11.0
    i_sleep_ma: float = 0.002
    battery_mah: float = 2400.0
    record_detector_trace: bool = False
    record_timeseries: bool = False
    record_uplinks: bool = False    # tests only: log honest uplink start times
    ts_bin_s: float = 600.0
