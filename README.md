# Downlink starvation in shared LoRaWAN cells

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23424369.svg)](https://doi.org/10.5281/zenodo.23424369)
![tests](https://github.com/lohith9/lorawan-downlink-starvation/actions/workflows/tests.yml/badge.svg)
![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

A simulator, a reference defense and the full experiment record for the paper
**"Downlink Starvation in Shared LoRaWAN Cells: Attacks by Authenticated Devices and Per-Tenant Downlink Budgets"**
(submitted to SysCom 2026).

Cities increasingly run one LoRaWAN network for many services. Every acknowledgment, MAC answer and command comes
from the gateway's transmitter, which in EU868 may be on for only 1% of each hour in the RX1 sub-band and 10% in
the RX2 sub-band. This project shows that **one device with valid keys that obeys every duty-cycle rule can use up
that budget**, and it gives operators a way to measure the risk in their own deployment and to test defenses.

## Main findings (simulation, 20 paired seeds)

| Setting | Critical ACKs within 60 s, no attack | With one compliant SF7 device |
|---|---|---|
| 3 default channels, 1000 devices, RX2 at SF12, default server (FCFS) | 87.8% | 43.5% |
| 8-channel EU868 plan | 98.8% | 64.7% (34.9% with two devices) |
| Same, with a per-tenant downlink budget | 98.8% | 98.8% |

- A duty-cycle check never flags the attacker: the rule limits a device's airtime, not its number of frames.
- Each single-knob server setting (duty-cycle check, ChirpStack-style RX2 preference, uplink-rate check, uniform
  rate limit) stops one form of the attack, and the attacker can switch to another.
- A **per-tenant downlink budget** sized from each tenant's declared traffic profile, alone or with DLGuard's
  detector, did best overall: closest to the no-attack level, or within 0.5 points of the best other setting, in
  every case the paper reports, including attackers holding a critical tenant's keys and cells with two or three
  gateways.

## Who this is for

- **City and enterprise operators**: describe your tenants in a JSON file and measure how exposed a cell is and
  what each server policy buys (`python -m lorawan_sim assess`).
- **Network-server developers**: `lorawan_sim/budget.py` is a short, dependency-free reference implementation of the
  per-tenant budget, meant to be ported.
- **Researchers**: a reproducible test bench with paired seeds, a plugin interface for new policies, and the raw
  results of every run in the paper.

## Quick start

Python 3.10 or later. The simulator uses only the standard library.

```
git clone https://github.com/lohith9/lorawan-downlink-starvation && cd lorawan-downlink-starvation
python -m lorawan_sim list
python -m lorawan_sim assess --seeds 5                                      # the paper's default cell
python -m lorawan_sim assess --scenario examples/city_8ch.json --attacker-tenant streetlight \
    --attacks none,sf7,sf7x2,swarm32 --schedulers fcfs,uplinkrate,ratelimit,tenantcap --seeds 20
```

`assess` prints ACK60 (the share of critical confirmed messages acknowledged within 60 s) for every attack and
policy, with 95% intervals, and the paired change against no attack. `pip install -e .` also installs the
`lorawan-dlsim` command.

From Python:

```python
from lorawan_sim import SimConfig, AttackConfig, SchedulerConfig, run
r = run(SimConfig(seed=1, channel_plan="8ch",
                  attack=AttackConfig(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True),
                  scheduler=SchedulerConfig(kind="tenantcap")))
print(r["ack_within_60s"], r["ul_tx_atk_per_h"])
```

## The reference defense

```python
from lorawan_sim.budget import TenantProfile, DownlinkBudget

budget = DownlinkBudget([
    TenantProfile("streetlight", period_s=900, confirmed_fraction=0.10, commands_per_hour=1/6, critical=True),
    TenantProfile("parking", period_s=600, mac_fraction=0.005),
], headroom=4.0, burst=3.0)

# in the network server, before spending gateway airtime on a downlink the device asked for:
if budget.try_acquire(dev_eui, tenant_of[dev_eui], now):
    schedule_downlink(...)
```

Each device gets a token bucket, counted in downlink frames, whose rate is `headroom` times the downlink rate its
tenant declared. The simulator's `tenantcap` policy and the reference implementation make identical decisions
(`tests/test_framework.py`).

## Layout

- `lorawan_sim/`: the simulator, standard library only.
  - `phy.py`: airtime, sensitivity, path loss, SF choice with a 3 dB margin.
  - `config.py`: every parameter and the tenant profiles. `channel_plan` is `"3ch"` (paper default) or `"8ch"`.
  - `sim.py`: devices, half-duplex gateways with rolling per-sub-band budgets, network server, energy, one or
    more gateways. Randomness comes from independent streams, so runs with the same seed are paired.
  - `schedulers.py`: server policies (FCFS, duty-cycle check, uplink-rate check, uniform rate limit, ChirpStack-style
    RX2 preference, RX1 only, tenant cap, DLGuard) and the plugin registry.
  - `budget.py`: the reference per-tenant budget. `scenario.py`: JSON scenarios. `cli.py`: the command line.
- `examples/`: `paper_default.json` and `city_8ch.json`, a template to edit.
- `experiments/run_experiments.py`: every experiment in the paper (E1 to E19, X1 to X6); `make_figures.py` builds
  the figures and `results/numbers.json`, which holds every number quoted in the paper.
- `diagrams/make_conf_architecture.py`: the paper's architecture figure, drawn from `numbers.json`.
- `results/`: raw results of all runs. `figures/`: generated figures. `tests/`: unit and regression tests.

## Reproduce the paper

```
pip install -r requirements.txt          # scipy and matplotlib, for the figures only
python -m unittest discover -s tests
python experiments/run_experiments.py    # about 30 min on 2 cores; --only E19_ runs one experiment
python experiments/make_figures.py
```

`--shard i/n` splits an experiment and `--merge NAME` joins the parts. Use a trailing underscore in `--only`
(`E1_`), because `E1` also matches `E10` to `E19`.

## Assumptions and limits

All results come from simulation. The model has one to three gateways, treats SFs as orthogonal, keeps devices
static, uses no ADR, ignores downlink collisions and models EU868 only. `dl_link_check=True` checks every downlink
against its link budget (gateway power per sub-band, receiver sensitivity at the downlink's SF): it leaves the
default results unchanged, and it shows that RX2 at SF9 only helps if the gateway sends at the 27 dBm the RX2
sub-band allows. The paper's limitations section discusses each assumption.

## Cite

See `CITATION.cff`, or cite the archive: Andra, L. S., Ryan, B., Bondada, S., Goluguri, V. S., Andra, L. S. (2026).
*Downlink Starvation in Shared LoRaWAN Cells: Simulator and Experiments.* Zenodo. doi:10.5281/zenodo.23424369 (all versions).
The paper cites v1.1.1, doi:10.5281/zenodo.23426958.

## Responsible use

This repository describes an attack so that it can be defended against. Read `SECURITY.md` before using it.

## License

MIT, see `LICENSE`.
