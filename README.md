# Downlink starvation in shared LoRaWAN cells

Simulator, experiment scripts and raw results for the paper
"Downlink Starvation in Shared LoRaWAN Cells: Attacks by Authenticated Devices and Per-Tenant Downlink Budgets"
(SysCom 2026).

The code models one EU868 LoRaWAN gateway shared by several tenants (streetlights, water sensors,
parking and waste bins). It measures what happens when one or more devices with valid keys send
frames that each ask the gateway for a reply, and it compares several network-server policies for
answering those requests.

## Layout

- `lorawan_sim/`: discrete-event simulator of an EU868 Class A network with one or more gateways
  - `phy.py`: airtime, receiver sensitivity, path loss, SF choice with a 3 dB margin
  - `config.py`: every parameter used in the paper, including the tenant profiles
  - `sim.py`: devices, half-duplex gateway with rolling duty-cycle budgets per sub-band, network server.
    Randomness comes from independent streams, so runs with the same seed have identical honest traffic.
  - `schedulers.py`: network-server policies: FCFS, duty-cycle check, uplink-rate check, uniform rate limit,
    ChirpStack-style RX2 preference, no-RX2-spill, RX1 only, per-tenant cap, and DLGuard
    (per-tenant cap + critical reserve + detector)
- `experiments/run_experiments.py`: runs all experiments and writes `results/*.json`
- `experiments/make_figures.py`: builds the figures and `results/numbers.json` (every number quoted in the paper, with paired 95% intervals)
- `diagrams/`: architecture, timeline and flowchart sources (needs Graphviz `dot`)
- `tests/`: unit tests (airtime, duty cycle, SF margin, paired randomness)
- `results/`: raw results of the runs reported in the paper
- `figures/`: generated figures

## Reproduce

Python 3.10.

```
pip install -r requirements.txt
python -m unittest discover -s tests
python experiments/run_experiments.py      # about 25 min on 2 cores; --only E1_,E2_ runs a subset
python experiments/make_figures.py
```

A single run:

```python
from lorawan_sim import SimConfig, AttackConfig, SchedulerConfig, run
r = run(SimConfig(seed=1,
                  attack=AttackConfig(n_attackers=1, compliant=True, sf=7, reachable_sf_only=True),
                  scheduler=SchedulerConfig(kind="fcfs")))
print(r["ack_within_60s"])
```

## Assumptions

A small number of gateways (1 to 3 in the paper), orthogonal spreading factors, static devices, no adaptive data rate, loss-free downlinks,
and assumed radio currents for energy. These are discussed in the paper's limitations section.
All results come from simulation; nothing was transmitted on a real network.

## License

MIT, see `LICENSE`.
