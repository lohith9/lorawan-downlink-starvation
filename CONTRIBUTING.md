# Contributing

Contributions that make the model more realistic or add defenses are welcome. The aim is a shared, reproducible
test bench on which operators, vendors and researchers compare downlink policies under the same attacks.

## Add a server policy

A policy is a class that receives the simulation object and answers each downlink request with `"rx1"`, `"rx2"` or
`None`. Subclass `FCFS` to inherit the regulatory duty-cycle and half-duplex checks:

```python
from lorawan_sim import FCFS, register_scheduler

@register_scheduler("myqueue")
class MyPolicy(FCFS):
    """One line that `python -m lorawan_sim list` shows."""

    def on_uplink(self, packet):          # every received uplink (optional)
        pass

    def decide(self, req, now):           # req: DownlinkRequest (dev, tenant, critical, toa1, toa2, has_ack, ...)
        if req.critical:
            return super().decide(req, now)
        return None
```

Then `SchedulerConfig(kind="myqueue")`, or `python -m lorawan_sim assess --schedulers fcfs,myqueue` once the module
that defines it is imported. Compare it with `tenantcap` on the paper's attacks (`none,sf7,sf7x2,swarm32`) with at
least 20 seeds before claiming an improvement, and report paired differences.

## Model your own deployment

Copy `examples/city_8ch.json`, change the tenants and the radio settings, and run
`python -m lorawan_sim assess --scenario my_city.json --seeds 20`. Unknown fields are rejected on purpose.

## Change the simulator

- Keep the default model bit-identical unless the change is a bug fix. `tests/test_framework.py::RegressionTest`
  fails when the default behavior changes; if that is intended, say so in the pull request and rerun
  `experiments/run_experiments.py` and `experiments/make_figures.py`.
- New behavior goes behind a configuration field whose default keeps the old behavior (see `channel_plan`).
- Add a unit test. Run `python -m unittest discover -s tests` before opening a pull request.

## Ideas we would like help with

- Non-orthogonal SFs, ADR, mobility and downlink collisions.
- Other regions: US915 (no duty cycle, only the half-duplex radio limits downlinks), AS923, IN865.
- Learning tenant profiles from traffic without letting an attacker poison them.
- Ports of `lorawan_sim/budget.py` to network servers.
