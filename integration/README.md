# Live network-server integration test (ChirpStack)

This addresses the reviewers' main open point: the paper's results were simulation-only, and the attack and
the per-tenant downlink budget had not been checked against a running network server.

It is **software-only and free**. No LoRaWAN radio and no gateway hardware are needed. We do not transmit on any
real network. A virtual gateway speaks the Semtech UDP packet-forwarder protocol to a local, unmodified
ChirpStack server running in Docker, exactly as a real gateway would.

## What this test shows, and what it does not

**Shows (server behaviour, measured, not assumed):**
- ChirpStack validates authenticated confirmed uplinks from devices whose keys we hold (ABP) and schedules a
  downlink (the ACK) for each, trying RX1 first and RX2 next, with no per-device downlink rate limit. This is
  the behaviour the paper read from the source code (Section 2), now observed at run time.
- Under a duty-cycle-compliant SF7 flood from one authenticated device, the gateway's transmit capacity is the
  bottleneck, and ACKs that do not fit in RX1 are scheduled in RX2 at the slow RX2 data rate, the mechanism the
  paper models.
- The reference policy `lorawan_sim/budget.py`, placed at the server's downlink egress, denies the attacker's
  requests once its per-tenant token bucket is empty, while honest devices within their profile are unaffected.

**Does not show (still future work, stated in the paper's limitations):**
- Real radio effects: over-the-air collisions, capture, interference and true airtime. The virtual gateway
  reports the frames and timing ChirpStack schedules; it does not model the air.
- An over-the-air reproduction. That needs EU868-legal RF, which cannot be transmitted in the US (US915), so it
  needs a conducted (wired/attenuated) rig or a collaborator in an EU868 region.

The enforcement point here is the server's **downlink egress** (the budget gate sits between ChirpStack's
scheduling decision and the gateway), not a patch to ChirpStack's Rust scheduler. The decision applied is the
exact per-device token-bucket check from the paper, on the exact downlinks ChirpStack chose to send. This is
stated plainly so the paper does not overclaim a source-level integration.

## Requirements

- Docker and Docker Compose.
- Python 3.10+ with the packages in `requirements.txt` (`pip install -r integration/requirements.txt`).

## Steps

```
# 1. Bring up the official, version-pinned ChirpStack stack (MQTT 1883, gRPC API 8080, gateway UDP 1700).
bash integration/setup_chirpstack.sh          # clones chirpstack/chirpstack-docker at a pinned tag and starts it

# 2. Provision tenant, application, device profiles and ABP devices (keys we control) over the gRPC API.
python3 integration/provision.py

# 3. Run the two scenarios and write integration/results.json and a short table.
python3 integration/run_integration.py

# 4. (optional) Tear down.
bash integration/setup_chirpstack.sh down
```

Paste `integration/results.json` and the printed table back into the paper task; it folds into Section 6
(a new "Live server check" subsection) and the limitations paragraph.

## Files

- `setup_chirpstack.sh`  clone + up/down of the official ChirpStack docker stack (pinned tag).
- `lorawan_frame.py`     build authenticated LoRaWAN 1.0.x ABP uplinks (CMAC-AES128 MIC) and parse downlinks.
- `udp_gateway.py`       virtual Semtech-UDP gateway: PUSH_DATA uplinks, receive PULL_RESP downlinks, classify
                         RX1/RX2 and SF, measure airtime; optional downlink-egress budget gate.
- `provision.py`         create the tenant, app, device profiles and ABP devices via the ChirpStack gRPC API.
- `budget_gate.py`       wraps `lorawan_sim/budget.py` for the egress gate (DevAddr -> tenant).
- `run_integration.py`   orchestrates the honest + compliant-SF7-attacker scenarios, with and without the gate.
- `requirements.txt`     Python packages for this harness only.
