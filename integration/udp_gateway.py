"""A virtual LoRaWAN gateway that speaks the Semtech UDP packet-forwarder protocol (GWMP v2) to a local
ChirpStack server. It forwards authenticated uplinks (PUSH_DATA / rxpk) and receives the downlinks the
server schedules (PULL_RESP / txpk), classifying each as RX1 or RX2 and measuring its airtime.

No radio is involved. This is how a real gateway talks to ChirpStack over UDP port 1700; here the "gateway"
is a Python process, so we can drive it with exactly the traffic the paper models and read back the server's
scheduling decisions.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lorawan_sim import phy  # noqa: E402
from integration.lorawan_frame import parse_downlink  # noqa: E402

PUSH_DATA, PUSH_ACK, PULL_DATA, PULL_RESP, PULL_ACK, TX_ACK = 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
RX2_FREQ_MHZ = 869.525


def _datr_sf(datr: str) -> int:
    # "SF12BW125" -> 12
    return int(datr.split("BW")[0][2:])


@dataclass
class Downlink:
    devaddr: int
    window: str      # "rx1" | "rx2"
    sf: int
    freq: float
    airtime_s: float
    ack: bool
    delivered: bool  # False if dropped by the egress budget gate


@dataclass
class VirtualGateway:
    eui: bytes = b"\x00\x11\x22\x33\x44\x55\x66\x77"
    host: str = "127.0.0.1"
    port: int = 1700
    gate: object = None                      # optional BudgetGate; None = native ChirpStack behaviour
    downlinks: list = field(default_factory=list)
    _uplink_ctx: dict = field(default_factory=dict)   # tmst -> (freq, sf) of the uplink, to classify its downlink
    _running: bool = False

    def __post_init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)
        self._tmst = int(time.time() * 1e6) & 0xFFFFFFFF

    def start(self):
        self._running = True
        threading.Thread(target=self._rx_loop, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()
        self._pull()

    def stop(self):
        self._running = False

    # ---- protocol helpers
    def _hdr(self, ptype: int, token: bytes) -> bytes:
        return bytes([0x02]) + token + bytes([ptype])

    def _pull(self):
        token = os.urandom(2)
        self.sock.sendto(self._hdr(PULL_DATA, token) + self.eui, (self.host, self.port))

    def _keepalive(self):
        while self._running:
            self._pull()
            time.sleep(5)

    def send_uplink(self, phy_payload: bytes, sf: int, freq: float = 868.1, now_s: float | None = None) -> None:
        """Forward one uplink to the server as a real gateway would (PUSH_DATA with one rxpk)."""
        self._tmst = (self._tmst + 200000) & 0xFFFFFFFF   # advance the gateway clock between uplinks
        tmst = self._tmst
        self._uplink_ctx[tmst] = (freq, sf, now_s if now_s is not None else time.time())
        rxpk = {"rxpk": [{
            "tmst": tmst, "chan": 0, "rfch": 0, "freq": freq, "stat": 1, "modu": "LORA",
            "datr": f"SF{sf}BW125", "codr": "4/5", "lsnr": 7.0, "rssi": -60, "size": len(phy_payload),
            "data": base64.b64encode(phy_payload).decode(),
        }]}
        token = os.urandom(2)
        pkt = self._hdr(PUSH_DATA, token) + self.eui + json.dumps(rxpk).encode()
        self.sock.sendto(pkt, (self.host, self.port))

    def _rx_loop(self):
        while self._running:
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 4 or data[0] != 0x02:
                continue
            ptype = data[3]
            if ptype == PULL_RESP:
                self._handle_downlink(data[4:], token=data[1:3])

    def _handle_downlink(self, payload: bytes, token: bytes):
        try:
            txpk = json.loads(payload.decode())["txpk"]
        except Exception:
            return
        phy_bytes = base64.b64decode(txpk["data"])
        info = parse_downlink(phy_bytes)
        sf = _datr_sf(txpk["datr"])
        freq = float(txpk["freq"])
        window = "rx2" if (abs(freq - RX2_FREQ_MHZ) < 0.01 or sf == 12 and freq > 869.0) else "rx1"
        at = phy.airtime(sf, info["size"], crc=False)
        delivered = True
        if self.gate is not None:
            now = time.time()
            delivered = self.gate.allow(info["devaddr"], now)
        self.downlinks.append(Downlink(info["devaddr"], window, sf, freq, at, info["ack"], delivered))
        # Always acknowledge the PULL_RESP so the server's view stays consistent (egress gate is downstream).
        txack = self._hdr(TX_ACK, token) + self.eui + json.dumps({"txpk_ack": {"error": "NONE"}}).encode()
        try:
            self.sock.sendto(txack, (self.host, self.port))
        except OSError:
            pass

    # ---- summaries
    def summary(self) -> dict:
        d = self.downlinks
        deliv = [x for x in d if x.delivered]
        return {
            "downlinks_total": len(d),
            "delivered": len(deliv),
            "dropped_by_gate": len(d) - len(deliv),
            "rx1": sum(1 for x in deliv if x.window == "rx1"),
            "rx2": sum(1 for x in deliv if x.window == "rx2"),
            "rx2_airtime_s": round(sum(x.airtime_s for x in deliv if x.window == "rx2"), 3),
            "rx1_airtime_s": round(sum(x.airtime_s for x in deliv if x.window == "rx1"), 3),
        }

    def per_device(self) -> dict:
        out: dict[int, dict] = {}
        for x in self.downlinks:
            e = out.setdefault(x.devaddr, {"delivered": 0, "dropped": 0, "rx1": 0, "rx2": 0})
            if x.delivered:
                e["delivered"] += 1
                e[x.window] += 1
            else:
                e["dropped"] += 1
        return out
