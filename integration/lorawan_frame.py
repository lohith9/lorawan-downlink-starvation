"""Build and parse LoRaWAN 1.0.x frames for the ChirpStack integration test.

Only what the harness needs: authenticated ABP uplinks (Confirmed/Unconfirmed Data Up) with a correct
AES-CMAC MIC and AES-CTR-style FRMPayload encryption, and a small parser for the downlinks ChirpStack
returns. This follows the LoRaWAN 1.0.x MAC layer (single NwkSKey). It does not implement OTAA, FOpts,
or 1.1 key separation, which the test does not use.

References for the message integrity code and payload encryption are the LoRaWAN 1.0.x specification,
Sections 4.3.3 (MIC) and 4.3.3.1 (FRMPayload encryption).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

# MType values in the MHDR (bits 7..5).
MTYPE_UNCONF_UP = 0b010
MTYPE_CONF_UP = 0b100
MTYPE_UNCONF_DOWN = 0b011
MTYPE_CONF_DOWN = 0b101
_FCTRL_ACK = 0x20


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 (ECB is the LoRaWAN primitive)
    return enc.update(block) + enc.finalize()


def _cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(msg)
    return c.finalize()


def _crypt_frmpayload(key: bytes, devaddr: int, fcnt: int, direction: int, payload: bytes) -> bytes:
    """AES-CTR-style FRMPayload (de)cipher; the same operation encrypts and decrypts."""
    out = bytearray()
    for i in range(0, len(payload), 16):
        block = i // 16 + 1
        a = bytes([0x01, 0, 0, 0, 0, direction]) + struct.pack("<I", devaddr) + struct.pack("<I", fcnt) + bytes([0x00, block])
        s = _aes_ecb(key, a)
        chunk = payload[i:i + 16]
        out += bytes(x ^ y for x, y in zip(chunk, s))
    return bytes(out)


def _mic(nwkskey: bytes, devaddr: int, fcnt: int, direction: int, msg: bytes) -> bytes:
    b0 = bytes([0x49, 0, 0, 0, 0, direction]) + struct.pack("<I", devaddr) + struct.pack("<I", fcnt) + bytes([0x00, len(msg)])
    return _cmac(nwkskey, b0 + msg)[:4]


@dataclass
class Device:
    name: str
    tenant: str
    devaddr: int          # 32-bit
    nwkskey: bytes        # 16 bytes
    appskey: bytes        # 16 bytes
    fcnt_up: int = 0

    def build_uplink(self, payload: bytes = b"\x01", fport: int = 1, confirmed: bool = True) -> bytes:
        """Return the PHYPayload bytes for one uplink, and advance the uplink frame counter."""
        fcnt = self.fcnt_up
        mhdr = bytes([(MTYPE_CONF_UP if confirmed else MTYPE_UNCONF_UP) << 5])
        fctrl = 0x00
        fhdr = struct.pack("<I", self.devaddr) + bytes([fctrl]) + struct.pack("<H", fcnt & 0xFFFF)
        key = self.appskey if fport > 0 else self.nwkskey
        enc = _crypt_frmpayload(key, self.devaddr, fcnt, 0, payload)
        msg = mhdr + fhdr + bytes([fport]) + enc
        phy = msg + _mic(self.nwkskey, self.devaddr, fcnt, 0, msg)
        self.fcnt_up += 1
        return phy


def parse_downlink(phy: bytes) -> dict:
    """Pull the fields the harness needs from a downlink PHYPayload."""
    mhdr = phy[0]
    mtype = mhdr >> 5
    devaddr = struct.unpack("<I", phy[1:5])[0]
    fctrl = phy[5]
    fcnt = struct.unpack("<H", phy[6:8])[0]
    return {
        "mtype": mtype,
        "confirmed_down": mtype == MTYPE_CONF_DOWN,
        "ack": bool(fctrl & _FCTRL_ACK),
        "devaddr": devaddr,
        "fcnt": fcnt,
        "size": len(phy),
    }


if __name__ == "__main__":
    # Round-trip self-check: MIC verifies and FRMPayload decrypts to the original.
    d = Device("t", "parking", 0x01020304, bytes(range(16)), bytes(range(16, 32)))
    phy = d.build_uplink(b"hello", fport=1, confirmed=True)
    mhdr, body, mic = phy[:1], phy[1:-4], phy[-4:]
    devaddr = struct.unpack("<I", body[0:4])[0]
    recomputed = _mic(d.nwkskey, devaddr, 0, 0, mhdr + body)
    assert recomputed == mic, "MIC mismatch"
    fport = body[7]
    dec = _crypt_frmpayload(d.appskey, devaddr, 0, 0, body[8:])
    assert dec == b"hello", f"decrypt mismatch: {dec!r}"
    print("lorawan_frame self-check OK (MIC verifies, FRMPayload round-trips)")
