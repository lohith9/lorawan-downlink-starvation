"""Physical layer helpers for the EU868 LoRaWAN model.

Airtime follows the formula in Semtech AN1200.13 (LoRa Modem Designer's Guide).
Receiver sensitivities are SX1276 values for a 125 kHz channel.
The path loss model is the log-distance model used by LoRaSim (Bor et al., 2016).
"""
import math

BW = 125e3
SF_RANGE = range(7, 13)
SENSITIVITY_DBM = {7: -123.0, 8: -126.0, 9: -129.0, 10: -132.0, 11: -134.5, 12: -137.0}

# LoRaSim log-distance model
PL_D0 = 127.41
D0 = 40.0
GAMMA = 2.08
SHADOW_SIGMA = 3.57

LORAWAN_OVERHEAD = 13  # MHDR(1) DevAddr(4) FCtrl(1) FCnt(2) FPort(1) MIC(4)
LORAWAN_OVERHEAD_NOPORT = 12


def symbol_time(sf, bw=BW):
    return (2 ** sf) / bw


def airtime(sf, phy_payload_bytes, crc=True, bw=BW, cr=1, n_preamble=8, explicit_header=True):
    """Time on air in seconds for one LoRa frame."""
    ts = symbol_time(sf, bw)
    de = 1 if (sf >= 11 and bw == 125e3) else 0
    h = 0 if explicit_header else 1
    num = 8 * phy_payload_bytes - 4 * sf + 28 + 16 * (1 if crc else 0) - 20 * h
    n_payload = 8 + max(math.ceil(num / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return (n_preamble + 4.25) * ts + n_payload * ts


def path_loss_db(distance_m, shadow_db=0.0):
    return PL_D0 + 10 * GAMMA * math.log10(max(distance_m, 1.0) / D0) + shadow_db


def pick_sf(rssi_dbm, margin_db=3.0):
    """Smallest SF whose sensitivity plus the margin the link can close.

    Returns None when even SF12 lacks the margin; the caller then redraws the
    device position, so every placed device has at least margin_db of link margin.
    """
    for sf in SF_RANGE:
        if rssi_dbm >= SENSITIVITY_DBM[sf] + margin_db:
            return sf
    return None
