"""Vendor-private payload codecs that are not part of the ZCL.

* Aqara/Xiaomi structured reports: attribute 0xFF01 on the Basic cluster and
  0x00F7 on the private cluster 0xFCC0 carry a list of ``tag, type, value``
  entries (ZCL-typed values); attribute 0xFF02 is a ZCL struct whose second
  element is the battery voltage.  Only the tag numbers are vendor-defined —
  what a tag *means* depends on the model and is resolved in ``quirks``.
* Tuya datapoints (cluster 0xEF00): ``dataReport``/``dataResponse`` frames
  carry one or more datapoints with a vendor-defined id, a type and a
  big-endian value.

Everything here is a pure function over bytes and is unit-tested without hardware.
"""

from __future__ import annotations

from typing import Any

from .types import DataType, ZclDecodeError, decode_value

# ---------------------------------------------------------------------------
# Aqara / Xiaomi (manufacturer "LUMI")
# ---------------------------------------------------------------------------

LUMI_MANUFACTURER_CODE = 0x115F
LUMI_ATTR_REPORT_BASIC = 0xFF01      # Basic cluster, type string/octstr → TLV list
LUMI_ATTR_REPORT_STRUCT = 0xFF02     # Basic cluster, type struct
LUMI_ATTR_REPORT_PRIVATE = 0x00F7    # cluster 0xFCC0, type octstr → TLV list

# Tags with a model-independent meaning
LUMI_TAG_BATTERY_MV = 0x01
LUMI_TAG_DEVICE_TEMPERATURE = 0x03
LUMI_TAG_POWER_OUTAGE_COUNT = 0x05
LUMI_TAG_PARENT_NWK = 0x0A
LUMI_TAG_ILLUMINANCE = 0x0B
LUMI_TAG_ENERGY = 0x95
LUMI_TAG_VOLTAGE = 0x96
LUMI_TAG_CURRENT = 0x97
LUMI_TAG_POWER = 0x98


def decode_lumi_tlv(raw: bytes | None, *, length_prefixed: bool = False) -> dict[int, Any]:
    """Decode a ``tag, ZCL type, value`` list. Stops at the first malformed entry
    and returns what was parsed so far (real reports occasionally carry padding).
    ``length_prefixed`` is for the verbatim frame bytes of a string attribute."""
    if not raw:
        return {}
    data = bytes(raw)
    if length_prefixed:
        if data[0] == 0xFF or data[0] > len(data) - 1:
            return {}
        data = data[1:1 + data[0]]
    out: dict[int, Any] = {}
    o = 0
    while o + 2 <= len(data):
        tag, dtype = data[o], data[o + 1]
        o += 2
        try:
            value, o = decode_value(dtype, data, o)
        except (ZclDecodeError, ValueError):
            break
        out[tag] = value
    return out


def decode_lumi_struct(items: Any) -> dict[int, Any]:
    """Attribute 0xFF02 (older sensors): struct ``[state?, battery_mV, ...]``."""
    if not isinstance(items, list) or len(items) < 2:
        return {}
    out: dict[int, Any] = {}
    if isinstance(items[1], (int, float)) and not isinstance(items[1], bool):
        out[LUMI_TAG_BATTERY_MV] = int(items[1])
    return out


def lumi_battery_percent(mv: int, *, vmin: int = 2850, vmax: int = 3000) -> float:
    """CR2032/CR2450 cells: the previous setup used a linear 2.85–3.0 V window."""
    pct = (mv - vmin) / (vmax - vmin) * 100
    return float(max(0, min(100, round(pct))))


def lumi_common_state(tags: dict[int, Any]) -> dict[str, Any]:
    """The model-independent part of an Aqara report."""
    out: dict[str, Any] = {}
    mv = tags.get(LUMI_TAG_BATTERY_MV)
    if isinstance(mv, int) and 1000 < mv < 4000:
        out["voltage"] = mv
        out["battery"] = lumi_battery_percent(mv)
    t = tags.get(LUMI_TAG_DEVICE_TEMPERATURE)
    if isinstance(t, int) and -40 <= t <= 125:
        out["device_temperature"] = t
    n = tags.get(LUMI_TAG_POWER_OUTAGE_COUNT)
    if isinstance(n, int):
        out["power_outage_count"] = max(0, n - 1)
    e = tags.get(LUMI_TAG_ENERGY)
    if isinstance(e, float):
        out["energy"] = round(e, 3)
    p = tags.get(LUMI_TAG_POWER)
    if isinstance(p, float):
        out["power"] = round(p, 2)
    v = tags.get(LUMI_TAG_VOLTAGE)
    if isinstance(v, float) and v > 50:
        out["voltage"] = round(v / 10, 1)   # mains plugs: 0.1 V units
    c = tags.get(LUMI_TAG_CURRENT)
    if isinstance(c, float):
        out["current"] = round(c / 1000, 3)  # mA
    lux = tags.get(LUMI_TAG_ILLUMINANCE)
    if isinstance(lux, int):
        out["illuminance"] = lux
        out["illuminance_lux"] = lux
    return out


# ---------------------------------------------------------------------------
# Tuya datapoints (cluster 0xEF00)
# ---------------------------------------------------------------------------

TUYA_CLUSTER = 0xEF00
TUYA_CMD_SET_DATA = 0x00          # client → server
TUYA_CMD_DATA_RESPONSE = 0x01     # server → client
TUYA_CMD_DATA_REPORT = 0x02       # server → client
TUYA_CMD_QUERY = 0x03             # client → server: "send me everything"
TUYA_CMD_STATUS_REPORT = 0x06     # server → client (newer firmware)
TUYA_CMD_TIME_SYNC = 0x24

TUYA_RAW = 0x00
TUYA_BOOL = 0x01
TUYA_VALUE = 0x02
TUYA_STRING = 0x03
TUYA_ENUM = 0x04
TUYA_BITMAP = 0x05

TUYA_TYPE_NAMES = {TUYA_RAW: "raw", TUYA_BOOL: "bool", TUYA_VALUE: "value", TUYA_STRING: "string", TUYA_ENUM: "enum", TUYA_BITMAP: "bitmap"}


def decode_tuya_datapoints(payload: bytes) -> list[tuple[int, int, Any]]:
    """``[(dp, type, value), ...]`` from a dataReport/dataResponse payload.

    Layout: sequence u16 (big-endian), then repeated ``dp u8, type u8, len u16 BE, data``.
    Values are big-endian; ``value`` is a signed 32-bit integer, ``enum`` a u8,
    ``bool`` a bool, ``bitmap`` an int, ``string`` UTF-8 text and ``raw`` bytes.
    """
    out: list[tuple[int, int, Any]] = []
    o = 2
    while o + 4 <= len(payload):
        dp, dtype = payload[o], payload[o + 1]
        n = int.from_bytes(payload[o + 2:o + 4], "big")
        o += 4
        if o + n > len(payload):
            break
        data = payload[o:o + n]
        o += n
        value: Any
        if dtype == TUYA_BOOL:
            value = bool(data[0]) if data else False
        elif dtype == TUYA_VALUE:
            value = int.from_bytes(data, "big", signed=True) if data else 0
        elif dtype == TUYA_ENUM:
            value = data[0] if data else 0
        elif dtype == TUYA_BITMAP:
            value = int.from_bytes(data, "big") if data else 0
        elif dtype == TUYA_STRING:
            value = data.decode("utf-8", errors="replace")
        else:
            value = bytes(data)
        out.append((dp, dtype, value))
    return out


def encode_tuya_datapoint(seq: int, dp: int, dtype: int, value: Any) -> bytes:
    """Payload of a ``setData`` (0x00) command for one datapoint."""
    if dtype == TUYA_BOOL:
        data = b"\x01" if value else b"\x00"
    elif dtype == TUYA_VALUE:
        data = int(value).to_bytes(4, "big", signed=True)
    elif dtype == TUYA_ENUM:
        data = bytes([int(value) & 0xFF])
    elif dtype == TUYA_BITMAP:
        v = int(value)
        data = v.to_bytes(4 if v > 0xFFFF else (2 if v > 0xFF else 1), "big")
    elif dtype == TUYA_STRING:
        data = str(value).encode("utf-8")
    else:
        data = bytes(value)
    return (seq & 0xFFFF).to_bytes(2, "big") + bytes([dp & 0xFF, dtype & 0xFF]) + len(data).to_bytes(2, "big") + data


__all__ = [
    "LUMI_MANUFACTURER_CODE", "LUMI_ATTR_REPORT_BASIC", "LUMI_ATTR_REPORT_STRUCT", "LUMI_ATTR_REPORT_PRIVATE",
    "decode_lumi_tlv", "decode_lumi_struct", "lumi_battery_percent", "lumi_common_state",
    "TUYA_CLUSTER", "TUYA_CMD_SET_DATA", "TUYA_CMD_DATA_RESPONSE", "TUYA_CMD_DATA_REPORT", "TUYA_CMD_QUERY", "TUYA_CMD_STATUS_REPORT",
    "TUYA_RAW", "TUYA_BOOL", "TUYA_VALUE", "TUYA_STRING", "TUYA_ENUM", "TUYA_BITMAP", "TUYA_TYPE_NAMES",
    "decode_tuya_datapoints", "encode_tuya_datapoint", "DataType",
]
