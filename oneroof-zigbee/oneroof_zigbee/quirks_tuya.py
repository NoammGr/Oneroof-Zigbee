"""Tuya datapoint heuristics for models without an explicit map.

A TS0601-style device hides everything behind cluster 0xEF00 datapoints whose
meaning is vendor-defined per product family.  When no built-in map and no
user definition exists, this module infers features from two things only:

* the datapoint ids *and wire types* the device has actually reported so far
  (``Device.context["tuya_seen"]``, maintained by the gateway), and
* Tuya's conventional id layout per product family (thermostat, cover,
  temperature/humidity sensor, smoke, presence radar, multi-gang switch …).

The rule is conservative: a family is chosen only when its signature — a set
of ``(dp, wire type)`` pairs — has been seen and no other family fits equally
well; within the chosen family a datapoint becomes a feature only when its
observed wire type agrees with the convention.  Everything else stays a raw
``dp_<n>`` value.  Inferred features carry ``"inferred": True`` so the UI and
discovery can mark them as a guess.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, replace
from typing import Any

from .devices import Device
from .quirks import Dp
from .zcl import vendor as vz

TUYA_DP_MANUFACTURERS = ("_TZE200_*", "_TZE204_*", "_TZE284_*", "_TZ3210_*")
SEEN_KEY = "tuya_seen"


# ---------------------------------------------------------------------------
# Observation bookkeeping
# ---------------------------------------------------------------------------


def is_tuya_dp_device(dev: Device) -> bool:
    """True when the device talks datapoints: cluster 0xEF00 plus a Tuya manufacturer id or a TS0601 model."""
    if not any(vz.TUYA_CLUSTER in ep.in_clusters for ep in dev.endpoints.values()):
        return False
    m = (dev.manufacturer or "").strip().lower()
    if any(fnmatch.fnmatchcase(m, p.lower()) for p in TUYA_DP_MANUFACTURERS):
        return True
    return (dev.model or "").strip().upper().startswith("TS0601")


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


def seen_datapoints(dev: Device) -> dict[int, dict[str, Any]]:
    """``{dp: {"type": wire type, "last": value, "ts": when}}`` (keys are strings on disk; normalised here)."""
    raw = dev.context.get(SEEN_KEY)
    out: dict[int, dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        try:
            dp = int(k)
        except (TypeError, ValueError):
            continue
        if isinstance(v, dict) and isinstance(v.get("type"), int):
            out[dp] = v
    return out


def record_datapoints(dev: Device, datapoints: list[tuple[int, int, Any]], ts: float) -> bool:
    """Remember every datapoint a report carried. Returns True when a new id or a new wire type appeared
    (the feature list may change then)."""
    seen = dev.context.get(SEEN_KEY)
    if not isinstance(seen, dict):
        seen = dev.context[SEEN_KEY] = {}
    changed = False
    for dp, dtype, value in datapoints:
        key = str(dp)
        prev = seen.get(key)
        if not isinstance(prev, dict) or prev.get("type") != dtype:
            changed = True
        seen[key] = {"type": dtype, "last": _jsonable(value), "ts": ts}
    return changed


# ---------------------------------------------------------------------------
# Family conventions
# ---------------------------------------------------------------------------

B, V, E, S = vz.TUYA_BOOL, vz.TUYA_VALUE, vz.TUYA_ENUM, vz.TUYA_STRING


@dataclass(frozen=True)
class Family:
    name: str
    kind: str
    category: str
    dps: dict[int, tuple[int, Dp]]                        # dp → (expected wire type, feature template)
    signatures: tuple[frozenset[tuple[int, int]], ...]    # any one of these (dp, type) sets identifies the family


def _dp(dp: int, key: str, name: str, **kw: Any) -> Dp:
    return Dp(dp, key, name, inferred=True, **kw)


def _t(dp: int, dtype: int, d: Dp) -> tuple[int, tuple[int, Dp]]:
    return dp, (dtype, d)


_BATTERY = dict(unit="%", icon="battery", category="diagnostic", min=0, max=100, device_class="battery")
_ON_OFF = {0: "OFF", 1: "ON"}
_TRUE_FALSE = {0: "false", 1: "true"}

FAMILIES: tuple[Family, ...] = (
    Family("thermostat", "Thermostat/TRV", "climate", dict((
        _t(1, B, _dp(1, "system_mode", "Mode", type="enum", access="rw", values={0: "off", 1: "heat"}, icon="sliders", category="control", dtype=B)),
        _t(2, V, _dp(2, "current_heating_setpoint", "Heating setpoint", access="rw", scale=10, unit="°C", icon="thermometer", category="control", min=5, max=35, step=0.5, device_class="temperature")),
        _t(3, V, _dp(3, "local_temperature", "Local temperature", scale=10, unit="°C", icon="thermometer", device_class="temperature")),
        _t(4, E, _dp(4, "preset", "Preset", type="enum", access="rw", values={0: "schedule", 1: "manual", 2: "boost", 3: "complex", 4: "comfort", 5: "eco"}, icon="sliders", category="control", dtype=E)),
        _t(7, B, _dp(7, "child_lock", "Child lock", type="binary", access="rw", values={0: "UNLOCK", 1: "LOCK"}, icon="lock", category="config", dtype=B)),
        _t(16, V, _dp(16, "current_heating_setpoint", "Heating setpoint", access="rw", unit="°C", icon="thermometer", category="control", min=5, max=35, step=1, device_class="temperature")),
        _t(24, V, _dp(24, "local_temperature", "Local temperature", scale=10, unit="°C", icon="thermometer", device_class="temperature")),
    )), (frozenset({(2, V), (3, V)}), frozenset({(16, V), (24, V)}))),
    Family("cover", "Curtain motor", "cover", dict((
        _t(1, E, _dp(1, "cover", "Cover", type="enum", access="w", values={0: "OPEN", 1: "STOP", 2: "CLOSE"}, icon="arrows", category="control", dtype=E, description="Open, close or stop")),
        _t(2, V, _dp(2, "position", "Position", access="rw", unit="%", icon="arrows", category="control", min=0, max=100, step=1, description="0 = closed, 100 = open")),
        _t(3, V, _dp(3, "position", "Position", unit="%", icon="arrows", category="control", min=0, max=100)),
        _t(5, E, _dp(5, "motor_reversal", "Motor direction", type="enum", access="rw", values={0: "forward", 1: "back"}, icon="arrows", category="config", dtype=E)),
        _t(7, E, _dp(7, "work_state", "Work state", type="enum", values={0: "opening", 1: "closing"}, icon="arrows", dtype=E)),
        _t(13, V, _dp(13, "battery", "Battery", **_BATTERY)),
    )), (frozenset({(1, E), (2, V)}), frozenset({(1, E), (3, V)}))),
    Family("temperature_humidity", "Temperature/humidity sensor", "sensor", dict((
        _t(1, V, _dp(1, "temperature", "Temperature", scale=10, unit="°C", icon="thermometer", device_class="temperature")),
        _t(2, V, _dp(2, "humidity", "Humidity", unit="%", icon="drop", device_class="humidity")),
        _t(4, V, _dp(4, "battery", "Battery", **_BATTERY)),
        _t(9, E, _dp(9, "temperature_unit", "Temperature unit", type="enum", access="rw", values={0: "celsius", 1: "fahrenheit"}, icon="thermometer", category="config", dtype=E)),
        _t(14, E, _dp(14, "battery_state", "Battery state", type="enum", values={0: "low", 1: "medium", 2: "high"}, icon="battery", category="diagnostic", dtype=E)),
        _t(15, V, _dp(15, "battery", "Battery", **_BATTERY)),
    )), (frozenset({(1, V), (2, V)}),)),
    Family("smoke", "Smoke detector", "sensor", dict((
        _t(1, E, _dp(1, "smoke", "Smoke", type="binary", values={0: "true", 1: "false"}, icon="shield", dtype=E, device_class="smoke", description="Smoke alarm (enum 0 = alarm)")),
        _t(14, E, _dp(14, "battery_low", "Battery low", type="binary", values={0: "true", 1: "false", 2: "false"}, icon="battery", category="diagnostic", dtype=E, device_class="battery")),
        _t(15, V, _dp(15, "battery", "Battery", **_BATTERY)),
    )), (frozenset({(1, E), (14, E)}), frozenset({(1, E), (15, V)}))),
    Family("water_leak", "Water leak sensor", "sensor", dict((
        _t(1, B, _dp(1, "water_leak", "Water leak", type="binary", values=_TRUE_FALSE, icon="drop", dtype=B, device_class="moisture")),
        _t(4, V, _dp(4, "battery", "Battery", **_BATTERY)),
    )), (frozenset({(1, B)}),)),
    Family("door", "Contact sensor", "sensor", dict((
        _t(1, B, _dp(1, "contact", "Contact", type="binary", values=_TRUE_FALSE, icon="shield", dtype=B, device_class="door")),
        _t(4, V, _dp(4, "battery", "Battery", **_BATTERY)),
    )), (frozenset({(1, B)}),)),
    Family("gas", "Gas detector", "sensor", dict((
        _t(1, B, _dp(1, "gas", "Gas", type="binary", values=_TRUE_FALSE, icon="shield", dtype=B, device_class="gas")),
    )), (frozenset({(1, B)}),)),
    Family("presence_radar", "Presence sensor (radar)", "sensor", dict((
        _t(1, B, _dp(1, "presence", "Presence", type="binary", values=_TRUE_FALSE, icon="hand", dtype=B, device_class="occupancy")),
        _t(2, V, _dp(2, "radar_sensitivity", "Radar sensitivity", access="rw", icon="sliders", category="config", min=0, max=9, step=1)),
        _t(3, V, _dp(3, "minimum_range", "Minimum range", access="rw", scale=100, unit="m", icon="arrows", category="config", min=0, max=9.5, step=0.1, device_class="distance")),
        _t(4, V, _dp(4, "maximum_range", "Maximum range", access="rw", scale=100, unit="m", icon="arrows", category="config", min=0, max=9.5, step=0.1, device_class="distance")),
        _t(9, V, _dp(9, "target_distance", "Target distance", scale=100, unit="m", icon="arrows", device_class="distance")),
        _t(101, V, _dp(101, "detection_delay", "Detection delay", access="rw", scale=10, unit="s", icon="clock", category="config", min=0, max=10, step=0.1)),
        _t(102, V, _dp(102, "fading_time", "Fading time", access="rw", scale=10, unit="s", icon="clock", category="config", min=0, max=1500, step=1)),
        _t(104, V, _dp(104, "illuminance_lux", "Illuminance", unit="lx", icon="sun", device_class="illuminance")),
    )), (frozenset({(1, B), (9, V)}), frozenset({(1, B), (104, V)}), frozenset({(1, B), (2, V), (3, V), (4, V)}))),
    Family("soil", "Soil sensor", "sensor", dict((
        _t(3, V, _dp(3, "soil_moisture", "Soil moisture", unit="%", icon="drop", device_class="moisture", min=0, max=100)),
        _t(5, V, _dp(5, "temperature", "Temperature", unit="°C", icon="thermometer", device_class="temperature")),
        _t(15, V, _dp(15, "battery", "Battery", **_BATTERY)),
    )), (frozenset({(3, V), (5, V)}),)),
    Family("light", "Light", "light", dict((
        _t(1, B, _dp(1, "state", "State", type="binary", access="rw", values=_ON_OFF, icon="power", category="control", dtype=B)),
        _t(2, E, _dp(2, "work_mode", "Mode", type="enum", access="rw", values={0: "white", 1: "colour", 2: "scene", 3: "music"}, icon="palette", category="control", dtype=E)),
        _t(3, V, _dp(3, "brightness", "Brightness", access="rw", icon="sun", category="control", min=10, max=1000, step=1)),
        _t(4, V, _dp(4, "color_temp", "Colour temperature", access="rw", icon="palette", category="control", min=0, max=1000, step=1)),
        _t(5, S, _dp(5, "color_hsv", "Colour (HSV hex)", type="text", access="rw", icon="palette", category="control", dtype=S)),
    )), (frozenset({(1, B), (2, E), (3, V)}),)),
    Family("switch", "Wall switch", "switch", dict(
        [_t(i, B, _dp(i, f"state_l{i}", f"Switch {i}", type="binary", access="rw", values=_ON_OFF, icon="power", category="control", dtype=B)) for i in range(1, 7)]
        + [_t(6 + i, V, _dp(6 + i, f"countdown_l{i}", f"Countdown {i}", access="rw", unit="s", icon="clock", category="config", min=0, max=86400, step=1)) for i in range(1, 7)]
    ), (frozenset({(1, B), (2, B)}),)),
    Family("siren", "Siren", "sensor", dict((
        _t(13, B, _dp(13, "alarm", "Alarm", type="binary", access="rw", values=_ON_OFF, icon="shield", category="control", dtype=B)),
        _t(5, E, _dp(5, "volume", "Volume", type="enum", access="rw", values={0: "low", 1: "medium", 2: "high"}, icon="sliders", category="config", dtype=E)),
        _t(7, V, _dp(7, "duration", "Alarm duration", access="rw", unit="s", icon="clock", category="config", min=0, max=1800, step=1)),
    )), (frozenset({(13, B), (5, E)}), frozenset({(13, B), (7, V)}))),
)


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------


def match_family(seen: dict[int, dict[str, Any]]) -> Family | None:
    """The single family whose signature the observed datapoints satisfy; ``None`` when none or several do."""
    pairs = {(dp, info["type"]) for dp, info in seen.items()}
    matched: list[tuple[Family, frozenset[tuple[int, int]]]] = []
    for fam in FAMILIES:
        if any(sig <= pairs for sig in fam.signatures):
            explained = frozenset(p for p in pairs if fam.dps.get(p[0], (None,))[0] == p[1])
            matched.append((fam, explained))
    # a family that explains strictly more of what was seen beats one it subsumes
    # (presence radar {1,9} over water leak {1}; cover {1,2,3} over thermostat {2,3})
    keep = [f for f, e in matched if not any(e < o for _, o in matched)]
    return keep[0] if len(keep) == 1 else None


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _adjust(fam: Family, d: Dp, info: dict[str, Any]) -> Dp:
    """Per-datapoint refinements from the last observed value (scale guesses that the id alone cannot settle)."""
    last = _num(info.get("last"))
    if last is None:
        return d
    if d.key == "humidity" and last > 100:
        return replace(d, scale=10)
    if fam.name == "soil" and d.key == "temperature" and last > 100:
        return replace(d, scale=10)
    return d


def infer(dev: Device) -> tuple[Family | None, tuple[Dp, ...]]:
    """``(family, datapoints)`` inferred from what the device has reported; ``(None, ())`` when nothing is safe."""
    seen = seen_datapoints(dev)
    if not seen:
        return None, ()
    fam = match_family(seen)
    if fam is None:
        return None, ()
    out: list[Dp] = []
    for dp in sorted(seen):
        spec = fam.dps.get(dp)
        if spec is None or spec[0] != seen[dp]["type"]:
            continue  # unknown to the family, or the wire type contradicts the convention: stays raw
        out.append(_adjust(fam, spec[1], seen[dp]))
    return fam, tuple(out)


def infer_kind(dev: Device) -> tuple[str, str] | None:
    """``(kind, category)`` for the inferred family, with gang counts for switches."""
    fam, dps = infer(dev)
    if fam is None or not dps:
        return None
    if fam.name == "switch":
        gangs = sum(1 for d in dps if d.key.startswith("state_l"))
        return f"Wall switch ({gangs} gang)", fam.category
    return fam.kind, fam.category


__all__ = ["TUYA_DP_MANUFACTURERS", "SEEN_KEY", "Family", "FAMILIES", "is_tuya_dp_device", "seen_datapoints", "record_datapoints",
           "match_family", "infer", "infer_kind"]
