"""Device features ("exposes").

``generic_features`` derives controls from the standard clusters a device
advertises — any Zigbee 3.0 device that follows the ZCL gets controls here.
``features_for`` then lets the model-knowledge layer (``quirks``) correct the
picture: sensors that misuse the On/Off cluster, multi-gang switches, remotes,
vendor-private reports.  Every feature dict carries ``key`` (the published
state key), ``base`` (the cluster-level key it derives from), ``endpoint`` and
``cluster`` so state translation and commands can map back to the wire."""

from __future__ import annotations

from typing import Any

from .devices import Device

# key → (cluster, attribute) for attribute-backed reads
ATTR_OF: dict[str, tuple[int, int]] = {
    "state": (0x0006, 0x0000), "power_on_behavior": (0x0006, 0x4003), "brightness": (0x0008, 0x0000),
    "color_temp": (0x0300, 0x0007), "temperature": (0x0402, 0x0000), "humidity": (0x0405, 0x0000),
    "pressure": (0x0403, 0x0000), "illuminance_lux": (0x0400, 0x0000), "occupancy": (0x0406, 0x0000),
    "battery": (0x0001, 0x0021), "voltage": (0x0B04, 0x0505), "current": (0x0B04, 0x0508), "power": (0x0B04, 0x050B),
    "energy": (0x0702, 0x0000), "position": (0x0102, 0x0008), "local_temperature": (0x0201, 0x0000),
    "current_heating_setpoint": (0x0201, 0x0012), "system_mode": (0x0201, 0x001C), "lock_state": (0x0101, 0x0000),
}

POWER_ON_BEHAVIOR = {"off": 0, "on": 1, "toggle": 2, "previous": 255}
POWER_ON_BEHAVIOR_REV = {v: k for k, v in POWER_ON_BEHAVIOR.items()}

# keys that belong to the on/off "family" and get a gang suffix on multi-gang devices
ONOFF_FAMILY = ("state", "power_on_behavior", "countdown", "brightness")

IAS_KEYS = {0x0015: ("contact", "Contact"), 0x000D: ("occupancy", "Motion"), 0x002A: ("water_leak", "Water leak"),
            0x0028: ("smoke", "Smoke"), 0x002B: ("carbon_monoxide", "CO"), 0x002D: ("vibration", "Vibration"),
            0x002C: ("emergency", "Emergency"), 0x0226: ("glass_break", "Glass break")}

REMOTE_ACTIONS = ("on", "off", "toggle", "brightness_move_up", "brightness_move_down", "brightness_stop", "brightness_step_up",
                  "brightness_step_down", "color_temperature_step_up", "color_temperature_step_down", "recall_1")


def _f(key: str, name: str, description: str, type_: str, access: str, *, icon: str, category: str,
       endpoint: int, cluster: int, **extra: Any) -> dict[str, Any]:
    return {"key": key, "name": name, "description": description, "type": type_, "access": access, "icon": icon,
            "category": category, "endpoint": endpoint, "cluster": cluster, "base": key, **extra}


def generic_features(dev: Device) -> list[dict[str, Any]]:
    """Features derived purely from clusters. Keys are not yet suffixed; see ``_assign_keys``."""
    out: list[dict[str, Any]] = []
    eps = sorted(dev.endpoints.values(), key=lambda e: e.id)
    client_only = not any(0x0006 in e.in_clusters for e in eps) and any({0x0006, 0x0008, 0x0005} & set(e.out_clusters) for e in eps)
    for ep in eps:
        if ep.profile == 0xA1E0:
            continue
        ins = set(ep.in_clusters)
        e = ep.id
        if 0x0006 in ins:
            out.append(_f("state", "State", "On/off state", "binary", "rw", icon="power", category="control", endpoint=e,
                          cluster=0x0006, value_on="ON", value_off="OFF", value_toggle="TOGGLE"))
            out.append(_f("power_on_behavior", "Power-on behaviour", "State after a power outage (StartUpOnOff)", "enum", "rw",
                          icon="plug", category="config", endpoint=e, cluster=0x0006, values=list(POWER_ON_BEHAVIOR)))
            out.append(_f("countdown", "Countdown", "Turn on now and switch off automatically after the given seconds (OnWithTimedOff)",
                          "action", "w", icon="clock", category="control", endpoint=e, cluster=0x0006, unit="s", min=1, max=6553))
        if 0x0008 in ins:
            out.append(_f("brightness", "Brightness", "Dimming level", "numeric", "rw", icon="sun", category="control",
                          endpoint=e, cluster=0x0008, min=0, max=254, step=1))
        if 0x0300 in ins:
            out.append(_f("color_temp", "Colour temperature", "In mireds; lower is cooler/bluer", "numeric", "rw", icon="palette",
                          category="control", endpoint=e, cluster=0x0300, min=153, max=500, step=1, unit="mired"))
            out.append(_f("color", "Colour (xy)", "CIE 1931 xy colour", "composite", "rw", icon="palette", category="control",
                          endpoint=e, cluster=0x0300, fields=["x", "y"], min=0, max=1, step=0.001))
        if 0x0102 in ins:
            out.append(_f("position", "Position", "0 = closed, 100 = open", "numeric", "rw", icon="arrows", category="control",
                          endpoint=e, cluster=0x0102, min=0, max=100, step=1, unit="%"))
            out.append(_f("cover", "Cover", "Open, close or stop", "enum", "w", icon="arrows", category="control", endpoint=e,
                          cluster=0x0102, values=["OPEN", "STOP", "CLOSE"], state_key="state"))
        if 0x0101 in ins:
            out.append(_f("state", "Lock", "Lock or unlock", "binary", "rw", icon="lock", category="control", endpoint=e,
                          cluster=0x0101, value_on="LOCK", value_off="UNLOCK"))
            out.append(_f("lock_state", "Lock state", "Reported bolt state", "enum", "r", icon="lock", category="sensor", endpoint=e,
                          cluster=0x0101, values=["locked", "unlocked", "not_fully_locked"]))
        if 0x0201 in ins:
            out.append(_f("local_temperature", "Local temperature", "Measured by the thermostat", "numeric", "r", icon="thermometer",
                          category="sensor", endpoint=e, cluster=0x0201, unit="°C"))
            out.append(_f("current_heating_setpoint", "Heating setpoint", "Target temperature", "numeric", "rw", icon="thermometer",
                          category="control", endpoint=e, cluster=0x0201, min=5, max=30, step=0.5, unit="°C"))
            out.append(_f("system_mode", "Mode", "Thermostat mode", "enum", "rw", icon="sliders", category="control", endpoint=e,
                          cluster=0x0201, values=["off", "heat", "auto"]))
            out.append(_f("running_state", "Running state", "Whether the valve/heater is active", "enum", "r", icon="bolt", category="sensor",
                          endpoint=e, cluster=0x0201, values=["idle", "heat", "cool"]))
        if 0x0B04 in ins:
            out.append(_f("power", "Power", "Instantaneous active power", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0B04, unit="W"))
            out.append(_f("current", "Current", "RMS current", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0B04, unit="A"))
            out.append(_f("voltage", "Voltage", "RMS voltage", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0B04, unit="V"))
        if 0x0702 in ins:
            out.append(_f("energy", "Energy", "Total consumed energy", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0702, unit="kWh"))
            if 0x0B04 not in ins:
                out.append(_f("power", "Power", "Instantaneous demand", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0702, unit="W"))
        if 0x0402 in ins:
            out.append(_f("temperature", "Temperature", "Measured temperature", "numeric", "r", icon="thermometer", category="sensor", endpoint=e, cluster=0x0402, unit="°C"))
        if 0x0405 in ins:
            out.append(_f("humidity", "Humidity", "Relative humidity", "numeric", "r", icon="drop", category="sensor", endpoint=e, cluster=0x0405, unit="%"))
        if 0x0403 in ins:
            out.append(_f("pressure", "Pressure", "Atmospheric pressure", "numeric", "r", icon="gauge", category="sensor", endpoint=e, cluster=0x0403, unit="hPa"))
        if 0x0400 in ins:
            out.append(_f("illuminance_lux", "Illuminance", "Light level", "numeric", "r", icon="sun", category="sensor", endpoint=e, cluster=0x0400, unit="lx"))
        if 0x0406 in ins:
            out.append(_f("occupancy", "Occupancy", "Presence detected", "binary", "r", icon="hand", category="sensor", endpoint=e, cluster=0x0406, value_on=True, value_off=False))
        if 0x040D in ins:
            out.append(_f("co2", "CO₂", "Carbon dioxide concentration", "numeric", "r", icon="gauge", category="sensor", endpoint=e, cluster=0x040D, unit="ppm"))
        if 0x042A in ins:
            out.append(_f("pm25", "PM2.5", "Fine particulate matter", "numeric", "r", icon="gauge", category="sensor", endpoint=e, cluster=0x042A, unit="µg/m³"))
        if 0x0500 in ins:
            zt = dev.context.get("zone_type")
            key, name = IAS_KEYS.get(zt, ("alarm_1", "Alarm"))
            out.append(_f(key, name, "IAS zone alarm state", "binary", "r", icon="shield", category="sensor", endpoint=e, cluster=0x0500, value_on=True, value_off=False))
            out.append(_f("tamper", "Tamper", "Enclosure opened", "binary", "r", icon="shield", category="diagnostic", endpoint=e, cluster=0x0500, value_on=True, value_off=False))
            out.append(_f("battery_low", "Battery low", "Device reports low battery", "binary", "r", icon="battery", category="diagnostic", endpoint=e, cluster=0x0500, value_on=True, value_off=False))
        if 0x0001 in ins:
            out.append(_f("battery", "Battery", "Remaining battery", "numeric", "r", icon="battery", category="diagnostic", endpoint=e, cluster=0x0001, unit="%", min=0, max=100))
        if 0x0003 in ins:
            out.append(_f("identify", "Identify", "Blink / beep the device for 10 s", "action", "w", icon="hand", category="diagnostic", endpoint=e, cluster=0x0003))
    if client_only and not any(f["base"] == "action" for f in out):
        ep1 = eps[0].id if eps else 1
        out.append(_f("action", "Action", "Last button event", "enum", "r", icon="hand", category="sensor", endpoint=ep1, cluster=0, values=list(REMOTE_ACTIONS)))
    out.append(_f("linkquality", "Link quality", "Signal strength of the last frame (0–255)", "numeric", "r", icon="signal", category="diagnostic",
                  endpoint=0, cluster=0, unit="lqi", min=0, max=255))
    return _assign_keys(dev, out)


_NO_SUFFIX = {"identify", "battery", "linkquality", "tamper", "battery_low", "action"}


def _assign_keys(dev: Device, feats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Suffix keys that would otherwise collide across endpoints: on/off family → ``_l1, _l2…``
    in endpoint order, anything else → ``_<endpoint>``. Single-endpoint devices keep bare keys."""
    by_base: dict[str, set[int]] = {}
    for f in feats:
        by_base.setdefault(f["base"], set()).add(f["endpoint"])
    onoff_eps = sorted(by_base.get("state", set()))
    multi_gang = len(onoff_eps) > 1 and any(f["base"] == "state" and f["cluster"] == 0x0006 for f in feats)
    for f in feats:
        if len(by_base[f["base"]]) <= 1 or f["base"] in _NO_SUFFIX:
            continue
        if multi_gang and f["base"] in ONOFF_FAMILY and f["endpoint"] in onoff_eps:
            n = onoff_eps.index(f["endpoint"]) + 1
            f["key"] = f"{f['base']}_l{n}"
            f["gang"] = f"l{n}"
            if f["base"] == "state":
                f["name"] = f"Switch {n}"
        else:
            f["key"] = f"{f['base']}_{f['endpoint']}"
    # identical duplicates (e.g. battery reported on two endpoints) keep the first
    seen: set[str] = set()
    out = []
    for f in feats:
        if f["key"] in seen:
            continue
        seen.add(f["key"])
        out.append(f)
    return out


# State keys with a known meaning. A value that is present in the device state but has no feature
# (imported without cluster information, vendor report the model table does not know …) is still
# exposed, read-only, so nothing the device reports is lost on the way to Home Assistant.
KNOWN_STATE_FEATURES: dict[str, tuple[str, str, str | None, str, str]] = {
    # key: (name, type, unit, icon, category)
    "temperature": ("Temperature", "numeric", "°C", "thermometer", "sensor"),
    "humidity": ("Humidity", "numeric", "%", "drop", "sensor"),
    "pressure": ("Pressure", "numeric", "hPa", "gauge", "sensor"),
    "illuminance": ("Illuminance", "numeric", "lx", "sun", "sensor"),
    "illuminance_lux": ("Illuminance", "numeric", "lx", "sun", "sensor"),
    "occupancy": ("Occupancy", "binary", None, "hand", "sensor"),
    "contact": ("Contact", "binary", None, "shield", "sensor"),
    "water_leak": ("Water leak", "binary", None, "drop", "sensor"),
    "smoke": ("Smoke", "binary", None, "shield", "sensor"),
    "gas": ("Gas", "binary", None, "shield", "sensor"),
    "vibration": ("Vibration", "binary", None, "shield", "sensor"),
    "tamper": ("Tamper", "binary", None, "shield", "diagnostic"),
    "battery_low": ("Battery low", "binary", None, "battery", "diagnostic"),
    "battery": ("Battery", "numeric", "%", "battery", "diagnostic"),
    "voltage": ("Battery voltage", "numeric", "mV", "battery", "diagnostic"),
    "device_temperature": ("Device temperature", "numeric", "°C", "thermometer", "diagnostic"),
    "power_outage_count": ("Power outages", "numeric", None, "counter", "diagnostic"),
    "power": ("Power", "numeric", "W", "bolt", "sensor"),
    "energy": ("Energy", "numeric", "kWh", "bolt", "sensor"),
    "current": ("Current", "numeric", "A", "bolt", "sensor"),
    "voltage_ac": ("Voltage", "numeric", "V", "bolt", "sensor"),
    "co2": ("CO₂", "numeric", "ppm", "gauge", "sensor"),
    "pm25": ("PM2.5", "numeric", "µg/m³", "gauge", "sensor"),
    "voc": ("VOC", "numeric", "ppb", "gauge", "sensor"),
    "action": ("Action", "text", None, "hand", "sensor"),
}


def _state_fallbacks(dev: Device, have: set[str]) -> list[dict[str, Any]]:
    out = []
    for key, (name, type_, unit, icon, category) in KNOWN_STATE_FEATURES.items():
        if key in have or key not in dev.state:
            continue
        extra: dict[str, Any] = {"from_state": True}
        if unit:
            extra["unit"] = unit
        if type_ == "binary":
            extra.update(value_on=True, value_off=False)
        out.append(_f(key, name, "Reported by the device", type_, "r", icon=icon, category=category, endpoint=0, cluster=0, **extra))
    return out


def features_for(dev: Device) -> list[dict[str, Any]]:
    from . import quirks
    info = quirks.describe(dev)
    feats = quirks.shape_features(dev, generic_features(dev), info)
    have = {f["key"] for f in feats}
    feats.extend(_state_fallbacks(dev, have))
    return feats


def feature_index(dev: Device) -> dict[str, dict[str, Any]]:
    return {f["key"]: f for f in features_for(dev)}
