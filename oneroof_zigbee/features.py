"""Generic device features ("exposes") derived from the standard clusters a
device advertises. No per-model database: any Zigbee 3.0 device that follows
the ZCL gets controls here. Vendor-private clusters (Tuya 0xEF00 etc.) are
listed under Clusters but do not produce features."""

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
    "heating_setpoint": (0x0201, 0x0012), "system_mode": (0x0201, 0x001C),
}

POWER_ON_BEHAVIOR = {"off": 0, "on": 1, "toggle": 2, "previous": 255}
POWER_ON_BEHAVIOR_REV = {v: k for k, v in POWER_ON_BEHAVIOR.items()}


def _f(key: str, name: str, description: str, type_: str, access: str, *, icon: str, category: str,
       endpoint: int, cluster: int, **extra: Any) -> dict[str, Any]:
    return {"key": key, "name": name, "description": description, "type": type_, "access": access, "icon": icon,
            "category": category, "endpoint": endpoint, "cluster": cluster, **extra}


def features_for(dev: Device) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    multi = len(dev.endpoints) > 1
    for ep in sorted(dev.endpoints.values(), key=lambda e: e.id):
        ins = set(ep.in_clusters)
        sfx = f"_{ep.id}" if multi else ""
        e = ep.id
        if 0x0006 in ins:
            out.append(_f("state" + sfx, "State", "On/off state", "binary", "rw", icon="power", category="control", endpoint=e,
                          cluster=0x0006, value_on="ON", value_off="OFF", value_toggle="TOGGLE"))
            out.append(_f("power_on_behavior" + sfx, "Power-on behaviour", "State after a power outage (StartUpOnOff)", "enum", "rw",
                          icon="plug", category="config", endpoint=e, cluster=0x0006, values=list(POWER_ON_BEHAVIOR)))
            out.append(_f("countdown" + sfx, "Countdown", "Turn on now and switch off automatically after the given seconds (OnWithTimedOff)",
                          "action", "w", icon="clock", category="control", endpoint=e, cluster=0x0006, unit="s", min=1, max=6553))
        if 0x0008 in ins:
            out.append(_f("brightness" + sfx, "Brightness", "Dimming level", "numeric", "rw", icon="sun", category="control",
                          endpoint=e, cluster=0x0008, min=0, max=254, step=1))
        if 0x0300 in ins:
            out.append(_f("color_temp" + sfx, "Colour temperature", "In mireds; lower is cooler/bluer", "numeric", "rw", icon="palette",
                          category="control", endpoint=e, cluster=0x0300, min=153, max=500, step=1, unit="mired"))
            out.append(_f("color" + sfx, "Colour (xy)", "CIE 1931 xy colour", "composite", "rw", icon="palette", category="control",
                          endpoint=e, cluster=0x0300, fields=["x", "y"], min=0, max=1, step=0.001))
        if 0x0102 in ins:
            out.append(_f("position" + sfx, "Position", "0 = closed, 100 = open", "numeric", "rw", icon="arrows", category="control",
                          endpoint=e, cluster=0x0102, min=0, max=100, step=1, unit="%"))
            out.append(_f("cover" + sfx, "Cover", "Open, close or stop", "enum", "w", icon="arrows", category="control", endpoint=e,
                          cluster=0x0102, values=["OPEN", "STOP", "CLOSE"], state_key="state"))
        if 0x0201 in ins:
            out.append(_f("local_temperature" + sfx, "Local temperature", "Measured by the thermostat", "numeric", "r", icon="thermometer",
                          category="sensor", endpoint=e, cluster=0x0201, unit="°C"))
            out.append(_f("heating_setpoint" + sfx, "Heating setpoint", "Target temperature", "numeric", "rw", icon="thermometer",
                          category="control", endpoint=e, cluster=0x0201, min=5, max=30, step=0.5, unit="°C"))
            out.append(_f("system_mode" + sfx, "Mode", "Thermostat mode", "enum", "rw", icon="sliders", category="control", endpoint=e,
                          cluster=0x0201, values=["off", "heat", "auto"]))
        if 0x0B04 in ins:
            out.append(_f("power" + sfx, "Power", "Instantaneous active power", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0B04, unit="W"))
            out.append(_f("current" + sfx, "Current", "RMS current", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0B04, unit="A"))
            out.append(_f("voltage" + sfx, "Voltage", "RMS voltage", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0B04, unit="V"))
        if 0x0702 in ins:
            out.append(_f("energy" + sfx, "Energy", "Total consumed energy", "numeric", "r", icon="bolt", category="sensor", endpoint=e, cluster=0x0702, unit="kWh"))
        if 0x0402 in ins:
            out.append(_f("temperature" + sfx, "Temperature", "Measured temperature", "numeric", "r", icon="thermometer", category="sensor", endpoint=e, cluster=0x0402, unit="°C"))
        if 0x0405 in ins:
            out.append(_f("humidity" + sfx, "Humidity", "Relative humidity", "numeric", "r", icon="drop", category="sensor", endpoint=e, cluster=0x0405, unit="%"))
        if 0x0403 in ins:
            out.append(_f("pressure" + sfx, "Pressure", "Atmospheric pressure", "numeric", "r", icon="gauge", category="sensor", endpoint=e, cluster=0x0403, unit="hPa"))
        if 0x0400 in ins:
            out.append(_f("illuminance_lux" + sfx, "Illuminance", "Light level", "numeric", "r", icon="sun", category="sensor", endpoint=e, cluster=0x0400, unit="lx"))
        if 0x0406 in ins:
            out.append(_f("occupancy" + sfx, "Occupancy", "Presence detected", "binary", "r", icon="hand", category="sensor", endpoint=e, cluster=0x0406, value_on=True, value_off=False))
        if 0x0500 in ins:
            zt = dev.context.get("zone_type")
            key, name = {0x0015: ("contact", "Contact"), 0x000D: ("occupancy", "Motion"), 0x002A: ("water_leak", "Water leak"),
                         0x0028: ("smoke", "Smoke"), 0x002B: ("carbon_monoxide", "CO"), 0x002D: ("vibration", "Vibration")}.get(zt, ("alarm_1", "Alarm"))
            out.append(_f(key + sfx, name, "IAS zone alarm state", "binary", "r", icon="shield", category="sensor", endpoint=e, cluster=0x0500, value_on=True, value_off=False))
            out.append(_f("tamper" + sfx, "Tamper", "Enclosure opened", "binary", "r", icon="shield", category="diagnostic", endpoint=e, cluster=0x0500, value_on=True, value_off=False))
            out.append(_f("battery_low" + sfx, "Battery low", "Device reports low battery", "binary", "r", icon="battery", category="diagnostic", endpoint=e, cluster=0x0500, value_on=True, value_off=False))
        if 0x0001 in ins:
            out.append(_f("battery" + sfx, "Battery", "Remaining battery", "numeric", "r", icon="battery", category="diagnostic", endpoint=e, cluster=0x0001, unit="%", min=0, max=100))
        if 0x0003 in ins:
            out.append(_f("identify" + sfx, "Identify", "Blink / beep the device for 10 s", "action", "w", icon="hand", category="diagnostic", endpoint=e, cluster=0x0003))
    out.append(_f("linkquality", "Link quality", "Signal strength of the last frame (0–255)", "numeric", "r", icon="signal", category="diagnostic",
                  endpoint=0, cluster=0, unit="lqi", min=0, max=255))
    return out
