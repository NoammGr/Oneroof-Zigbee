"""Home Assistant MQTT discovery payloads.

Entities are derived from the device's *features* (``features.features_for``:
clusters corrected by the model-knowledge layer), so a contact sensor that
reports through the On/Off cluster becomes a ``binary_sensor`` with device
class ``door`` and not a ``switch``.  Each feature becomes one HA entity with
a stable ``unique_id`` so renaming in HA survives restarts; in the legacy
layout the object ids and payload keys are the ones the previous setup used
(``contact``, ``occupancy``, ``battery``, ``action``, ``state_l1``…), which is
what keeps entity ids after an import.
"""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..devices import Device
from ..features import features_for
from .topics import Topics

# state key → (device_class, unit, state_class, entity_category)
_SENSOR_META: dict[str, tuple[str | None, str | None, str | None, str | None]] = {
    "battery": ("battery", "%", "measurement", "diagnostic"),
    "voltage": ("voltage", "V", "measurement", None),
    "device_temperature": ("temperature", "°C", "measurement", "diagnostic"),
    "power_outage_count": (None, None, "total_increasing", "diagnostic"),
    "temperature": ("temperature", "°C", "measurement", None),
    "local_temperature": ("temperature", "°C", "measurement", None),
    "humidity": ("humidity", "%", "measurement", None),
    "pressure": ("pressure", "hPa", "measurement", None),
    "illuminance_lux": ("illuminance", "lx", "measurement", None),
    "illuminance": ("illuminance", "lx", "measurement", None),
    "power": ("power", "W", "measurement", None),
    "energy": ("energy", "kWh", "total_increasing", None),
    "current": ("current", "A", "measurement", None),
    "co2": ("carbon_dioxide", "ppm", "measurement", None),
    "pm25": ("pm25", "µg/m³", "measurement", None),
    "voc": ("volatile_organic_compounds_parts", "ppb", "measurement", None),
    "target_distance": ("distance", "m", "measurement", None),
    "linkquality": (None, "lqi", "measurement", "diagnostic"),
    "position": (None, "%", "measurement", None),
}

_BINARY_CLASS: dict[str, str | None] = {
    "contact": "door", "occupancy": "motion", "presence": "occupancy", "water_leak": "moisture", "smoke": "smoke",
    "carbon_monoxide": "carbon_monoxide", "gas": "gas", "vibration": "vibration", "tamper": "tamper", "battery_low": "battery",
    "emergency": "safety", "glass_break": "sound", "alarm_1": None, "alarm_2": None, "window_open": "window",
}

_ICONS = {"action": "mdi:gesture-double-tap", "linkquality": "mdi:signal", "power_outage_count": "mdi:counter", "power_on_behavior": "mdi:power-settings",
          "indicator_mode": "mdi:led-on", "preset": "mdi:tune", "lock_state": "mdi:lock"}


def _device_block(dev: Device, t: Topics) -> dict[str, Any]:
    block = {
        "identifiers": t.device_identifiers(dev),
        "name": dev.friendly_name,
        "manufacturer": dev.manufacturer or "Zigbee",
        "model": dev.model or "unknown",
        "via_device": t.via_device(),
    }
    if dev.sw_build:
        block["sw_version"] = str(dev.sw_build)  # Home Assistant rejects the whole message on a null here
    return block


def _strip_nulls(obj: Any) -> Any:
    """Home Assistant validates discovery payloads strictly: a null where a string is expected
    rejects the entire entity. Never emit null values."""
    if isinstance(obj, dict):
        return {k: _strip_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_nulls(v) for v in obj if v is not None]
    return obj


def _topics(base: str, prefix: str, legacy: bool) -> Topics:
    return Topics(base, prefix, legacy)


def _suffix(f: dict[str, Any]) -> str:
    """Object-id suffix for a feature: the gang name or endpoint suffix it carries."""
    key, base = f["key"], f["base"]
    return key[len(base):] if key.startswith(base) and key != base else ""


def discovery_messages(dev: Device, base: str, prefix: str, *, legacy: bool = False) -> list[tuple[str, bytes]]:
    """Return [(topic, payload)] for all entities of a device. Empty payload = remove."""
    out: list[tuple[str, bytes]] = []
    t = _topics(base, prefix, legacy)
    state_topic = t.state(dev)
    set_topic = t.set(dev)
    avail = [{"topic": f"{base}/bridge/state"}, {"topic": t.availability(dev)}]
    if t.availability_template():
        for a in avail:
            a["value_template"] = t.availability_template()
    common = {
        "availability": avail, "availability_mode": "all",
        "device": _device_block(dev, t),
        "origin": {"name": "OneRoof Zigbee", "sw_version": __version__},
        "state_topic": state_topic,
    }
    done: set[str] = set()

    def add(component: str, object_id: str, cfg: dict[str, Any]) -> None:
        if object_id in done:
            return
        done.add(object_id)
        payload = {**common, **cfg, "unique_id": t.unique_id(dev, object_id)}
        if not legacy:
            payload["object_id"] = f"{dev.friendly_name}_{object_id}"
        payload = {k: v for k, v in payload.items() if v is not None}
        out.append((t.discovery_topic(component, dev, object_id), json.dumps(_strip_nulls(payload)).encode()))

    feats = features_for(dev)
    by_ep: dict[int, dict[str, dict[str, Any]]] = {}
    for f in feats:
        by_ep.setdefault(f["endpoint"], {})[f["base"]] = f
    handled: set[str] = set()

    # -- composite entities (one per endpoint) ------------------------------------------------
    for _ep, bases in by_ep.items():
        st = bases.get("state")
        if st and st["cluster"] == 0x0006 and st["access"] == "rw":
            sfx = _suffix(st)
            br, ct, col = bases.get("brightness"), bases.get("color_temp"), bases.get("color")
            if br or ct or col:
                cfg: dict[str, Any] = {"name": None, "schema": "json", "command_topic": set_topic, "brightness": bool(br),
                                       "supported_color_modes": (["xy", "color_temp"] if ct or col else ["brightness"])}
                if ct:
                    cfg["min_mireds"], cfg["max_mireds"] = ct.get("min", 153), ct.get("max", 500)
                add("light", f"light{sfx}", cfg)
                handled |= {x["key"] for x in (st, br, ct, col) if x}
            else:
                add("switch", f"switch{sfx}", {"name": None if not sfx else st["name"], "command_topic": set_topic,
                                               "value_template": f"{{{{ value_json.{st['key']} }}}}",
                                               "payload_on": json.dumps({st["key"]: "ON"}), "payload_off": json.dumps({st["key"]: "OFF"}),
                                               "state_on": "ON", "state_off": "OFF"})
                handled.add(st["key"])
        elif st and st["cluster"] == 0x0101:
            add("lock", f"lock{_suffix(st)}", {"name": None, "command_topic": set_topic, "value_template": f"{{{{ value_json.{st['key']} }}}}",
                                               "payload_lock": json.dumps({st["key"]: "LOCK"}), "payload_unlock": json.dumps({st["key"]: "UNLOCK"}),
                                               "state_locked": "LOCK", "state_unlocked": "UNLOCK"})
            handled.add(st["key"])
        pos, cov = bases.get("position"), bases.get("cover")
        if cov or (pos and pos["access"] == "rw"):
            sfx = _suffix(pos or cov)
            cfg = {"name": None, "command_topic": set_topic}
            if cov:
                cfg.update({"payload_open": '{"state": "OPEN"}', "payload_close": '{"state": "CLOSE"}', "payload_stop": '{"state": "STOP"}'})
            if pos:
                cfg.update({"position_topic": state_topic, "position_template": f"{{{{ value_json.{pos['key']} }}}}"})
                if pos["access"] == "rw":
                    cfg.update({"set_position_topic": set_topic, "set_position_template": '{"%s": {{ position }} }' % pos["key"]})
            add("cover", f"cover{sfx}", cfg)
            handled |= {x["key"] for x in (pos, cov) if x}
        lt, sp = bases.get("local_temperature"), bases.get("current_heating_setpoint")
        if sp:
            sfx = _suffix(sp)
            mode, preset = bases.get("system_mode"), bases.get("preset")
            cfg = {"name": None, "temperature_state_topic": state_topic, "temperature_state_template": f"{{{{ value_json.{sp['key']} }}}}",
                   "temperature_command_topic": set_topic, "temperature_command_template": '{"%s": {{ value }} }' % sp["key"],
                   "min_temp": sp.get("min", 5), "max_temp": sp.get("max", 30), "temp_step": sp.get("step", 0.5), "temperature_unit": "C"}
            if lt:
                cfg.update({"current_temperature_topic": state_topic, "current_temperature_template": f"{{{{ value_json.{lt['key']} }}}}"})
            if mode and mode["access"] == "rw":
                cfg.update({"mode_state_topic": state_topic, "mode_state_template": f"{{{{ value_json.{mode['key']} }}}}",
                            "mode_command_topic": set_topic, "mode_command_template": '{"%s": "{{ value }}" }' % mode["key"],
                            "modes": [m for m in mode.get("values", []) if m in ("off", "heat", "cool", "auto")]})
                handled.add(mode["key"])
            else:
                cfg["modes"] = ["heat"]
            if preset and preset["access"] == "rw":
                cfg.update({"preset_mode_state_topic": state_topic, "preset_mode_value_template": f"{{{{ value_json.{preset['key']} }}}}",
                            "preset_mode_command_topic": set_topic, "preset_mode_command_template": '{"%s": "{{ value }}" }' % preset["key"],
                            "preset_modes": preset.get("values", [])})
                handled.add(preset["key"])
            add("climate", f"climate{sfx}", cfg)
            handled |= {x["key"] for x in (lt, sp) if x}

    # -- one entity per remaining feature ------------------------------------------------------
    for f in feats:
        key, typ, acc = f["key"], f["type"], f["access"]
        if key in handled or typ == "action" or typ == "composite":
            continue
        tmpl = f"{{{{ value_json.{key} }}}}"
        diag = "diagnostic" if f["category"] == "diagnostic" else ("config" if f["category"] == "config" else None)
        if typ == "binary" and acc == "r":
            cfg = {"name": f["name"], "value_template": tmpl, "payload_on": True, "payload_off": False, "entity_category": diag}
            if f["base"] == "contact":  # our contact: true == closed; HA door: on == open
                cfg["value_template"] = f"{{{{ not value_json.{key} }}}}"
            dc = f.get("device_class") or _BINARY_CLASS.get(f["base"])
            if dc:
                cfg["device_class"] = dc
            add("binary_sensor", key, cfg)
        elif typ == "binary" and key == "child_lock":
            add("lock", key, {"name": f["name"], "command_topic": set_topic, "value_template": tmpl, "entity_category": "config",
                              "payload_lock": json.dumps({key: "LOCK"}), "payload_unlock": json.dumps({key: "UNLOCK"}),
                              "state_locked": "LOCK", "state_unlocked": "UNLOCK"})
        elif typ == "binary":
            on, off = f.get("value_on", "ON"), f.get("value_off", "OFF")
            add("switch", key, {"name": f["name"], "command_topic": set_topic, "value_template": tmpl, "entity_category": diag,
                                "payload_on": json.dumps({key: on}), "payload_off": json.dumps({key: off}), "state_on": on, "state_off": off})
        elif typ == "numeric" and acc == "r":
            dc, unit, sc, ec = _SENSOR_META.get(f["base"], (None, f.get("unit"), "measurement", None))
            if f["base"] == "voltage" and f.get("unit") == "mV":
                unit = "mV"
            dc = f.get("device_class") or dc
            add("sensor", key, {"name": f["name"], "value_template": tmpl, "device_class": dc, "unit_of_measurement": unit or f.get("unit"),
                                "state_class": sc, "entity_category": diag or ec, "icon": _ICONS.get(f["base"]),
                                "enabled_by_default": False if f["base"] in ("voltage", "device_temperature", "power_outage_count") and f["category"] == "diagnostic" else None})
        elif typ == "numeric":
            dc, unit, _sc, _ec = _SENSOR_META.get(f["base"], (None, f.get("unit"), None, None))
            add("number", key, {"name": f["name"], "command_topic": set_topic, "value_template": tmpl, "command_template": '{"%s": {{ value }} }' % key,
                                "min": f.get("min"), "max": f.get("max"), "step": f.get("step"), "unit_of_measurement": unit or f.get("unit"),
                                "device_class": f.get("device_class") or dc, "entity_category": diag, "mode": "slider" if f.get("max") is not None else "box"})
        elif typ == "enum" and acc == "r":
            add("sensor", key, {"name": f["name"], "value_template": tmpl, "icon": _ICONS.get(f["base"]), "entity_category": diag,
                                "enabled_by_default": True})
        elif typ == "enum":
            add("select", key, {"name": f["name"], "command_topic": set_topic, "value_template": tmpl, "command_template": '{"%s": "{{ value }}" }' % key,
                                "options": f.get("values", []), "entity_category": diag, "icon": _ICONS.get(f["base"])})
        elif typ == "text" and acc == "r":
            add("sensor", key, {"name": f["name"], "value_template": tmpl, "entity_category": diag})
    return out


def removal_messages(dev: Device, prefix: str, *, legacy: bool = False) -> list[tuple[str, bytes]]:
    """Blank retained configs so HA deletes the entities."""
    return [(topic, b"") for topic, _ in discovery_messages(dev, "x", prefix, legacy=legacy)]


def bridge_discovery(base: str, prefix: str, *, legacy: bool = False) -> list[tuple[str, bytes]]:
    device = {"identifiers": [Topics(base, prefix, legacy).bridge_identifier()], "name": "OneRoof Zigbee bridge", "manufacturer": "OneRoof",
              "model": "gateway", "sw_version": __version__}
    avail_b: dict[str, Any] = {"topic": f"{base}/bridge/state"}
    if legacy:
        avail_b["value_template"] = "{{ value_json.state }}"
    common = {"device": device, "availability": [avail_b]}
    msgs = [
        (f"{prefix}/switch/oneroof_zigbee_bridge/permit_join/config", json.dumps({
            **common, "name": "Permit join", "unique_id": "oneroof_zigbee_bridge_permit_join", "icon": "mdi:human-greeting-proximity",
            "state_topic": f"{base}/bridge/permit_join", "value_template": "{{ value_json.open }}",
            "state_on": True, "state_off": False,
            "command_topic": f"{base}/bridge/request/permit_join",
            "payload_on": '{"seconds": 60}', "payload_off": '{"seconds": 0}',
        }).encode()),
        (f"{prefix}/sensor/oneroof_zigbee_bridge/security_alert/config", json.dumps({
            **common, "name": "Last security alert", "unique_id": "oneroof_zigbee_bridge_security_alert", "icon": "mdi:shield-alert",
            "state_topic": f"{base}/bridge/security", "value_template": "{{ value_json.type }}",
            "json_attributes_topic": f"{base}/bridge/security",
        }).encode()),
        (f"{prefix}/sensor/oneroof_zigbee_bridge/devices/config", json.dumps({
            **common, "name": "Devices", "unique_id": "oneroof_zigbee_bridge_devices", "icon": "mdi:zigbee",
            "state_topic": f"{base}/bridge/info", "value_template": "{{ value_json.device_count }}",
            "json_attributes_topic": f"{base}/bridge/info", "entity_category": "diagnostic",
        }).encode()),
    ]
    return msgs
