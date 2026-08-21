"""Home Assistant MQTT discovery payloads.

Entities are derived from the clusters each endpoint exposes — no per-model
database.  Each (device, cluster) becomes one or more HA entities with a
stable `unique_id` so renaming in HA survives restarts.
"""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..devices import Device

# cluster id → list of (component, object_id, extra config)
_SENSORS: dict[int, list[tuple[str, str, dict[str, Any]]]] = {
    0x0001: [
        ("sensor", "battery", {"device_class": "battery", "unit_of_measurement": "%", "state_class": "measurement",
                               "value_template": "{{ value_json.battery }}", "entity_category": "diagnostic"}),
        ("sensor", "voltage", {"device_class": "voltage", "unit_of_measurement": "V", "state_class": "measurement",
                               "value_template": "{{ value_json.voltage }}", "entity_category": "diagnostic", "enabled_by_default": False}),
    ],
    0x0402: [("sensor", "temperature", {"device_class": "temperature", "unit_of_measurement": "°C", "state_class": "measurement",
                                       "value_template": "{{ value_json.temperature }}"})],
    0x0403: [("sensor", "pressure", {"device_class": "pressure", "unit_of_measurement": "hPa", "state_class": "measurement",
                                    "value_template": "{{ value_json.pressure }}"})],
    0x0405: [("sensor", "humidity", {"device_class": "humidity", "unit_of_measurement": "%", "state_class": "measurement",
                                    "value_template": "{{ value_json.humidity }}"})],
    0x0400: [("sensor", "illuminance", {"device_class": "illuminance", "unit_of_measurement": "lx", "state_class": "measurement",
                                       "value_template": "{{ value_json.illuminance_lux }}"})],
    0x0406: [("binary_sensor", "occupancy", {"device_class": "occupancy", "value_template": "{{ value_json.occupancy }}",
                                            "payload_on": True, "payload_off": False})],
    0x0B04: [
        ("sensor", "power", {"device_class": "power", "unit_of_measurement": "W", "state_class": "measurement",
                             "value_template": "{{ value_json.power }}"}),
        ("sensor", "voltage_ac", {"device_class": "voltage", "unit_of_measurement": "V", "state_class": "measurement",
                                  "value_template": "{{ value_json.voltage }}"}),
        ("sensor", "current", {"device_class": "current", "unit_of_measurement": "A", "state_class": "measurement",
                               "value_template": "{{ value_json.current }}"}),
    ],
    0x0702: [("sensor", "energy", {"device_class": "energy", "unit_of_measurement": "kWh", "state_class": "total_increasing",
                                  "value_template": "{{ value_json.energy }}"})],
}

_IAS_BY_ZONE_TYPE: dict[int, tuple[str, str]] = {
    0x0015: ("contact", "door"),          # contact switch → HA "door" (inverted below)
    0x000D: ("occupancy", "motion"),
    0x002A: ("water_leak", "moisture"),
    0x0028: ("smoke", "smoke"),
    0x002B: ("carbon_monoxide", "carbon_monoxide"),
    0x002D: ("vibration", "vibration"),
}


def _device_block(dev: Device) -> dict[str, Any]:
    return {
        "identifiers": [f"oneroof_zigbee_{dev.ieee_str}"],
        "name": dev.friendly_name,
        "manufacturer": dev.manufacturer or "Zigbee",
        "model": dev.model or "unknown",
        "sw_version": dev.sw_build or None,
        "via_device": "oneroof_zigbee_bridge",
    }


def discovery_messages(dev: Device, base: str, prefix: str) -> list[tuple[str, bytes]]:
    """Return [(topic, payload)] for all entities of a device. Empty payload = remove."""
    out: list[tuple[str, bytes]] = []
    state_topic = f"{base}/{dev.ieee_str}/state"
    set_topic = f"{base}/{dev.ieee_str}/set"
    avail = [{"topic": f"{base}/bridge/state"}, {"topic": f"{base}/{dev.ieee_str}/availability"}]
    common = {
        "availability": avail, "availability_mode": "all",
        "device": _device_block(dev),
        "origin": {"name": "OneRoof Zigbee", "sw_version": __version__},
        "state_topic": state_topic,
    }

    def add(component: str, object_id: str, cfg: dict[str, Any]) -> None:
        uid = f"oneroof_zigbee_{dev.ieee_str}_{object_id}"
        payload = {**common, **cfg, "unique_id": uid, "object_id": f"{dev.friendly_name}_{object_id}"}
        payload = {k: v for k, v in payload.items() if v is not None}
        out.append((f"{prefix}/{component}/{dev.ieee_str}/{object_id}/config", json.dumps(payload).encode()))

    seen_in: set[int] = set()
    for ep in dev.endpoints.values():
        ins = set(ep.in_clusters)
        seen_in |= ins
        suffix = "" if len(dev.endpoints) == 1 else f"_{ep.id}"

        if 0x0006 in ins and (0x0008 in ins or 0x0300 in ins):
            cfg: dict[str, Any] = {
                "name": None, "schema": "json", "command_topic": set_topic, "brightness": 0x0008 in ins,
                "supported_color_modes": (["xy", "color_temp"] if 0x0300 in ins else ["brightness"]),
            }
            add("light", f"light{suffix}", cfg)
        elif 0x0006 in ins:
            comp = "switch"
            add(comp, f"switch{suffix}", {"name": None, "command_topic": set_topic,
                                          "value_template": "{{ value_json.state }}",
                                          "payload_on": '{"state": "ON"}', "payload_off": '{"state": "OFF"}',
                                          "state_on": "ON", "state_off": "OFF"})
        if 0x0102 in ins:
            add("cover", f"cover{suffix}", {"name": None, "command_topic": set_topic,
                                            "payload_open": '{"state": "OPEN"}', "payload_close": '{"state": "CLOSE"}',
                                            "payload_stop": '{"state": "STOP"}',
                                            "position_topic": state_topic, "position_template": "{{ value_json.position }}",
                                            "set_position_topic": set_topic, "set_position_template": '{"position": {{ position }} }'})
        if 0x0201 in ins:
            add("climate", f"climate{suffix}", {"name": None, "current_temperature_topic": state_topic,
                                                "current_temperature_template": "{{ value_json.local_temperature }}",
                                                "temperature_state_topic": state_topic,
                                                "temperature_state_template": "{{ value_json.heating_setpoint }}",
                                                "temperature_command_topic": set_topic,
                                                "temperature_command_template": '{"heating_setpoint": {{ value }} }',
                                                "mode_state_topic": state_topic, "mode_state_template": "{{ value_json.system_mode }}",
                                                "mode_command_topic": set_topic, "mode_command_template": '{"system_mode": "{{ value }}" }',
                                                "modes": ["off", "heat", "auto"], "temp_step": 0.5})
        if 0x0500 in ins:
            zone_type = dev.context.get("zone_type")
            key, dclass = _IAS_BY_ZONE_TYPE.get(zone_type, ("alarm_1", None)) if zone_type is not None else ("alarm_1", None)
            cfg = {"value_template": f"{{{{ value_json.{key} }}}}", "payload_on": True, "payload_off": False}
            if key == "contact":  # our "contact": true == closed; HA door: on == open
                cfg = {"value_template": "{{ not value_json.contact }}", "payload_on": True, "payload_off": False}
            if dclass:
                cfg["device_class"] = dclass
            add("binary_sensor", f"{key}{suffix}", cfg)
            add("binary_sensor", f"tamper{suffix}", {"device_class": "tamper", "value_template": "{{ value_json.tamper }}",
                                                     "payload_on": True, "payload_off": False, "entity_category": "diagnostic"})
        for cluster, entities in _SENSORS.items():
            if cluster in ins:
                for comp, obj, cfg in entities:
                    add(comp, f"{obj}{suffix}", dict(cfg))

    # diagnostics every device gets
    add("sensor", "linkquality", {"name": "Link quality", "unit_of_measurement": "lqi", "state_class": "measurement",
                                  "value_template": "{{ value_json.linkquality }}", "entity_category": "diagnostic",
                                  "icon": "mdi:signal"})
    return out


def removal_messages(dev: Device, prefix: str) -> list[tuple[str, bytes]]:
    """Blank retained configs so HA deletes the entities."""
    return [(topic, b"") for topic, _ in discovery_messages(dev, "x", prefix)]


def bridge_discovery(base: str, prefix: str) -> list[tuple[str, bytes]]:
    device = {"identifiers": ["oneroof_zigbee_bridge"], "name": "OneRoof Zigbee bridge", "manufacturer": "OneRoof",
              "model": "gateway", "sw_version": __version__}
    common = {"device": device, "availability": [{"topic": f"{base}/bridge/state"}]}
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
