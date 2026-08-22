"""Model-knowledge layer: kinds, feature shaping, HA discovery and vendor report decoding.

Every case builds a Device with the endpoints/clusters the real model advertises (synthetic
IEEEs) and checks what the generic layer + quirks make of it. No hardware, no network.
"""

from __future__ import annotations

import asyncio
import json
import struct

import pytest

from oneroof_zigbee import quirks
from oneroof_zigbee.devices import Device, Endpoint
from oneroof_zigbee.features import features_for, generic_features
from oneroof_zigbee.ha.discovery import discovery_messages
from oneroof_zigbee.zcl import vendor as vz
from oneroof_zigbee.zcl.global_commands import decode_global_command
from oneroof_zigbee.zcl.frame import decode_frame

IEEE = 0x00158D0000000001
NWK = 0x2345


def mk(manufacturer: str, model: str, eps: dict[int, tuple[list[int], list[int], int]], *, power: str = "battery",
       router: bool = False, ctx: dict | None = None, ieee: int = IEEE) -> Device:
    d = Device(ieee=ieee, nwk=NWK, friendly_name="test", manufacturer=manufacturer, model=model, power_source=power,
               is_router=router, rx_on_when_idle=router)
    for ep, (ins, outs, did) in eps.items():
        d.endpoints[ep] = Endpoint(ep, 0x0104, did, list(ins), list(outs))
    if ctx:
        d.context.update(ctx)
    return d


def keys(dev: Device) -> dict[str, dict]:
    return {f["key"]: f for f in features_for(dev)}


def ha(dev: Device, *, legacy: bool = True) -> dict[str, tuple[str, dict]]:
    """object_id → (component, payload)"""
    out = {}
    for topic, payload in discovery_messages(dev, "oz", "homeassistant", legacy=legacy):
        parts = topic.split("/")
        out[parts[-2]] = (parts[1], json.loads(payload))
    return out


# ---------------------------------------------------------------------------------------------
# Fixture table: (manufacturer, model, endpoints, power, router) → expectations
# ---------------------------------------------------------------------------------------------

LUMI_SENSOR_EP = ([0x0000, 0x0003, 0xFFFF, 0x0019], [0x0000, 0x0004, 0x0003, 0x0006, 0x0008, 0x0005, 0x0019], 0x5F01)
IAS_EP = lambda extra=(): ([0x0000, 0x0001, 0x0003, 0x0500, *extra], [0x0019], 0x0402)  # noqa: E731

CASES = [
    # id, manufacturer, model, endpoints, power, router, ctx, kind, category, present keys, absent keys, {object_id: (component, device_class)}
    ("aqara_magnet", "LUMI", "lumi.sensor_magnet.aq2", {1: LUMI_SENSOR_EP}, "battery", False, None,
     "Contact sensor", "sensor", {"contact", "battery", "voltage", "device_temperature", "linkquality"}, {"state", "power_on_behavior", "countdown", "action"},
     {"contact": ("binary_sensor", "door"), "battery": ("sensor", "battery"), "voltage": ("sensor", "voltage")}),
    ("aqara_magnet_onoff_server", "LUMI", "lumi.sensor_magnet", {1: ([0x0000, 0x0003, 0x0006, 0xFFFF], [0x0019], 0x5F01)}, "battery", False, None,
     "Contact sensor", "sensor", {"contact", "battery"}, {"state", "power_on_behavior", "countdown"}, {"contact": ("binary_sensor", "door")}),
    ("aqara_motion", "LUMI", "lumi.sensor_motion.aq2", {1: ([0x0000, 0x0003, 0x0400, 0x0406, 0xFFFF], [0x0000, 0x0019], 0x0107)}, "battery", False, None,
     "Motion sensor", "sensor", {"occupancy", "illuminance_lux", "battery"}, {"state"}, {"occupancy": ("binary_sensor", "motion"), "illuminance": ("sensor", "illuminance")}),
    ("aqara_weather", "LUMI", "lumi.weather", {1: ([0x0000, 0x0001, 0x0003, 0x0402, 0x0403, 0x0405, 0xFFFF], [0x0000, 0x0004, 0xFFFF], 0x5F01)}, "battery", False, None,
     "Temperature/humidity/pressure sensor", "sensor", {"temperature", "humidity", "pressure", "battery", "voltage"}, {"state", "identify"},
     {"temperature": ("sensor", "temperature"), "humidity": ("sensor", "humidity"), "pressure": ("sensor", "pressure")}),
    ("aqara_wleak", "LUMI", "lumi.sensor_wleak.aq1", {1: IAS_EP()}, "battery", False, {"zone_type": 0x002A},
     "Water leak sensor", "sensor", {"water_leak", "battery", "tamper", "battery_low"}, {"state"}, {"water_leak": ("binary_sensor", "moisture")}),
    ("aqara_vibration", "LUMI", "lumi.vibration.aq1", {1: ([0x0000, 0x0003, 0x0019, 0x0101], [0x0000, 0x0004, 0x0003, 0x0005, 0x0019, 0x0101], 0x000A)}, "battery", False, None,
     "Vibration sensor", "sensor", {"action", "battery"}, {"state", "lock_state"}, {"action": ("sensor", None)}),
    ("aqara_button", "LUMI", "lumi.sensor_switch.aq2", {1: ([0x0000, 0x0006, 0x0003], [0x0000, 0x0004, 0x0006, 0x0008, 0x0005, 0x0019], 0x5F01)}, "battery", False, None,
     "Button", "remote", {"action", "battery"}, {"state", "power_on_behavior", "countdown"}, {"action": ("sensor", None)}),
    ("aqara_2button", "LUMI", "lumi.remote.b286acn01", {1: ([0x0000, 0x0003, 0x0019, 0x0012], [0x0000, 0x0004, 0x0003, 0x0005, 0x0019, 0x0012], 0x5F01),
                                                          2: ([0x0003, 0x0012], [0x0003, 0x0012], 0x5F01), 3: ([0x0003, 0x0012], [0x0003, 0x0012], 0x5F01)}, "battery", False, None,
     "Wireless switch (2 button)", "remote", {"action", "battery"}, {"state"}, {"action": ("sensor", None)}),
    ("aqara_plug", "LUMI", "lumi.plug.maus01", {1: ([0x0000, 0x0004, 0x0003, 0x0006, 0x0010, 0x0005, 0x000A, 0x0001, 0x0002], [0x0019, 0x000A], 0x0051),
                                                 2: ([0x000C], [0x000C, 0x0004], 0x0009), 3: ([0x000C], [0x000C], 0x0083)}, "mains", True, None,
     "Smart plug", "plug", {"state", "power", "energy", "device_temperature"}, {"countdown", "power_on_behavior"}, {"switch": ("switch", None), "power": ("sensor", "power"), "energy": ("sensor", "energy")}),
    ("aqara_2gang", "LUMI", "lumi.switch.b2naus01", {1: ([0x0000, 0x0004, 0x0003, 0x0006, 0x0002, 0x0009, 0xFCC0], [0x000A, 0x0019], 0x0100), 2: ([0x0006, 0x0004, 0x0005], [], 0x0100),
                                                      41: ([0x0012], [], 0x0100), 42: ([0x0012], [], 0x0100), 51: ([0x0012], [], 0x0100)}, "mains", True, None,
     "Wall switch (2 gang)", "switch", {"state_left", "state_right", "action"}, {"state", "state_l1", "countdown", "countdown_left"},
     {"switch_left": ("switch", None), "switch_right": ("switch", None), "action": ("sensor", None)}),
    ("aqara_curtain", "LUMI", "lumi.curtain", {1: ([0x0000, 0x0004, 0x0003, 0x0005, 0x000A, 0x000D, 0x0102, 0x0006], [0x000A, 0x0019], 0x0202)}, "mains", True, None,
     "Curtain motor", "cover", {"position", "cover"}, {"state", "countdown"}, {"cover": ("cover", None)}),
    ("aqara_smoke", "LUMI", "lumi.sensor_smoke", {1: ([0x0000, 0x0001, 0x0003, 0x000C, 0x0012, 0x0500], [0x0019], 0x0402)}, "battery", False, {"zone_type": 0x0028},
     "Smoke detector", "sensor", {"smoke", "battery"}, {"state"}, {"smoke": ("binary_sensor", "smoke")}),
    ("tuya_plug", "_TZ3000_ko6v90pg", "TS011F", {1: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0702, 0x0B04, 0xE000, 0xE001], [0x0019, 0x000A], 0x0051)}, "mains", True, None,
     "Smart plug", "plug", {"state", "power_on_behavior", "countdown", "power", "energy", "current", "voltage", "child_lock", "indicator_mode"}, set(),
     {"switch": ("switch", None), "power": ("sensor", "power"), "energy": ("sensor", "energy"), "child_lock": ("lock", None), "indicator_mode": ("select", None), "power_on_behavior": ("select", None)}),
    ("tuya_2gang", "_TZ3000_owgcnkrh", "TS0012", {1: ([0x0000, 0x0004, 0x0005, 0x0006, 0xE001], [0x0019, 0x000A], 0x0100), 2: ([0x0004, 0x0005, 0x0006, 0xE001], [], 0x0100)}, "mains", True, None,
     "Wall switch (2 gang)", "switch", {"state_l1", "state_l2"}, {"state"}, {"switch_l1": ("switch", None), "switch_l2": ("switch", None)}),
    ("tuya_4relay", "_TZ3000_u3oupgdy", "TS0004", {i: ([0x0000, 0x0004, 0x0005, 0x0006], [], 0x0100) for i in (1, 2, 3, 4)}, "mains", True, None,
     "Relay (4 channel)", "switch", {"state_l1", "state_l2", "state_l3", "state_l4"}, {"state"}, {"switch_l4": ("switch", None)}),
    ("tuya_4button", "_TZ3000_vp6clf9d", "TS0044", {i: ([0x0000, 0x0001, 0x0006], [0x0019, 0x000A], 0x0000) for i in (1, 2, 3, 4)}, "battery", False, None,
     "Button (4 button)", "remote", {"action", "battery"}, {"state", "state_l1"}, {"action": ("sensor", None)}),
    ("tuya_contact", "_TZ3000_26fmupbb", "TS0203", {1: IAS_EP()}, "battery", False, {"zone_type": 0x0015},
     "Contact sensor", "sensor", {"contact", "battery"}, {"state"}, {"contact": ("binary_sensor", "door")}),
    ("tuya_motion", "_TZ3000_mmtwjmaq", "TS0202", {1: IAS_EP()}, "battery", False, {"zone_type": 0x000D},
     "Motion sensor", "sensor", {"occupancy", "battery"}, set(), {"occupancy": ("binary_sensor", "motion")}),
    ("tuya_th", "_TZE200_locansqn", "TS0601", {1: ([0x0000, 0x0004, 0x0005, 0xEF00], [0x0019, 0x000A], 0x0051)}, "battery", False, None,
     "Temperature/humidity sensor", "sensor", {"temperature", "humidity", "battery"}, {"state"}, {"temperature": ("sensor", "temperature"), "humidity": ("sensor", "humidity")}),
    ("tuya_trv", "_TZE200_ckud7u2l", "TS0601", {1: ([0x0000, 0x0004, 0x0005, 0xEF00], [0x0019, 0x000A], 0x0051)}, "battery", False, None,
     "Thermostat/TRV", "climate", {"current_heating_setpoint", "local_temperature", "child_lock", "preset"}, {"state"}, {"climate": ("climate", None), "child_lock": ("lock", None)}),
    ("tuya_cover", "_TZE200_fzo2pocs", "TS0601", {1: ([0x0000, 0x0004, 0x0005, 0xEF00], [0x0019, 0x000A], 0x0051)}, "mains", True, None,
     "Curtain motor", "cover", {"cover", "position"}, {"state"}, {"cover": ("cover", None)}),
    ("tuya_radar", "_TZE200_ztc6ggyl", "TS0601", {1: ([0x0000, 0x0004, 0x0005, 0xEF00], [0x0019, 0x000A], 0x0051)}, "mains", True, None,
     "Presence sensor (radar)", "sensor", {"presence", "target_distance", "illuminance_lux", "radar_sensitivity"}, {"state"},
     {"presence": ("binary_sensor", "occupancy"), "radar_sensitivity": ("number", None)}),
    ("tuya_bulb", "_TZ3210_abcdefgh", "TS0505B", {1: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0300, 0x1000], [0x000A, 0x0019], 0x010D)}, "mains", True, None,
     "Bulb (colour)", "light", {"state", "brightness", "color_temp", "color"}, set(), {"light": ("light", None)}),
    ("ikea_bulb", "IKEA of Sweden", "TRADFRI bulb E27 WS opal 980lm", {1: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0300, 0x0B05, 0x1000], [0x0005, 0x0019, 0x0020, 0x1000], 0x010C)}, "mains", True, None,
     "Bulb (colour temperature)", "light", {"state", "brightness", "color_temp"}, set(), {"light": ("light", None)}),
    ("ikea_remote", "IKEA of Sweden", "TRADFRI remote control", {1: ([0x0000, 0x0001, 0x0003, 0x0009, 0x0020, 0x1000, 0xFC7C], [0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0019, 0x1000], 0x0830)}, "battery", False, None,
     "Remote (5 button)", "remote", {"action", "battery"}, {"state"}, {"action": ("sensor", None), "battery": ("sensor", "battery")}),
    ("ikea_motion", "IKEA of Sweden", "TRADFRI motion sensor", {1: ([0x0000, 0x0001, 0x0003, 0x0009, 0x0B05, 0x1000], [0x0003, 0x0004, 0x0006, 0x0008, 0x0019, 0x1000], 0x0800)}, "battery", False, None,
     "Motion sensor", "sensor", {"occupancy", "battery"}, {"state", "action"}, {"occupancy": ("binary_sensor", "motion")}),
    ("ikea_blind", "IKEA of Sweden", "FYRTUR block-out roller blind", {1: ([0x0000, 0x0001, 0x0003, 0x0004, 0x0005, 0x0020, 0x0102, 0x1000, 0xFC7C], [0x0019, 0x1000], 0x0202)}, "battery", False, None,
     "Roller blind", "cover", {"position", "cover", "battery"}, set(), {"cover": ("cover", None)}),
    ("ikea_plug", "IKEA of Sweden", "TRETAKT Smart plug", {1: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x1000, 0xFC7C], [0x0005, 0x0019, 0x0020, 0x1000], 0x010A)}, "mains", True, None,
     "Smart plug", "plug", {"state"}, set(), {"switch": ("switch", None)}),
    ("hue_bulb", "Signify Netherlands B.V.", "LCA001", {11: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0300, 0x1000, 0xFC01], [0x0019], 0x010D), 242: ([], [0x0021], 0x0061)}, "mains", True, None,
     "Bulb (colour)", "light", {"state", "brightness", "color"}, set(), {"light": ("light", None)}),
    ("hue_dimmer", "Philips", "RWL021", {1: ([0x0000], [0x0003, 0x0004, 0x0006, 0x0008, 0x0005, 0x1000], 0x0830), 2: ([0x0000, 0x0001, 0x0003, 0xFC00], [0x0019], 0x0850)}, "battery", False, None,
     "Dimmer switch", "remote", {"action", "battery"}, {"state"}, {"action": ("sensor", None)}),
    ("hue_motion", "Philips", "SML001", {1: ([0x0000], [0x0003, 0x0004, 0x0006, 0x0008, 0x0005, 0x1000], 0x0830), 2: ([0x0000, 0x0001, 0x0003, 0x0400, 0x0402, 0x0406], [0x0019], 0x0107)}, "battery", False, None,
     "Motion sensor", "sensor", {"occupancy", "illuminance_lux", "temperature", "battery"}, {"state", "action"}, {"occupancy": ("binary_sensor", "motion"), "temperature": ("sensor", "temperature")}),
    ("sonoff_button", "eWeLink", "WB01", {1: ([0x0000, 0x0001, 0x0003], [0x0003, 0x0006], 0x0000)}, "battery", False, None,
     "Button", "remote", {"action", "battery"}, {"state"}, {"action": ("sensor", None)}),
    ("sonoff_th", "eWeLink", "TH01", {1: ([0x0000, 0x0001, 0x0003, 0x0402, 0x0405], [0x0003], 0x0302)}, "battery", False, None,
     "Temperature/humidity sensor", "sensor", {"temperature", "humidity", "battery"}, set(), {"temperature": ("sensor", "temperature")}),
    ("sonoff_contact", "eWeLink", "DS01", {1: IAS_EP()}, "battery", False, {"zone_type": 0x0015},
     "Contact sensor", "sensor", {"contact", "battery"}, {"state"}, {"contact": ("binary_sensor", "door")}),
    ("sonoff_trv", "SONOFF", "TRVZB", {1: ([0x0000, 0x0001, 0x0003, 0x0006, 0x0020, 0x0201, 0x0204, 0xFC11], [0x000A, 0x0019], 0x0301)}, "battery", False, None,
     "Thermostat/TRV", "climate", {"current_heating_setpoint", "local_temperature", "system_mode"}, {"state", "countdown"}, {"climate": ("climate", None)}),
    ("sonoff_mini", "SONOFF", "ZBMINIL2", {1: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0020, 0xFC57, 0xFC11], [0x0019], 0x0100)}, "mains", True, None,
     "Switch module", "switch", {"state"}, set(), {"switch": ("switch", None)}),
    ("heiman_smoke", "HEIMAN", "SmokeSensor-EM", {1: ([0x0000, 0x0001, 0x0003, 0x0500, 0x0502], [0x0019], 0x0402)}, "battery", False, {"zone_type": 0x0028},
     "Smoke detector", "sensor", {"smoke", "battery"}, set(), {"smoke": ("binary_sensor", "smoke")}),
    ("heiman_gas", "HEIMAN", "GASSensor-EM", {1: ([0x0000, 0x0003, 0x0500, 0x0502], [0x0019], 0x0402)}, "mains", True, {"zone_type": 0x002B},
     "Gas detector", "sensor", {"gas"}, {"carbon_monoxide"}, {"gas": ("binary_sensor", "gas")}),
    ("frient_plug", "frient A/S", "SPLZB-131", {2: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0702, 0x0B04], [0x0019], 0x0051)}, "mains", True, None,
     "Smart plug (metering)", "plug", {"state", "power", "energy"}, set(), {"switch": ("switch", None), "energy": ("sensor", "energy")}),
    ("frient_motion", "frient A/S", "MOSZB-140", {35: ([0x0000, 0x0003, 0x000F, 0x0020, 0x0500], [0x0019], 0x0402), 38: ([0x0000, 0x0003, 0x0402], [], 0x0302), 39: ([0x0000, 0x0003, 0x0400], [], 0x0106)}, "battery", False, {"zone_type": 0x000D},
     "Motion sensor", "sensor", {"occupancy", "temperature", "illuminance_lux"}, set(), {"occupancy": ("binary_sensor", "motion")}),
    ("thirdreality_switch", "Third Reality, Inc", "3RSS008Z", {1: ([0x0000, 0x0001, 0x0003, 0x0004, 0x0005, 0x0006], [0x0019], 0x0002)}, "battery", False, None,
     "Switch actuator", "switch", {"state", "battery"}, {"countdown", "power_on_behavior"}, {"switch": ("switch", None)}),
    ("danfoss_trv", "Danfoss", "eTRV0100", {1: ([0x0000, 0x0001, 0x0003, 0x000A, 0x0020, 0x0201, 0x0204, 0x0B05], [0x0000, 0x0019], 0x0301)}, "battery", False, None,
     "Thermostat/TRV", "climate", {"current_heating_setpoint", "local_temperature", "battery"}, set(), {"climate": ("climate", None)}),
    ("bosch_contact", "BOSCH", "RBSH-SWD-ZB", {1: ([0x0000, 0x0001, 0x0003, 0x0500, 0x0B05], [0x0019], 0x0402)}, "battery", False, {"zone_type": 0x0015},
     "Contact sensor", "sensor", {"contact", "battery"}, set(), {"contact": ("binary_sensor", "door")}),
    ("yale_lock", "Yale", "YRD226 TSDB", {1: ([0x0000, 0x0001, 0x0003, 0x0004, 0x0009, 0x000A, 0x0101, 0x0020], [0x000A, 0x0019], 0x000A)}, "battery", False, None,
     "Door lock", "lock", {"state", "lock_state", "battery"}, {"countdown", "power_on_behavior"}, {"lock": ("lock", None), "lock_state": ("sensor", None)}),
    ("kwikset_lock", "Kwikset", "SMARTCODE_DEADBOLT_10", {1: ([0x0000, 0x0001, 0x0003, 0x0004, 0x0009, 0x000A, 0x0101, 0x0020], [0x000A, 0x0019], 0x000A)}, "battery", False, None,
     "Door lock", "lock", {"state", "lock_state"}, set(), {"lock": ("lock", None)}),
    ("ubisys_s2", "ubisys", "S2", {1: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006], [0x0019], 0x0002), 2: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006], [], 0x0002),
                                   3: ([0x0000, 0x0003], [0x0003, 0x0004, 0x0005, 0x0006, 0x0008], 0x0001), 4: ([0x0000, 0x0003], [0x0003, 0x0004, 0x0005, 0x0006, 0x0008], 0x0001), 5: ([0x0000, 0x0702], [], 0x0053)}, "mains", True, None,
     "Switch (2 gang)", "switch", {"state_l1", "state_l2", "energy"}, {"state"}, {"switch_l1": ("switch", None), "switch_l2": ("switch", None)}),
    ("gledopto", "GLEDOPTO", "GL-C-008", {11: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0300, 0x1000], [0x0019], 0x0210)}, "mains", True, None,
     "LED controller", "light", {"state", "brightness", "color"}, set(), {"light": ("light", None)}),
    ("lixee", "LiXee", "ZLinky_TIC", {1: ([0x0000, 0x0003, 0x0702, 0x0B01, 0x0B04, 0xFF66], [0x0019], 0x0053)}, "mains", True, None,
     "Electricity meter", "meter", {"energy", "power"}, {"state"}, {"energy": ("sensor", "energy")}),
    ("visonic", "Visonic", "MCT-340 E", {1: ([0x0000, 0x0001, 0x0003, 0x0020, 0x0402, 0x0500], [0x0019], 0x0402)}, "battery", False, {"zone_type": 0x0015},
     "Contact sensor", "sensor", {"contact", "temperature", "battery"}, set(), {"contact": ("binary_sensor", "door")}),
    ("aurora_double", "Aurora", "AU-A1ZBDSS", {1: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0B04], [0x0019], 0x0051), 2: ([0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0B04], [], 0x0051)}, "mains", True, None,
     "Double socket", "plug", {"state_left", "state_right", "power_1", "power_2"}, {"state"}, {"switch_left": ("switch", None), "switch_right": ("switch", None)}),
    # unknown models: heuristics must still produce a sane kind
    ("unknown_battery_onoff_remote", "Acme", "KNOB-1", {1: ([0x0000, 0x0001, 0x0003], [0x0006, 0x0008], 0x0104)}, "battery", False, None,
     "Button/remote", "remote", {"action", "battery"}, {"state"}, {"action": ("sensor", None)}),
    ("unknown_battery_onoff_server", "Acme", "SENS-9", {1: ([0x0000, 0x0001, 0x0003, 0x0006], [], 0x0000)}, "battery", False, None,
     "Button/remote", "remote", {"battery"}, {"state", "power_on_behavior", "countdown"}, {"battery": ("sensor", "battery")}),
    ("unknown_multi_gang", "Acme", "SW-3", {i: ([0x0000, 0x0004, 0x0005, 0x0006], [], 0x0100) for i in (1, 2, 3)}, "mains", True, None,
     "Wall switch (3 gang)", "switch", {"state_l1", "state_l2", "state_l3"}, {"state"}, {"switch_l1": ("switch", None), "switch_l3": ("switch", None)}),
    ("unknown_plug", "Acme", "PLUG-X", {1: ([0x0000, 0x0003, 0x0006, 0x0702], [], 0x0051)}, "mains", True, None,
     "Smart plug", "plug", {"state", "energy", "power"}, set(), {"switch": ("switch", None), "energy": ("sensor", "energy")}),
    ("unknown_ias_leak", "Acme", "LEAK-1", {1: IAS_EP()}, "battery", False, {"zone_type": 0x002A},
     "Water leak sensor", "sensor", {"water_leak"}, set(), {"water_leak": ("binary_sensor", "moisture")}),
    ("unknown_ias_co", "Acme", "CO-1", {1: IAS_EP()}, "battery", False, {"zone_type": 0x002B},
     "CO detector", "sensor", {"carbon_monoxide"}, set(), {"carbon_monoxide": ("binary_sensor", "carbon_monoxide")}),
    ("unknown_lock", "Acme", "LOCK-1", {1: ([0x0000, 0x0001, 0x0101], [], 0x000A)}, "battery", False, None,
     "Door lock", "lock", {"state", "lock_state"}, set(), {"lock": ("lock", None)}),
    ("unknown_th", "Acme", "TH-1", {1: ([0x0000, 0x0001, 0x0402, 0x0405], [], 0x0302)}, "battery", False, None,
     "Temperature/humidity sensor", "sensor", {"temperature", "humidity"}, {"state"}, {"humidity": ("sensor", "humidity")}),
]


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_model_kind_features_and_discovery(case):
    _id, manu, model, eps, power, router, ctx, kind, category, present, absent, entities = case
    dev = mk(manu, model, eps, power=power, router=router, ctx=ctx)
    info = quirks.describe(dev)
    assert info.kind == kind, f"kind {info.kind!r}"
    assert info.category == category
    assert dev.kind == kind and dev.category == category and dev.vendor
    feats = keys(dev)
    assert present <= set(feats), f"missing {present - set(feats)}; have {sorted(feats)}"
    assert not (absent & set(feats)), f"unexpected {absent & set(feats)}"
    if category in ("sensor", "remote", "meter"):
        for k, f in feats.items():
            assert f["access"] in ("r", "w") or f["category"] == "config", f"{k} should be read-only on a {category}"
    for k, f in feats.items():
        assert f["key"] == k and "base" in f and "endpoint" in f and "cluster" in f and "type" in f and "access" in f
    disc = ha(dev)
    for obj, (comp, dclass) in entities.items():
        assert obj in disc, f"no HA entity {obj}; have {sorted(disc)}"
        got_comp, payload = disc[obj]
        assert got_comp == comp, f"{obj}: {got_comp} != {comp}"
        if dclass:
            assert payload.get("device_class") == dclass, f"{obj}: device_class {payload.get('device_class')!r}"
        assert payload["unique_id"] == f"{dev.ieee_str}_{obj}_zigbee2mqtt"
        assert payload["device"]["identifiers"] == [f"zigbee2mqtt_{dev.ieee_str}"]
        assert payload["state_topic"] == "oz/test"
    # plug-only controls never leak onto sensors/remotes
    if category in ("sensor", "remote"):
        assert not {"switch", "power_on_behavior", "countdown"} & set(disc)
    assert "linkquality" in disc and disc["linkquality"][0] == "sensor"


def test_native_layout_object_ids_and_to_json():
    dev = mk("LUMI", "lumi.sensor_magnet.aq2", {1: LUMI_SENSOR_EP})
    disc = ha(dev, legacy=False)
    assert disc["contact"][1]["unique_id"] == f"oneroof_zigbee_{dev.ieee_str}_contact"
    assert disc["contact"][1]["object_id"] == "test_contact"
    j = dev.to_json()
    assert j["kind"] == "Contact sensor" and j["vendor"] == "Aqara" and j["category"] == "sensor"
    back = Device.from_json(j)
    assert back.model == "lumi.sensor_magnet.aq2" and back.kind == "Contact sensor"


def test_contact_template_is_inverted_for_ha_door_class():
    dev = mk("LUMI", "lumi.sensor_magnet.aq2", {1: LUMI_SENSOR_EP})
    assert ha(dev)["contact"][1]["value_template"] == "{{ not value_json.contact }}"


def test_generic_layer_unchanged_for_plain_zigbee_bulb():
    dev = mk("Acme!", "Bulb-1", {1: ([0, 6, 8], [], 0x0101)}, power="mains", router=True)
    assert {f["key"] for f in generic_features(dev)} == {"state", "power_on_behavior", "countdown", "brightness", "linkquality"}
    assert {f["key"] for f in features_for(dev)} == {"state", "power_on_behavior", "countdown", "brightness", "linkquality"}
    assert dev.kind == "Dimmable light" and dev.vendor == "Acme!"


def test_vendor_names_without_quirk():
    assert quirks.vendor_name("_TZ3000_zzzzzzzz") == "Tuya"
    assert quirks.vendor_name("_TZ1800_abcdefgh") == "Lidl"
    assert quirks.vendor_name("IKEA of Sweden") == "IKEA"
    assert quirks.vendor_name(" Legrand") == "Legrand"
    assert quirks.vendor_name("Signify Netherlands B.V.") == "Philips Hue"
    assert quirks.vendor_name("SomeNewVendor") == "SomeNewVendor"
    assert quirks.vendor_name(None) is None


def test_binding_policy_sleepy_aqara_never_binds_tuya_plug_defaults():
    assert quirks.binding_policy(mk("LUMI", "lumi.weather", {})) == ()
    assert quirks.binding_policy(mk("LUMI", "lumi.sensor_magnet.aq2", {})) == ()
    assert quirks.binding_policy(mk("_TZ3000_ko6v90pg", "TS011F", {})) is None
    assert quirks.binding_policy(mk("Acme", "X", {})) is None


# ---------------------------------------------------------------------------------------------
# Aqara structured reports
# ---------------------------------------------------------------------------------------------


def _tlv(*entries: tuple[int, int, bytes]) -> bytes:
    return b"".join(bytes([tag, dtype]) + raw for tag, dtype, raw in entries)


WEATHER_TLV = _tlv((0x01, 0x21, (3015).to_bytes(2, "little")), (0x03, 0x28, (25).to_bytes(1, "little", signed=True)),
                   (0x04, 0x21, (5032).to_bytes(2, "little")), (0x05, 0x21, (3).to_bytes(2, "little")),
                   (0x06, 0x24, (5).to_bytes(5, "little")), (0x64, 0x29, (2135).to_bytes(2, "little", signed=True)),
                   (0x65, 0x21, (4512).to_bytes(2, "little")), (0x66, 0x2B, (100210).to_bytes(4, "little", signed=True)),
                   (0x0A, 0x21, (0).to_bytes(2, "little")))


def test_lumi_tlv_decoder():
    tags = vz.decode_lumi_tlv(WEATHER_TLV)
    assert tags[0x01] == 3015 and tags[0x03] == 25 and tags[0x64] == 2135 and tags[0x65] == 4512 and tags[0x66] == 100210
    assert vz.decode_lumi_tlv(bytes([len(WEATHER_TLV)]) + WEATHER_TLV, length_prefixed=True) == tags
    assert vz.decode_lumi_tlv(WEATHER_TLV[:5]) == {0x01: 3015}  # truncated tail is dropped, not fatal
    assert vz.decode_lumi_tlv(b"", length_prefixed=True) == {} and vz.decode_lumi_tlv(None) == {}
    assert vz.lumi_battery_percent(3015) == 100 and vz.lumi_battery_percent(2925) == 50 and vz.lumi_battery_percent(2700) == 0


def test_lumi_weather_report_decodes_to_state():
    dev = mk("LUMI", "lumi.weather", {1: ([0x0000, 0x0001, 0x0003, 0x0402, 0x0403, 0x0405], [], 0x5F01)})
    raw = bytes([len(WEATHER_TLV)]) + WEATHER_TLV  # string attribute as it sits in the frame
    state, used = quirks.decode_vendor_attributes(dev, 1, 0x0000, [(0xFF01, 0x42, raw.decode("latin-1"), raw)])
    assert used == {0xFF01}
    assert state == {"voltage": 3015, "battery": 100.0, "device_temperature": 25, "power_outage_count": 2,
                     "temperature": 21.35, "humidity": 45.12, "pressure": 1002.1}
    # through the frame codec: the "string" survives as raw bytes on the record
    frame = decode_frame(bytes([0x18, 0x10, 0x0A]) + (0xFF01).to_bytes(2, "little") + b"\x42" + raw)
    rec = decode_global_command(frame).records[0]
    assert rec.attr == 0xFF01 and rec.raw == raw


def test_lumi_magnet_report_contact_and_onoff_attribute():
    dev = mk("LUMI", "lumi.sensor_magnet.aq2", {1: LUMI_SENSOR_EP})
    tlv = _tlv((0x01, 0x21, (2985).to_bytes(2, "little")), (0x64, 0x10, b"\x01"))
    raw = bytes([len(tlv)]) + tlv
    state, _ = quirks.decode_vendor_attributes(dev, 1, 0x0000, [(0xFF01, 0x42, "", raw)])
    assert state["contact"] is False and state["voltage"] == 2985 and state["battery"] == 90.0
    # the On/Off attribute 0 report becomes contact, not a switch state
    assert quirks.translate_state(dev, 1, {"state": "ON"}) == {"contact": False}
    assert quirks.translate_state(dev, 1, {"state": "OFF"}) == {"contact": True}
    # generic battery-voltage reads (V) are normalised to mV for Aqara like the previous setup
    assert quirks.translate_state(dev, 1, {"voltage": 3.0, "battery": 100.0}) == {"voltage": 3000, "battery": 100.0}


def test_lumi_struct_ff02_and_private_cluster():
    dev = mk("LUMI", "lumi.sensor_ht", {1: ([0x0000, 0x0001, 0x0402, 0x0405], [], 0x5F01)})
    state, used = quirks.decode_vendor_attributes(dev, 1, 0x0000, [(0xFF02, 0x4C, [True, 3005, 0], None)])
    assert used == {0xFF02} and state["voltage"] == 3005 and state["battery"] == 100.0
    dev2 = mk("LUMI", "lumi.motion.ac02", {1: ([0x0000, 0x0001, 0x0003, 0x0400, 0x0406, 0xFCC0], [], 0x0107)})
    tlv = _tlv((0x01, 0x21, (2900).to_bytes(2, "little")), (0x0B, 0x21, (120).to_bytes(2, "little")))
    state, used = quirks.decode_vendor_attributes(dev2, 1, 0xFCC0, [(0x00F7, 0x41, tlv, bytes([len(tlv)]) + tlv)])
    assert used == {0x00F7} and state["illuminance_lux"] == 120 and state["voltage"] == 2900


def test_lumi_buttons_and_vibration_actions():
    two = mk("LUMI", "lumi.remote.b286acn01", {1: ([0x0000, 0x0012], [], 0x5F01), 2: ([0x0012], [], 0x5F01), 3: ([0x0012], [], 0x5F01)})
    assert quirks.decode_vendor_attributes(two, 1, 0x0012, [(0x0055, 0x21, 1, None)])[0] == {"action": "single_left"}
    assert quirks.decode_vendor_attributes(two, 2, 0x0012, [(0x0055, 0x21, 2, None)])[0] == {"action": "double_right"}
    assert quirks.decode_vendor_attributes(two, 3, 0x0012, [(0x0055, 0x21, 0, None)])[0] == {"action": "hold_both"}
    one = mk("LUMI", "lumi.remote.b1acn01", {1: ([0x0000, 0x0012], [], 0x5F01)})
    assert quirks.decode_vendor_attributes(one, 1, 0x0012, [(0x0055, 0x21, 2, None)])[0] == {"action": "double"}
    aq2 = mk("LUMI", "lumi.sensor_switch.aq2", {1: ([0x0000, 0x0006], [], 0x5F01)})
    assert quirks.translate_state(aq2, 1, {"state": "ON"}) == {"action": "single"}
    assert quirks.translate_state(aq2, 1, {"state": "OFF"}) == {}
    assert quirks.decode_vendor_attributes(aq2, 1, 0x0006, [(0x8000, 0x21, 3, None)])[0] == {"action": "triple"}
    vib = mk("LUMI", "lumi.vibration.aq1", {1: ([0x0000, 0x0101], [], 0x000A)})
    assert quirks.decode_vendor_attributes(vib, 1, 0x0101, [(0x0055, 0x21, 2, None)])[0] == {"action": "tilt"}


def test_lumi_plug_analog_inputs_and_switch_gangs():
    plug = mk("LUMI", "lumi.plug.maus01", {1: ([0x0000, 0x0006], [], 0x0051), 2: ([0x000C], [], 0x0009), 3: ([0x000C], [], 0x0083)}, power="mains", router=True)
    assert quirks.decode_vendor_attributes(plug, 2, 0x000C, [(0x0055, 0x39, 12.345, None)])[0] == {"power": 12.35}
    assert quirks.decode_vendor_attributes(plug, 3, 0x000C, [(0x0055, 0x39, 1.2345, None)])[0] == {"energy": 1.234}
    sw = mk("LUMI", "lumi.switch.b2naus01", {1: ([0x0000, 0x0006], [], 0x0100), 2: ([0x0006], [], 0x0100), 41: ([0x0012], [], 0x0100), 42: ([0x0012], [], 0x0100), 51: ([0x0012], [], 0x0100)}, power="mains", router=True)
    assert quirks.translate_state(sw, 1, {"state": "ON"}) == {"state_left": "ON"}
    assert quirks.translate_state(sw, 2, {"state": "OFF"}) == {"state_right": "OFF"}
    assert quirks.decode_vendor_attributes(sw, 51, 0x0012, [(0x0055, 0x21, 1, None)])[0] == {"action": "single_both"}


# ---------------------------------------------------------------------------------------------
# Tuya datapoints
# ---------------------------------------------------------------------------------------------


def _dp(dp: int, dtype: int, data: bytes) -> bytes:
    return bytes([dp, dtype]) + len(data).to_bytes(2, "big") + data


def _tuya(seq: int, *dps: bytes) -> bytes:
    return seq.to_bytes(2, "big") + b"".join(dps)


def test_tuya_dp_codec_roundtrip():
    payload = _tuya(7, _dp(1, vz.TUYA_VALUE, struct.pack(">i", 235)), _dp(2, vz.TUYA_BOOL, b"\x01"), _dp(4, vz.TUYA_ENUM, b"\x02"),
                    _dp(5, vz.TUYA_BITMAP, b"\x00\x05"), _dp(6, vz.TUYA_STRING, b"hi"), _dp(7, vz.TUYA_RAW, b"\x01\x02"))
    assert vz.decode_tuya_datapoints(payload) == [(1, 2, 235), (2, 1, True), (4, 4, 2), (5, 5, 5), (6, 3, "hi"), (7, 0, b"\x01\x02")]
    assert vz.decode_tuya_datapoints(payload[:12]) == [(1, 2, 235)]  # truncated second dp dropped
    assert vz.encode_tuya_datapoint(1, 2, vz.TUYA_VALUE, -15) == b"\x00\x01\x02\x02\x00\x04\xff\xff\xff\xf1"
    assert vz.encode_tuya_datapoint(3, 7, vz.TUYA_BOOL, True) == b"\x00\x03\x07\x01\x00\x01\x01"


def test_tuya_th_sensor_report():
    dev = mk("_TZE200_locansqn", "TS0601", {1: ([0x0000, 0xEF00], [], 0x0051)})
    payload = _tuya(1, _dp(1, 2, struct.pack(">i", 235)), _dp(2, 2, struct.pack(">i", 47)), _dp(4, 2, struct.pack(">i", 90)))
    assert quirks.decode_tuya_report(dev, vz.TUYA_CMD_DATA_REPORT, payload) == {"temperature": 23.5, "humidity": 47, "battery": 90}
    dev10 = mk("_TZE200_bjawzodf", "TS0601", {1: ([0x0000, 0xEF00], [], 0x0051)})
    assert quirks.decode_tuya_report(dev10, vz.TUYA_CMD_DATA_RESPONSE, _tuya(1, _dp(2, 2, struct.pack(">i", 478)))) == {"humidity": 47.8}
    assert quirks.decode_tuya_report(dev, vz.TUYA_CMD_SET_DATA, payload) == {}  # only reports are decoded


def test_tuya_trv_cover_radar_and_generic_fallback():
    trv = mk("_TZE200_ckud7u2l", "TS0601", {1: ([0x0000, 0xEF00], [], 0x0051)})
    st = quirks.decode_tuya_report(trv, 2, _tuya(1, _dp(2, 2, struct.pack(">i", 215)), _dp(3, 2, struct.pack(">i", 201)), _dp(7, 1, b"\x01"), _dp(4, 4, b"\x01"), _dp(109, 2, struct.pack(">i", 40))))
    assert st == {"current_heating_setpoint": 21.5, "local_temperature": 20.1, "child_lock": "LOCK", "preset": "manual", "position": 40}
    assert quirks.encode_tuya_command(trv, "current_heating_setpoint", 22, 5) == _tuya(5, _dp(2, 2, struct.pack(">i", 220)))
    assert quirks.encode_tuya_command(trv, "child_lock", "UNLOCK", 6) == _tuya(6, _dp(7, 1, b"\x00"))
    assert quirks.encode_tuya_command(trv, "preset", "eco", 7) == _tuya(7, _dp(4, 4, b"\x05"))
    assert quirks.encode_tuya_command(trv, "local_temperature", 1, 8) is None  # read-only
    with pytest.raises(ValueError):
        quirks.encode_tuya_command(trv, "preset", "nonsense", 9)
    cover = mk("_TZE200_fzo2pocs", "TS0601", {1: ([0x0000, 0xEF00], [], 0x0051)}, power="mains", router=True)
    assert quirks.decode_tuya_report(cover, 2, _tuya(1, _dp(3, 2, struct.pack(">i", 65)))) == {"position": 65}
    assert quirks.encode_tuya_command(cover, "cover", "CLOSE", 1) == _tuya(1, _dp(1, 4, b"\x02"))
    assert quirks.encode_tuya_command(cover, "position", 30, 2) == _tuya(2, _dp(2, 2, struct.pack(">i", 30)))
    radar = mk("_TZE200_ztc6ggyl", "TS0601", {1: ([0x0000, 0xEF00], [], 0x0051)}, power="mains", router=True)
    st = quirks.decode_tuya_report(radar, 2, _tuya(1, _dp(1, 1, b"\x01"), _dp(9, 2, struct.pack(">i", 150)), _dp(104, 2, struct.pack(">i", 120))))
    assert st == {"presence": True, "target_distance": 1.5, "illuminance_lux": 120}
    unknown = mk("_TZE200_notinthetable", "TS0601", {1: ([0x0000, 0xEF00], [], 0x0051)})
    st = quirks.decode_tuya_report(unknown, 2, _tuya(1, _dp(1, 1, b"\x01"), _dp(17, 2, struct.pack(">i", 42)), _dp(3, 0, b"\xaa\xbb")))
    assert st == {"dp_1": True, "dp_17": 42, "dp_3": "aabb"}
    assert unknown.kind == "Tuya device (datapoints)" and unknown.vendor == "Tuya"
    unknown.state.update(st)
    assert {"dp_1", "dp_17", "dp_3"} <= set(keys(unknown))


# ---------------------------------------------------------------------------------------------
# Remotes: commands the device sends to us
# ---------------------------------------------------------------------------------------------


def test_remote_actions_generic_ikea_hue_sonoff_tuya():
    gen = mk("Acme", "KNOB-1", {1: ([0x0000, 0x0001], [0x0006, 0x0008], 0x0104)})
    assert quirks.remote_action(gen, 1, 0x0006, 0x02, b"", None) == "toggle"
    assert quirks.remote_action(gen, 1, 0x0008, 0x05, b"\x00\x53", None) == "brightness_move_up"
    assert quirks.remote_action(gen, 1, 0x0008, 0x02, b"\x01\x2b\x00\x00", None) == "brightness_step_down"
    assert quirks.remote_action(gen, 1, 0x0008, 0x07, b"", None) == "brightness_stop"
    assert quirks.remote_action(gen, 1, 0x0300, 0x4C, b"\x01\x2b\x00\x0a\x00\x00\x00\x00\x00", None) == "color_temperature_step_up"
    assert quirks.remote_action(gen, 1, 0x0005, 0x05, b"\x00\x00\x03", None) == "recall_3"
    assert quirks.remote_action(gen, 1, 0x0006, 0x99, b"", None) is None
    ikea = mk("IKEA of Sweden", "TRADFRI remote control", {1: ([0x0000, 0x0001], [0x0005, 0x0006, 0x0008], 0x0830)})
    assert quirks.remote_action(ikea, 1, 0x0008, 0x06, b"\x00\x2b\x00\x05", None) == "brightness_up_click"
    assert quirks.remote_action(ikea, 1, 0x0008, 0x05, b"\x01\x53", None) == "brightness_down_hold"
    assert quirks.remote_action(ikea, 1, 0x0008, 0x07, b"", None) == "brightness_down_release"
    assert quirks.remote_action(ikea, 1, 0x0005, 0x07, (257).to_bytes(2, "little") + b"\x0d\x00", 0x117C) == "arrow_left_click"
    assert quirks.remote_action(ikea, 1, 0x0005, 0x08, (3328).to_bytes(2, "little") + b"\x00\x00", 0x117C) == "arrow_right_hold"
    assert quirks.remote_action(ikea, 1, 0x0005, 0x09, b"\x00\x00", 0x117C) == "arrow_right_release"
    hue = mk("Philips", "RWL021", {1: ([0x0000], [0x0006, 0x0008], 0x0830), 2: ([0x0000, 0x0001, 0xFC00], [], 0x0850)})
    assert quirks.remote_action(hue, 2, 0xFC00, 0x00, bytes([0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00]), 0x100B) == "up_hold"
    assert quirks.remote_action(hue, 2, 0xFC00, 0x00, bytes([0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00]), 0x100B) == "off_press_release"
    sonoff = mk("eWeLink", "WB01", {1: ([0x0000, 0x0001], [0x0006], 0x0000)})
    assert [quirks.remote_action(sonoff, 1, 0x0006, c, b"", None) for c in (0x02, 0x01, 0x00)] == ["single", "double", "long"]
    t4 = mk("_TZ3000_vp6clf9d", "TS0044", {i: ([0x0000, 0x0001, 0x0006], [], 0x0000) for i in (1, 2, 3, 4)})
    assert quirks.remote_action(t4, 3, 0x0006, 0xFD, b"\x01", None) == "3_double"
    t1 = mk("_TZ3000_xkwalgne", "TS0041", {1: ([0x0000, 0x0001, 0x0006], [], 0x0000)})
    assert quirks.remote_action(t1, 1, 0x0006, 0xFD, b"\x02", None) == "hold"
    somrig = mk("IKEA of Sweden", "SOMRIG shortcut button", {1: ([0x0000, 0x0001, 0xFC80], [], 0x0006), 2: ([0xFC80], [], 0x0006)})
    assert quirks.remote_action(somrig, 2, 0xFC80, 0x03, b"", 0x117C) == "2_short_release"


# ---------------------------------------------------------------------------------------------
# Through the gateway: reports, remote events and commands end up on MQTT with the right keys
# ---------------------------------------------------------------------------------------------


async def _gateway_with(tmp_path, dev_fn):
    from tests.test_gateway import make
    fake, coord, broker, gw, t = await make(tmp_path)
    dev = dev_fn()
    reg = gw.registry.add_or_update(dev.ieee, dev.nwk, manufacturer=dev.manufacturer, model=dev.model, power_source=dev.power_source,
                                    is_router=dev.is_router, rx_on_when_idle=dev.rx_on_when_idle, interviewed=True)
    reg.endpoints.update(dev.endpoints)
    reg.context.update(dev.context)
    await gw._announce(reg)
    await gw._publish_bridge_info()
    return fake, broker, gw, reg, t


async def test_gateway_aqara_report_publishes_contact_and_battery(tmp_path):
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("LUMI", "lumi.sensor_magnet.aq2", {1: LUMI_SENSOR_EP}, ieee=0x00158D0000000002))
    tlv = _tlv((0x01, 0x21, (2985).to_bytes(2, "little")), (0x03, 0x28, b"\x19"), (0x64, 0x10, b"\x01"))
    raw = bytes([len(tlv)]) + tlv
    fake.emit_incoming(NWK, 0x0000, bytes([0x18, 0x21, 0x0A]) + (0xFF01).to_bytes(2, "little") + b"\x42" + raw)
    await asyncio.sleep(0.05)
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["contact"] is False and state["voltage"] == 2985 and state["battery"] == 90.0 and state["device_temperature"] == 25
    assert "state" not in state
    # an On/Off attribute report on a contact sensor is contact, never a switch
    fake.emit_incoming(NWK, 0x0006, bytes([0x18, 0x22, 0x0A, 0x00, 0x00, 0x10, 0x00]))
    await asyncio.sleep(0.05)
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["contact"] is True and "state" not in state
    disc = json.loads(broker.last(f"homeassistant/binary_sensor/{dev.ieee_str}/contact/config"))
    assert disc["device_class"] == "door"
    assert broker.last(f"homeassistant/switch/{dev.ieee_str}/switch/config") is None
    assert json.loads(broker.last("oneroof/zigbee/bridge/devices"))[0]["kind"] == "Contact sensor"
    await t.close()


async def test_gateway_tuya_report_and_dp_command(tmp_path):
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("_TZE200_ckud7u2l", "TS0601", {1: ([0x0000, 0x0004, 0x0005, 0xEF00], [0x0019], 0x0051)}, ieee=0x00158D0000000003))
    payload = _tuya(1, _dp(2, 2, struct.pack(">i", 215)), _dp(3, 2, struct.pack(">i", 201)))
    fake.emit_incoming(NWK, 0xEF00, bytes([0x09, 0x31, 0x02]) + payload)
    await asyncio.sleep(0.05)
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["current_heating_setpoint"] == 21.5 and state["local_temperature"] == 20.1
    fake.requests.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"current_heating_setpoint": 19}')
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert len(reqs) == 1 and int.from_bytes(reqs[0].data[4:6], "little") == 0xEF00
    zcl = reqs[0].data[10:]
    assert zcl[2] == 0x00 and zcl[5:] == _dp(2, 2, struct.pack(">i", 190))  # setData dp2 = 19.0 °C
    assert json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))["current_heating_setpoint"] == 19
    climate = json.loads(broker.last(f"homeassistant/climate/{dev.ieee_str}/climate/config"))
    assert climate["temperature_state_template"] == "{{ value_json.current_heating_setpoint }}"
    await t.close()


async def test_gateway_remote_action_is_published_then_cleared(tmp_path):
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("IKEA of Sweden", "TRADFRI remote control",
                                                                         {1: ([0x0000, 0x0001, 0x0003], [0x0005, 0x0006, 0x0008], 0x0830)}, ieee=0x00158D0000000004))
    published: list[dict] = []
    orig = broker.publish

    async def spy(topic, payload, retain=False, qos=0):
        if topic == f"oneroof/zigbee/{dev.ieee_str}/state":
            published.append(json.loads(payload))
        await orig(topic, payload, retain, qos)

    broker.publish = spy
    fake.emit_incoming(NWK, 0x0006, bytes([0x01, 0x40, 0x02]))  # client→server toggle
    await asyncio.sleep(0.05)
    assert [p["action"] for p in published] == ["toggle", ""]
    fake.emit_incoming(NWK, 0x0008, bytes([0x01, 0x41, 0x06, 0x00, 0x2b, 0x00, 0x05]))  # step up with on/off
    await asyncio.sleep(0.05)
    assert published[-2]["action"] == "brightness_up_click"
    assert "state" not in published[-1]
    assert json.loads(broker.last(f"homeassistant/sensor/{dev.ieee_str}/action/config"))["value_template"] == "{{ value_json.action }}"
    await t.close()


async def test_gateway_ikea_motion_on_with_timed_off(tmp_path):
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("IKEA of Sweden", "TRADFRI motion sensor",
                                                                         {1: ([0x0000, 0x0001, 0x0003], [0x0006, 0x0008], 0x0800)}, ieee=0x00158D0000000005))
    fake.emit_incoming(NWK, 0x0006, bytes([0x01, 0x42, 0x42, 0x00]) + (2).to_bytes(2, "little") + b"\x00\x00")  # on for 0.2 s
    await asyncio.sleep(0.05)
    assert json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))["occupancy"] is True
    await asyncio.sleep(1.2)
    assert json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))["occupancy"] is False
    await t.close()


async def test_gateway_multi_gang_commands_route_to_endpoint(tmp_path):
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("_TZ3000_owgcnkrh", "TS0012", {1: ([0x0000, 0x0004, 0x0005, 0x0006], [0x0019], 0x0100),
                                                                                                        2: ([0x0004, 0x0005, 0x0006], [], 0x0100)}, power="mains", router=True, ieee=0x00158D0000000006))
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    fake.requests.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"state_l2": "ON"}')
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert len(reqs) == 1 and reqs[0].data[2] == 2 and reqs[0].data[10:][2] == 0x01  # dst endpoint 2, "on"
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["state_l2"] == "ON" and "state" not in state
    # a report from endpoint 1 lands on state_l1
    from oneroof_zigbee.znp.unpi import Frame, FrameType
    from oneroof_zigbee.znp.wire import Writer
    w = Writer().u16(0).u16(0x0006).u16(NWK).u8(1).u8(1).u8(0).u8(200).u8(1).u32(0).u8(9).lv(bytes([0x18, 0x09, 0x0A, 0x00, 0x00, 0x10, 0x00]))
    fake.emit(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes()))
    await asyncio.sleep(0.05)
    assert json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))["state_l1"] == "OFF"
    sw2 = json.loads(broker.last(f"homeassistant/switch/{dev.ieee_str}/switch_l2/config"))
    assert sw2["payload_on"] == '{"state_l2": "ON"}' and sw2["value_template"] == "{{ value_json.state_l2 }}"
    await t.close()


async def test_gateway_lock_command(tmp_path):
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("Yale", "YRD226 TSDB", {1: ([0x0000, 0x0001, 0x0003, 0x0101], [0x0019], 0x000A)}, ieee=0x00158D0000000007))
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    fake.requests.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"state": "LOCK"}')
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert len(reqs) == 1 and int.from_bytes(reqs[0].data[4:6], "little") == 0x0101 and reqs[0].data[10:][2] == 0x00
    assert json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))["state"] == "LOCK"
    fake.emit_incoming(NWK, 0x0101, bytes([0x18, 0x09, 0x0A, 0x00, 0x00, 0x30, 0x02]))  # lock_state = unlocked
    await asyncio.sleep(0.05)
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["state"] == "UNLOCK" and state["lock_state"] == "unlocked"
    lock = json.loads(broker.last(f"homeassistant/lock/{dev.ieee_str}/lock/config"))
    assert lock["payload_lock"] == '{"state": "LOCK"}' and lock["state_locked"] == "LOCK"
    await t.close()


def test_legacy_identities_for_aqara_h1_switch_tuya_smoke_and_motion():
    """Entity identities the previous layout used for these models must be reproduced exactly,
    or Home Assistant creates new entities and dashboards break."""
    import json
    from oneroof_zigbee.devices import Device, Endpoint
    from oneroof_zigbee.ha.discovery import discovery_messages

    def uids(dev):
        return {json.loads(p)["unique_id"] for _t, p in discovery_messages(dev, "zigbee2mqtt", "homeassistant", legacy=True)}

    sw = Device(ieee=0x54EF440000000001, nwk=0x2345, friendly_name="Room switch", manufacturer="LUMI", model="lumi.switch.b2lc04")
    sw.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [0, 3, 4, 5, 6, 0xFCC0], [], "switch")
    sw.endpoints[2] = Endpoint(2, 0x0104, 0x0100, [4, 5, 6], [], "switch")
    sw.interviewed = True
    assert sw.kind == "Wall switch (2 gang)"
    assert {"0x54ef440000000001_switch_left_zigbee2mqtt", "0x54ef440000000001_switch_right_zigbee2mqtt",
            "0x54ef440000000001_device_temperature_zigbee2mqtt"} <= uids(sw)

    smoke = Device(ieee=0xA4C1380000000002, nwk=0x4567, friendly_name="Smoke", manufacturer="_TZE200_rccxox8p", model="TS0601")
    smoke.endpoints[1] = Endpoint(1, 0x0104, 0x0051, [0, 4, 5, 0xEF00], [0x19, 0xA], "sensor")
    smoke.interviewed = True
    assert smoke.kind == "Smoke detector"
    assert {"0xa4c1380000000002_smoke_zigbee2mqtt", "0xa4c1380000000002_battery_zigbee2mqtt"} <= uids(smoke)

    motion = Device(ieee=0x00158D0000000002, nwk=0x3457, friendly_name="Stairs", manufacturer="LUMI", model="lumi.sensor_motion.aq2")
    motion.endpoints[1] = Endpoint(1, 0x0104, 0x0107, [0, 0xFFFF, 0x406, 0x400, 0x500, 1, 3], [0, 0x19], "sensor")
    motion.interviewed = True
    u = uids(motion)
    assert "0x00158d0000000002_illuminance_zigbee2mqtt" in u and "0x00158d0000000002_occupancy_zigbee2mqtt" in u
    assert not any(k in x for x in u for k in ("alarm_1", "tamper", "battery_low")), "no spurious IAS entities on Aqara motion"


def test_discovery_payloads_never_contain_nulls():
    """Home Assistant rejects a discovery message outright when a field is null (e.g.
    device.sw_version); every payload for every fixture model must be null-free."""
    import json
    from oneroof_zigbee.ha.discovery import discovery_messages

    def walk(o, path="$"):
        if isinstance(o, dict):
            for k, v in o.items():
                assert v is not None, f"null at {path}.{k}"
                walk(v, f"{path}.{k}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")

    for case in CASES:
        _id, manu, model, eps, power, router, ctx, *_ = case
        dev = mk(manu, model, eps, power=power, router=router, ctx=ctx)
        dev.sw_build = None  # the common state right after an import
        for legacy in (True, False):
            for topic, payload in discovery_messages(dev, "zigbee2mqtt", "homeassistant", legacy=legacy):
                walk(json.loads(payload), topic)
