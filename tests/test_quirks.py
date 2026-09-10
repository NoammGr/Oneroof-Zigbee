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
from oneroof_zigbee.devices import Device, Endpoint, ieee_str
from oneroof_zigbee.features import features_for, generic_features
from oneroof_zigbee.ha.discovery import discovery_messages
from oneroof_zigbee.zcl import vendor as vz
from oneroof_zigbee.zcl.clusters import decode_attributes
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
    ("oneroof_irblaster", "NoammGr", "IRBlaster", {1: ([0x0000, 0x0003, 0x0201, 0x0202, 0xFC00], [0x0019], 0x0301), 2: ([0x0006], [], 0x0002),
                                                    3: ([0x0402, 0x0405], [], 0x0302)}, "mains", True, None,
     "AC IR blaster", "climate",
     {"current_heating_setpoint", "system_mode", "fan_mode", "swing", "local_temperature", "temperature", "humidity", "learn_key", "send_key", "protocol",
      "hold", "last_result", "code_count", "temperature_offset", "led_brightness", "led_quiet"},
     {"state", "countdown", "power_on_behavior", "running_state", "current_cooling_setpoint", "target_temperature"},
     {"climate": ("climate", None), "protocol": ("select", None), "learn_key": ("text", None), "send_key": ("text", None),
      "hold": ("switch", None), "led_quiet": ("switch", None), "temperature_offset": ("number", None), "led_brightness": ("number", None),
      "last_result": ("sensor", None), "code_count": ("sensor", None), "temperature": ("sensor", "temperature"), "humidity": ("sensor", "humidity")}),
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
        if comp == "cover":
            # the shared payload is not "open"/"closed": a cover goes by its position (or assumes)
            assert "state_topic" not in payload and payload.get("position_topic", "oz/test") == "oz/test"
        else:
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
    # a devices.json written by a newer (or withdrawn) version carries keys this one does not
    # know; they are dropped, not fatal - the gateway must still start with its devices
    j["location"] = "Kitchen"
    j["endpoints"]["1"]["future_field"] = 1
    back = Device.from_json(j)
    assert back.model == "lumi.sensor_magnet.aq2" and not hasattr(back, "location")


def test_entity_id_proposed_to_ha_follows_the_panel_name():
    """The object_id in a discovery message is what Home Assistant turns into the entity id the
    first time it creates the entity. An unnamed device (still called by its address) is therefore
    offered as binary_sensor.0x..._contact; one named in the panel first gets the friendly id.
    The unique_id never moves with the name - that is what makes HA keep the entity (and its old
    id) across a later rename instead of creating a second one."""
    ieee = 0x00158D00000000D3
    dev = Device(ieee=ieee, nwk=NWK, friendly_name=ieee_str(ieee), manufacturer="LUMI", model="lumi.sensor_magnet.aq2")
    dev.endpoints[1] = Endpoint(1, 0x0104, LUMI_SENSOR_EP[2], list(LUMI_SENSOR_EP[0]), list(LUMI_SENSOR_EP[1]))
    unnamed = ha(dev, legacy=False)["contact"][1]
    assert unnamed["object_id"] == "0x00158d00000000d3_contact", "the address is the only name the gateway knows"
    assert unnamed["device"]["name"] == "0x00158d00000000d3"
    assert unnamed["device_class"] == "door"

    dev.friendly_name = "Back door"
    named = ha(dev, legacy=False)["contact"][1]
    assert named["object_id"] == "Back door_contact", "HA slugifies this to binary_sensor.back_door_contact"
    assert named["device"]["name"] == "Back door"
    assert named["unique_id"] == unnamed["unique_id"] == f"oneroof_zigbee_{ieee_str(ieee)}_contact"

    # the compatibility layout proposes no object_id at all: HA derives the id from the names
    assert "object_id" not in ha(dev, legacy=True)["contact"][1]


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
    assert not broker.last(f"homeassistant/switch/{dev.ieee_str}/switch/config")  # absent, or blanked by the sweep
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


def test_values_in_state_are_exposed_even_without_cluster_information():
    """Imported without clusters (previous database lacked them): model knowledge and the state
    safety net still produce the entities the previous layout had."""
    import json
    from oneroof_zigbee.devices import Device, Endpoint
    from oneroof_zigbee.features import features_for
    from oneroof_zigbee.ha.discovery import discovery_messages
    d = Device(ieee=0x00158D0000000005, nwk=0x7777, friendly_name="Rack sensor", manufacturer="LUMI", model="lumi.weather")
    d.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [], [], "switch")
    d.interviewed = True
    d.state.update({"pressure": 1000.5, "temperature": 32.66, "humidity": 33.74, "voltage": 2865, "battery": 10})
    keys = {f["key"] for f in features_for(d)}
    assert {"temperature", "humidity", "pressure", "battery", "voltage"} <= keys
    uids = {json.loads(p)["unique_id"] for _t, p in discovery_messages(d, "zigbee2mqtt", "homeassistant", legacy=True)}
    assert {"0x00158d0000000005_temperature_zigbee2mqtt", "0x00158d0000000005_humidity_zigbee2mqtt",
            "0x00158d0000000005_pressure_zigbee2mqtt"} <= uids
    # unknown model with only state: the safety net alone
    u = Device(ieee=0x00158D0000000006, nwk=0x7778, friendly_name="Mystery", manufacturer="Acme", model="X1")
    u.endpoints[1] = Endpoint(1, 0x0104, 0x0100, [], [], "unknown")
    u.interviewed = True
    u.state.update({"temperature": 21.5, "contact": False, "frobnicate": 3})
    fk = {f["key"]: f for f in features_for(u)}
    assert fk["temperature"]["from_state"] and fk["temperature"]["access"] == "r" and fk["contact"]["type"] == "binary"
    assert "frobnicate" not in fk, "unknown keys are not invented into entities"


# ---------------------------------------------------------------------------------------------
# Thermostats that are not radiator valves: cooling, fan, one target temperature, an IR blaster
# ---------------------------------------------------------------------------------------------

IRB_EPS = {1: ([0x0000, 0x0003, 0x0201, 0x0202, 0xFC00], [0x0019], 0x0301), 2: ([0x0006], [], 0x0002), 3: ([0x0402, 0x0405], [], 0x0302)}


def irblaster() -> Device:
    return mk("NoammGr", "IRBlaster", IRB_EPS, power="mains", router=True, ieee=0x00124B0022AA1234)


def test_cooling_capable_thermostat_gets_cooling_setpoint_and_full_mode_list():
    ac = mk("Acme", "AC-1", {1: ([0x0000, 0x0201, 0x0202], [], 0x0301)}, power="mains", router=True,
            ctx={"thermostat_sequence": 4, "cool_setpoint_min": 16, "cool_setpoint_max": 30, "heat_setpoint_min": 16, "heat_setpoint_max": 30})
    f = keys(ac)
    assert f["current_cooling_setpoint"]["min"] == 16 and f["current_cooling_setpoint"]["max"] == 30
    assert f["current_heating_setpoint"]["min"] == 16
    assert f["system_mode"]["values"] == ["off", "auto", "cool", "heat", "dry", "fan_only"]
    assert f["fan_mode"]["values"] == ["low", "medium", "high", "auto"] and f["fan_mode"]["cluster"] == 0x0202
    cool_only = mk("Acme", "AC-2", {1: ([0x0000, 0x0201], [], 0x0301)}, power="mains", router=True, ctx={"thermostat_sequence": 0})
    f = keys(cool_only)
    assert "current_heating_setpoint" not in f and f["system_mode"]["values"] == ["off", "cool", "auto", "dry", "fan_only"]
    # two independent setpoints → Home Assistant gets a low/high range, both writable
    cl = ha(ac)["climate"][1]
    assert cl["temperature_low_state_template"] == "{{ value_json.current_heating_setpoint }}"
    assert cl["temperature_high_command_template"] == '{"current_cooling_setpoint": {{ value }} }'
    assert cl["modes"] == ["off", "auto", "cool", "heat", "dry", "fan_only"] and cl["fan_modes"] == ["low", "medium", "high", "auto"]
    assert "temperature_command_topic" not in cl


def test_plain_trv_is_unchanged():
    trv = mk("SONOFF", "TRVZB", {1: ([0x0000, 0x0001, 0x0003, 0x0006, 0x0020, 0x0201, 0x0204, 0xFC11], [0x000A, 0x0019], 0x0301)})
    f = keys(trv)
    sp = f["current_heating_setpoint"]
    assert (sp["min"], sp["max"], sp["step"], sp["unit"]) == (5, 30, 0.5, "°C")
    assert f["system_mode"]["values"] == ["off", "heat", "auto"]
    assert "current_cooling_setpoint" not in f and "fan_mode" not in f and "target_temperature" not in f and "running_state" in f
    cl = ha(trv)["climate"][1]
    assert cl["temperature_state_template"] == "{{ value_json.current_heating_setpoint }}" and cl["modes"] == ["off", "heat", "auto"]
    assert "fan_modes" not in cl and "temperature_low_state_template" not in cl
    # the generic layer alone, without a quirk, is heating-only too
    plain = mk("Nobody", "T1", {1: ([0x0000, 0x0201], [], 0x0301)})
    assert {f["key"] for f in generic_features(plain)} == {"local_temperature", "current_heating_setpoint", "system_mode", "running_state", "linkquality"}


def test_irblaster_features_exposes_and_discovery():
    dev = irblaster()
    f = keys(dev)
    tt = f["current_heating_setpoint"]
    assert (tt["min"], tt["max"], tt["step"], tt["cluster"], tt["endpoint"]) == (16, 30, 1, 0x0201, 1)
    assert f["system_mode"]["values"] == ["off", "auto", "cool", "heat", "dry", "fan_only"]
    assert f["swing"]["base"] == "state" and f["swing"]["endpoint"] == 2 and f["swing"]["cluster"] == 0x0006 and f["swing"]["name"] == "Swing"
    assert {k for k, x in f.items() if x["category"] == "ir"} == {"learn_key", "send_key", "protocol", "hold", "last_result", "code_count"}
    assert f["learn_key"]["access"] == "w" and f["learn_key"]["max_length"] == 15 and f["learn_key"]["cluster"] == 0xFC00
    assert f["temperature_offset"]["category"] == "config" and f["temperature_offset"]["step"] == 0.1
    disc = ha(dev)
    cl = disc["climate"][1]
    assert cl["temperature_state_template"] == "{{ value_json.current_heating_setpoint }}"
    assert cl["temperature_command_template"] == '{"current_heating_setpoint": {{ value }} }' and (cl["min_temp"], cl["max_temp"], cl["temp_step"]) == (16, 30, 1)
    assert cl["modes"] == ["off", "auto", "cool", "heat", "dry", "fan_only"] and cl["fan_modes"] == ["low", "medium", "high", "auto"]
    assert cl["fan_mode_command_template"] == '{"fan_mode": "{{ value }}" }'
    # the louver belongs to the air conditioner: it is the climate entity's swing mode, not a
    # toggle standing on its own (see test_air_conditioner_louver_is_the_climate_entitys_swing…)
    assert "swing" not in disc
    assert cl["swing_modes"] == ["ON", "OFF"] and cl["swing_mode_state_template"] == "{{ value_json.swing }}"
    assert disc["learn_key"][1]["command_template"] == '{"learn_key": "{{ value }}" }' and disc["learn_key"][1]["max"] == 15
    assert disc["protocol"][1]["options"] == ["learn", "auto", "coolix", "gree", "daikin", "electra"]
    assert disc["hold"][1]["payload_on"] == '{"hold": "ON"}'
    assert disc["temperature_offset"][1]["min"] == -10 and disc["temperature_offset"][1]["step"] == 0.1
    assert "switch" not in disc and "running_state" not in disc
    from oneroof_zigbee.ha.exposes import exposes_for
    ex = {e.get("property") or e["type"]: e for e in exposes_for(dev)}
    climate = ex["climate"]["features"]
    assert [x["property"] for x in climate] == ["local_temperature", "current_heating_setpoint", "system_mode", "fan_mode"]
    assert ex["learn_key"]["type"] == "text" and ex["learn_key"]["access"] == 2
    assert ex["switch"]["features"][0]["property"] == "swing"


def test_irblaster_private_cluster_reports_decode_by_model_not_globally():
    dev = irblaster()
    recs = [(0x0003, 0x42, b"learned c24a1: gree protocol verified & enabled", None), (0x0004, 0x21, 7, None),
            (0x0005, 0x29, -150, None), (0x0006, 0x42, "gree", None), (0x0002, 0x10, 1, None), (0x0008, 0x10, 0, None), (0x0007, 0x20, 40, None)]
    state, used = quirks.decode_vendor_attributes(dev, 1, 0xFC00, recs)
    assert state == {"last_result": "learned c24a1: gree protocol verified & enabled", "code_count": 7, "temperature_offset": -1.5, "protocol": "gree",
                     "hold": "ON", "led_quiet": "OFF", "led_brightness": 40}
    assert used == {0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008}
    # the same cluster id on a Hue device is still Philips' button cluster: nothing is claimed
    hue = mk("Signify Netherlands B.V.", "RWL021", {1: ([0x0000, 0x0001, 0x0003, 0xFC00], [0x0006, 0x0008], 0x0830)})
    assert quirks.decode_vendor_attributes(hue, 1, 0xFC00, [(0x0003, 0x42, b"x", None)]) == ({}, set())
    # standard thermostat / fan reports land on the family keys; both setpoints are one target
    st = quirks.translate_state(dev, 1, decode_attributes(0x0201, [(0x0011, 2400), (0x0012, 2400), (0x001C, 3), (0x0000, 2315)], dev.context))
    assert st == {"current_heating_setpoint": 24.0, "system_mode": "cool", "local_temperature": 23.15}
    dev.state["system_mode"] = "cool"
    assert quirks.translate_state(dev, 1, decode_attributes(0x0202, [(0x0000, 5)])) == {"fan_mode": "auto"}
    assert quirks.translate_state(dev, 1, decode_attributes(0x0202, [(0x0000, 6)])) == {"fan_mode": "smart"}
    assert quirks.translate_state(dev, 2, decode_attributes(0x0006, [(0x0000, 1)])) == {"swing": "ON"}
    assert decode_attributes(0x0201, [(0x0000, -0x8000)]) == {}  # 0x8000 = unknown temperature


def test_irblaster_one_set_temperature_is_the_setpoint_of_the_mode_in_force():
    """ZCL keeps an air conditioner's two setpoints a dead band apart (cooling 25 / heating 24
    while cooling at 25), and the IR blaster reports them in separate frames. The trailing one
    used to overwrite the set temperature a second after it was picked: Apple Home showed 24."""
    dev = irblaster()
    dev.state["system_mode"] = "cool"
    frames = [decode_attributes(0x0201, [(0x0011, 2500)], dev.context), decode_attributes(0x0201, [(0x0012, 2400)], dev.context)]
    assert quirks.translate_state(dev, 1, frames[0]) == {"current_heating_setpoint": 25.0}
    assert quirks.translate_state(dev, 1, frames[1]) == {}                       # the partner, not the set temperature
    # heating: the heating setpoint leads and the cooling one (a degree above) is the partner
    dev.state["system_mode"] = "heat"
    assert quirks.translate_state(dev, 1, decode_attributes(0x0201, [(0x0011, 2600)], dev.context)) == {}
    assert quirks.translate_state(dev, 1, decode_attributes(0x0201, [(0x0012, 2500)], dev.context)) == {"current_heating_setpoint": 25.0}
    # both in one frame: the mode's own setpoint wins whichever order they come in
    assert quirks.translate_state(dev, 1, decode_attributes(0x0201, [(0x0011, 2600), (0x0012, 2500)], dev.context)) == {"current_heating_setpoint": 25.0}
    # a mode change in the same frame decides for that frame
    assert quirks.translate_state(dev, 1, decode_attributes(0x0201, [(0x001C, 3), (0x0011, 2200), (0x0012, 2100)], dev.context)) == {"system_mode": "cool", "current_heating_setpoint": 22.0}
    # switched off, the pair stays as the last mode left it - the gateway remembers which
    dev.state["system_mode"] = "off"
    assert quirks.translate_state(dev, 1, decode_attributes(0x0201, [(0x0012, 2100)], dev.context)) == {}
    assert quirks.translate_state(dev, 1, decode_attributes(0x0201, [(0x0011, 2200)], dev.context)) == {"current_heating_setpoint": 22.0}
    assert dev.context["single_setpoint_mode"] == "cool"


def test_irblaster_private_attribute_encoding_types_and_limits():
    dev = irblaster()
    from oneroof_zigbee.zcl.types import DataType
    assert quirks.encode_private_attribute(dev, 0xFC00, "learn_key", "*") == (0x0000, DataType.string, "*")
    assert quirks.encode_private_attribute(dev, 0xFC00, "send_key", "c24a1") == (0x0001, DataType.string, "c24a1")
    assert quirks.encode_private_attribute(dev, 0xFC00, "hold", "ON") == (0x0002, DataType.bool_, True)
    assert quirks.encode_private_attribute(dev, 0xFC00, "temperature_offset", -1.5) == (0x0005, DataType.int16, -150)
    assert quirks.encode_private_attribute(dev, 0xFC00, "led_brightness", 40) == (0x0007, DataType.uint8, 40)
    assert quirks.encode_private_attribute(dev, 0xFC00, "led_quiet", False) == (0x0008, DataType.bool_, False)
    with pytest.raises(ValueError):
        quirks.encode_private_attribute(dev, 0xFC00, "learn_key", "a" * 16)
    assert quirks.feedback_reads(dev, 0xFC00) == (0x0003, 0x0004, 0x0006)
    assert quirks.extra_reporting(dev) == {0xFC00: ((0x0003, DataType.string, 1, 3600, None),)}


def oneroof_router() -> Device:
    # the One Roof router firmware: one endpoint (8), Basic + Identify only, mains, router
    return mk("One Roof", "oneroof.router", {8: ([0x0000, 0x0003], [], 0x0008)}, power="mains", router=True, ieee=0x00124B00AABB0008)


def test_oneroof_router_is_ours_not_an_unknown_device():
    dev = oneroof_router()
    info = quirks.describe(dev)
    assert (info.kind, info.vendor, info.category) == ("One Roof Router", "One Roof", "unknown")
    assert info.description.startswith("Range extender")
    f = keys(dev)
    assert set(f) == {"identify", "linkquality", "transmit_power"}
    tp = f["transmit_power"]
    assert (tp["endpoint"], tp["cluster"], tp["access"], tp["min"], tp["max"], tp["unit"], tp["category"]) == (8, 0x0000, "rw", -20, 20, "dBm", "config")
    from oneroof_zigbee.zcl.types import DataType
    assert quirks.encode_private_attribute(dev, 0x0000, "transmit_power", 20) == (0x1337, DataType.int8, 20)
    assert quirks.extra_reads(dev) == {0x0000: (0x1337,)}
    # the read at interview decodes through the model table; the standard Basic attributes still decode normally
    state, used = quirks.decode_vendor_attributes(dev, 8, 0x0000, [(0x1337, 0x28, 9, None), (0x4000, 0x42, "20260905", None)])
    assert state == {"transmit_power": 9} and used == {0x1337}
    disc = ha(dev)
    assert disc["transmit_power"][0] == "number" and disc["transmit_power"][1]["min"] == -20 and disc["transmit_power"][1]["max"] == 20
    assert "switch" not in disc and "light" not in disc


async def test_gateway_oneroof_router_transmit_power_writes_basic_0x1337_on_ep8(tmp_path):
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, oneroof_router)
    writes: list[tuple[int, int, int, int, object]] = []

    async def fake_write(d, ep, cluster, attr, dtype, value):
        writes.append((ep, cluster, attr, int(dtype), value))

    gw._write_attr = fake_write
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"transmit_power": 20}')
    assert writes == [(8, 0x0000, 0x1337, 0x28, 20)]
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["transmit_power"] == 20
    assert json.loads(broker.last("oneroof/zigbee/bridge/devices"))[0]["kind"] == "One Roof Router"
    await t.close()


async def test_gateway_irblaster_commands_write_the_right_attributes(tmp_path):
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, irblaster)
    writes: list[tuple[int, int, int, int, object]] = []

    async def fake_write(d, ep, cluster, attr, dtype, value):
        writes.append((ep, cluster, attr, int(dtype), value))

    gw._write_attr = fake_write  # the fake coordinator does not answer Write Attributes
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    fake.requests.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"system_mode": "cool", "target_temperature": 24, "fan_mode": "auto", "swing": "ON"}')
    assert (1, 0x0201, 0x001C, 0x30, 3) in writes and (1, 0x0201, 0x0011, 0x29, 2400) in writes and (1, 0x0202, 0x0000, 0x30, 5) in writes
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert len(reqs) == 1 and reqs[0].data[2] == 2 and int.from_bytes(reqs[0].data[4:6], "little") == 0x0006 and reqs[0].data[10:][2] == 0x01  # swing = On on ep 2
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["system_mode"] == "cool" and state["current_heating_setpoint"] == 24 and state["fan_mode"] == "auto" and state["swing"] == "ON"
    # in heat the single target goes to the heating setpoint
    writes.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"system_mode": "heat", "target_temperature": 22}')
    assert (1, 0x0201, 0x0012, 0x29, 2200) in writes
    # the device-specific cluster: char strings, bool, int16 ×100 — standard attributes, no manufacturer code
    writes.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"learn_key": "*", "hold": "ON", "temperature_offset": -1.5, "protocol": "gree"}')
    assert writes == [(1, 0xFC00, 0x0000, 0x42, "*"), (1, 0xFC00, 0x0002, 0x10, True), (1, 0xFC00, 0x0005, 0x29, -150), (1, 0xFC00, 0x0006, 0x42, "gree")]
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["hold"] == "ON" and state["temperature_offset"] == -1.5 and state["protocol"] == "gree" and "learn_key" not in state
    # a report from the device is the source of truth: last_result (string) and code_count on 0xFC00
    from oneroof_zigbee.znp.unpi import Frame, FrameType
    from oneroof_zigbee.znp.wire import Writer
    body = b"learned c24a1: gree protocol verified & enabled"
    zcl = bytes([0x18, 0x09, 0x0A]) + (0x0003).to_bytes(2, "little") + b"\x42" + bytes([len(body)]) + body + (0x0004).to_bytes(2, "little") + b"\x21" + (8).to_bytes(2, "little")
    w = Writer().u16(0).u16(0xFC00).u16(NWK).u8(1).u8(1).u8(0).u8(200).u8(1).u32(0).u8(9).lv(zcl)
    fake.emit(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes()))
    await asyncio.sleep(0.05)
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["last_result"] == body.decode() and state["code_count"] == 8
    assert json.loads(broker.last("oneroof/zigbee/bridge/devices"))[0]["kind"] == "AC IR blaster"
    await t.close()


async def test_gateway_gang_alias_routes_old_style_keys(tmp_path):
    """A HomeKit bridge built on an older exposes generation may say state_left where the device
    now exposes state_l1: the command routes by gang position instead of being dropped silently."""
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("_TZ3000_owgcnkrh", "TS0012", {1: ([0x0000, 0x0004, 0x0005, 0x0006], [0x0019], 0x0100),
                                                                                                        2: ([0x0004, 0x0005, 0x0006], [], 0x0100)}, power="mains", router=True, ieee=0x00158D0000000031))
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    fake.requests.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"state_left": "ON"}')
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert len(reqs) == 1 and reqs[0].data[2] == 1, "state_left lands on gang 1 (state_l1)"
    state = json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["state_l1"] == "ON" and "state_left" not in state
    await t.close()


async def test_gateway_color_accepts_hue_saturation_payload(tmp_path):
    """HomeKit bridges publish zigbee2mqtt-style {"color":{"hue","saturation"}}; the gateway must
    turn it into a move_to_hue_and_saturation, not silently ignore it."""
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("IKEA of Sweden", "TRADFRI bulb E27 CWS", {1: ([0x0000, 0x0006, 0x0008, 0x0300], [], 0x0100)},
                                                                        power="mains", router=True, ieee=0x00158D0000000032))
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    fake.requests.clear()
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"color": {"hue": 120, "saturation": 50}}')
    reqs = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert any(int.from_bytes(f.data[4:6], "little") == 0x0300 for f in reqs), "a colour-cluster command was sent"
    await t.close()


async def test_climate_device_is_polled_on_its_thermostat_cluster(tmp_path):
    """A thermostat whose firmware refuses to report its setpoints (ZCL 0x8c) must still refresh:
    the poll asks the thermostat cluster, not the on/off one, which says nothing about temperature."""
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: mk("NoammGr", "IRBlaster",
        {1: ([0x0000, 0x0201, 0x0202], [], 0x0301), 2: ([0x0006], [], 0x0100)}, power="mains", router=True,
        ieee=0x00158D0000000041))
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    dev.last_seen = 0.0          # long silent
    dev.reporting = [{"endpoint": 1, "cluster": 0x0201, "attribute": 0x0012, "status": "status 0x8c"}]
    assert gw._poll_after(dev) == gw.UNREPORTED_POLL_AFTER_S, "a device that cannot report is polled often"
    fake.requests.clear()
    await gw._poll_silent_routers()
    sent = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST]
    assert sent, "the device was polled"
    assert any(int.from_bytes(f.data[4:6], "little") == 0x0201 for f in sent), "on the thermostat cluster"
    await t.close()


def test_air_conditioner_description_is_what_other_apps_expect():
    """The contract with everything downstream (Home Assistant, the One Roof Bridge on its way to
    Apple Home): the one set temperature under the property name the world knows, whole degrees
    only, the louver as a plain switch, and the on-board sensors as their own readings — so a
    consumer that never heard of this device still shows temperature, humidity, swing and a
    setpoint it can actually change."""
    from oneroof_zigbee.ha.exposes import exposes_for
    dev = irblaster()
    ex = {e.get("property") or e["type"]: e for e in exposes_for(dev)}
    sp = next(x for x in ex["climate"]["features"] if x["property"] == "current_heating_setpoint")
    assert sp["value_step"] == 1 and sp["value_min"] == 16 and sp["value_max"] == 30, sp
    assert sp["access"] & 2, "the setpoint must be settable"
    assert "target_temperature" not in ex, "no invented property name that other apps cannot find"
    assert ex["switch"]["features"][0]["property"] == "swing", "the louver is a switch anyone can toggle"
    assert ex["temperature"]["type"] == "numeric" and ex["temperature"]["unit"] == "°C"
    assert ex["humidity"]["type"] == "numeric" and ex["humidity"]["unit"] == "%"


def test_air_conditioner_louver_is_the_climate_entitys_swing_not_a_stray_toggle():
    """The louver is its own on/off endpoint on the wire. Home Assistant models it as the climate
    entity's swing mode, and every consumer downstream — the Apple Home bridge included — looks for
    it there; a separate switch entity for the same thing is both a duplicate and invisible to
    anything that only understands climate."""
    ac = irblaster()
    ac.friendly_name = "Bedroom AC"
    entities = ha(ac, legacy=False)

    component, climate = entities["climate"]
    assert component == "climate"
    assert climate["swing_modes"] == ["ON", "OFF"]
    assert climate["swing_mode_state_template"] == "{{ value_json.swing }}"
    assert climate["swing_mode_command_template"] == '{"swing": "{{ value }}" }'
    assert climate["swing_mode_command_topic"] == climate["mode_command_topic"]

    # ...and it is not published twice
    switches = [oid for oid, (comp, _) in entities.items() if comp == "switch"]
    assert not any("swing" in oid for oid in switches), switches
    assert "switch" not in entities, "the louver came back as its own toggle"


def test_a_plain_switch_endpoint_is_still_a_switch():
    """Only an air conditioner's louver is folded away. A two-gang switch keeps both toggles."""
    gang = mk("Acme", "SW-2", {1: ([0x0006], [], 0x0100), 2: ([0x0006], [], 0x0100)},
              power="mains", router=True)
    entities = ha(gang, legacy=False)
    assert sum(1 for comp, _ in entities.values() if comp == "switch") == 2


def test_the_louver_survives_as_state_when_the_device_has_no_setpoint():
    """No climate entity, no swing mode to fold it into: it stays a toggle rather than vanishing."""
    fan = mk("Acme", "FAN-1", {1: ([0x0006], [], 0x0100)}, power="mains", router=True)
    entities = ha(fan, legacy=False)
    assert any(comp == "switch" for comp, _ in entities.values())


async def test_air_conditioner_temperature_survives_a_refused_setpoint_attribute(tmp_path):
    """An air conditioner has one set temperature but the ZCL has two setpoint attributes, and a
    device may implement only one of them. When the one we pick is refused, the temperature must
    still change — otherwise mode, fan and louver all work and only the temperature does nothing."""
    import json as _json
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Frame, FrameType, Subsystem
    from oneroof_zigbee.znp.wire import Writer

    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: irblaster())
    dev.state["system_mode"] = "cool"

    refused = []

    def hook(f: Frame):
        dst = int.from_bytes(f.data[0:2], "little")
        dst_ep, src_ep = f.data[2], f.data[3]
        cluster = int.from_bytes(f.data[4:6], "little")
        zframe = f.data[10:]
        seq, cmd = zframe[1], zframe[2]
        if cluster != 0x0201 or cmd != 0x02:      # only thermostat writes
            return []
        attr = int.from_bytes(zframe[3:5], "little")

        def reply(payload):
            w = (Writer().u16(0).u16(cluster).u16(dst).u8(dst_ep).u8(src_ep).u8(0).u8(180)
                 .u8(1).u32(0).u8(seq).lv(payload))
            return [Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes())]

        if attr == 0x0011:                        # cooling setpoint: not implemented here
            refused.append(attr)
            return reply(bytes([0x18, seq, 0x04, 0x86]) + attr.to_bytes(2, "little"))
        return reply(bytes([0x18, seq, 0x04, 0x00]))

    fake.on_data_request = hook
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"current_heating_setpoint": 23}',
                        user="admin")
    for _ in range(60):
        await asyncio.sleep(0.05)
        if _json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state")).get("current_heating_setpoint") == 23:
            break

    assert refused == [0x0011], "the cooling setpoint should have been tried first in cool mode"
    writes = [f.data[10:] for f in fake.requests
              if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST
              and int.from_bytes(f.data[4:6], "little") == 0x0201 and f.data[12] == 0x02]
    attrs = [int.from_bytes(w[3:5], "little") for w in writes]
    assert attrs == [0x0011, 0x0012], f"expected a fallback to the heating setpoint, wrote {attrs}"
    assert int.from_bytes(writes[-1][6:8], "little") == 2300, "the value must survive the fallback"

    state = _json.loads(broker.last(f"oneroof/zigbee/{dev.ieee_str}/state"))
    assert state["current_heating_setpoint"] == 23
    await t.close()


async def test_a_command_that_failed_says_so_in_the_log(tmp_path):
    """The audit records that a command arrived. If carrying it out then failed and nothing said
    so, the log would read as though the device had done it."""
    fake, broker, gw, dev, t = await _gateway_with(tmp_path, lambda: irblaster())
    seen = []
    gw.audit.subscribe(lambda rec: seen.append(rec))

    fake.on_data_request = lambda f: []           # the device answers nothing at all
    await broker.inject(f"oneroof/zigbee/{dev.ieee_str}/set", b'{"current_heating_setpoint": 23}',
                        user="admin")
    for _ in range(200):
        await asyncio.sleep(0.05)
        if any(r.get("type") == "command_failed" for r in seen):
            break

    failed = [r for r in seen if r.get("type") == "command_failed"]
    assert failed, [r.get("type") for r in seen]
    assert failed[0]["ieee"] == dev.ieee_str and failed[0]["keys"] == ["current_heating_setpoint"]
    assert failed[0]["by"] == "admin" and failed[0]["error"]
    await t.close()


async def test_aqara_devices_are_told_they_live_on_a_zigbee_hub(tmp_path):
    """zigbee2mqtt writes mode=1 to Aqara's private cluster (0xFCC0, manufacturer 0x115F) on
    every configure — it is what tells the device it lives on a Zigbee hub. Without it some
    models keep waiting for the proprietary Mi Home presence protocol, decide no hub is there,
    and blink their indicator red/blue while still obeying every command."""
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem

    fake, broker, gw, dev, t = await _gateway_with(
        tmp_path, lambda: mk("LUMI", "lumi.switch.b2lc04",
                             {1: ([0x0000, 0x0006, 0xFCC0], [0x0019], 0x0100),
                              2: ([0x0006], [], 0x0100)},
                             power="mains", router=False, ieee=0x54EF44100000AAAA))
    fake.requests.clear()
    await gw._vendor_settle(dev)

    writes = []
    for f in fake.requests:
        if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST \
                and int.from_bytes(f.data[4:6], "little") == 0xFCC0:
            writes.append(f.data[10:])
    assert writes, "no write ever reached the Aqara private cluster"
    z = writes[0]
    assert z[0] & 0x04, "the write must be manufacturer-specific"
    assert int.from_bytes(z[1:3], "little") == 0x115F, "…with the LUMI manufacturer code"
    assert z[4] == 0x02, "a Write Attributes command"
    assert int.from_bytes(z[5:7], "little") == 0x0009 and z[7] == 0x20 and z[8] == 1, \
        "mode (0x0009), uint8, value 1 — exactly what zigbee2mqtt writes"


async def test_the_lumi_write_goes_out_even_when_the_cluster_is_undeclared(tmp_path):
    """Xiaomi devices answer on 0xFCC0 without declaring it in their simple descriptor — the
    real lumi.switch.b2lc04 interviews as plain on/off endpoints. Gating the write on the
    declared cluster list silently skipped exactly the devices that need it."""
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    fake, broker, gw, dev, t = await _gateway_with(
        tmp_path, lambda: mk("LUMI", "lumi.switch.b2lc04",
                             {1: ([0x0000, 0x0006], [0x0019], 0x0100),   # no 0xFCC0 declared
                              2: ([0x0006], [], 0x0100)},
                             power="mains", router=False, ieee=0x54EF44100000AAAB))
    fake.requests.clear()
    await gw._vendor_settle(dev)
    sent = [f for f in fake.requests if f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST
            and int.from_bytes(f.data[4:6], "little") == 0xFCC0]
    assert sent, "the undeclared cluster silently skipped the write again"
    assert sent[0].data[2] == 1, "defaults to endpoint 1, as zigbee2mqtt does"
    await t.close()


async def test_non_aqara_devices_get_no_lumi_write(tmp_path):
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.unpi import Subsystem
    fake, broker, gw, dev, t2 = await _gateway_with(
        tmp_path, lambda: mk("Acme", "PLUG-9", {1: ([0x0000, 0x0006], [], 0x0100)},
                             power="mains", router=True, ieee=0x00124B00000000BB))
    fake.requests.clear()
    await gw._vendor_settle(dev)
    assert not any(f.subsystem is Subsystem.AF and f.command == c.AfCmd.DATA_REQUEST
                   and int.from_bytes(f.data[4:6], "little") == 0xFCC0 for f in fake.requests)
    await t2.close()


async def test_a_lumi_device_without_the_attribute_still_finishes(tmp_path):
    """Older lumi models refuse the write; a refusal must stay a shrug, not an error that
    aborts the rest of the configuration."""
    fake, broker, gw, dev, t = await _gateway_with(
        tmp_path, lambda: mk("LUMI", "lumi.sensor_magnet.aq2",
                             {1: ([0x0000, 0x0006, 0xFCC0], [], 0x0402)},
                             ieee=0x00158D00000000CC))
    def refuse(f):
        return []          # the device never answers at all — worst case
    fake.on_data_request = refuse
    await gw._vendor_settle(dev)   # must not raise


def test_a_report_from_an_unlisted_endpoint_never_speaks_for_the_whole_device():
    """Some devices answer on an endpoint their descriptors did not list (Aqara's shared 0xF2).
    A single-switch device: that is its switch. A two-gang switch: nobody knows which gang spoke,
    and the old plain-key fallback showed one gang's answer as a "state" of the whole device -
    which the Apple Home bridge then displayed as the light."""
    two = mk("_TZ3000_owgcnkrh", "TS0012", {1: ([0x0000, 0x0004, 0x0005, 0x0006], [0x0019], 0x0100),
                                            2: ([0x0004, 0x0005, 0x0006], [], 0x0100)}, power="mains", router=True)
    assert quirks.translate_state(two, 0xF2, {"state": "ON"}) == {}, "ambiguous: dropped"
    assert quirks.translate_state(two, 2, {"state": "ON"}) == {"state_l2": "ON"}, "a listed endpoint maps as before"
    one = mk("_TZ3000_ko6v90pg", "TS011F", {1: ([0x0000, 0x0006, 0x0B04], [0x0019], 0x0051)}, power="mains", router=True)
    assert quirks.translate_state(one, 0xF2, {"state": "OFF"}) == {"state": "OFF"}, "one switch: that one"
    assert quirks.translate_state(one, 0xF2, {"countdown": 5}) == {"countdown": 5}


def test_a_second_dimmer_channel_is_a_template_light_in_home_assistant():
    """A two-channel dimmer publishes state_l2 / brightness_l2 in the shared payload. The JSON
    light schema only knows "state" and "brightness": under it the second channel showed the
    first channel's state and switched the first channel. The template schema names the keys."""
    dev = mk("Acme", "Dimmer-2", {1: ([0x0000, 0x0006, 0x0008], [], 0x0101), 2: ([0x0006, 0x0008], [], 0x0101)},
             power="mains", router=True)
    feats = keys(dev)
    assert {"state_l1", "brightness_l1", "state_l2", "brightness_l2"} <= set(feats), sorted(feats)
    disc = ha(dev)
    comp, l2 = disc["light_l2"]
    assert comp == "light" and l2["schema"] == "template"
    assert l2["state_template"] == "{{ 'on' if value_json.state_l2 == 'ON' else 'off' }}"
    assert l2["brightness_template"] == "{{ value_json.brightness_l2 }}"
    assert l2["command_on_template"].startswith('{"state_l2": "ON"') and '"brightness_l2": {{ brightness }}' in l2["command_on_template"]
    assert l2["command_off_template"].startswith('{"state_l2": "OFF"')
    assert l2["state_topic"] == "oz/test"
    single = mk("Acme", "Bulb", {1: ([0x0000, 0x0006, 0x0008], [], 0x0101)}, power="mains", router=True)
    assert ha(single)["light"][1]["schema"] == "json", "one channel keeps the JSON schema HA knows best"
