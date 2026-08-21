"""Zigbee Home Automation profile constants and endpoint classification."""

from __future__ import annotations

from typing import Iterable

PROFILE_HA = 0x0104
PROFILE_ZLL = 0xC05E
PROFILE_GP = 0xA1E0
PROFILE_ZDO = 0x0000

# HA device ids (HA profile spec, table 5.1)
DEVICE_ON_OFF_SWITCH = 0x0000
DEVICE_LEVEL_CONTROL_SWITCH = 0x0001
DEVICE_ON_OFF_OUTPUT = 0x0002
DEVICE_LEVEL_CONTROLLABLE_OUTPUT = 0x0003
DEVICE_SCENE_SELECTOR = 0x0004
DEVICE_CONFIGURATION_TOOL = 0x0005
DEVICE_REMOTE_CONTROL = 0x0006
DEVICE_COMBINED_INTERFACE = 0x0007
DEVICE_RANGE_EXTENDER = 0x0008
DEVICE_MAINS_POWER_OUTLET = 0x0009
DEVICE_DOOR_LOCK = 0x000A
DEVICE_DOOR_LOCK_CONTROLLER = 0x000B
DEVICE_SIMPLE_SENSOR = 0x000C
DEVICE_CONSUMPTION_AWARENESS = 0x000D
DEVICE_HOME_GATEWAY = 0x0050
DEVICE_SMART_PLUG = 0x0051
DEVICE_WHITE_GOODS = 0x0052
DEVICE_METER_INTERFACE = 0x0053
DEVICE_ON_OFF_LIGHT = 0x0100
DEVICE_DIMMABLE_LIGHT = 0x0101
DEVICE_COLOR_DIMMABLE_LIGHT = 0x0102
DEVICE_ON_OFF_LIGHT_SWITCH = 0x0103
DEVICE_DIMMER_SWITCH = 0x0104
DEVICE_COLOR_DIMMER_SWITCH = 0x0105
DEVICE_LIGHT_SENSOR = 0x0106
DEVICE_OCCUPANCY_SENSOR = 0x0107
DEVICE_ON_OFF_BALLAST = 0x0108
DEVICE_DIMMABLE_BALLAST = 0x0109
DEVICE_ON_OFF_PLUG_IN_UNIT = 0x010A
DEVICE_DIMMABLE_PLUG_IN_UNIT = 0x010B
DEVICE_COLOR_TEMPERATURE_LIGHT = 0x010C
DEVICE_EXTENDED_COLOR_LIGHT = 0x010D
DEVICE_LIGHT_LEVEL_SENSOR = 0x010E
DEVICE_SHADE = 0x0200
DEVICE_SHADE_CONTROLLER = 0x0201
DEVICE_WINDOW_COVERING_DEVICE = 0x0202
DEVICE_WINDOW_COVERING_CONTROLLER = 0x0203
DEVICE_HEATING_COOLING_UNIT = 0x0300
DEVICE_THERMOSTAT = 0x0301
DEVICE_TEMPERATURE_SENSOR = 0x0302
DEVICE_PUMP = 0x0303
DEVICE_PUMP_CONTROLLER = 0x0304
DEVICE_PRESSURE_SENSOR = 0x0305
DEVICE_FLOW_SENSOR = 0x0306
DEVICE_MINI_SPLIT_AC = 0x0307
DEVICE_IAS_CIE = 0x0400
DEVICE_IAS_ACE = 0x0401
DEVICE_IAS_ZONE = 0x0402
DEVICE_IAS_WARNING_DEVICE = 0x0403

DEVICE_NAMES: dict[int, str] = {
    DEVICE_ON_OFF_SWITCH: "on_off_switch",
    DEVICE_LEVEL_CONTROL_SWITCH: "level_control_switch",
    DEVICE_ON_OFF_OUTPUT: "on_off_output",
    DEVICE_LEVEL_CONTROLLABLE_OUTPUT: "level_controllable_output",
    DEVICE_SCENE_SELECTOR: "scene_selector",
    DEVICE_CONFIGURATION_TOOL: "configuration_tool",
    DEVICE_REMOTE_CONTROL: "remote_control",
    DEVICE_COMBINED_INTERFACE: "combined_interface",
    DEVICE_RANGE_EXTENDER: "range_extender",
    DEVICE_MAINS_POWER_OUTLET: "mains_power_outlet",
    DEVICE_DOOR_LOCK: "door_lock",
    DEVICE_DOOR_LOCK_CONTROLLER: "door_lock_controller",
    DEVICE_SIMPLE_SENSOR: "simple_sensor",
    DEVICE_CONSUMPTION_AWARENESS: "consumption_awareness_device",
    DEVICE_HOME_GATEWAY: "home_gateway",
    DEVICE_SMART_PLUG: "smart_plug",
    DEVICE_WHITE_GOODS: "white_goods",
    DEVICE_METER_INTERFACE: "meter_interface",
    DEVICE_ON_OFF_LIGHT: "on_off_light",
    DEVICE_DIMMABLE_LIGHT: "dimmable_light",
    DEVICE_COLOR_DIMMABLE_LIGHT: "color_dimmable_light",
    DEVICE_ON_OFF_LIGHT_SWITCH: "on_off_light_switch",
    DEVICE_DIMMER_SWITCH: "dimmer_switch",
    DEVICE_COLOR_DIMMER_SWITCH: "color_dimmer_switch",
    DEVICE_LIGHT_SENSOR: "light_sensor",
    DEVICE_OCCUPANCY_SENSOR: "occupancy_sensor",
    DEVICE_ON_OFF_BALLAST: "on_off_ballast",
    DEVICE_DIMMABLE_BALLAST: "dimmable_ballast",
    DEVICE_ON_OFF_PLUG_IN_UNIT: "on_off_plug_in_unit",
    DEVICE_DIMMABLE_PLUG_IN_UNIT: "dimmable_plug_in_unit",
    DEVICE_COLOR_TEMPERATURE_LIGHT: "color_temperature_light",
    DEVICE_EXTENDED_COLOR_LIGHT: "extended_color_light",
    DEVICE_LIGHT_LEVEL_SENSOR: "light_level_sensor",
    DEVICE_SHADE: "shade",
    DEVICE_SHADE_CONTROLLER: "shade_controller",
    DEVICE_WINDOW_COVERING_DEVICE: "window_covering_device",
    DEVICE_WINDOW_COVERING_CONTROLLER: "window_covering_controller",
    DEVICE_HEATING_COOLING_UNIT: "heating_cooling_unit",
    DEVICE_THERMOSTAT: "thermostat",
    DEVICE_TEMPERATURE_SENSOR: "temperature_sensor",
    DEVICE_PUMP: "pump",
    DEVICE_PUMP_CONTROLLER: "pump_controller",
    DEVICE_PRESSURE_SENSOR: "pressure_sensor",
    DEVICE_FLOW_SENSOR: "flow_sensor",
    DEVICE_MINI_SPLIT_AC: "mini_split_ac",
    DEVICE_IAS_CIE: "ias_control_and_indicating_equipment",
    DEVICE_IAS_ACE: "ias_ancillary_control_equipment",
    DEVICE_IAS_ZONE: "ias_zone",
    DEVICE_IAS_WARNING_DEVICE: "ias_warning_device",
}

# Cluster ids used for classification (kept local to avoid a circular import)
_CL_ON_OFF = 0x0006
_CL_LEVEL = 0x0008
_CL_COLOR = 0x0300
_CL_WINDOW_COVERING = 0x0102
_CL_THERMOSTAT = 0x0201
_CL_ELECTRICAL = 0x0B04
_CL_METERING = 0x0702
_CL_IAS_ZONE = 0x0500
_SENSOR_CLUSTERS = {0x0400, 0x0402, 0x0403, 0x0405, 0x0406, 0x0500, 0x040D, 0x042A}

_LIGHT_DEVICE_IDS = {
    DEVICE_ON_OFF_LIGHT,
    DEVICE_DIMMABLE_LIGHT,
    DEVICE_COLOR_DIMMABLE_LIGHT,
    DEVICE_COLOR_TEMPERATURE_LIGHT,
    DEVICE_EXTENDED_COLOR_LIGHT,
    DEVICE_ON_OFF_BALLAST,
    DEVICE_DIMMABLE_BALLAST,
    DEVICE_DIMMABLE_PLUG_IN_UNIT,
    DEVICE_LEVEL_CONTROLLABLE_OUTPUT,
}
_PLUG_DEVICE_IDS = {DEVICE_SMART_PLUG, DEVICE_MAINS_POWER_OUTLET, DEVICE_ON_OFF_PLUG_IN_UNIT}
_SWITCH_DEVICE_IDS = {
    DEVICE_ON_OFF_SWITCH,
    DEVICE_LEVEL_CONTROL_SWITCH,
    DEVICE_ON_OFF_LIGHT_SWITCH,
    DEVICE_DIMMER_SWITCH,
    DEVICE_COLOR_DIMMER_SWITCH,
    DEVICE_REMOTE_CONTROL,
    DEVICE_SCENE_SELECTOR,
}
_COVER_DEVICE_IDS = {DEVICE_SHADE, DEVICE_WINDOW_COVERING_DEVICE}
_CLIMATE_DEVICE_IDS = {DEVICE_THERMOSTAT, DEVICE_HEATING_COOLING_UNIT, DEVICE_MINI_SPLIT_AC}
_SENSOR_DEVICE_IDS = {
    DEVICE_SIMPLE_SENSOR,
    DEVICE_LIGHT_SENSOR,
    DEVICE_OCCUPANCY_SENSOR,
    DEVICE_LIGHT_LEVEL_SENSOR,
    DEVICE_TEMPERATURE_SENSOR,
    DEVICE_PRESSURE_SENSOR,
    DEVICE_FLOW_SENSOR,
    DEVICE_IAS_ZONE,
}


def classify(in_clusters: Iterable[int], out_clusters: Iterable[int], device_id: int | None) -> str:
    """Derive a coarse category from server clusters and the HA device id.

    Returns one of ``light``, ``switch``, ``sensor``, ``cover``, ``climate``,
    ``plug``, ``unknown``.  The device id wins when it is a known HA id;
    otherwise the server cluster set decides.
    """
    ins = set(in_clusters)
    outs = set(out_clusters)

    if device_id in _LIGHT_DEVICE_IDS:
        return "light"
    if device_id in _PLUG_DEVICE_IDS:
        return "plug"
    if device_id in _COVER_DEVICE_IDS:
        return "cover"
    if device_id in _CLIMATE_DEVICE_IDS:
        return "climate"
    if device_id in _SENSOR_DEVICE_IDS:
        return "sensor"
    if device_id in _SWITCH_DEVICE_IDS:
        return "switch"

    # Fall back to cluster heuristics
    if _CL_WINDOW_COVERING in ins:
        return "cover"
    if _CL_THERMOSTAT in ins:
        return "climate"
    if _CL_ON_OFF in ins:
        if _CL_COLOR in ins or _CL_LEVEL in ins:
            return "light"
        if _CL_ELECTRICAL in ins or _CL_METERING in ins:
            return "plug"
        return "switch"
    if ins & _SENSOR_CLUSTERS:
        return "sensor"
    if _CL_ON_OFF in outs or _CL_LEVEL in outs:
        return "switch"  # a remote/controller that *sends* on/off
    return "unknown"


def describe_endpoint(
    in_clusters: Iterable[int],
    out_clusters: Iterable[int],
    device_id: int | None,
    profile_id: int | None = PROFILE_HA,
) -> dict:
    """Return a JSON-able description of an endpoint."""
    from .clusters import cluster_name  # local import to avoid cycles at module load

    ins = sorted(set(in_clusters))
    outs = sorted(set(out_clusters))
    return {
        "profile_id": profile_id,
        "device_id": device_id,
        "device_type": DEVICE_NAMES.get(device_id, "unknown") if device_id is not None else "unknown",
        "category": classify(ins, outs, device_id),
        "in_clusters": [{"id": c, "name": cluster_name(c)} for c in ins],
        "out_clusters": [{"id": c, "name": cluster_name(c)} for c in outs],
    }


__all__ = ["PROFILE_HA", "PROFILE_ZLL", "PROFILE_GP", "PROFILE_ZDO", "DEVICE_NAMES", "classify", "describe_endpoint"]
