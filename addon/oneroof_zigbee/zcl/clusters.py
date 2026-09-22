"""Cluster models and converters between ZCL attributes and JSON state.

Every cluster is described by a :class:`Cluster` (attribute ids/types and
command ids).  Two converter entry points sit on top:

* :func:`decode_attributes` turns ``[(attr_id, raw_value), ...]`` into plain
  JSON-able state such as ``{"temperature": 21.35}``.
* :func:`encode_command` turns ``("on_off", "on", {})`` or
  ``("level", "move_to_level_with_on_off", {"level": 128})`` into
  ``(command_id, payload_bytes)``.

Some conversions depend on other attributes (multipliers/divisors, IAS zone
type).  Callers may pass a per-device-endpoint ``context`` dict which the
converters read and update with raw attribute values they care about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .frame import DIRECTION_CLIENT_TO_SERVER, DIRECTION_SERVER_TO_CLIENT
from .types import DataType, ZclDecodeError, decode_value, encode_value

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Attribute:
    id: int
    name: str
    dtype: DataType
    writable: bool = False
    reportable: bool = True
    unit: str | None = None


@dataclass(frozen=True)
class CommandParam:
    name: str
    dtype: DataType
    default: Any = None  # None → required


@dataclass(frozen=True)
class CommandDef:
    id: int
    name: str
    params: tuple[CommandParam, ...] = ()


@dataclass
class Cluster:
    id: int
    name: str
    attributes: dict[int, Attribute] = field(default_factory=dict)
    commands: dict[int, str] = field(default_factory=dict)  # client→server (received by server)
    server_commands: dict[int, str] = field(default_factory=dict)  # server→client
    command_defs: dict[str, CommandDef] = field(default_factory=dict)  # client→server by name
    server_command_defs: dict[str, CommandDef] = field(default_factory=dict)  # server→client by name
    decoder: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]] | None = None

    def attribute_by_name(self, name: str) -> Attribute | None:
        for a in self.attributes.values():
            if a.name == name:
                return a
        return None


def _attrs(*rows: tuple[int, str, DataType] | tuple[int, str, DataType, bool]) -> dict[int, Attribute]:
    out: dict[int, Attribute] = {}
    for row in rows:
        writable = bool(row[3]) if len(row) > 3 else False
        out[row[0]] = Attribute(row[0], row[1], row[2], writable=writable)
    return out


def _cmds(*defs: CommandDef) -> tuple[dict[int, str], dict[str, CommandDef]]:
    return {d.id: d.name for d in defs}, {d.name: d for d in defs}


# Short aliases
U8, U16, I16, B8, B16, E8, E16, BOOL, STR = (
    DataType.uint8,
    DataType.uint16,
    DataType.int16,
    DataType.bitmap8,
    DataType.bitmap16,
    DataType.enum8,
    DataType.enum16,
    DataType.bool_,
    DataType.string,
)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

POWER_SOURCE = {
    0: "unknown",
    1: "mains_single_phase",
    2: "mains_three_phase",
    3: "battery",
    4: "dc",
    5: "emergency_mains_constant",
    6: "emergency_mains_transfer",
}

COLOR_MODE = {0: "hs", 1: "xy", 2: "color_temp"}

SYSTEM_MODE = {
    0: "off",
    1: "auto",
    3: "cool",
    4: "heat",
    5: "emergency_heating",
    6: "precooling",
    7: "fan_only",
    8: "dry",
    9: "sleep",
}
SYSTEM_MODE_BY_NAME = {v: k for k, v in SYSTEM_MODE.items()}

# Thermostat ControlSequenceOfOperation (0x001B): which of cooling / heating the device can do
CONTROL_SEQUENCE_COOLING = {0, 1, 4, 5}
CONTROL_SEQUENCE_HEATING = {2, 3, 4, 5}

# Fan Control FanMode (0x0000). "on" (4) and "smart" (6) are accepted by most air conditioners
# and treated like auto; the gateway offers the four the UI can reason about.
FAN_MODE = {0: "off", 1: "low", 2: "medium", 3: "high", 4: "on", 5: "auto", 6: "smart"}
FAN_MODE_BY_NAME = {v: k for k, v in FAN_MODE.items()}
FAN_MODES = ["low", "medium", "high", "auto"]

IAS_ZONE_TYPE = {
    0x0000: "standard_cie",
    0x000D: "motion",
    0x0015: "contact",
    0x0028: "fire",
    0x002A: "water",
    0x002B: "carbon_monoxide",
    0x002C: "personal_emergency",
    0x002D: "vibration",
    0x010F: "remote_control",
    0x0115: "key_fob",
    0x021D: "keypad",
    0x0225: "standard_warning_device",
    0x0226: "glass_break",
    0x0229: "security_repeater",
    0xFFFF: "invalid",
}

IAS_ENROLL_RESPONSE_CODE = {0: "success", 1: "not_supported", 2: "no_enroll_permit", 3: "too_many_zones"}

# Zone status bits (ZCL 8.2.2.2.1.3)
ZS_ALARM1 = 1 << 0
ZS_ALARM2 = 1 << 1
ZS_TAMPER = 1 << 2
ZS_BATTERY = 1 << 3
ZS_SUPERVISION = 1 << 4
ZS_RESTORE = 1 << 5
ZS_TROUBLE = 1 << 6
ZS_AC_MAINS = 1 << 7
ZS_TEST = 1 << 8
ZS_BATTERY_DEFECT = 1 << 9


# ---------------------------------------------------------------------------
# Converter helpers
# ---------------------------------------------------------------------------


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _ratio(ctx: dict[str, Any], mult_key: str, div_key: str, default_mult: int, default_div: int) -> float:
    mult = ctx.get(mult_key)
    div = ctx.get(div_key)
    if not _num(mult) or mult == 0:
        mult = default_mult
    if not _num(div) or div == 0:
        div = default_div
    return mult / div


def ias_zone_status_to_state(zone_status: int, zone_type: int | None) -> dict[str, Any]:
    """Map an IAS zone status bitmap into named booleans based on zone type."""
    alarm1 = bool(zone_status & ZS_ALARM1)
    alarm2 = bool(zone_status & ZS_ALARM2)
    kind = IAS_ZONE_TYPE.get(zone_type if zone_type is not None else -1)
    state: dict[str, Any] = {}
    if kind == "contact":
        state["contact"] = not alarm1  # alarm = opened
    elif kind == "motion":
        state["occupancy"] = alarm1 or alarm2
    elif kind == "water":
        state["water_leak"] = alarm1 or alarm2
    elif kind == "fire":
        state["smoke"] = alarm1 or alarm2
    elif kind == "carbon_monoxide":
        state["carbon_monoxide"] = alarm1 or alarm2
    elif kind == "vibration":
        state["vibration"] = alarm1 or alarm2
    elif kind == "glass_break":
        state["glass_break"] = alarm1 or alarm2
    elif kind == "personal_emergency":
        state["emergency"] = alarm1 or alarm2
    else:
        state["alarm_1"] = alarm1
        state["alarm_2"] = alarm2
    state["tamper"] = bool(zone_status & ZS_TAMPER)
    state["battery_low"] = bool(zone_status & ZS_BATTERY)
    if zone_status & ZS_TROUBLE:
        state["trouble"] = True
    if zone_status & ZS_AC_MAINS:
        state["ac_mains_fault"] = True
    if zone_status & ZS_TEST:
        state["test"] = True
    if zone_status & ZS_BATTERY_DEFECT:
        state["battery_defect"] = True
    return state


# ---------------------------------------------------------------------------
# Per-cluster decoders: (named raw attrs in this batch, context) -> state
# ---------------------------------------------------------------------------


def _dec_basic(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k in ("manufacturer_name", "model_id", "date_code", "sw_build_id"):
        if isinstance(a.get(k), str):
            out[k] = a[k].strip("\x00 ")
    for k in ("zcl_version", "app_version", "stack_version", "hw_version"):
        if _num(a.get(k)):
            out[k] = a[k]
    ps = a.get("power_source")
    if _num(ps):
        out["power_source"] = POWER_SOURCE.get(ps & 0x7F, f"unknown_{ps & 0x7F}")
        out["battery_backup"] = bool(ps & 0x80)
    return out


def _dec_power_cfg(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if _num(a.get("battery_voltage")):
        out["voltage"] = round(a["battery_voltage"] / 10, 1)  # 100 mV units → V
    if _num(a.get("battery_percentage_remaining")):
        out["battery"] = round(min(a["battery_percentage_remaining"] / 2, 100), 1)
    return out


def _dec_identify(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    return {"identify_time": a["identify_time"]} if _num(a.get("identify_time")) else {}


_START_UP_ON_OFF = {0: "off", 1: "on", 2: "toggle", 255: "previous"}


def _dec_on_off(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    v = a.get("on_off")
    if v is not None:
        out["state"] = "ON" if v else "OFF"
    if "start_up_on_off" in a:
        raw = a["start_up_on_off"]
        # enum8 0xFF is the spec's "previous" here, which the generic decoder reports as None
        out["power_on_behavior"] = _START_UP_ON_OFF.get(255 if raw is None else raw, str(raw))
    return out


def _dec_level(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("current_level")
    if not _num(v):
        return {}
    return {"brightness": max(0, min(254, int(v)))}


def _dec_color(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    color: dict[str, Any] = {}
    if _num(a.get("current_x")):
        color["x"] = round(a["current_x"] / 65535, 4)
    if _num(a.get("current_y")):
        color["y"] = round(a["current_y"] / 65535, 4)
    if _num(a.get("current_hue")):
        color["hue"] = round(a["current_hue"] * 360 / 254, 1)
    if _num(a.get("current_saturation")):
        color["saturation"] = round(a["current_saturation"] * 100 / 254, 1)
    if color:
        out["color"] = color
    if _num(a.get("color_temperature_mireds")):
        out["color_temp"] = a["color_temperature_mireds"]
    if _num(a.get("color_mode")):
        out["color_mode"] = COLOR_MODE.get(a["color_mode"], f"unknown_{a['color_mode']}")
    return out


def _dec_temperature(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("measured_value")
    return {"temperature": round(v / 100, 2)} if _num(v) else {}


def _dec_pressure(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("measured_value")
    return {"pressure": v} if _num(v) else {}


def _dec_humidity(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("measured_value")
    return {"humidity": round(v / 100, 2)} if _num(v) else {}


def _dec_illuminance(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("measured_value")
    if not _num(v):
        return {}
    out: dict[str, Any] = {"illuminance": v}
    # ZCL: MeasuredValue = 10000 × log10(Illuminance) + 1 ; 0 means "too low to measure"
    out["illuminance_lux"] = 0.0 if v == 0 else round(10 ** ((v - 1) / 10000), 2)
    return out


def _dec_occupancy(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("occupancy")
    return {"occupancy": bool(v & 0x01)} if _num(v) else {}


def _dec_ias_zone(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if _num(a.get("zone_type")):
        ctx["zone_type"] = a["zone_type"]
        out["zone_type"] = IAS_ZONE_TYPE.get(a["zone_type"], f"unknown_0x{a['zone_type']:04x}")
    if _num(a.get("zone_state")):
        out["enrolled"] = a["zone_state"] == 1
    if _num(a.get("zone_status")):
        out.update(ias_zone_status_to_state(a["zone_status"], ctx.get("zone_type")))
    if _num(a.get("ias_cie_address")):
        out["ias_cie_address"] = f"0x{a['ias_cie_address']:016x}"
    return out


def _dec_electrical(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    for k in (
        "ac_voltage_multiplier",
        "ac_voltage_divisor",
        "ac_current_multiplier",
        "ac_current_divisor",
        "ac_power_multiplier",
        "ac_power_divisor",
    ):
        if _num(a.get(k)):
            ctx[k] = a[k]
    out: dict[str, Any] = {}
    if _num(a.get("rms_voltage")):
        r = _ratio(ctx, "ac_voltage_multiplier", "ac_voltage_divisor", 1, 1)
        out["voltage"] = round(a["rms_voltage"] * r, 2)
    if _num(a.get("rms_current")):
        r = _ratio(ctx, "ac_current_multiplier", "ac_current_divisor", 1, 1000)
        out["current"] = round(a["rms_current"] * r, 3)
    if _num(a.get("active_power")):
        r = _ratio(ctx, "ac_power_multiplier", "ac_power_divisor", 1, 1)
        out["power"] = round(a["active_power"] * r, 2)
    return out


def _dec_metering(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    for k in ("multiplier", "divisor"):
        if _num(a.get(k)):
            ctx[k] = a[k]
    out: dict[str, Any] = {}
    r = _ratio(ctx, "multiplier", "divisor", 1, 1000)
    if _num(a.get("current_summation_delivered")):
        out["energy"] = round(a["current_summation_delivered"] * r, 3)  # kWh
    if _num(a.get("instantaneous_demand")):
        out["power"] = round(a["instantaneous_demand"] * r * 1000, 2)  # kW → W
    return out


def _dec_window_covering(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    v = a.get("current_position_lift_percentage")
    if _num(v):
        out["position"] = 100 - max(0, min(100, int(v)))  # ZCL 100 = fully closed
    v = a.get("current_position_tilt_percentage")
    if _num(v):
        out["tilt"] = 100 - max(0, min(100, int(v)))
    return out


def _dec_thermostat(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if _num(a.get("local_temperature")) and a["local_temperature"] != -0x8000:
        out["local_temperature"] = round(a["local_temperature"] / 100, 2)
    if _num(a.get("occupied_heating_setpoint")):
        out["current_heating_setpoint"] = round(a["occupied_heating_setpoint"] / 100, 2)
    if _num(a.get("occupied_cooling_setpoint")):
        out["current_cooling_setpoint"] = round(a["occupied_cooling_setpoint"] / 100, 2)
    if _num(a.get("system_mode")):
        out["system_mode"] = SYSTEM_MODE.get(a["system_mode"], f"unknown_{a['system_mode']}")
    if _num(a.get("running_state")):
        out["running_state"] = "heat" if a["running_state"] & 0x01 else ("cool" if a["running_state"] & 0x02 else "idle")
    # Capabilities and limits are remembered in the device context so the feature layer can offer
    # a cooling setpoint and the right mode list (an air conditioner is not a radiator valve).
    if _num(a.get("control_sequence")):
        ctx["thermostat_sequence"] = int(a["control_sequence"])
    for name, key in (("min_heat_setpoint_limit", "heat_setpoint_min"), ("max_heat_setpoint_limit", "heat_setpoint_max"),
                      ("min_cool_setpoint_limit", "cool_setpoint_min"), ("max_cool_setpoint_limit", "cool_setpoint_max")):
        if _num(a.get(name)):
            ctx[key] = round(a[name] / 100, 2)
    return out


def _dec_fan(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if _num(a.get("fan_mode")):
        out["fan_mode"] = FAN_MODE.get(a["fan_mode"], f"unknown_{a['fan_mode']}")
    if _num(a.get("fan_mode_sequence")):
        ctx["fan_mode_sequence"] = int(a["fan_mode_sequence"])
    return out


def _dec_groups(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("name_support")
    return {"group_name_support": bool(v & 0x80)} if _num(v) else {}


LOCK_STATE = {0: "not_fully_locked", 1: "locked", 2: "unlocked"}


def _dec_door_lock(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    v = a.get("lock_state")
    if _num(v):
        out["lock_state"] = LOCK_STATE.get(v, f"unknown_{v}")
        if v in (1, 2):
            out["state"] = "LOCK" if v == 1 else "UNLOCK"
    v = a.get("door_state")
    if _num(v):
        out["door_state"] = {0: "open", 1: "closed", 2: "error_jammed", 3: "error_forced_open", 4: "error_unspecified"}.get(v, f"unknown_{v}")
    return out


def _dec_binary(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("present_value")
    return {"present_value": bool(v)} if isinstance(v, (bool, int)) else {}


def _dec_multistate(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("present_value")
    return {"present_value": v} if _num(v) else {}


def _dec_analog(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    v = a.get("present_value")
    return {"present_value": round(v, 3)} if _num(v) else {}


def _dec_concentration(key: str) -> Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]:
    def dec(a: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        v = a.get("measured_value")
        return {key: round(v, 1)} if _num(v) else {}
    return dec


# ---------------------------------------------------------------------------
# Cluster table
# ---------------------------------------------------------------------------


def _transition() -> CommandParam:
    return CommandParam("transition_time", U16, 0)  # 1/10 s


def _make_clusters() -> dict[int, Cluster]:
    clusters: list[Cluster] = []

    clusters.append(
        Cluster(
            0x0000,
            "basic",
            _attrs(
                (0x0000, "zcl_version", U8),
                (0x0001, "app_version", U8),
                (0x0002, "stack_version", U8),
                (0x0003, "hw_version", U8),
                (0x0004, "manufacturer_name", STR),
                (0x0005, "model_id", STR),
                (0x0006, "date_code", STR),
                (0x0007, "power_source", E8),
                (0x4000, "sw_build_id", STR),
            ),
            *_cmds(CommandDef(0x00, "reset_to_factory_defaults")),
            decoder=_dec_basic,
        )
    )

    clusters.append(
        Cluster(
            0x0001,
            "power_configuration",
            _attrs(
                (0x0020, "battery_voltage", U8),
                (0x0021, "battery_percentage_remaining", U8),
            ),
            decoder=_dec_power_cfg,
        )
    )

    ids, defs = _cmds(
        CommandDef(0x00, "identify", (CommandParam("time", U16, 10),)),
        CommandDef(0x01, "identify_query"),
        CommandDef(0x40, "trigger_effect", (CommandParam("effect", U8, 0), CommandParam("variant", U8, 0))),
    )
    clusters.append(
        Cluster(
            0x0003,
            "identify",
            _attrs((0x0000, "identify_time", U16, True)),
            ids,
            {0x00: "identify_query_response"},
            defs,
            decoder=_dec_identify,
        )
    )

    clusters.append(
        Cluster(
            0x0004,
            "groups",
            _attrs((0x0000, "name_support", B8)),
            decoder=_dec_groups,
        )
    )

    ids, defs = _cmds(CommandDef(0x00, "off"), CommandDef(0x01, "on"), CommandDef(0x02, "toggle"))
    clusters.append(
        Cluster(0x0006, "on_off", _attrs((0x0000, "on_off", BOOL), (0x4001, "on_time", DataType.uint16), (0x4002, "off_wait_time", DataType.uint16), (0x4003, "start_up_on_off", DataType.enum8)), ids, {}, defs, decoder=_dec_on_off)
    )

    ids, defs = _cmds(
        CommandDef(0x00, "move_to_level", (CommandParam("level", U8), _transition())),
        CommandDef(0x01, "move", (CommandParam("mode", U8), CommandParam("rate", U8))),
        CommandDef(0x02, "step", (CommandParam("mode", U8), CommandParam("step_size", U8), _transition())),
        CommandDef(0x03, "stop"),
        CommandDef(0x04, "move_to_level_with_on_off", (CommandParam("level", U8), _transition())),
        CommandDef(0x05, "move_with_on_off", (CommandParam("mode", U8), CommandParam("rate", U8))),
        CommandDef(0x06, "step_with_on_off", (CommandParam("mode", U8), CommandParam("step_size", U8), _transition())),
        CommandDef(0x07, "stop_with_on_off"),
    )
    clusters.append(
        Cluster(
            0x0008,
            "level_control",
            _attrs((0x0000, "current_level", U8), (0x0011, "on_level", U8, True)),
            ids,
            {},
            defs,
            decoder=_dec_level,
        )
    )

    clusters.append(Cluster(0x000A, "time"))
    clusters.append(Cluster(0x0019, "ota"))

    ids, defs = _cmds(
        CommandDef(0x00, "up_open"),
        CommandDef(0x01, "down_close"),
        CommandDef(0x02, "stop"),
        CommandDef(0x05, "go_to_lift_percentage", (CommandParam("percentage", U8),)),
        CommandDef(0x08, "go_to_tilt_percentage", (CommandParam("percentage", U8),)),
    )
    clusters.append(
        Cluster(
            0x0102,
            "window_covering",
            _attrs(
                (0x0000, "window_covering_type", E8),
                (0x0008, "current_position_lift_percentage", U8),
                (0x0009, "current_position_tilt_percentage", U8),
            ),
            ids,
            {},
            defs,
            decoder=_dec_window_covering,
        )
    )

    ids, defs = _cmds(
        CommandDef(
            0x00,
            "setpoint_raise_lower",
            (CommandParam("mode", E8, 0), CommandParam("amount", DataType.int8)),
        ),
    )
    clusters.append(
        Cluster(
            0x0201,
            "thermostat",
            _attrs(
                (0x0000, "local_temperature", I16),
                (0x0011, "occupied_cooling_setpoint", I16, True),
                (0x0012, "occupied_heating_setpoint", I16, True),
                (0x0015, "min_heat_setpoint_limit", I16),
                (0x0016, "max_heat_setpoint_limit", I16),
                (0x0017, "min_cool_setpoint_limit", I16),
                (0x0018, "max_cool_setpoint_limit", I16),
                (0x001B, "control_sequence", E8),
                (0x001C, "system_mode", E8, True),
                (0x0029, "running_state", B16),
            ),
            ids,
            {},
            defs,
            decoder=_dec_thermostat,
        )
    )

    ids, defs = _cmds(
        CommandDef(0x00, "move_to_hue", (CommandParam("hue", U8), CommandParam("direction", E8, 0), _transition())),
        CommandDef(0x03, "move_to_saturation", (CommandParam("saturation", U8), _transition())),
        CommandDef(
            0x06,
            "move_to_hue_and_saturation",
            (CommandParam("hue", U8), CommandParam("saturation", U8), _transition()),
        ),
        CommandDef(0x07, "move_to_color", (CommandParam("x", U16), CommandParam("y", U16), _transition())),
        CommandDef(0x0A, "move_to_color_temp", (CommandParam("color_temp", U16), _transition())),
    )
    clusters.append(
        Cluster(
            0x0300,
            "color_control",
            _attrs(
                (0x0000, "current_hue", U8),
                (0x0001, "current_saturation", U8),
                (0x0003, "current_x", U16),
                (0x0004, "current_y", U16),
                (0x0007, "color_temperature_mireds", U16),
                (0x0008, "color_mode", E8),
                (0x400B, "color_temp_physical_min", U16),
                (0x400C, "color_temp_physical_max", U16),
            ),
            ids,
            {},
            defs,
            decoder=_dec_color,
        )
    )

    clusters.append(
        Cluster(
            0x0400,
            "illuminance_measurement",
            _attrs((0x0000, "measured_value", U16), (0x0001, "min_measured_value", U16), (0x0002, "max_measured_value", U16)),
            decoder=_dec_illuminance,
        )
    )
    clusters.append(
        Cluster(
            0x0402,
            "temperature_measurement",
            _attrs((0x0000, "measured_value", I16), (0x0001, "min_measured_value", I16), (0x0002, "max_measured_value", I16)),
            decoder=_dec_temperature,
        )
    )
    clusters.append(
        Cluster(
            0x0403,
            "pressure_measurement",
            _attrs((0x0000, "measured_value", I16), (0x0001, "min_measured_value", I16), (0x0002, "max_measured_value", I16)),
            decoder=_dec_pressure,
        )
    )
    clusters.append(
        Cluster(
            0x0405,
            "relative_humidity",
            _attrs((0x0000, "measured_value", U16), (0x0001, "min_measured_value", U16), (0x0002, "max_measured_value", U16)),
            decoder=_dec_humidity,
        )
    )
    clusters.append(
        Cluster(
            0x0406,
            "occupancy_sensing",
            _attrs((0x0000, "occupancy", B8), (0x0001, "occupancy_sensor_type", E8)),
            decoder=_dec_occupancy,
        )
    )

    ids, defs = _cmds(
        CommandDef(
            0x00,
            "zone_enroll_response",
            (CommandParam("enroll_response_code", E8, 0), CommandParam("zone_id", U8, 0)),
        ),
    )
    srv_ids, srv_defs = _cmds(
        CommandDef(
            0x00,
            "zone_status_change_notification",
            (
                CommandParam("zone_status", B16),
                CommandParam("extended_status", B8, 0),
                CommandParam("zone_id", U8, 0),
                CommandParam("delay", U16, 0),
            ),
        ),
        CommandDef(0x01, "zone_enroll_request", (CommandParam("zone_type", E16), CommandParam("manufacturer", U16, 0))),
    )
    clusters.append(
        Cluster(
            0x0500,
            "ias_zone",
            _attrs(
                (0x0000, "zone_state", E8),
                (0x0001, "zone_type", E16),
                (0x0002, "zone_status", B16),
                (0x0010, "ias_cie_address", DataType.eui64, True),
                (0x0011, "zone_id", U8),
            ),
            ids,
            srv_ids,
            defs,
            srv_defs,
            decoder=_dec_ias_zone,
        )
    )

    clusters.append(
        Cluster(
            0x0702,
            "metering",
            _attrs(
                (0x0000, "current_summation_delivered", DataType.uint48),
                (0x0300, "unit_of_measure", E8),
                (0x0301, "multiplier", DataType.uint24),
                (0x0302, "divisor", DataType.uint24),
                (0x0303, "summation_formatting", B8),
                (0x0306, "metering_device_type", B8),
                (0x0400, "instantaneous_demand", DataType.int24),
            ),
            decoder=_dec_metering,
        )
    )

    clusters.append(
        Cluster(
            0x0B04,
            "electrical_measurement",
            _attrs(
                (0x0000, "measurement_type", DataType.bitmap32),
                (0x0505, "rms_voltage", U16),
                (0x0508, "rms_current", U16),
                (0x050B, "active_power", I16),
                (0x0600, "ac_voltage_multiplier", U16),
                (0x0601, "ac_voltage_divisor", U16),
                (0x0602, "ac_current_multiplier", U16),
                (0x0603, "ac_current_divisor", U16),
                (0x0604, "ac_power_multiplier", U16),
                (0x0605, "ac_power_divisor", U16),
            ),
            decoder=_dec_electrical,
        )
    )

    clusters.append(Cluster(0x0005, "scenes", _attrs((0x0000, "scene_count", U8), (0x0001, "current_scene", U8), (0x0002, "current_group", U16))))
    clusters.append(Cluster(0x000F, "binary_input", _attrs((0x0004, "active_text", STR), (0x001C, "description", STR), (0x002E, "inactive_text", STR),
                                                          (0x0051, "out_of_service", BOOL), (0x0055, "present_value", BOOL), (0x006F, "status_flags", B8)), decoder=_dec_binary))
    clusters.append(Cluster(0x000C, "analog_input", _attrs((0x001C, "description", STR), (0x0055, "present_value", DataType.single)), decoder=_dec_analog))
    clusters.append(Cluster(0x000D, "analog_output", _attrs((0x001C, "description", STR), (0x0055, "present_value", DataType.single, True)), decoder=_dec_analog))
    clusters.append(Cluster(0x0012, "multistate_input", _attrs((0x001C, "description", STR), (0x0055, "present_value", U16)), decoder=_dec_multistate))
    clusters.append(Cluster(0x0020, "poll_control", _attrs((0x0000, "check_in_interval", DataType.uint32, True), (0x0003, "short_poll_interval", U16))))

    ids, defs = _cmds(
        CommandDef(0x00, "lock_door", (CommandParam("pin_code", DataType.octstr, b""),)),
        CommandDef(0x01, "unlock_door", (CommandParam("pin_code", DataType.octstr, b""),)),
        CommandDef(0x02, "toggle", (CommandParam("pin_code", DataType.octstr, b""),)),
    )
    clusters.append(
        Cluster(
            0x0101,
            "door_lock",
            _attrs((0x0000, "lock_state", E8), (0x0001, "lock_type", E8), (0x0002, "actuator_enabled", BOOL), (0x0003, "door_state", E8),
                   (0x0055, "present_value", U16)),  # 0x0055 is what some vibration sensors misuse this cluster for
            ids,
            {0x20: "operation_event_notification", 0x21: "programming_event_notification"},
            defs,
            decoder=_dec_door_lock,
        )
    )
    clusters.append(Cluster(0x0202, "fan_control", _attrs((0x0000, "fan_mode", E8, True), (0x0001, "fan_mode_sequence", E8)), decoder=_dec_fan))
    clusters.append(Cluster(0x0204, "thermostat_ui", _attrs((0x0000, "temperature_display_mode", E8, True), (0x0001, "keypad_lockout", E8, True))))
    clusters.append(Cluster(0x040D, "carbon_dioxide", _attrs((0x0000, "measured_value", DataType.single)), decoder=_dec_concentration("co2")))
    clusters.append(Cluster(0x042A, "pm25", _attrs((0x0000, "measured_value", DataType.single)), decoder=_dec_concentration("pm25")))
    clusters.append(Cluster(0x0B05, "diagnostics"))
    clusters.append(Cluster(0xE000, "tuya_private_e000"))
    clusters.append(Cluster(0xE001, "tuya_private_e001"))
    clusters.append(Cluster(0xEF00, "tuya_datapoints", {}, {0x00: "set_data", 0x03: "query_data"}, {0x01: "data_response", 0x02: "data_report", 0x06: "status_report"}))
    clusters.append(Cluster(0xFC00, "philips_private", {}, {}, {0x00: "button_event"}))
    clusters.append(Cluster(0xFC02, "samjin_private", _attrs((0x0010, "acceleration", B8), (0x0012, "x_axis", I16), (0x0013, "y_axis", I16), (0x0014, "z_axis", I16))))
    clusters.append(Cluster(0xFC11, "sonoff_private"))
    clusters.append(Cluster(0xFC7C, "ikea_private"))
    clusters.append(Cluster(0xFCC0, "lumi_private", _attrs((0x00F7, "lumi_report", DataType.octstr), (0x0201, "power_outage_memory", BOOL, True))))

    return {c.id: c for c in clusters}


CLUSTERS: dict[int, Cluster] = _make_clusters()
CLUSTERS_BY_NAME: dict[str, Cluster] = {c.name: c for c in CLUSTERS.values()}


def cluster_name(cluster_id: int) -> str:
    c = CLUSTERS.get(cluster_id)
    return c.name if c else f"cluster_0x{cluster_id:04x}"


def get_cluster(cluster: int | str) -> Cluster | None:
    if isinstance(cluster, str):
        return CLUSTERS_BY_NAME.get(cluster)
    return CLUSTERS.get(cluster)


# ---------------------------------------------------------------------------
# Converter API
# ---------------------------------------------------------------------------


def decode_attributes(
    cluster_id: int,
    pairs: list[tuple[int, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert raw ``(attr_id, value)`` pairs into JSON state.

    Unknown clusters/attributes are exposed as ``"<cluster>_0x<attr>"`` keys
    when the value is a JSON-friendly scalar so nothing is silently lost.
    """
    ctx = context if context is not None else {}
    cluster = CLUSTERS.get(cluster_id)
    named: dict[str, Any] = {}
    extra: dict[str, Any] = {}
    for attr_id, value in pairs:
        a = cluster.attributes.get(attr_id) if cluster else None
        if a is not None:
            named[a.name] = value
        elif isinstance(value, (int, float, str, bool)) or value is None:
            extra[f"{cluster_name(cluster_id)}_0x{attr_id:04x}"] = value
    out: dict[str, Any] = {}
    if cluster and cluster.decoder:
        out.update(cluster.decoder(named, ctx))
    else:
        out.update(named)
    out.update(extra)
    return out


def _coerce_param(cluster_id: int, cmd: str, p: CommandParam, params: dict[str, Any]) -> Any:
    if p.name in params:
        v = params[p.name]
    elif p.default is not None:
        v = p.default
    else:
        raise ValueError(f"{cluster_name(cluster_id)}.{cmd}: missing parameter '{p.name}'")

    # Friendly conversions
    if cluster_id == 0x0300 and p.name in ("x", "y") and isinstance(v, float):
        v = int(round(max(0.0, min(1.0, v)) * 65535))
    if cluster_id == 0x0300 and cmd == "move_to_color_temp" and p.name == "color_temp" and isinstance(v, float):
        v = int(round(v))
    if p.name == "transition_time" and isinstance(v, float):
        v = int(round(v))  # already in 1/10 s; float given → round
    if cluster_id == 0x0201 and p.name == "mode" and isinstance(v, str):
        v = SYSTEM_MODE_BY_NAME[v]
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, float) and p.dtype not in (DataType.single, DataType.double, DataType.semi):
        v = int(round(v))
    return v


def encode_command(
    cluster_id: int,
    name: str,
    params: dict[str, Any] | None = None,
    *,
    direction: int = DIRECTION_CLIENT_TO_SERVER,
) -> tuple[int, bytes]:
    """Build ``(command_id, payload)`` for a cluster-specific command by name."""
    params = params or {}
    cluster = CLUSTERS.get(cluster_id)
    if cluster is None:
        raise ValueError(f"unknown cluster 0x{cluster_id:04x}")
    defs = cluster.command_defs if direction == DIRECTION_CLIENT_TO_SERVER else cluster.server_command_defs
    d = defs.get(name)
    if d is None:
        raise ValueError(f"unknown command '{name}' for cluster {cluster.name}")
    out = bytearray()
    for p in d.params:
        out += encode_value(p.dtype, _coerce_param(cluster_id, name, p, params))
    return d.id, bytes(out)


def decode_cluster_command(
    cluster_id: int,
    cmd: int,
    direction: int,
    payload: bytes,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Decode a cluster-specific command payload into a dict.

    The result always contains ``"command"`` (name or ``"cmd_0x.."``) and the
    decoded parameters; for IAS zone status notifications it additionally
    contains the derived state (``contact``/``occupancy``/...) using the zone
    type remembered in ``context`` (key ``zone_type``) if available.
    """
    ctx = context if context is not None else {}
    cluster = CLUSTERS.get(cluster_id)
    out: dict[str, Any] = {"cluster": cluster_name(cluster_id), "command": f"cmd_0x{cmd:02x}"}
    if cluster is None:
        out["payload"] = payload.hex()
        return out
    defs = cluster.server_command_defs if direction == DIRECTION_SERVER_TO_CLIENT else cluster.command_defs
    d = next((x for x in defs.values() if x.id == cmd), None)
    if d is None:
        out["payload"] = payload.hex()
        return out
    out["command"] = d.name
    offset = 0
    for p in d.params:
        try:
            value, offset = decode_value(p.dtype, payload, offset)
        except ZclDecodeError:
            if p.default is None:
                out["truncated"] = True
            value = p.default
        out[p.name] = value

    if cluster_id == 0x0500:
        if d.name == "zone_status_change_notification" and isinstance(out.get("zone_status"), int):
            out.update(ias_zone_status_to_state(out["zone_status"], ctx.get("zone_type")))
        elif d.name == "zone_enroll_request" and isinstance(out.get("zone_type"), int):
            ctx["zone_type"] = out["zone_type"]
            out["zone_type_name"] = IAS_ZONE_TYPE.get(out["zone_type"], f"unknown_0x{out['zone_type']:04x}")
        elif d.name == "zone_enroll_response" and isinstance(out.get("enroll_response_code"), int):
            out["enroll_response"] = IAS_ENROLL_RESPONSE_CODE.get(out["enroll_response_code"], "unknown")
    return out


__all__ = [
    "Attribute",
    "CommandParam",
    "CommandDef",
    "Cluster",
    "CLUSTERS",
    "CLUSTERS_BY_NAME",
    "cluster_name",
    "get_cluster",
    "decode_attributes",
    "encode_command",
    "decode_cluster_command",
    "ias_zone_status_to_state",
    "IAS_ZONE_TYPE",
    "SYSTEM_MODE",
    "CONTROL_SEQUENCE_COOLING",
    "CONTROL_SEQUENCE_HEATING",
    "FAN_MODE",
    "FAN_MODE_BY_NAME",
    "FAN_MODES",
    "POWER_SOURCE",
    "COLOR_MODE",
    "LOCK_STATE",
]
