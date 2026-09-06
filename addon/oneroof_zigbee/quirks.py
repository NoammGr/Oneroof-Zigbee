"""Model knowledge: what a device *is* and how it deviates from the plain ZCL.

The generic layer (``features.generic_features``, ``zcl.profile.classify``)
derives controls from the clusters a device advertises.  That is right for
well-behaved Zigbee 3.0 products and wrong for the rest: an Aqara door sensor
reports contact through the On/Off cluster and would show up as a switchable
plug; a Tuya TS0601 hides everything behind datapoints; IKEA remotes *send*
on/off commands instead of reporting anything; sleepy Aqara sensors reject
binds.

This module holds a declarative table keyed by (manufacturer pattern, model
pattern) → :class:`Quirk`.  A quirk says

* what the device is (``kind``, ``vendor``, ``category``),
* which generic features to drop, add or re-label,
* how to read the On/Off attribute (``on_off_as``: contact / occupancy / action …),
* the names of multi-gang endpoints (``gangs``),
* which clusters may be bound (``bind``; ``()`` = never bind, the device rejects it),
* how to interpret the vendor's private reports (Aqara tags, Tuya datapoints,
  multistate buttons, analog inputs, remote commands).

Unknown models fall back to the cluster heuristics with a device-level kind.
Two things sit in front of / behind this table: user definitions
(``definitions.py``, installed with :func:`set_definitions`) are consulted
first by :func:`find_quirk`; Tuya datapoint devices without any map get their
features inferred from what they reported (``quirks_tuya.py``, via
:func:`tuya_dps`).

Rule of thumb for entries: *precision beats breadth*.  Every line claims only
what the model does; anything uncertain is left to the generic layer.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Callable

from .devices import Device
from .zcl import vendor as vz
from .zcl.types import DataType

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

Conv = Callable[[Any], Any]


@dataclass(frozen=True)
class Dp:
    """One Tuya datapoint as a feature."""

    dp: int
    key: str
    name: str
    type: str = "numeric"            # numeric | binary | enum | text
    access: str = "r"
    scale: float = 1.0               # reported value / scale
    values: dict[int, str] | None = None   # enum id → label (or bool → label for binary)
    unit: str | None = None
    category: str = "sensor"
    icon: str = "sliders"
    dtype: int = vz.TUYA_VALUE       # wire type used when writing
    min: float | None = None
    max: float | None = None
    step: float | None = None
    description: str = ""
    inverted: bool = False           # binary: swap true/false; numeric: publish 100 − value (percent positions)
    device_class: str | None = None  # Home Assistant device class override
    inferred: bool = False           # guessed from Tuya conventions, not from a model table


@dataclass(frozen=True)
class PrivateAttr:
    """One attribute of a device-specific cluster, known from the model table. Read and written as a
    *standard* attribute (no manufacturer code) with exactly this wire type."""

    attr: int
    key: str
    dtype: DataType
    scale: float = 1.0                     # published value = wire value / scale
    values: dict[Any, str] | None = None   # wire value → label (bool → "ON"/"OFF", enum id → name)
    max_len: int = 31                      # strings: the device's limit


@dataclass(frozen=True)
class Quirk:
    vendor: str
    kind: str
    category: str                                   # light plug switch sensor remote cover climate lock meter
    manufacturer: tuple[str, ...]                   # fnmatch patterns (case-insensitive)
    model: tuple[str, ...]
    description: str = ""
    on_off_as: str | None = None                    # On/Off attr 0 → read-only key (contact, occupancy, water_leak, action …)
    remove: tuple[str, ...] = ()                    # generic base keys to drop
    add: tuple[dict[str, Any], ...] = ()            # extra feature dicts (see features._f)
    gangs: tuple[str, ...] | None = None            # endpoint suffixes for multi-gang on/off in endpoint order
    gang_labels: tuple[str, ...] | None = None
    bind: tuple[int, ...] | None = None             # None → default; () → never bind/configure reporting
    lumi_tags: dict[int, tuple[str, Any]] = field(default_factory=dict)   # Aqara tag → (key, divisor | callable)
    multistate: dict[int, str] = field(default_factory=dict)              # endpoint → button name for multistate actions
    analog: dict[int, str] = field(default_factory=dict)                  # endpoint → key for analog input 0x000C / output 0x000D
    dps: tuple[Dp, ...] = ()
    cover_inverted: bool = False
    illuminance_linear: bool = False               # measured value is lux, not 10000·log10(lux)+1
    ias_key: str | None = None                      # override the IAS zone state key (e.g. "gas")
    ias_class: str | None = None                    # HA device class for ias_key
    actions: tuple[str, ...] = ()                   # documented action values
    action_map: dict[str, str] = field(default_factory=dict)   # generic action → model-specific name
    buttons: int = 0                                # Tuya-style buttons: 1 → no endpoint prefix in actions
    tuya_onoff_attrs: bool = False                  # child_lock/indicator_mode on On/Off attrs 0x8000/0x8001
    user_defined: bool = False                      # compiled from definitions.yaml rather than this table
    relabel: dict[tuple[int, str], dict[str, Any]] = field(default_factory=dict)   # (endpoint, base) → feature overrides (key, name, icon …)
    single_setpoint: bool = False                   # cooling and heating setpoints are one target temperature (air conditioners)
    private_attrs: dict[int, tuple[PrivateAttr, ...]] = field(default_factory=dict)  # device-specific cluster → its attributes
    reporting: dict[int, tuple[tuple[int, DataType, int, int, Any], ...]] = field(default_factory=dict)  # extra reporting: cluster → (attr, dtype, min, max, change)
    read_on_join: dict[int, tuple[int, ...]] = field(default_factory=dict)         # extra attributes to read at interview: cluster → attrs
    context_defaults: dict[str, Any] = field(default_factory=dict)                  # converter context the model is known to have (before any read)

    def matches(self, manufacturer: str | None, model: str | None) -> bool:
        m = (manufacturer or "").strip().lower()
        d = (model or "").strip().lower()
        return any(fnmatch.fnmatchcase(m, p.lower()) for p in self.manufacturer) and any(fnmatch.fnmatchcase(d, p.lower()) for p in self.model)


def _q(vendor: str, kind: str, category: str, manufacturer: str | tuple[str, ...], model: str | tuple[str, ...], **kw: Any) -> Quirk:
    mf = (manufacturer,) if isinstance(manufacturer, str) else tuple(manufacturer)
    md = (model,) if isinstance(model, str) else tuple(model)
    return Quirk(vendor, kind, category, mf, md, **kw)


def _f(key: str, name: str, description: str, type_: str, access: str, *, icon: str, category: str,
       endpoint: int = 1, cluster: int = 0, **extra: Any) -> dict[str, Any]:
    return {"key": key, "name": name, "description": description, "type": type_, "access": access, "icon": icon,
            "category": category, "endpoint": endpoint, "cluster": cluster, "base": key, **extra}


# Re-usable feature definitions -------------------------------------------

def _battery(ep: int = 1) -> dict[str, Any]:
    return _f("battery", "Battery", "Remaining battery", "numeric", "r", icon="battery", category="diagnostic", endpoint=ep, cluster=0x0001, unit="%", min=0, max=100)


def _voltage_mv(ep: int = 1) -> dict[str, Any]:
    return _f("voltage", "Battery voltage", "Battery voltage in mV", "numeric", "r", icon="battery", category="diagnostic", endpoint=ep, cluster=0x0000, unit="mV")


def _device_temperature(ep: int = 1) -> dict[str, Any]:
    return _f("device_temperature", "Device temperature", "Temperature inside the device", "numeric", "r", icon="thermometer", category="diagnostic", endpoint=ep, cluster=0x0000, unit="°C")


def _power_outage_count(ep: int = 1) -> dict[str, Any]:
    return _f("power_outage_count", "Power outages", "Number of power outages seen by the device", "numeric", "r", icon="bolt", category="diagnostic", endpoint=ep, cluster=0x0000)


def _action(values: tuple[str, ...], ep: int = 1, description: str = "Last button event") -> dict[str, Any]:
    return _f("action", "Action", description, "enum", "r", icon="hand", category="sensor", endpoint=ep, cluster=0, values=list(values))


def _binary_sensor(key: str, name: str, description: str, ep: int = 1, cluster: int = 0, category: str = "sensor", icon: str = "shield") -> dict[str, Any]:
    return _f(key, name, description, "binary", "r", icon=icon, category=category, endpoint=ep, cluster=cluster, value_on=True, value_off=False)


def _numeric_sensor(key: str, name: str, description: str, unit: str | None, ep: int = 1, cluster: int = 0, icon: str = "gauge", category: str = "sensor") -> dict[str, Any]:
    return _f(key, name, description, "numeric", "r", icon=icon, category=category, endpoint=ep, cluster=cluster, unit=unit)


_LUMI_SENSOR_EXTRAS = (_voltage_mv(), _device_temperature(), _power_outage_count())
_LUMI_CLICK_ACTIONS = ("single", "double", "triple", "quadruple", "hold", "release", "shake")
_LUMI_TWO_BUTTON_ACTIONS = tuple(f"{c}_{b}" for b in ("left", "right", "both") for c in ("single", "double", "hold"))
_TUYA_1_BUTTON = ("single", "double", "hold")
_TUYA_N_BUTTON = lambda n: tuple(f"{i}_{c}" for i in range(1, n + 1) for c in ("single", "double", "hold"))  # noqa: E731
_IKEA_5_BUTTON = ("toggle", "toggle_hold", "brightness_up_click", "brightness_down_click", "brightness_up_hold", "brightness_down_hold",
                  "brightness_up_release", "brightness_down_release", "arrow_left_click", "arrow_right_click", "arrow_left_hold",
                  "arrow_right_hold", "arrow_left_release", "arrow_right_release")
_IKEA_ON_OFF = ("on", "off", "brightness_move_up", "brightness_move_down", "brightness_stop")
_IKEA_STYRBAR = _IKEA_ON_OFF + ("arrow_left_click", "arrow_right_click", "arrow_left_hold", "arrow_right_hold", "arrow_left_release", "arrow_right_release")
_IKEA_SOMRIG = tuple(f"{i}_{c}" for i in (1, 2) for c in ("initial_press", "long_press", "short_release", "long_release", "double_press"))
_HUE_DIMMER = tuple(f"{b}_{t}" for b in ("on", "up", "down", "off") for t in ("press", "hold", "press_release", "hold_release"))
_GENERIC_REMOTE = ("on", "off", "toggle", "brightness_move_up", "brightness_move_down", "brightness_stop", "brightness_step_up", "brightness_step_down",
                   "color_temperature_step_up", "color_temperature_step_down", "color_temperature_move_up", "color_temperature_move_down", "color_temperature_move_stop")
_IKEA_5_MAP = {"brightness_step_up": "brightness_up_click", "brightness_step_down": "brightness_down_click",
               "brightness_move_up": "brightness_up_hold", "brightness_move_down": "brightness_down_hold"}

_SENSOR_CONTROLS = ("state", "power_on_behavior", "countdown", "brightness", "color_temp", "color", "identify")
_LOCK_REMOVE = ("power_on_behavior", "countdown", "brightness", "color_temp", "color")
_PLUG_TIMERS = ("countdown",)
_AQARA_MAINS_REMOVE = ("power_on_behavior", "countdown")

# ---------------------------------------------------------------------------
# Tuya datapoint maps (TS0601).  dp numbers are vendor-defined per product family.
# ---------------------------------------------------------------------------

_DP_TEMP_HUM = (
    Dp(1, "temperature", "Temperature", scale=10, unit="°C", icon="thermometer"),
    Dp(2, "humidity", "Humidity", unit="%", icon="drop"),
    Dp(4, "battery", "Battery", unit="%", icon="battery", category="diagnostic", min=0, max=100),
)
_DP_TEMP_HUM_DIV10 = (
    Dp(1, "temperature", "Temperature", scale=10, unit="°C", icon="thermometer"),
    Dp(2, "humidity", "Humidity", scale=10, unit="%", icon="drop"),
    Dp(4, "battery", "Battery", unit="%", icon="battery", category="diagnostic", min=0, max=100),
)
_TRV_PRESET = {0: "schedule", 1: "manual", 2: "boost", 3: "complex", 4: "comfort", 5: "eco"}
_DP_TRV_CKUD = (
    Dp(2, "current_heating_setpoint", "Heating setpoint", access="rw", scale=10, unit="°C", icon="thermometer", category="control", min=5, max=35, step=0.5),
    Dp(3, "local_temperature", "Local temperature", scale=10, unit="°C", icon="thermometer"),
    Dp(4, "preset", "Preset", type="enum", access="rw", values=_TRV_PRESET, icon="sliders", category="control", dtype=vz.TUYA_ENUM),
    Dp(7, "child_lock", "Child lock", type="binary", access="rw", values={0: "UNLOCK", 1: "LOCK"}, icon="lock", category="config", dtype=vz.TUYA_BOOL),
    Dp(18, "window_detection", "Window detection", type="binary", access="rw", values={0: "OFF", 1: "ON"}, icon="shield", category="config", dtype=vz.TUYA_BOOL),
    Dp(44, "local_temperature_calibration", "Temperature calibration", access="rw", scale=10, unit="°C", icon="thermometer", category="config", min=-9, max=9, step=0.5),
    Dp(109, "position", "Valve position", unit="%", icon="gauge", min=0, max=100),
)
_DP_TRV_BRT100 = (
    Dp(1, "preset", "Preset", type="enum", access="rw", values={0: "programming", 1: "manual", 2: "temporary_manual", 3: "holiday"}, icon="sliders", category="control", dtype=vz.TUYA_ENUM),
    Dp(2, "current_heating_setpoint", "Heating setpoint", access="rw", unit="°C", icon="thermometer", category="control", min=5, max=45, step=1),
    Dp(3, "local_temperature", "Local temperature", scale=10, unit="°C", icon="thermometer"),
    Dp(4, "boost_heating", "Boost heating", type="binary", access="rw", values={0: "OFF", 1: "ON"}, icon="bolt", category="control", dtype=vz.TUYA_BOOL),
    Dp(8, "window_detection", "Window detection", type="binary", access="rw", values={0: "OFF", 1: "ON"}, icon="shield", category="config", dtype=vz.TUYA_BOOL),
    Dp(13, "child_lock", "Child lock", type="binary", access="rw", values={0: "UNLOCK", 1: "LOCK"}, icon="lock", category="config", dtype=vz.TUYA_BOOL),
    Dp(14, "battery", "Battery", unit="%", icon="battery", category="diagnostic", min=0, max=100),
)
_DP_WALL_THERMOSTAT_MOES = (
    Dp(1, "system_mode", "Mode", type="enum", access="rw", values={0: "off", 1: "heat"}, icon="sliders", category="control", dtype=vz.TUYA_BOOL),
    Dp(16, "current_heating_setpoint", "Heating setpoint", access="rw", unit="°C", icon="thermometer", category="control", min=5, max=35, step=1),
    Dp(24, "local_temperature", "Local temperature", scale=10, unit="°C", icon="thermometer"),
    Dp(40, "child_lock", "Child lock", type="binary", access="rw", values={0: "UNLOCK", 1: "LOCK"}, icon="lock", category="config", dtype=vz.TUYA_BOOL),
)
_DP_COVER = (
    Dp(1, "cover", "Cover", type="enum", access="w", values={0: "OPEN", 1: "STOP", 2: "CLOSE"}, icon="arrows", category="control", dtype=vz.TUYA_ENUM, description="Open, close or stop"),
    Dp(2, "position", "Position", access="rw", unit="%", icon="arrows", category="control", min=0, max=100, step=1, description="0 = closed, 100 = open"),
    Dp(3, "position", "Position", access="r", unit="%", icon="arrows", category="control", min=0, max=100),
)
_DP_COVER_BATTERY = _DP_COVER + (Dp(13, "battery", "Battery", unit="%", icon="battery", category="diagnostic", min=0, max=100),)
_DP_SMOKE = (
    Dp(1, "smoke", "Smoke", type="binary", values={0: "true", 1: "false"}, icon="shield", dtype=vz.TUYA_ENUM),  # 0 = alarm
    Dp(14, "battery_low", "Battery low", type="binary", values={0: "true", 1: "false", 2: "false"}, icon="battery", category="diagnostic", dtype=vz.TUYA_ENUM),
    Dp(15, "battery", "Battery", unit="%", icon="battery", category="diagnostic", min=0, max=100),
    Dp(101, "test", "Self-test", type="binary", values={0: "false", 1: "true"}, icon="shield", category="diagnostic", dtype=vz.TUYA_BOOL),
)
_DP_PRESENCE_RADAR = (
    Dp(1, "presence", "Presence", type="binary", values={0: "false", 1: "true"}, icon="hand", dtype=vz.TUYA_BOOL),
    Dp(2, "radar_sensitivity", "Radar sensitivity", access="rw", icon="sliders", category="config", min=0, max=9, step=1),
    Dp(3, "minimum_range", "Minimum range", access="rw", scale=100, unit="m", icon="arrows", category="config", min=0, max=9.5, step=0.1),
    Dp(4, "maximum_range", "Maximum range", access="rw", scale=100, unit="m", icon="arrows", category="config", min=0, max=9.5, step=0.1),
    Dp(9, "target_distance", "Target distance", scale=100, unit="m", icon="arrows"),
    Dp(101, "detection_delay", "Detection delay", access="rw", scale=10, unit="s", icon="clock", category="config", min=0, max=10, step=0.1),
    Dp(102, "fading_time", "Fading time", access="rw", scale=10, unit="s", icon="clock", category="config", min=0, max=1500, step=1),
    Dp(104, "illuminance_lux", "Illuminance", unit="lx", icon="sun"),
)

# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

_AQ = "Aqara"
_LUMI_SENSOR = dict(bind=(), remove=_SENSOR_CONTROLS)

# One Roof IR blaster: its own cluster (§ "NoammGr IRBlaster" in the docs)
_IRB = 0xFC00
_ONOFF = {False: "OFF", True: "ON"}
_IRBLASTER_ATTRS = (
    PrivateAttr(0x0000, "learn_key", DataType.string, max_len=15),
    PrivateAttr(0x0001, "send_key", DataType.string, max_len=15),
    PrivateAttr(0x0002, "hold", DataType.bool_, values=_ONOFF),
    PrivateAttr(0x0003, "last_result", DataType.string),
    PrivateAttr(0x0004, "code_count", DataType.uint16),
    PrivateAttr(0x0005, "temperature_offset", DataType.int16, scale=100),
    PrivateAttr(0x0006, "protocol", DataType.string),
    PrivateAttr(0x0007, "led_brightness", DataType.uint8),
    PrivateAttr(0x0008, "led_quiet", DataType.bool_, values=_ONOFF),
)


def _lumi_sensor(kind: str, models: tuple[str, ...] | str, **kw: Any) -> Quirk:
    base: dict[str, Any] = {**_LUMI_SENSOR, "add": _LUMI_SENSOR_EXTRAS + (_battery(),), "category": "sensor"}
    base.update(kw)
    return _q(_AQ, kind, base.pop("category"), "LUMI", models, **base)


QUIRKS: tuple[Quirk, ...] = (
    # ---- Xiaomi / Aqara ------------------------------------------------------------------------
    _lumi_sensor("Contact sensor", ("lumi.sensor_magnet", "lumi.sensor_magnet.aq2"), on_off_as="contact",
                 lumi_tags={0x64: ("contact", lambda v: not bool(v))}, description="Door/window sensor; contact via the On/Off attribute"),
    _lumi_sensor("Contact sensor", ("lumi.magnet.ac01", "lumi.magnet.acn001"), lumi_tags={0x64: ("contact", lambda v: not bool(v))}),
    _lumi_sensor("Motion sensor", ("lumi.sensor_motion", "lumi.sensor_motion.aq2"), illuminance_linear=True,
                 remove=_SENSOR_CONTROLS + ("alarm_1", "tamper", "battery_low"),
                 lumi_tags={0x64: ("occupancy", bool), 0x65: ("illuminance_lux", 1)}),
    _lumi_sensor("Motion sensor", ("lumi.motion.ac02", "lumi.motion.agl04", "lumi.motion.ac01"), illuminance_linear=True),
    _lumi_sensor("Temperature/humidity/pressure sensor", "lumi.weather",
                 lumi_tags={0x64: ("temperature", 100), 0x65: ("humidity", 100), 0x66: ("pressure", 100)},
                 add=_LUMI_SENSOR_EXTRAS + (_battery(), _numeric_sensor("temperature", "Temperature", "Measured temperature", "°C", cluster=0x0402, icon="thermometer"),
                                            _numeric_sensor("humidity", "Humidity", "Relative humidity", "%", cluster=0x0405, icon="drop"),
                                            _numeric_sensor("pressure", "Pressure", "Atmospheric pressure", "hPa", cluster=0x0403, icon="gauge"))),
    _lumi_sensor("Temperature/humidity sensor", ("lumi.sensor_ht", "lumi.sensor_ht.agl02"), lumi_tags={0x64: ("temperature", 100), 0x65: ("humidity", 100)},
                 add=_LUMI_SENSOR_EXTRAS + (_battery(), _numeric_sensor("temperature", "Temperature", "Measured temperature", "°C", cluster=0x0402, icon="thermometer"),
                                            _numeric_sensor("humidity", "Humidity", "Relative humidity", "%", cluster=0x0405, icon="drop"))),
    _lumi_sensor("Water leak sensor", ("lumi.sensor_wleak.aq1", "lumi.flood.agl02"), lumi_tags={0x64: ("water_leak", bool)}),
    _lumi_sensor("Vibration sensor", "lumi.vibration.aq1", remove=_SENSOR_CONTROLS + ("lock_state",), add=_LUMI_SENSOR_EXTRAS + (_battery(), _action(("vibration", "tilt", "drop"), description="Last vibration event")),
                 actions=("vibration", "tilt", "drop")),
    _lumi_sensor("Smoke detector", "lumi.sensor_smoke", ias_key="smoke", ias_class="smoke"),
    _lumi_sensor("Gas detector", "lumi.sensor_natgas", ias_key="gas", ias_class="gas"),
    _lumi_sensor("Air quality sensor", "lumi.airmonitor.acn01", analog={1: "voc"},
                 add=_LUMI_SENSOR_EXTRAS + (_battery(), _numeric_sensor("voc", "VOC", "Volatile organic compounds", "ppb", cluster=0x000C, icon="drop"))),
    _lumi_sensor("Light sensor", "lumi.sen_ill.mgl01", illuminance_linear=True),
    _lumi_sensor("Button", ("lumi.sensor_switch", "lumi.sensor_switch.aq2"), category="remote", on_off_as="action",
                 add=_LUMI_SENSOR_EXTRAS + (_battery(), _action(_LUMI_CLICK_ACTIONS)), actions=_LUMI_CLICK_ACTIONS),
    _lumi_sensor("Button", ("lumi.sensor_switch.aq3", "lumi.remote.b1acn01", "lumi.remote.b1acn02"), category="remote", multistate={1: ""},
                 add=_LUMI_SENSOR_EXTRAS + (_battery(), _action(_LUMI_CLICK_ACTIONS)), actions=_LUMI_CLICK_ACTIONS),
    _lumi_sensor("Wireless switch (1 button)", ("lumi.remote.b186acn01", "lumi.remote.b186acn02"), category="remote", multistate={1: ""},
                 add=_LUMI_SENSOR_EXTRAS + (_battery(), _action(("single", "double", "hold"))), actions=("single", "double", "hold")),
    _lumi_sensor("Wireless switch (2 button)", ("lumi.remote.b286acn01", "lumi.remote.b286acn02", "lumi.sensor_86sw2", "lumi.sensor_86sw2.es1"), category="remote",
                 multistate={1: "left", 2: "right", 3: "both"}, add=_LUMI_SENSOR_EXTRAS + (_battery(), _action(_LUMI_TWO_BUTTON_ACTIONS)), actions=_LUMI_TWO_BUTTON_ACTIONS),
    _q(_AQ, "Smart plug", "plug", "LUMI", ("lumi.plug", "lumi.plug.maus01", "lumi.plug.mmeu01", "lumi.plug.maeu01", "lumi.plug.mitw01", "lumi.plug.mmeu01"),
       remove=_AQARA_MAINS_REMOVE, lumi_tags={0x64: ("state", lambda v: "ON" if v else "OFF")}, analog={2: "power", 3: "energy"},
       add=(_device_temperature(), _power_outage_count(), _numeric_sensor("power", "Power", "Instantaneous active power", "W", cluster=0x000C, icon="bolt"),
            _numeric_sensor("energy", "Energy", "Total consumed energy", "kWh", cluster=0x000C, icon="bolt"))),
    _q(_AQ, "Wall switch (1 gang)", "switch", "LUMI", ("lumi.switch.b1naus01", "lumi.switch.b1laus01", "lumi.switch.l1aeu1", "lumi.switch.n1aeu1",
                                                       "lumi.switch.b1nacn02", "lumi.switch.b1lacn02", "lumi.ctrl_neutral1", "lumi.ctrl_ln1", "lumi.ctrl_ln1.aq1",
                                                       "lumi.switch.b1lc04", "lumi.switch.b1nc01", "lumi.switch.l1acn1"),
       remove=_AQARA_MAINS_REMOVE, multistate={41: "", 42: "", 51: ""}, add=(_device_temperature(), _power_outage_count(), _action(("single", "double", "hold"))),
       actions=("single", "double", "hold")),
    _q(_AQ, "Wall switch (2 gang)", "switch", "LUMI", ("lumi.switch.b2naus01", "lumi.switch.b2laus01", "lumi.switch.l2aeu1", "lumi.switch.n2aeu1",
                                                       "lumi.switch.b2nacn02", "lumi.switch.b2lacn02", "lumi.ctrl_neutral2", "lumi.ctrl_ln2", "lumi.ctrl_ln2.aq1",
                                                       "lumi.switch.b2lc04", "lumi.switch.b2nc01", "lumi.switch.l2acn1"),
       remove=_AQARA_MAINS_REMOVE, gangs=("left", "right"), gang_labels=("Left", "Right"), multistate={41: "left", 42: "right", 51: "both"},
       add=(_device_temperature(), _power_outage_count(), _action(_LUMI_TWO_BUTTON_ACTIONS)), actions=_LUMI_TWO_BUTTON_ACTIONS),
    _q(_AQ, "Wall switch (3 gang)", "switch", "LUMI", ("lumi.switch.n3acn3", "lumi.switch.l3acn3"),
       remove=_AQARA_MAINS_REMOVE, gangs=("left", "center", "right"), gang_labels=("Left", "Center", "Right"), add=(_device_temperature(), _power_outage_count())),
    _q(_AQ, "Curtain motor", "cover", "LUMI", ("lumi.curtain", "lumi.curtain.aq2", "lumi.curtain.hagl04", "lumi.curtain.acn002"), remove=("state", "power_on_behavior", "countdown"),
       analog={1: "position"}, lumi_tags={0x64: ("position", 1)}, add=(_device_temperature(),)),
    _q(_AQ, "Bulb (colour temperature)", "light", "LUMI", ("lumi.light.*",)),
    _q(_AQ, "Thermostat/TRV", "climate", "LUMI", ("lumi.airrtc.agl001",), remove=("state", "power_on_behavior", "countdown"), add=(_battery(),)),

    # ---- Tuya ----------------------------------------------------------------------------------
    _q("Tuya", "Smart plug", "plug", ("_TZ3000_*", "_TZ3210_*", "_TYZB01_*"), ("TS011F", "TS0121"), tuya_onoff_attrs=True),
    _q("Tuya", "Wall switch (1 gang)", "switch", ("_TZ3000_*", "_TYZB01_*", "_TZ3210_*"), ("TS0001", "TS0011")),
    _q("Tuya", "Wall switch (2 gang)", "switch", ("_TZ3000_*", "_TYZB01_*", "_TZ3210_*"), ("TS0012",), gangs=("l1", "l2"), gang_labels=("Left", "Right")),
    _q("Tuya", "Wall switch (3 gang)", "switch", ("_TZ3000_*", "_TYZB01_*", "_TZ3210_*"), ("TS0013",), gangs=("l1", "l2", "l3"), gang_labels=("Left", "Center", "Right")),
    _q("Tuya", "Wall switch (4 gang)", "switch", ("_TZ3000_*", "_TYZB01_*", "_TZ3210_*"), ("TS0014",), gangs=("l1", "l2", "l3", "l4")),
    _q("Tuya", "Relay (2 channel)", "switch", ("_TZ3000_*", "_TYZB01_*", "_TZ3210_*"), ("TS0002",), gangs=("l1", "l2")),
    _q("Tuya", "Relay (3 channel)", "switch", ("_TZ3000_*", "_TYZB01_*", "_TZ3210_*"), ("TS0003",), gangs=("l1", "l2", "l3")),
    _q("Tuya", "Relay (4 channel)", "switch", ("_TZ3000_*", "_TYZB01_*", "_TZ3210_*"), ("TS0004",), gangs=("l1", "l2", "l3", "l4")),
    _q("Tuya", "Button (1 button)", "remote", ("_TZ3000_*", "_TYZB02_*", "_TZ3400_*"), ("TS0041", "TS0041A"), buttons=1, add=(_battery(), _action(_TUYA_1_BUTTON)), actions=_TUYA_1_BUTTON),
    _q("Tuya", "Button (2 button)", "remote", ("_TZ3000_*", "_TYZB02_*", "_TZ3400_*"), ("TS0042",), buttons=2, add=(_battery(), _action(_TUYA_N_BUTTON(2))), actions=_TUYA_N_BUTTON(2)),
    _q("Tuya", "Button (3 button)", "remote", ("_TZ3000_*", "_TYZB02_*", "_TZ3400_*"), ("TS0043",), buttons=3, add=(_battery(), _action(_TUYA_N_BUTTON(3))), actions=_TUYA_N_BUTTON(3)),
    _q("Tuya", "Button (4 button)", "remote", ("_TZ3000_*", "_TYZB02_*", "_TZ3400_*"), ("TS0044",), buttons=4, add=(_battery(), _action(_TUYA_N_BUTTON(4))), actions=_TUYA_N_BUTTON(4)),
    _q("Tuya", "Temperature/humidity sensor", "sensor", ("_TZ3000_*", "_TYZB01_*", "_TZ2000_*"), ("TS0201",), remove=_SENSOR_CONTROLS),
    _q("Tuya", "Motion sensor", "sensor", ("_TZ3000_*", "_TYZB01_*", "_TZ1800_*", "_TZ3040_*"), ("TS0202",), remove=_SENSOR_CONTROLS),
    _q("Tuya", "Contact sensor", "sensor", ("_TZ3000_*", "_TYZB01_*", "_TZ1800_*"), ("TS0203",), remove=_SENSOR_CONTROLS),
    _q("Tuya", "Gas detector", "sensor", ("_TZ3000_*", "_TYZB01_*"), ("TS0204",), remove=_SENSOR_CONTROLS, ias_key="gas", ias_class="gas"),
    _q("Tuya", "Smoke detector", "sensor", ("_TZ3000_*", "_TYZB01_*"), ("TS0205",), remove=_SENSOR_CONTROLS),
    _q("Tuya", "Water leak sensor", "sensor", ("_TZ3000_*", "_TYZB01_*"), ("TS0207",), remove=_SENSOR_CONTROLS),
    _q("Tuya", "Vibration sensor", "sensor", ("_TZ3000_*", "_TYZB01_*"), ("TS0210",), remove=_SENSOR_CONTROLS),
    _q("Tuya", "Dimmable light", "light", ("_TZ3000_*", "_TZ3210_*"), ("TS0501B", "TS0501A")),
    _q("Tuya", "Bulb (colour temperature)", "light", ("_TZ3000_*", "_TZ3210_*"), ("TS0502B", "TS0502A")),
    _q("Tuya", "Bulb (colour)", "light", ("_TZ3000_*", "_TZ3210_*"), ("TS0503B", "TS0503A", "TS0504B", "TS0504A", "TS0505B", "TS0505A")),
    _q("Tuya", "Curtain module", "cover", ("_TZ3000_*", "_TZ3210_*"), ("TS130F",), remove=("state", "power_on_behavior", "countdown")),
    _q("Tuya", "Smoke detector", "sensor", ("_TZE200_rccxox8p", "_TZE200_ntcy3xu1", "_TZE200_m9skfctm", "_TZE200_dq1mfjug", "_TZE200_vzekyi4c",
                                            "_TZE204_ntcy3xu1", "_TZE200_e2bedvo9", "_TZE200_aycxwiau"), "TS0601",
       remove=_SENSOR_CONTROLS, dps=_DP_SMOKE, bind=(), description="Smoke alarm reported through datapoints"),
    _q("Tuya", "Temperature/humidity sensor", "sensor", ("_TZE200_bjawzodf", "_TZE200_zl1kmjqx"), "TS0601", remove=_SENSOR_CONTROLS, dps=_DP_TEMP_HUM_DIV10, bind=()),
    _q("Tuya", "Temperature/humidity sensor", "sensor", ("_TZE200_locansqn", "_TZE200_bq5c8xfe", "_TZE200_qoy0ekbd", "_TZE200_znbl8dj5", "_TZE200_a8sdabtg",
                                                         "_TZE200_qyflbnbj", "_TZE200_utkemkbs", "_TZE204_qyflbnbj", "_TZE204_yjjdcqsq", "_TZE200_yjjdcqsq"),
       "TS0601", remove=_SENSOR_CONTROLS, dps=_DP_TEMP_HUM, bind=()),
    _q("Tuya", "Thermostat/TRV", "climate", ("_TZE200_ckud7u2l", "_TZE200_ywdxldoj", "_TZE200_do5qy8zo", "_TZE200_cwnjrr72", "_TZE200_pvvbommb",
                                             "_TZE200_9sfg7gm0", "_TZE200_2atgpdho", "_TZE200_cpmgn2cf", "_TZE200_8thwkzxl", "_TZE200_4eeyebrt",
                                             "_TZE200_8whxpsiw", "_TZE200_xby0s3ta", "_TZE200_7fqkphoq"),
       "TS0601", remove=_SENSOR_CONTROLS, dps=_DP_TRV_CKUD, bind=()),
    _q("Moes", "Thermostat/TRV", "climate", ("_TZE200_b6wax7g0",), "TS0601", remove=_SENSOR_CONTROLS, dps=_DP_TRV_BRT100, bind=(), description="BRT-100"),
    _q("Moes", "Wall thermostat", "climate", ("_TZE200_aoclfnxz", "_TZE200_ztvwu4nk", "_TZE200_ye5jkfsb", "_TZE200_u9bfwha0", "_TZE204_aoclfnxz", "_TZE200_2ekuz3dz"),
       "TS0601", remove=_SENSOR_CONTROLS, dps=_DP_WALL_THERMOSTAT_MOES, description="BHT-002 family"),
    _q("Tuya", "Curtain motor", "cover", ("_TZE200_fzo2pocs", "_TZE200_zah67ekd", "_TZE200_xuzcvlku", "_TZE200_wmcdj3aq", "_TZE200_cowvfni3", "_TZE200_rddyvrci",
                                          "_TZE200_nogaemzt", "_TZE200_5zbp6j0u", "_TZE200_nueqqe6k", "_TZE200_xaabybja", "_TZE200_rmymn92d", "_TZE200_gubdgai2",
                                          "_TZE200_bqcqqjpb", "_TZE200_yenbr4om", "_TZE200_nkoabg8w", "_TZE200_4vobcgd3", "_TZE200_r0jdjrvi", "_TZE200_pk0sfzvr",
                                          "_TZE200_fdtjuw7u", "_TZE200_zpzndjez", "_TZE200_3i3exuay", "_TZE200_tvrvdj6o", "_TZE204_guvc7pdy"),
       "TS0601", remove=_SENSOR_CONTROLS, dps=_DP_COVER),
    _q("Tuya", "Roller blind (battery)", "cover", ("_TZE200_zvo63cmo", "_TZE200_1jmzrwc5"), "TS0601", remove=_SENSOR_CONTROLS, dps=_DP_COVER_BATTERY),
    _q("Tuya", "Presence sensor (radar)", "sensor", ("_TZE200_ztc6ggyl", "_TZE204_ztc6ggyl", "_TZE200_ikvncluo", "_TZE200_lyetpprm", "_TZE200_wukb7rhc",
                                                     "_TZE200_jva8ink8", "_TZE200_mrf6vtua", "_TZE200_ar0slwnd", "_TZE200_sfiy5tfs", "_TZE200_holel4dk",
                                                     "_TZE200_xpq2rzhq", "_TZE204_qasjif9e", "_TZE204_xsm7l9xa"),
       "TS0601", remove=_SENSOR_CONTROLS, dps=_DP_PRESENCE_RADAR),
    _q("Tuya", "Tuya device (datapoints)", "unknown", ("_TZE200_*", "_TZE204_*", "_TZE284_*"), "TS0601", remove=_SENSOR_CONTROLS, description="Unknown datapoint map; raw datapoints are exposed"),

    # ---- IKEA ----------------------------------------------------------------------------------
    _q("IKEA", "Bulb", "light", "IKEA of Sweden", ("TRADFRI bulb *", "TRADFRIbulb*", "LED*", "NYMANE*", "STOFTMOLN*", "GUNNARP*", "JORMLIEN*", "LEPTITER*", "ORMANAS*", "PILSKOTT*", "TRADFRI Light*")),
    _q("IKEA", "LED driver", "light", "IKEA of Sweden", ("TRADFRI Driver *", "TRADFRI transformer *", "SILVERGLANS*")),
    _q("IKEA", "Smart plug", "plug", "IKEA of Sweden", ("TRADFRI control outlet", "TRETAKT Smart plug", "ASKVADER on/off switch")),
    _q("IKEA", "Smart plug (metering)", "plug", "IKEA of Sweden", ("INSPELNING Smart plug",)),
    _q("IKEA", "Remote (5 button)", "remote", "IKEA of Sweden", ("TRADFRI remote control",), remove=_SENSOR_CONTROLS, action_map=_IKEA_5_MAP,
       add=(_battery(), _action(_IKEA_5_BUTTON)), actions=_IKEA_5_BUTTON),
    _q("IKEA", "Remote (2 button)", "remote", "IKEA of Sweden", ("TRADFRI on/off switch", "RODRET Dimmer", "TRADFRI open/close remote"), remove=_SENSOR_CONTROLS,
       add=(_battery(), _action(_IKEA_ON_OFF)), actions=_IKEA_ON_OFF),
    _q("IKEA", "Remote (STYRBAR)", "remote", "IKEA of Sweden", ("Remote Control N2",), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_IKEA_STYRBAR)), actions=_IKEA_STYRBAR),
    _q("IKEA", "Shortcut button", "remote", "IKEA of Sweden", ("TRADFRI SHORTCUT Button",), remove=_SENSOR_CONTROLS,
       add=(_battery(), _action(("on", "brightness_move_up", "brightness_stop"))), actions=("on", "brightness_move_up", "brightness_stop")),
    _q("IKEA", "Shortcut button (2 button)", "remote", "IKEA of Sweden", ("SOMRIG shortcut button",), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_IKEA_SOMRIG)), actions=_IKEA_SOMRIG),
    _q("IKEA", "Wireless dimmer", "remote", "IKEA of Sweden", ("TRADFRI wireless dimmer",), remove=_SENSOR_CONTROLS,
       add=(_battery(), _action(("brightness_move_up", "brightness_move_down", "brightness_stop", "brightness_move_to_level")))),
    _q("IKEA", "Sound controller", "remote", "IKEA of Sweden", ("SYMFONISK Sound Controller", "SYMFONISK sound remote gen2"), remove=_SENSOR_CONTROLS,
       add=(_battery(), _action(("toggle", "brightness_move_up", "brightness_move_down", "brightness_stop", "brightness_step_up", "brightness_step_down")))),
    _q("IKEA", "Motion sensor", "sensor", "IKEA of Sweden", ("TRADFRI motion sensor",), remove=_SENSOR_CONTROLS, on_off_as="occupancy",
       add=(_battery(), _binary_sensor("occupancy", "Motion", "Motion detected (the sensor sends on-with-timed-off)", icon="hand")),
       description="Sends On/Off commands; occupancy is derived from them"),
    _q("IKEA", "Motion sensor", "sensor", "IKEA of Sweden", ("VALLHORN Wireless Motion Sensor",), remove=_SENSOR_CONTROLS),
    _q("IKEA", "Contact sensor", "sensor", "IKEA of Sweden", ("PARASOLL Door/Window Sensor",), remove=_SENSOR_CONTROLS),
    _q("IKEA", "Water leak sensor", "sensor", "IKEA of Sweden", ("BADRING Water Leakage Sensor",), remove=_SENSOR_CONTROLS),
    _q("IKEA", "Roller blind", "cover", "IKEA of Sweden", ("FYRTUR block-out roller blind", "KADRILJ roller blind", "PRAKTLYSING cellular blind", "TREDANSEN block-out cellul blind"),
       remove=("state", "power_on_behavior", "countdown")),
    _q("IKEA", "Signal repeater", "unknown", "IKEA of Sweden", ("TRADFRI Signal Repeater",), remove=_SENSOR_CONTROLS),
    _q("IKEA", "Air purifier", "unknown", "IKEA of Sweden", ("STARKVIND Air purifier",)),

    # ---- Philips Hue ---------------------------------------------------------------------------
    _q("Philips Hue", "Smart plug", "plug", ("Philips", "Signify Netherlands B.V."), ("LOM*",)),
    _q("Philips Hue", "Bulb", "light", ("Philips", "Signify Netherlands B.V."), ("LC*", "LW*", "LT*", "LL*", "LS*", "LG*", "LD*", "LA*", "LX*", "LE*", "LP*", "LB*", "LV*", "929*", "915*", "1741*", "1742*", "1743*", "1744*", "1745*", "1746*", "1747*", "1748*", "3261*", "3216*", "3418*", "4090*", "7602031P7", "4034031P7", "4080248P9", "4080148P9", "5045*", "5055*", "5062*", "5063*", "5410*"),
       remove=("countdown",)),
    _q("Philips Hue", "Dimmer switch", "remote", ("Philips", "Signify Netherlands B.V."), ("RWL020", "RWL021", "RWL022"), remove=_SENSOR_CONTROLS,
       add=(_battery(), _action(_HUE_DIMMER)), actions=_HUE_DIMMER),
    _q("Philips Hue", "Tap dial switch", "remote", ("Philips", "Signify Netherlands B.V."), ("RDM002",), remove=_SENSOR_CONTROLS,
       add=(_battery(), _action(tuple(f"button_{i}_{t}" for i in (1, 2, 3, 4) for t in ("press", "hold", "press_release", "hold_release")) + ("dial_rotate_left", "dial_rotate_right")))),
    _q("Philips Hue", "Smart button", "remote", ("Philips", "Signify Netherlands B.V."), ("ROM001", "ROM002"), remove=_SENSOR_CONTROLS,
       add=(_battery(), _action(("on_press", "on_hold", "on_press_release", "on_hold_release")))),
    _q("Philips Hue", "Wall switch module", "remote", ("Philips", "Signify Netherlands B.V."), ("RDM001", "RDM004"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_HUE_DIMMER))),
    _q("Philips Hue", "Motion sensor", "sensor", ("Philips", "Signify Netherlands B.V."), ("SML001", "SML002", "SML003", "SML004"), remove=_SENSOR_CONTROLS),
    _q("Philips Hue", "Contact sensor", "sensor", ("Philips", "Signify Netherlands B.V."), ("SOC001",), remove=_SENSOR_CONTROLS),

    # ---- Sonoff --------------------------------------------------------------------------------
    _q("Sonoff", "Button", "remote", ("eWeLink", "SONOFF"), ("WB01", "WB-01", "SNZB-01", "SNZB-01P"), remove=_SENSOR_CONTROLS,
       action_map={"toggle": "single", "on": "double", "off": "long"}, add=(_battery(), _action(("single", "double", "long"))), actions=("single", "double", "long")),
    _q("Sonoff", "Temperature/humidity sensor", "sensor", ("eWeLink", "SONOFF"), ("TH01", "SNZB-02", "SNZB-02D", "SNZB-02P", "SNZB-02LD", "SNZB-02WD"), remove=_SENSOR_CONTROLS),
    _q("Sonoff", "Motion sensor", "sensor", ("eWeLink", "SONOFF"), ("MS01", "ms01", "SNZB-03", "SNZB-03P"), remove=_SENSOR_CONTROLS),
    _q("Sonoff", "Contact sensor", "sensor", ("eWeLink", "SONOFF"), ("DS01", "SNZB-04", "SNZB-04P"), remove=_SENSOR_CONTROLS),
    _q("Sonoff", "Presence sensor", "sensor", ("eWeLink", "SONOFF"), ("SNZB-06P",), remove=_SENSOR_CONTROLS),
    _q("Sonoff", "Smart plug", "plug", ("eWeLink", "SONOFF"), ("S26R2ZB", "SA-003-Zigbee", "S31 Lite zb", "S31ZB", "S40ZBTPB", "S60ZBTPF", "S60ZBTPG")),
    _q("Sonoff", "Switch module", "switch", ("eWeLink", "SONOFF"), ("01MINIZB", "ZBMINI", "ZBMINI-L", "ZBMINIL2", "ZBMINIR2", "ZBMicro", "BASICZBR3")),
    _q("Sonoff", "Thermostat/TRV", "climate", ("eWeLink", "SONOFF"), ("TRVZB",), remove=_SENSOR_CONTROLS),
    _q("Sonoff", "Water leak sensor", "sensor", ("eWeLink", "SONOFF"), ("SNZB-05P",), remove=_SENSOR_CONTROLS),

    # ---- Innr ----------------------------------------------------------------------------------
    _q("Innr", "Smart plug", "plug", "innr", ("SP *", "OSP *")),
    _q("Innr", "Bulb", "light", "innr", ("RB *", "RS *", "AE *", "BY *", "FL *", "RF *", "OFL *", "OPL *", "BF *", "BE *", "BG *", "RC *", "OGL *", "OSL *", "PL *", "ST *", "TL *", "UC *", "WCA *", "WSD *", "XL *")),
    _q("Innr", "Remote", "remote", "innr", ("RC 110", "RC 210", "RC 250"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),

    # ---- OSRAM / LEDVANCE ----------------------------------------------------------------------
    _q("OSRAM", "Smart plug", "plug", ("OSRAM", "LEDVANCE"), ("Plug 01", "Plug Z3", "Outdoor Plug", "PLUG COMPACT EU T", "SMART+ Plug*")),
    _q("OSRAM", "Bulb", "light", ("OSRAM", "LEDVANCE"), ("Classic*", "CLA60*", "PAR16*", "Flex*", "Gardenpole*", "Outdoor*", "A60*", "B40*", "CLA*", "LIGHTIFY*", "Ceiling*", "Panel*", "Surface Light*", "Garden*", "Lightify*", "ZLL Light"), ),
    _q("OSRAM", "Remote (4 button)", "remote", ("OSRAM", "LEDVANCE"), ("Lightify Switch Mini", "Switch 4x EU-LIGHTIFY", "Switch 4x-LIGHTIFY", "Switch-LIGHTIFY"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("OSRAM", "Motion sensor", "sensor", ("OSRAM", "LEDVANCE"), ("Motion Sensor-A", "SMART+ Motion*"), remove=_SENSOR_CONTROLS),

    # ---- Samjin / SmartThings / Centralite -----------------------------------------------------
    _q("SmartThings", "Multipurpose sensor", "sensor", ("Samjin", "SmartThings", "CentraLite"), ("multi", "multiv4", "3300-S", "3320-L", "3321-S"), remove=_SENSOR_CONTROLS),
    _q("SmartThings", "Motion sensor", "sensor", ("Samjin", "SmartThings", "CentraLite"), ("motion", "motionv4", "motionv5", "3325-S", "3326-L", "3305-S"), remove=_SENSOR_CONTROLS),
    _q("SmartThings", "Button", "remote", ("Samjin", "SmartThings"), ("button",), remove=_SENSOR_CONTROLS, add=(_battery(),)),
    _q("SmartThings", "Smart plug", "plug", ("Samjin", "SmartThings", "CentraLite"), ("outlet", "outletv4", "3200-Sgb", "3210-L", "4257050-ZHAC", "4257050-RZHAC")),
    _q("SmartThings", "Water leak sensor", "sensor", ("Samjin", "SmartThings", "CentraLite"), ("water", "moisturev4", "3315-S", "3315-G", "3315-Seu"), remove=_SENSOR_CONTROLS),
    _q("SmartThings", "Contact sensor", "sensor", ("SmartThings", "CentraLite"), ("3310-S", "3310-G", "3300"), remove=_SENSOR_CONTROLS),
    _q("Centralite", "Thermostat", "climate", "CentraLite", ("3157100", "3157100-E"), remove=_SENSOR_CONTROLS),
    _q("Centralite", "Keypad", "remote", "CentraLite", ("3400", "3400-D", "3405-L"), remove=_SENSOR_CONTROLS, add=(_battery(),)),

    # ---- Heiman --------------------------------------------------------------------------------
    _q("Heiman", "Smoke detector", "sensor", ("HEIMAN", "Heiman"), ("HS1SA", "HS1SA-E", "HS3SA", "HS1SA-M", "SmokeSensor-*", "SMOK_V16", "SMOK_YDLV10", "HS3SA-E"), remove=_SENSOR_CONTROLS),
    _q("Heiman", "Gas detector", "sensor", ("HEIMAN", "Heiman"), ("HS1CG", "HS1CG-E", "HS1CG-M", "HS3CG", "GASSensor-*", "GAS_V15"), remove=_SENSOR_CONTROLS, ias_key="gas", ias_class="gas"),
    _q("Heiman", "CO detector", "sensor", ("HEIMAN", "Heiman"), ("HS1CA", "HS1CA-E", "HS1CA-M", "COSensor-*"), remove=_SENSOR_CONTROLS),
    _q("Heiman", "Water leak sensor", "sensor", ("HEIMAN", "Heiman"), ("HS1WL", "HS1WL-E", "HS1-WL-E", "HS3WL", "WaterSensor-*", "WaterSensor2-*"), remove=_SENSOR_CONTROLS),
    _q("Heiman", "Contact sensor", "sensor", ("HEIMAN", "Heiman"), ("HS1DS", "HS1DS-E", "HS3DS", "DoorSensor-*", "DOOR_TPV13", "DoorSensor-EF-3.0"), remove=_SENSOR_CONTROLS),
    _q("Heiman", "Motion sensor", "sensor", ("HEIMAN", "Heiman"), ("HS1MS", "HS1MS-M", "HS3MS", "PIRSensor-*", "PIR_TPV13"), remove=_SENSOR_CONTROLS),
    _q("Heiman", "Temperature/humidity sensor", "sensor", ("HEIMAN", "Heiman"), ("HS1HT", "HS1HT-N", "HS3HT", "HT-EM", "TH-T_V14"), remove=_SENSOR_CONTROLS),
    _q("Heiman", "Smart plug", "plug", ("HEIMAN", "Heiman"), ("HS2SK", "HS2SK_nxp", "SmartPlug-*", "SmartPlug")),
    _q("Heiman", "Siren", "unknown", ("HEIMAN", "Heiman"), ("HS2WD-E", "WarningDevice", "WarningDevice-EF-3.0"), remove=_SENSOR_CONTROLS),
    _q("Heiman", "Remote", "remote", ("HEIMAN", "Heiman"), ("HS1RC", "HS1RC-N", "HS1RC-EM", "RC-EM", "RC_V14", "RC-EF-3.0"), remove=_SENSOR_CONTROLS, add=(_battery(),)),

    # ---- Develco / frient ----------------------------------------------------------------------
    _q("frient", "Smoke detector", "sensor", ("frient A/S", "Develco Products A/S", "Develco"), ("SMSZB-120", "SMSZB-120 *"), remove=_SENSOR_CONTROLS),
    _q("frient", "Heat detector", "sensor", ("frient A/S", "Develco Products A/S", "Develco"), ("HESZB-120", "HESZB-120 *"), remove=_SENSOR_CONTROLS),
    _q("frient", "Contact sensor", "sensor", ("frient A/S", "Develco Products A/S", "Develco"), ("WISZB-120", "WISZB-121", "WISZB-137", "WISZB-138"), remove=_SENSOR_CONTROLS),
    _q("frient", "Motion sensor", "sensor", ("frient A/S", "Develco Products A/S", "Develco"), ("MOSZB-140", "MOSZB-141", "MOSZB-153", "MOSZB-130"), remove=_SENSOR_CONTROLS),
    _q("frient", "Water leak sensor", "sensor", ("frient A/S", "Develco Products A/S", "Develco"), ("FLSZB-110",), remove=_SENSOR_CONTROLS),
    _q("frient", "Smart plug (metering)", "plug", ("frient A/S", "Develco Products A/S", "Develco"), ("SPLZB-131", "SPLZB-132", "SPLZB-134", "SPLZB-137", "SPLZB-141", "SPLZB-142", "SMRZB-332", "SMRZB-143", "SMRZB-153", "SMRZB-333")),
    _q("frient", "Electricity meter interface", "meter", ("frient A/S", "Develco Products A/S", "Develco"), ("EMIZB-132", "EMIZB-141", "EMIZB-151", "ZHEMI101"), remove=_SENSOR_CONTROLS),
    _q("frient", "Humidity sensor", "sensor", ("frient A/S", "Develco Products A/S", "Develco"), ("HMSZB-110", "HMSZB-120"), remove=_SENSOR_CONTROLS),
    _q("frient", "Air quality sensor", "sensor", ("frient A/S", "Develco Products A/S", "Develco"), ("AQSZB-110",), remove=_SENSOR_CONTROLS),
    _q("frient", "Keypad", "remote", ("frient A/S", "Develco Products A/S", "Develco"), ("KEPZB-110", "KEYZB-110"), remove=_SENSOR_CONTROLS, add=(_battery(),)),
    _q("frient", "Siren", "unknown", ("frient A/S", "Develco Products A/S", "Develco"), ("SIRZB-110", "SIRZB-111"), remove=_SENSOR_CONTROLS),

    # ---- Third Reality ------------------------------------------------------------------------
    _q("Third Reality", "Switch actuator", "switch", "Third Reality, Inc", ("3RSS007Z", "3RSS008Z", "3RSS009Z"), remove=("countdown", "power_on_behavior")),
    _q("Third Reality", "Button", "remote", "Third Reality, Inc", ("3RSB015BZ", "3RSB22BZ", "3RSB22BZ-ABT"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(("single", "double", "hold")))),
    _q("Third Reality", "Contact sensor", "sensor", "Third Reality, Inc", ("3RDS17BZ", "3RDTS01056Z"), remove=_SENSOR_CONTROLS),
    _q("Third Reality", "Motion sensor", "sensor", "Third Reality, Inc", ("3RMS16BZ", "3RMS12BZ"), remove=_SENSOR_CONTROLS),
    _q("Third Reality", "Temperature/humidity sensor", "sensor", "Third Reality, Inc", ("3RTHS24BZ", "3RTHS0224Z", "3RTHS0224BZ"), remove=_SENSOR_CONTROLS),
    _q("Third Reality", "Smart plug", "plug", "Third Reality, Inc", ("3RSP019BZ", "3RSP02028BZ", "3RSPE01044BZ", "3RSPE02044BZ")),
    _q("Third Reality", "Water leak sensor", "sensor", "Third Reality, Inc", ("3RWS18BZ",), remove=_SENSOR_CONTROLS),
    _q("Third Reality", "Vibration sensor", "sensor", "Third Reality, Inc", ("3RVS01031Z",), remove=_SENSOR_CONTROLS),
    _q("Third Reality", "Soil moisture sensor", "sensor", "Third Reality, Inc", ("3RSM0147Z",), remove=_SENSOR_CONTROLS),
    _q("Third Reality", "Night light", "light", "Third Reality, Inc", ("3RSNL02043Z", "3RSNL02043Z-ABT")),

    # ---- Danfoss / Eurotronic / Bosch ---------------------------------------------------------
    _q("Danfoss", "Thermostat/TRV", "climate", "Danfoss", ("eTRV0100", "eTRV0101", "eTRV0103", "TRV001", "TRV003"), remove=_SENSOR_CONTROLS, description="Ally radiator thermostat"),
    _q("Danfoss", "Room sensor", "sensor", "Danfoss", ("eT093WRO", "eT093WRG"), remove=_SENSOR_CONTROLS),
    _q("Eurotronic", "Thermostat/TRV", "climate", "Eurotronic", ("SPZB0001",), remove=_SENSOR_CONTROLS, description="Spirit Zigbee"),
    _q("Bosch", "Thermostat/TRV", "climate", ("BOSCH", "Bosch"), ("RBSH-TRV0-ZB-EU", "RBSH-TRV1-ZB-EU"), remove=_SENSOR_CONTROLS, description="Radiator thermostat II"),
    _q("Bosch", "Room thermostat", "climate", ("BOSCH", "Bosch"), ("RBSH-RTH0-ZB-EU", "RBSH-RTH0-BAT-ZB-EU"), remove=_SENSOR_CONTROLS, description="Room thermostat II"),
    _q("Bosch", "Contact sensor", "sensor", ("BOSCH", "Bosch"), ("RBSH-SWD-ZB", "RBSH-SWD2-ZB", "RBSH-SWDV-ZB"), remove=_SENSOR_CONTROLS, description="Door/window contact II"),
    _q("Bosch", "Motion sensor", "sensor", ("BOSCH", "Bosch"), ("RFDL-ZB-MS", "RFPR-ZB-SH-EU", "RBSH-MMD-ZB-EU"), remove=_SENSOR_CONTROLS),
    _q("Bosch", "Smart plug", "plug", ("BOSCH", "Bosch"), ("RBSH-SP-ZB-EU",)),
    _q("Bosch", "Smoke detector", "sensor", ("BOSCH", "Bosch"), ("RBSH-SD-ZB-EU",), remove=_SENSOR_CONTROLS),

    # ---- Locks ---------------------------------------------------------------------------------
    _q("Yale", "Door lock", "lock", "Yale", ("YRD*", "YRL*", "YMF*", "YRC*", "easyCodeTouch*", "c700*", "D2*", "Y5*"), remove=_LOCK_REMOVE),
    _q("Kwikset", "Door lock", "lock", "Kwikset", ("SMARTCODE*", "SMARTCODE_DEADBOLT_*", "SMARTCODE_LEVER_*", "SMARTCODE_CONVERT_*", "SMARTCODE_CONVERT_GEN1"), remove=_LOCK_REMOVE),
    _q("Schlage", "Door lock", "lock", ("Schlage", "Allegion"), ("BE468", "BE469", "BE469ZP", "FE599", "BE468ZP", "BE489"), remove=_LOCK_REMOVE),

    # ---- Ubisys --------------------------------------------------------------------------------
    _q("Ubisys", "Switch (1 gang)", "switch", "ubisys", ("S1", "S1-R"), remove=("countdown",)),
    _q("Ubisys", "Switch (2 gang)", "switch", "ubisys", ("S2", "S2-R"), remove=("countdown",), gangs=("l1", "l2")),
    _q("Ubisys", "Dimmer", "light", "ubisys", ("D1", "D1-R"), remove=("countdown",)),
    _q("Ubisys", "Shutter control", "cover", "ubisys", ("J1", "J1-R"), remove=("state", "power_on_behavior", "countdown")),
    _q("Ubisys", "Control unit", "remote", "ubisys", ("C4",), remove=_SENSOR_CONTROLS, add=(_action(_GENERIC_REMOTE),)),

    # ---- Gledopto / Paulmann / Müller Licht ----------------------------------------------------
    _q("Gledopto", "LED controller", "light", "GLEDOPTO", ("GL-C-*", "GL-MC-*", "GL-SD-*", "GL-LB-*", "GLEDOPTO", "GL-P-*"), remove=("countdown",)),
    _q("Gledopto", "Bulb", "light", "GLEDOPTO", ("GL-B-*", "GL-S-*", "GL-D-*", "GL-G-*", "GL-FL-*", "GL-W-*", "GL-SO-*", "GL-X-*", "GL-H-*"), remove=("countdown",)),
    _q("Paulmann", "Light", "light", ("Paulmann Licht GmbH", "Paulmann Licht", "Paulmann"), ("Dimmablelight", "RGBW light", "CCT light", "RGB light", "Switch Controller", "371000001", "371000002", "500.47", "500.48", "500.49", "50049", "50131", "50133", "50134", "50063", "50064", "50067", "50068", "50069", "50070", "50071", "50073", "50074", "50075", "50076", "50078", "50079", "50080", "50081", "50082", "50083", "50084", "50085", "50086", "50087", "50088", "50089", "50093", "50094", "50095", "50096", "50097", "50098", "50099", "50100", "50104", "50105", "50106"), remove=("countdown",)),
    _q("Müller Licht", "Remote", "remote", "MLI", ("tint remote", "ZBT-Remote-ALL-RGBW", "tint-Remote-white"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("Müller Licht", "Bulb", "light", "MLI", ("ZBT-*", "tint-*", "45*", "404*"), remove=("countdown",)),

    # ---- Meters / misc -------------------------------------------------------------------------
    _q("LiXee", "Electricity meter", "meter", "LiXee", ("ZLinky_TIC",), remove=_SENSOR_CONTROLS),
    _q("LiXee", "Pulse meter", "meter", "LiXee", ("ZiPulses",), remove=_SENSOR_CONTROLS),
    _q("Visonic", "Contact sensor", "sensor", "Visonic", ("MCT-340 E", "MCT-340 SMA", "MCT-350 SMA", "MCT-370 SMA"), remove=_SENSOR_CONTROLS),
    _q("Visonic", "Motion sensor", "sensor", "Visonic", ("MP-840", "MP-841", "MP-902"), remove=_SENSOR_CONTROLS),
    _q("Xfinity", "Contact sensor", "sensor", ("Sercomm Corp.", "Universal Electronics Inc"), ("SZ-DWS04", "SZ-DWS04N_SF", "SZ-DWS08", "XHS2-UE", "XHS2-SE", "URC4450BC0-X-R"), remove=_SENSOR_CONTROLS),
    _q("Sercomm", "Motion sensor", "sensor", "Sercomm Corp.", ("SZ-PIR02", "SZ-PIR04", "SZ-PIR04N"), remove=_SENSOR_CONTROLS),
    _q("Sercomm", "Water leak sensor", "sensor", "Sercomm Corp.", ("SZ-WTD02N_SF", "SZ-WTD03"), remove=_SENSOR_CONTROLS),
    _q("Sercomm", "Smart plug", "plug", "Sercomm Corp.", ("SZ-ESW01", "SZ-ESW01-AU")),
    _q("Linkind", "Motion sensor", "sensor", ("lk", "Linkind"), ("ZB-MotionSensor-D0003", "ZB-MotionSensor-D0001"), remove=_SENSOR_CONTROLS),
    _q("Linkind", "Contact sensor", "sensor", ("lk", "Linkind"), ("ZB-DoorSensor-D0003", "ZB-DoorSensor-D0001"), remove=_SENSOR_CONTROLS),
    _q("Linkind", "Smart plug", "plug", ("lk", "Linkind"), ("ZBT-ONOFFPlug-D0005", "ZB-PlugMeter-D0001")),
    _q("Linkind", "Bulb", "light", ("lk", "Linkind"), ("ZBT-CCTLight-*", "ZBT-DIMLight-*", "ZBT-RGBWLight-*", "ZBT-ExtendedColor", "ZBT-ColorTemperature", "ZBT-DimmableLight"), remove=("countdown",)),
    _q("Linkind", "Remote", "remote", ("lk", "Linkind"), ("ZBT-CCTSwitch-D0001", "ZBT-DIMSwitch-*", "ZB-RemoteControl-D0001"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("Namron", "Switch", "switch", ("NAMRON AS", "Namron AS", "Namron"), ("4512704", "4512705", "4512744", "4512746", "4512748"), remove=("countdown",)),
    _q("Namron", "Dimmer", "light", ("NAMRON AS", "Namron AS", "Namron"), ("4512700", "4512701", "4512702", "4512703", "4512760", "4512761", "3802960", "3802961", "3802962", "3802963", "3802964", "3802965", "1402755", "1402767", "1402768"), remove=("countdown",)),
    _q("Namron", "Remote", "remote", ("NAMRON AS", "Namron AS", "Namron"), ("4512706", "4512721", "4512726", "4512729", "4512730", "4512731"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("Namron", "Thermostat", "climate", ("NAMRON AS", "Namron AS", "Namron"), ("4512737", "4512738", "4512749", "4512750", "4512751", "4512752", "4512782", "4512783"), remove=_SENSOR_CONTROLS),
    _q("Sunricher", "Dimmer", "light", "Sunricher", ("ZG9101SAC-HP", "ZG9101SAC-HP-Switch", "ZG9030A-MW", "ZG2835", "SR-ZG9040A", "SR-ZG9101SAC-HP-Switch", "ZG9101SAC-HP-AC", "HK-SL-DIM-A", "SR-ZG9100A-DIM"), remove=("countdown",)),
    _q("Sunricher", "Switch", "switch", "Sunricher", ("SR-ZG9100A", "ZG9100A", "SR-ZG9100A-S", "HK-SL-RDIM-A"), remove=("countdown",)),
    _q("Sunricher", "Remote", "remote", "Sunricher", ("ZG2833K8_EU05", "ZG2833K4_EU06", "ZG2833K2_EU07", "ZG2833PAC", "ZG2819S-RGBW", "ZG2819S-CCT", "SR-ZG9001K8-DIM", "SR-ZG9001K4-DIM2", "SR-ZG9001K2-DIM", "SR-ZG9001K12-DIM-Z4", "SR-ZG9001K12-DIM-Z5", "ZG2835RAC", "SR-ZG9001T4-DIM-EU", "SR-ZG2835"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("Sunricher", "Motion sensor", "sensor", "Sunricher", ("ZG9030A-MW-S", "SR-ZG9030A-MW", "ZG9030A-MW-PIR"), remove=_SENSOR_CONTROLS),
    _q("Aurora", "Bulb", "light", "Aurora", ("FWG125Bulb50AU", "FWGU10Bulb50AU", "FWMT10Bulb50AU", "FWBulb51AU", "FWA60Bulb50AU", "FWST64Bulb50AU", "FWBulb50AU", "FWGU10Bulb50AU", "RGBGU10Bulb50AU", "RGBCXStrip50AU", "TWGU10Bulb50AU", "TWBulb51AU", "TWBulb50AU", "TWMPROZXBulb50AU", "TWCL50AU", "RGBBulb51AU", "RGBCCTBulb50AU"), remove=("countdown",)),
    _q("Aurora", "Motion sensor", "sensor", "Aurora", ("AU-A1ZBPIRS", "MotionSensor51AU"), remove=_SENSOR_CONTROLS),
    _q("Aurora", "Double socket", "plug", "Aurora", ("AU-A1ZBDSS", "DoubleSocket50AU"), gangs=("left", "right"), gang_labels=("Left", "Right")),
    # ---- One Roof hardware ----------------------------------------------------------------------
    # Zigbee infrared blaster for air conditioners. Endpoint 1 is a standard 4-pipe Thermostat +
    # Fan Control (the AC state), endpoint 2 an On/Off output that is the louver swing, endpoint 3
    # the on-board temperature/humidity sensor; 0xFC00 is the device's own cluster for learning and
    # sending codes (standard attributes, no manufacturer code — see PrivateAttr).
    _q("NoammGr", "AC IR blaster", "climate", "NoammGr", "IRBlaster",
       description="Infrared blaster that drives an air conditioner: learn the remote's codes once, then control it like a thermostat",
       remove=("countdown", "power_on_behavior", "running_state"),
       relabel={(2, "state"): {"key": "swing", "name": "Swing", "description": "Louver swing / oscillation", "icon": "wind"}},
       single_setpoint=True,
       context_defaults={"thermostat_sequence": 4, "cool_setpoint_min": 16, "cool_setpoint_max": 30, "heat_setpoint_min": 16, "heat_setpoint_max": 30},
       private_attrs={_IRB: _IRBLASTER_ATTRS},
       add=(
           _f("learn_key", "Learn code", "Write a code key or * to learn the next remote press for the current AC state (press the remote within 20 s)",
              "text", "w", icon="remote", category="ir", cluster=_IRB, max_length=15),
           _f("send_key", "Send code", "Transmit a stored code by its key — off, c24a1 (cool 24 °C fan auto swing on) or a named code such as light",
              "text", "w", icon="remote", category="ir", cluster=_IRB, max_length=15),
           _f("protocol", "IR protocol", "learn replays the learned frames; auto adopts the protocol detected from a learned frame; or a native encoder",
              "enum", "rw", icon="sliders", category="ir", cluster=_IRB, values=["learn", "auto", "coolix", "gree", "daikin", "electra"]),
           _f("hold", "Hold (local thermostat)", "Cycle the AC around the setpoint using the board's own temperature sensor",
              "binary", "rw", icon="thermometer", category="ir", cluster=_IRB, value_on="ON", value_off="OFF"),
           _f("last_result", "Last result", "Feedback from the last learn, send or remote press", "text", "r", icon="text", category="ir", cluster=_IRB),
           _f("code_count", "Stored codes", "Number of IR codes the device has learned", "numeric", "r", icon="counter", category="ir", cluster=_IRB),
           _f("temperature_offset", "Temperature offset", "Calibration of the on-board sensor", "numeric", "rw", icon="thermometer", category="config",
              cluster=_IRB, min=-10, max=10, step=0.1, unit="°C"),
           _f("led_brightness", "LED brightness", "Status LED brightness", "numeric", "rw", icon="sun", category="config", cluster=_IRB, min=1, max=100, step=1, unit="%"),
           _f("led_quiet", "LED quiet", "LED off while joined and healthy", "binary", "rw", icon="sun", category="config", cluster=_IRB, value_on="ON", value_off="OFF"),
       ),
       reporting={_IRB: ((0x0003, DataType.string, 1, 3600, None),)},
       read_on_join={_IRB: (0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008)}),
    # One Roof router: our own CC2652P range extender (the coordinator firmware repo, TARGET=router). A pure relay —
    # one endpoint (8) with Basic + Identify; Basic 0x1337 is the radio's transmit power, readable and writable,
    # persisted on the stick. Identify blinks its green LED.
    _q("One Roof", "One Roof Router", "unknown", "One Roof", "oneroof.router",
       description="Range extender: relays traffic for the devices around it and gives them a nearby parent. Nothing to switch — only its radio power and Identify",
       remove=("state", "power_on_behavior", "countdown", "brightness", "color_temp", "color"),
       private_attrs={0x0000: (PrivateAttr(0x1337, "transmit_power", DataType.int8),)},
       read_on_join={0x0000: (0x1337,)},
       add=(_f("transmit_power", "Transmit power", "Radio transmit power in dBm — 9 by default, up to 20 with the stick's amplifier. Saved on the stick across power cycles",
               "numeric", "rw", icon="signal", category="config", endpoint=8, cluster=0x0000, min=-20, max=20, step=1, unit="dBm"),)),
    _q("Aurora", "Smart plug", "plug", "Aurora", ("AU-A1ZBPIAB", "SmartPlug51AU", "SingleSocket50AU", "AU-A1ZBPIA")),
    _q("Aurora", "Contact sensor", "sensor", "Aurora", ("AU-A1ZBDWS", "DoorSensor51AU", "WindowSensor51AU"), remove=_SENSOR_CONTROLS),
    _q("Aurora", "Remote", "remote", "Aurora", ("AU-A1ZBRC", "WallRemote50AU", "Remote50AU", "AU-A1ZBR2GW", "AU-A1ZB2WDM"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("Aurora", "Dimmer", "light", "Aurora", ("AU-A1ZBMPRO1", "WallDimmerMaster", "AU-A1ZBDM", "AU-A1ZBIN1", "TWMPROZXBulb50AU"), remove=("countdown",)),
    _q("Lidl", "Smart plug", "plug", ("_TZ3000_kdi2o9m6", "_TZ3000_g5xawfcq", "_TZ3000_cphmq0q7", "_TZ3000_00mk2xzy", "_TZ3000_dksbtrzs", "_TZ3000_1obwwnmq", "_TZ3000_vzopcetz", "_TZ3000_wzauvbcs", "_TZ3000_4g6vgvne"), "TS011F", tuya_onoff_attrs=True, description="Silvercrest"),
    _q("Lidl", "Motion sensor", "sensor", "_TZ1800_fcdjzz3s", "TS0202", remove=_SENSOR_CONTROLS, description="Silvercrest"),
    _q("Lidl", "Contact sensor", "sensor", "_TZ1800_ejwkn2h2", "TS0203", remove=_SENSOR_CONTROLS, description="Silvercrest"),
    _q("Lidl", "Remote", "remote", "_TZ3000_*", "TS1001", remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE)), description="Silvercrest"),
    _q("Legrand", "Connected outlet", "plug", (" Legrand", "Legrand"), ("Connected outlet", "Connected outlet (US)", "Mobile outlet", "Plug-in socket", "Connected outlet (double)")),
    _q("Legrand", "Shutter switch", "cover", (" Legrand", "Legrand"), ("Shutter switch with neutral", "Shutter SW with level control", "Shutter switch"), remove=("state", "power_on_behavior", "countdown")),
    _q("Legrand", "Dimmer switch", "light", (" Legrand", "Legrand"), ("Dimmer switch w/o neutral", "Dimmer switch with neutral", "Dimmer switch wo neutral"), remove=("countdown",)),
    _q("Legrand", "Light switch", "switch", (" Legrand", "Legrand"), ("Light switch with neutral", "Micromodule switch", "Contactor", "Connected Light switch"), remove=("countdown",)),
    _q("Legrand", "Remote switch", "remote", (" Legrand", "Legrand"), ("Remote switch", "Double gangs remote switch", "Remote toggle switch", "Remote motion sensor", "Remote switch Wake up / Sleep", "Remote dimmer switch", "Pocket remote"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("Legrand", "Power consumption module", "meter", (" Legrand", "Legrand"), ("DIN power consumption module", "Micromodule meter"), remove=_SENSOR_CONTROLS),
    _q("Netatmo", "Wall switch", "switch", ("Netatmo", " Legrand"), ("Connected light switch", "Connected Light switch 2G", "Double gangs connected light switch"), remove=("countdown",)),
    _q("Schneider Electric", "Dimmer", "light", "Schneider Electric", ("PUCK/DIMMER/1", "NHROTARY/DIMMER/1", "CH/DIMMER/1", "CCT5011-0001", "CCT5011-0002", "E8331DST350ZB", "E8332DST350ZB", "EH-ZB-RTS", "MEG5116-0300/MEG5171-0000", "NHPB/DIMMER/1", "LK Dimmer", "CH2AX/DIMMER/1"), remove=("countdown",)),
    _q("Schneider Electric", "Switch", "switch", "Schneider Electric", ("PUCK/SWITCH/1", "NHPB/SWITCH/1", "CH/SWITCH/1", "CCT5010-0001", "CCT5010-0003", "MEG5161-0000", "EH-ZB-LMACT", "CH2AX/SWITCH/1", "LK Switch"), remove=("countdown",)),
    _q("Schneider Electric", "Shutter control", "cover", "Schneider Electric", ("NHPB/SHUTTER/1", "PUCK/SHUTTER/1", "CCT5015-0001", "CH/SHUTTER/1", "1GANG/SHUTTER/1", "MEG5165-0000", "NHROTARY/SHUTTER/1"), remove=("state", "power_on_behavior", "countdown")),
    _q("Schneider Electric", "Thermostat/TRV", "climate", "Schneider Electric", ("iTRV", "Thermostat", "EH-ZB-VACT", "EH-ZB-SPD-V2", "EH-ZB-HACT", "WV704R0A0902", "CCTFR6700", "EKO07259"), remove=_SENSOR_CONTROLS),
    _q("Schneider Electric", "Motion sensor", "sensor", "Schneider Electric", ("CCT595011_AS", "CCT595011", "W599001", "W599501", "SED-MOTION", "A9MEM1570"), remove=_SENSOR_CONTROLS),
    _q("Schneider Electric", "Water leak sensor", "sensor", "Schneider Electric", ("CCT593011_AS", "CCT593011", "W599521"), remove=_SENSOR_CONTROLS),
    _q("Schneider Electric", "Remote", "remote", "Schneider Electric", ("FLS/SYSTEM-M/4", "FLS/AIRLINK/4", "CCTFR6730", "CCT592011_AS", "NHPB/SWITCH/2", "NHPB/DIMMER/2", "SED-ZB-RTS"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("eWeLink", "Remote", "remote", "eWeLink", ("ZB-SW01", "ZB-SW02", "ZB-SW03", "ZB-SW04", "ZB-SW05", "MC01"), remove=_SENSOR_CONTROLS, add=(_battery(), _action(_GENERIC_REMOTE))),
    _q("eWeLink", "Smart plug", "plug", "eWeLink", ("SA-030-1", "ZB-SA-003", "ZB-SP01")),
)

# Vendor display names for models without a quirk -------------------------

VENDOR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("LUMI", "Aqara"), ("Xiaomi*", "Xiaomi"), ("_TZ1800_*", "Lidl"), ("_TZ*", "Tuya"), ("_TYZB*", "Tuya"), ("_TYST*", "Tuya"), ("TUYA*", "Tuya"), ("Tuya*", "Tuya"),
    ("IKEA of Sweden", "IKEA"), ("Philips", "Philips Hue"), ("Signify Netherlands B.V.", "Philips Hue"), ("eWeLink", "eWeLink"), ("SONOFF", "Sonoff"),
    ("innr", "Innr"), ("OSRAM", "OSRAM"), ("LEDVANCE", "LEDVANCE"), ("Samjin", "SmartThings"), ("SmartThings", "SmartThings"), ("CentraLite", "Centralite"),
    ("HEIMAN", "Heiman"), ("Heiman", "Heiman"), ("frient A/S", "frient"), ("Develco Products A/S", "Develco"), ("Develco", "Develco"), ("Third Reality, Inc", "Third Reality"),
    ("Danfoss", "Danfoss"), ("Eurotronic", "Eurotronic"), (" Legrand", "Legrand"), ("Legrand", "Legrand"), ("Netatmo", "Netatmo"), ("Schneider Electric", "Schneider Electric"),
    ("BOSCH", "Bosch"), ("Bosch", "Bosch"), ("Yale", "Yale"), ("Kwikset", "Kwikset"), ("Schlage", "Schlage"), ("Allegion", "Schlage"), ("ubisys", "Ubisys"),
    ("GLEDOPTO", "Gledopto"), ("Paulmann*", "Paulmann"), ("MLI", "Müller Licht"), ("LiXee", "LiXee"), ("Visonic", "Visonic"), ("Sercomm Corp.", "Sercomm"),
    ("Universal Electronics Inc", "Xfinity"), ("lk", "Linkind"), ("Linkind", "Linkind"), ("NAMRON AS", "Namron"), ("Namron*", "Namron"), ("Sunricher", "Sunricher"),
    ("Aurora", "Aurora"), ("Moes", "Moes"), ("Lidl*", "Lidl"), ("Silicon Labs", "Silicon Labs"), ("Texas Instruments", "Texas Instruments"), ("Sengled*", "Sengled"),
    ("Nanoleaf", "Nanoleaf"), ("Shelly", "Shelly"), ("Candeo", "Candeo"), ("Busch-Jaeger", "Busch-Jaeger"), ("Niko NV", "Niko"), ("Hive", "Hive"), ("Computime", "Hive"),
)


_DEFINITIONS: Any = None  # definitions.Definitions, installed by the gateway; user entries take precedence over QUIRKS


def set_definitions(defs: Any) -> None:
    """Install (or clear, with ``None``) the user-defined device definitions consulted by :func:`find_quirk`."""
    global _DEFINITIONS
    _DEFINITIONS = defs


def builtin_quirk(manufacturer: str | None, model: str | None) -> Quirk | None:
    if not manufacturer and not model:
        return None
    for q in QUIRKS:
        if q.matches(manufacturer, model):
            return q
    return None


def find_quirk(manufacturer: str | None, model: str | None) -> Quirk | None:
    if _DEFINITIONS is not None:
        q = _DEFINITIONS.quirk_for(manufacturer, model)
        if q is not None:
            return q
    return builtin_quirk(manufacturer, model)


def vendor_name(manufacturer: str | None, quirk: Quirk | None = None) -> str | None:
    if quirk:
        return quirk.vendor
    if not manufacturer:
        return None
    m = manufacturer.strip()
    for pat, name in VENDOR_PATTERNS:
        if fnmatch.fnmatchcase(m.lower(), pat.lower()):
            return name
    return m


# ---------------------------------------------------------------------------
# Device-level classification (no quirk)
# ---------------------------------------------------------------------------

_CATEGORY_LABEL = {"light": "Light", "plug": "Smart plug", "switch": "Switch", "sensor": "Sensor", "remote": "Button/remote", "cover": "Cover",
                   "climate": "Thermostat", "lock": "Lock", "meter": "Electricity meter", "unknown": "Unknown device"}



def category_label(category: str) -> str:
    return _CATEGORY_LABEL.get(category, "Unknown device")


_IAS_KIND = {0x0015: ("Contact sensor", "contact"), 0x000D: ("Motion sensor", "occupancy"), 0x002A: ("Water leak sensor", "water_leak"),
             0x0028: ("Smoke detector", "smoke"), 0x002B: ("CO detector", "carbon_monoxide"), 0x002D: ("Vibration sensor", "vibration"),
             0x002C: ("Panic button", "emergency"), 0x0226: ("Glass break sensor", "glass_break"), 0x0115: ("Key fob", "alarm_1"),
             0x021D: ("Keypad", "alarm_1"), 0x0225: ("Siren", "alarm_1")}

_SWITCH_DEVICE_IDS = {0x0000, 0x0001, 0x0004, 0x0006, 0x0103, 0x0104, 0x0105}


def is_battery_powered(dev: Device) -> bool:
    if dev.power_source:
        return "batt" in dev.power_source.lower()
    return not dev.rx_on_when_idle and not dev.is_router and bool(dev.endpoints)


def classify_device(dev: Device) -> tuple[str, str]:
    """Return ``(kind label, category)`` from clusters, device ids and power source."""
    ins: set[int] = set()
    outs: set[int] = set()
    ids: set[int] = set()
    onoff_eps = 0
    for ep in dev.endpoints.values():
        if ep.profile == 0xA1E0:  # Green Power proxy endpoint, not a function of the device
            continue
        ins |= set(ep.in_clusters)
        outs |= set(ep.out_clusters)
        ids.add(ep.device_id)
        if 0x0006 in ep.in_clusters:
            onoff_eps += 1
    if not ins and not outs:
        return ("Unknown device", "unknown")
    battery = is_battery_powered(dev)
    zt = dev.context.get("zone_type")
    if 0x0500 in ins:
        kind, _ = _IAS_KIND.get(zt, ("Security sensor", "alarm_1")) if zt is not None else ("Security sensor", "alarm_1")
        if kind in ("Key fob", "Keypad", "Panic button"):
            return (kind, "remote")
        return (kind, "sensor")
    if 0x0101 in ins and 0x0006 not in ins:
        return ("Door lock", "lock")
    if 0x0102 in ins:
        return ("Cover", "cover")
    if 0x0201 in ins:
        return ("Thermostat/TRV" if battery else "Thermostat", "climate")
    if 0x0006 in ins:
        if 0x0300 in ins:
            if 0x010C in ids and not ids & {0x010D, 0x0102, 0x0200, 0x0210}:
                return ("Bulb (colour temperature)", "light")
            return ("Bulb (colour)", "light")
        if 0x0008 in ins and ids & {0x0101, 0x010C, 0x0100, 0x0102, 0x010D}:
            return ("Bulb (colour temperature)" if 0x010C in ids else "Dimmable light", "light")
        if 0x0008 in ins:
            return ("Dimmer", "light")
        if battery:
            return ("Button/remote", "remote")
        if 0x0702 in ins or 0x0B04 in ins:
            if onoff_eps > 1:
                return (f"Smart plug ({onoff_eps} outlet)", "plug")
            return ("Smart plug", "plug")
        if onoff_eps > 1:
            return (f"Wall switch ({onoff_eps} gang)", "switch")
        if ids & {0x0051, 0x0009, 0x010A}:
            return ("Smart plug", "plug")
        if ids & _SWITCH_DEVICE_IDS:
            return ("Wall switch", "switch")
        return ("Switch", "switch")
    measure = {0x0402, 0x0405, 0x0403, 0x0400, 0x0406, 0x040D, 0x042A}
    if ins & measure:
        parts = []
        if 0x0406 in ins:
            parts.append("Motion")
        if 0x0402 in ins:
            parts.append("Temperature")
        if 0x0405 in ins:
            parts.append("humidity")
        if 0x0403 in ins:
            parts.append("pressure")
        if 0x040D in ins or 0x042A in ins:
            parts.append("air quality")
        if 0x0400 in ins and not parts:
            parts.append("Light")
        label = "/".join(parts) if parts else "Sensor"
        label = label[0].upper() + label[1:]
        return (label + " sensor", "sensor")
    if outs & {0x0006, 0x0008, 0x0005, 0x0300}:
        return ("Button/remote", "remote")
    if 0x0702 in ins or 0x0B04 in ins:
        return ("Electricity meter", "meter")
    if 0x0001 in ins and battery:
        return ("Battery device", "unknown")
    return ("Unknown device", "unknown")


# ---------------------------------------------------------------------------
# Public description
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceInfo:
    kind: str
    vendor: str | None
    category: str
    quirk: Quirk | None

    @property
    def description(self) -> str | None:
        return self.quirk.description or None if self.quirk else None


def tuya_dps(dev: Device, q: Quirk | None = None) -> tuple[Dp, ...]:
    """The datapoint map in force for a device: the quirk's (built-in or user-defined) map, else the
    conventions inferred from what the device has reported (``quirks_tuya``)."""
    if q is None:
        q = find_quirk(dev.manufacturer, dev.model)
    if q is not None and q.dps:
        return q.dps
    from . import quirks_tuya as qt
    if not qt.is_tuya_dp_device(dev):
        return ()
    return qt.infer(dev)[1]


def describe(dev: Device) -> DeviceInfo:
    q = find_quirk(dev.manufacturer, dev.model)
    if q is not None:
        kind, cat = q.kind, q.category
        if cat == "unknown" and q.dps == () and dev.endpoints:
            from . import quirks_tuya as qt
            guess = qt.infer_kind(dev) if qt.is_tuya_dp_device(dev) else None
            if guess is not None:
                kind, cat = guess
            else:
                k2, c2 = classify_device(dev)
                if c2 != "unknown":
                    kind, cat = k2, c2
        if q.kind in ("Bulb", "Light") and dev.endpoints:
            k2, c2 = classify_device(dev)
            if c2 == "light":
                kind = k2
    else:
        kind, cat = classify_device(dev)
    return DeviceInfo(kind, vendor_name(dev.manufacturer, q), cat, q)


def binding_policy(dev: Device) -> tuple[int, ...] | None:
    """Clusters the gateway may bind/configure for reporting: ``None`` = default, ``()`` = none."""
    q = find_quirk(dev.manufacturer, dev.model)
    return q.bind if q else None


# ---------------------------------------------------------------------------
# Feature shaping
# ---------------------------------------------------------------------------

_IAS_DEFAULT = {0x0015: ("contact", "Contact"), 0x000D: ("occupancy", "Motion"), 0x002A: ("water_leak", "Water leak"), 0x0028: ("smoke", "Smoke"),
                0x002B: ("carbon_monoxide", "CO"), 0x002D: ("vibration", "Vibration"), 0x002C: ("emergency", "Emergency"), 0x0226: ("glass_break", "Glass break")}


def shape_features(dev: Device, generic: list[dict[str, Any]], info: DeviceInfo) -> list[dict[str, Any]]:
    """Apply the quirk (or the device-level heuristics) to the generic feature list."""
    q = info.quirk
    out = [dict(f) for f in generic]
    remove = set(q.remove) if q else set()
    on_off_as = q.on_off_as if q else None

    if q is None:
        if info.category == "remote":
            remove |= {"state", "power_on_behavior", "countdown", "brightness", "color_temp", "color"}
        elif info.category in ("sensor", "meter", "lock", "climate", "cover") and is_battery_powered(dev):
            remove |= {"power_on_behavior", "countdown"}
    elif q.category != "remote" and not any(x["key"] == "action" for x in q.add):
        remove.add("action")  # the generic "this sends on/off commands" guess does not apply to a known non-remote
    if q and q.category == "remote":
        remove |= set(_SENSOR_CONTROLS)
    if q and q.category in ("plug", "switch"):
        remove |= {"brightness", "color_temp", "color"}  # some plugs advertise Level Control without meaning it

    if on_off_as and on_off_as != "action":
        name = {"contact": "Contact", "occupancy": "Motion", "water_leak": "Water leak", "smoke": "Smoke", "vibration": "Vibration"}.get(on_off_as, on_off_as.replace("_", " ").capitalize())
        desc = {"contact": "true = closed", "occupancy": "Motion detected"}.get(on_off_as, "Derived from the On/Off attribute")
        ep = next((f["endpoint"] for f in out if f["base"] == "state"), 1)
        out = [f for f in out if f["base"] not in ("state", "power_on_behavior", "countdown")]
        if not any(f["base"] == on_off_as for f in out):
            out.append(_binary_sensor(on_off_as, name, desc, ep=ep, cluster=0x0006, icon="hand" if on_off_as == "occupancy" else "shield"))
    elif on_off_as == "action":
        remove |= {"state", "power_on_behavior", "countdown"}

    out = [f for f in out if f["base"] not in remove]

    if q and q.relabel:
        for f in out:
            ov = q.relabel.get((f["endpoint"], f["base"]))
            if ov:
                f.update(ov)
    if q and q.single_setpoint:
        # one target temperature: the device keeps both ZCL setpoints equal (an air conditioner has
        # a single "set temperature"); the pair is replaced by target_temperature
        sps = [f for f in out if f["base"] in ("current_cooling_setpoint", "current_heating_setpoint")]
        if sps:
            ref = next((f for f in sps if f["base"] == "current_cooling_setpoint"), sps[0])
            at = out.index(sps[0])
            out = [f for f in out if f["base"] not in ("current_cooling_setpoint", "current_heating_setpoint")]
            # An air conditioner has ONE set temperature, but it is published under the property
            # name the rest of the world uses for a settable setpoint: every Zigbee consumer —
            # Home Assistant, the One Roof Bridge on its way to Apple Home, anything speaking the
            # usual dialect — looks for this name and would otherwise find no control at all.
            out.insert(at, _f("current_heating_setpoint", "Temperature", "Target temperature — one setpoint for cooling and heating", "numeric", "rw",
                              icon="thermometer", category="control", endpoint=ref["endpoint"], cluster=0x0201,
                              min=ref.get("min", 16), max=ref.get("max", 30), step=1, unit="°C", single_setpoint=True))

    if q and q.ias_key:
        for f in out:
            if f["cluster"] == 0x0500 and f["base"] in {k for k, _ in _IAS_DEFAULT.values()} | {"alarm_1"}:
                f["key"] = f["base"] = q.ias_key
                f["name"] = q.kind.replace(" detector", "").replace(" sensor", "")
                f.pop("values", None)

    if q and q.gangs:
        eps = sorted(ep.id for ep in dev.endpoints.values() if 0x0006 in ep.in_clusters)
        for f in out:
            if f["base"] in ("state", "power_on_behavior", "countdown", "brightness") and f["endpoint"] in eps:
                i = eps.index(f["endpoint"])
                if i < len(q.gangs):
                    f["key"] = f"{f['base']}_{q.gangs[i]}"
                    if q.gang_labels and i < len(q.gang_labels):
                        f["name"] = q.gang_labels[i] if f["base"] == "state" else f"{f['name']} ({q.gang_labels[i]})"
                    f["gang"] = q.gangs[i]

    if q and q.tuya_onoff_attrs:
        ep = next((f["endpoint"] for f in out if f["base"] == "state"), 1)
        out.append(_f("child_lock", "Child lock", "Lock the physical button", "binary", "rw", icon="lock", category="config", endpoint=ep, cluster=0x0006,
                      value_on="LOCK", value_off="UNLOCK"))
        out.append(_f("indicator_mode", "Indicator", "LED indicator behaviour", "enum", "rw", icon="sun", category="config", endpoint=ep, cluster=0x0006,
                      values=["off", "off/on", "on/off", "on"]))

    if q:
        have = {f["key"] for f in out}
        for extra in q.add:
            if extra["key"] not in have:
                out.append(dict(extra))
                have.add(extra["key"])
    if any(vz.TUYA_CLUSTER in ep.in_clusters for ep in dev.endpoints.values()):
        have = {f["key"] for f in out}
        mapped: set[int] = set()
        seen: set[str] = set()
        for dp in tuya_dps(dev, q):
            mapped.add(dp.dp)
            if dp.key in seen or dp.key in have:
                continue  # same key reported by another dp (e.g. cover position set vs report): keep the first
            seen.add(dp.key)
            out.append(_dp_feature(dp))
        # datapoints without a meaning stay visible as raw values so the UI can show (and the user can teach) them
        from . import quirks_tuya as qt
        raw: dict[int, Any] = {dp: info_.get("last") for dp, info_ in qt.seen_datapoints(dev).items()}
        for k, v in dev.state.items():
            if k.startswith("dp_") and k[3:].isdigit():
                raw.setdefault(int(k[3:]), v)
        for n in sorted(raw):
            k = f"dp_{n}"
            if n in mapped or k in have:
                continue
            v = raw[n]
            t = "binary" if isinstance(v, bool) else ("numeric" if isinstance(v, (int, float)) else "text")
            out.append(_f(k, f"Datapoint {n}", "Raw Tuya datapoint (meaning unknown for this model)", t, "r", icon="sliders", category="sensor", endpoint=1, cluster=vz.TUYA_CLUSTER, dp=n))

    if info.category in ("sensor", "remote", "meter"):
        for f in out:
            if f["category"] == "control" and f["access"] != "r" and f["type"] != "action":
                f["access"] = "r"
                f["category"] = "sensor"
    elif info.category == "light" and not any(f["base"] == "brightness" for f in out) and info.kind.startswith("Dimm"):
        pass

    # linkquality always last
    out.sort(key=lambda f: f["key"] == "linkquality")
    return out


def _dp_feature(dp: Dp) -> dict[str, Any]:
    extra: dict[str, Any] = {"dp": dp.dp, "dp_type": dp.dtype}
    if dp.inferred:
        extra["inferred"] = True
    if dp.device_class:
        extra["device_class"] = dp.device_class
    if dp.unit:
        extra["unit"] = dp.unit
    if dp.min is not None:
        extra["min"] = dp.min
    if dp.max is not None:
        extra["max"] = dp.max
    if dp.step is not None:
        extra["step"] = dp.step
    if dp.type == "enum" and dp.values:
        extra["values"] = list(dp.values.values())
    if dp.type == "binary":
        on, off = (dp.values or {1: True, 0: False}).get(1, True), (dp.values or {1: True, 0: False}).get(0, False)
        extra["value_on"], extra["value_off"] = (True if on == "true" else on), (False if off == "false" else off)
    cat = dp.category if dp.access == "r" or dp.category != "sensor" else "control"
    return _f(dp.key, dp.name, dp.description or dp.name, dp.type, dp.access, icon=dp.icon, category=cat, endpoint=1, cluster=0xEF00, **extra)


# ---------------------------------------------------------------------------
# State translation (wire → published keys)
# ---------------------------------------------------------------------------

_LUMI_CLICKS = {0: "hold", 1: "single", 2: "double", 3: "triple", 4: "quadruple", 16: "hold", 17: "release", 18: "shake", 255: "release"}


def translate_state(dev: Device, ep: int, changed: dict[str, Any], features: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Rename decoded keys to the device's published keys (multi-gang suffixes, on/off as
    contact/occupancy/action, Aqara voltage in mV, linear illuminance)."""
    if not changed:
        return changed
    q = find_quirk(dev.manufacturer, dev.model)
    from .features import features_for
    feats = features if features is not None else features_for(dev)
    by_ep_base: dict[tuple[int, str], str] = {}
    by_base: dict[str, list[str]] = {}
    for f in feats:
        by_ep_base.setdefault((f["endpoint"], f["base"]), f["key"])
        if f["key"] not in by_base.setdefault(f["base"], []):
            by_base[f["base"]].append(f["key"])
    out: dict[str, Any] = {}
    for k, v in changed.items():
        if q and q.on_off_as and k == "state" and isinstance(v, str):
            on = v == "ON"
            if q.on_off_as == "action":
                if on:
                    out["action"] = "single"
                continue
            out[q.on_off_as] = (not on) if q.on_off_as == "contact" else on
            continue
        if q and q.on_off_as and k in ("power_on_behavior",):
            continue
        key = by_ep_base.get((ep, k))
        if key is None and k in ("state", "brightness", "power_on_behavior", "countdown"):
            # A report from an endpoint we have no feature for (the shared ep 0xF2, a bulb that
            # answers on an endpoint its descriptor did not list). One feature of that kind on the
            # device: it is that one. Several (a multi-gang switch): nobody knows which gang spoke,
            # and writing it to the plain key would show one gang's answer as the whole device's.
            keys = by_base.get(k, [])
            if len(keys) == 1:
                key = keys[0]
            elif keys:
                continue
            else:
                key = k
        out[key or k] = v
    if q and q.single_setpoint and "current_cooling_setpoint" in out:
        # both ZCL setpoints mean the same thing here: report them as the one set temperature
        out["current_heating_setpoint"] = out.pop("current_cooling_setpoint")
    if q and q.vendor == "Aqara":
        v = out.get("voltage")
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v < 100:
            out["voltage"] = int(round(v * 1000))
    if q and q.illuminance_linear and "illuminance" in out and isinstance(out["illuminance"], (int, float)):
        out["illuminance_lux"] = out["illuminance"]
    return out


# ---------------------------------------------------------------------------
# Vendor attribute decoding (reports / read responses)
# ---------------------------------------------------------------------------

Record = tuple[int, int | None, Any, bytes | None]  # attr, dtype, value, raw


def decode_vendor_attributes(dev: Device, ep: int, cluster: int, records: list[Record]) -> tuple[dict[str, Any], set[int]]:
    """Model-aware decoding of vendor-private attributes. Returns ``(state, consumed attr ids)``;
    attributes not consumed are decoded by the standard cluster decoders."""
    q = find_quirk(dev.manufacturer, dev.model)
    manuf = (dev.manufacturer or "").strip().lower()
    out: dict[str, Any] = {}
    used: set[int] = set()
    is_lumi = manuf == "lumi" or (q is not None and q.vendor == "Aqara")

    for attr, _dtype, value, raw in records:
        pa = _private_attr(q, cluster, attr=attr)
        if pa is not None:
            out[pa.key] = _decode_private(pa, value)
            used.add(attr)
        elif is_lumi and cluster == 0x0000 and attr == vz.LUMI_ATTR_REPORT_BASIC:
            tags = vz.decode_lumi_tlv(raw, length_prefixed=True) if raw else {}
            out.update(_lumi_state(q, tags))
            used.add(attr)
        elif is_lumi and cluster == 0x0000 and attr == vz.LUMI_ATTR_REPORT_STRUCT:
            out.update(_lumi_state(q, vz.decode_lumi_struct(value)))
            used.add(attr)
        elif is_lumi and cluster == 0xFCC0 and attr == vz.LUMI_ATTR_REPORT_PRIVATE:
            tags = vz.decode_lumi_tlv(value if isinstance(value, (bytes, bytearray)) else raw, length_prefixed=not isinstance(value, (bytes, bytearray)))
            out.update(_lumi_state(q, tags))
            used.add(attr)
        elif cluster == 0x0012 and attr == 0x0055 and isinstance(value, int) and q and q.multistate:
            btn = q.multistate.get(ep)
            if btn is not None:
                click = _LUMI_CLICKS.get(value)
                if click:
                    out["action"] = f"{click}_{btn}" if btn else click
            used.add(attr)
        elif cluster == 0x0101 and attr == 0x0055 and isinstance(value, int) and q and q.kind == "Vibration sensor":
            act = {1: "vibration", 2: "tilt", 3: "drop"}.get(value)
            if act:
                out["action"] = act
            used.add(attr)
        elif cluster == 0x0006 and attr == 0x8000 and isinstance(value, int) and q and q.on_off_as == "action":
            out["action"] = {2: "double", 3: "triple", 4: "quadruple", 128: "many"}.get(value, f"{value}_clicks")
            used.add(attr)
        elif cluster in (0x000C, 0x000D) and attr == 0x0055 and q and q.analog.get(ep) and isinstance(value, (int, float)):
            key = q.analog[ep]
            out[key] = round(float(value), 2 if key != "energy" else 3)
            if key == "position":
                out[key] = int(round(float(value)))
            used.add(attr)
        elif cluster == 0x0006 and attr == 0x8000 and q and q.tuya_onoff_attrs:
            out["child_lock"] = "LOCK" if value else "UNLOCK"
            used.add(attr)
        elif cluster == 0x0006 and attr == 0x8001 and q and q.tuya_onoff_attrs and isinstance(value, int):
            out["indicator_mode"] = {0: "off", 1: "off/on", 2: "on/off", 3: "on"}.get(value, str(value))
            used.add(attr)
        elif cluster == 0x0006 and attr == 0x8002 and isinstance(value, int) and manuf.startswith("_tz"):
            out["power_on_behavior"] = {0: "off", 1: "on", 2: "previous"}.get(value, str(value))
            used.add(attr)
    return out, used


def _private_attr(q: Quirk | None, cluster: int, *, attr: int | None = None, key: str | None = None) -> PrivateAttr | None:
    if q is None or cluster not in q.private_attrs:
        return None
    for pa in q.private_attrs[cluster]:
        if (attr is not None and pa.attr == attr) or (key is not None and pa.key == key):
            return pa
    return None


def _decode_private(pa: PrivateAttr, value: Any) -> Any:
    if pa.dtype in (DataType.string, DataType.long_string):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).decode("utf-8", "replace")
        return "" if value is None else str(value)
    if pa.dtype == DataType.bool_:
        v = bool(value)
        return pa.values.get(v, v) if pa.values else v
    if pa.values is not None and isinstance(value, int):
        return pa.values.get(value, str(value))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return round(value / pa.scale, 2) if pa.scale != 1 else value
    return value


def private_attribute(dev: Device, cluster: int, key: str) -> PrivateAttr | None:
    """The model-table attribute behind a feature key on a device-specific cluster, if any."""
    return _private_attr(find_quirk(dev.manufacturer, dev.model), cluster, key=key)


def encode_private_attribute(dev: Device, cluster: int, key: str, value: Any) -> tuple[int, DataType, Any]:
    """``(attr, dtype, wire value)`` for writing a feature of a device-specific cluster. Raises
    ``ValueError`` for a value the attribute cannot take (too long, not one of the choices)."""
    pa = private_attribute(dev, cluster, key)
    if pa is None:
        raise ValueError(f"{key} is not writable on this device")
    if pa.dtype in (DataType.string, DataType.long_string):
        s = str(value)
        if len(s.encode("utf-8")) > pa.max_len:
            raise ValueError(f"{key} must be at most {pa.max_len} characters")
        return pa.attr, pa.dtype, s
    if pa.dtype == DataType.bool_:
        on = str(value).strip().upper() in ("ON", "TRUE", "1", "LOCK") if isinstance(value, str) else bool(value)
        return pa.attr, pa.dtype, on
    if pa.values is not None:
        rev = {str(v).lower(): k for k, v in pa.values.items()}
        if str(value).lower() not in rev:
            raise ValueError(f"{key} must be one of {sorted(pa.values.values())}")
        return pa.attr, pa.dtype, rev[str(value).lower()]
    return pa.attr, pa.dtype, int(round(float(value) * pa.scale))


def extra_reporting(dev: Device) -> dict[int, tuple[tuple[int, DataType, int, int, Any], ...]]:
    """Reporting the model table adds on top of the standard-cluster defaults."""
    q = find_quirk(dev.manufacturer, dev.model)
    return dict(q.reporting) if q else {}


def extra_reads(dev: Device) -> dict[int, tuple[int, ...]]:
    """Attributes the model table wants read at interview, on top of the standard-cluster defaults."""
    q = find_quirk(dev.manufacturer, dev.model)
    return dict(q.read_on_join) if q else {}


def feedback_reads(dev: Device, cluster: int) -> tuple[int, ...]:
    """Read-only attributes of a device-specific cluster worth re-reading after a write to it (a
    command in disguise answers through them, e.g. last_result / code_count)."""
    q = find_quirk(dev.manufacturer, dev.model)
    if q is None or cluster not in q.private_attrs:
        return ()
    from .features import features_for
    ro = {f["key"] for f in features_for(dev) if f["cluster"] == cluster and f["access"] == "r"}
    return tuple(pa.attr for pa in q.private_attrs[cluster] if pa.key in ro or pa.key == "protocol")


def _lumi_state(q: Quirk | None, tags: dict[int, Any]) -> dict[str, Any]:
    if not tags:
        return {}
    out = vz.lumi_common_state(tags)
    if q is None:
        return out
    for tag, (key, conv) in q.lumi_tags.items():
        if tag not in tags or tags[tag] is None:
            continue
        v = tags[tag]
        try:
            if callable(conv):
                out[key] = conv(v)
            elif isinstance(v, (int, float)) and not isinstance(v, bool):
                out[key] = round(v / conv, 2) if conv != 1 else v
        except (TypeError, ValueError):
            continue
    return out


# ---------------------------------------------------------------------------
# Tuya datapoints
# ---------------------------------------------------------------------------


def decode_tuya_values(dev: Device, datapoints: list[tuple[int, int, Any]]) -> dict[str, Any]:
    """Published keys for decoded ``(dp, type, value)`` triples: mapped datapoints become their feature key,
    the rest ``dp_<n>``. Used for live reports and to rebuild state after a definition change."""
    q = find_quirk(dev.manufacturer, dev.model)
    dps = {d.dp: d for d in tuya_dps(dev, q)}
    out: dict[str, Any] = {}
    for dp, _dtype, value in datapoints:
        d = dps.get(dp)
        if d is None:
            if isinstance(value, (bool, int, float, str)):
                out[f"dp_{dp}"] = value
            elif isinstance(value, bytes):
                out[f"dp_{dp}"] = value.hex()
            continue
        if d.type == "numeric" and isinstance(value, (int, float)) and not isinstance(value, bool):
            v = value / d.scale if d.scale != 1 else value
            if d.inverted or (d.key == "position" and q and q.cover_inverted):
                v = 100 - v
            out[d.key] = round(v, 2) if isinstance(v, float) else v
        elif d.type == "enum" and d.values is not None:
            out[d.key] = d.values.get(int(value) if not isinstance(value, bool) else int(value), str(value))
        elif d.type == "binary":
            on = bool(value) != d.inverted
            if d.values:
                lab = d.values.get(1 if on else 0, on)
                out[d.key] = True if lab == "true" else (False if lab == "false" else lab)
            else:
                out[d.key] = on
        else:
            out[d.key] = value if not isinstance(value, bytes) else value.hex()
    return out


def decode_tuya_report(dev: Device, cmd: int, payload: bytes) -> dict[str, Any]:
    if cmd not in (vz.TUYA_CMD_DATA_RESPONSE, vz.TUYA_CMD_DATA_REPORT, vz.TUYA_CMD_STATUS_REPORT):
        return {}
    return decode_tuya_values(dev, vz.decode_tuya_datapoints(payload))


def encode_tuya_command(dev: Device, key: str, value: Any, seq: int) -> bytes | None:
    """Payload for a ``setData`` that writes feature ``key``; ``None`` if the key is not a writable dp."""
    q = find_quirk(dev.manufacturer, dev.model)
    d = next((d for d in tuya_dps(dev, q) if d.key == key and d.access in ("rw", "w")), None)
    if d is None:
        return None
    if d.type == "enum" and d.values is not None:
        rev = {v: k for k, v in d.values.items()}
        if value not in rev:
            raise ValueError(f"{key} must be one of {list(rev)}")
        return vz.encode_tuya_datapoint(seq, d.dp, d.dtype, rev[value])
    if d.type == "binary":
        if d.values:
            rev = {v: k for k, v in d.values.items()}
            if value in rev:
                value = rev[value]
            elif isinstance(value, str) and value.upper() in rev:
                value = rev[value.upper()]
            elif value in ("true", "false"):
                value = value == "true"
        return vz.encode_tuya_datapoint(seq, d.dp, d.dtype, bool(value) != d.inverted)
    if d.type == "numeric":
        v = float(value)
        if d.min is not None and v < d.min or d.max is not None and v > d.max:
            raise ValueError(f"{key} must be between {d.min} and {d.max}")
        if d.inverted or (d.key == "position" and q and q.cover_inverted):
            v = 100 - v
        return vz.encode_tuya_datapoint(seq, d.dp, d.dtype, int(round(v * d.scale)))
    return vz.encode_tuya_datapoint(seq, d.dp, d.dtype, value)


# ---------------------------------------------------------------------------
# Remote / button commands (device acts as a client and *sends* commands)
# ---------------------------------------------------------------------------


def remote_action(dev: Device, ep: int, cluster: int, cmd: int, payload: bytes, manufacturer: int | None) -> str | None:
    """Map a command a device sent *to us* (on/off, level, scenes, vendor buttons) to a legacy-style action name."""
    q = find_quirk(dev.manufacturer, dev.model)
    ctx = dev.context
    action: str | None = None
    if cluster == 0x0006:
        if cmd == 0xFD and payload:  # Tuya TS004x press type
            t = {0: "single", 1: "double", 2: "hold"}.get(payload[0], f"press_{payload[0]}")
            action = t if (q and q.buttons == 1) else f"{ep}_{t}"
        else:
            action = {0x00: "off", 0x01: "on", 0x02: "toggle", 0x40: "off", 0x41: "on", 0x42: "on"}.get(cmd)
    elif cluster == 0x0008:
        if cmd in (0x01, 0x05) and payload:
            d = "up" if payload[0] == 0 else "down"
            ctx["last_move"] = d
            action = f"brightness_move_{d}"
        elif cmd in (0x02, 0x06) and payload:
            action = f"brightness_step_{'up' if payload[0] == 0 else 'down'}"
        elif cmd in (0x03, 0x07):
            action = "brightness_stop"
        elif cmd in (0x00, 0x04):
            action = "brightness_move_to_level"
    elif cluster == 0x0005:
        if manufacturer == 0x117C and len(payload) >= 2:  # IKEA arrows
            v = int.from_bytes(payload[0:2], "little")
            if cmd == 0x07:
                action = "arrow_left_click" if v == 257 else "arrow_right_click"
            elif cmd == 0x08:
                d = "left" if v == 3329 else "right"
                ctx["last_arrow"] = d
                action = f"arrow_{d}_hold"
            elif cmd == 0x09:
                action = f"arrow_{ctx.get('last_arrow', 'right')}_release"
        elif cmd == 0x05 and len(payload) >= 3:
            action = f"recall_{payload[2]}"
        elif cmd == 0x04 and len(payload) >= 3:
            action = f"store_{payload[2]}"
    elif cluster == 0x0300:
        if cmd == 0x4C and payload:
            action = "color_temperature_step_up" if payload[0] == 1 else "color_temperature_step_down"
        elif cmd == 0x4B and payload:
            action = {0: "color_temperature_move_stop", 1: "color_temperature_move_up", 3: "color_temperature_move_down"}.get(payload[0])
        elif cmd == 0x0A:
            action = "color_temperature_move"
        elif cmd == 0x07:
            action = "color_move"
        elif cmd == 0x47:
            action = "color_stop"
    elif cluster == 0xFC00 and cmd == 0x00 and len(payload) >= 5:  # Philips Hue buttons
        btn = {1: "on", 2: "up", 3: "down", 4: "off"}.get(payload[0], f"button_{payload[0]}")
        if q and "Tap dial" in q.kind:
            btn = f"button_{payload[0]}"
        t = {0: "press", 1: "hold", 2: "press_release", 3: "hold_release"}.get(payload[4], f"type_{payload[4]}")
        action = f"{btn}_{t}"
    elif cluster == 0xFC80 and cmd in (0x01, 0x02, 0x03, 0x04, 0x06):  # IKEA SOMRIG/RODRET button cluster
        t = {0x01: "initial_press", 0x02: "long_press", 0x03: "short_release", 0x04: "long_release", 0x06: "double_press"}[cmd]
        action = f"{ep}_{t}"
    if action is None:
        return None
    if q:
        if action == "brightness_stop" and q.action_map.get("brightness_move_up"):
            action = f"brightness_{ctx.get('last_move', 'up')}_release"
        else:
            action = q.action_map.get(action, action)
    return action


__all__ = ["Quirk", "Dp", "QUIRKS", "find_quirk", "builtin_quirk", "set_definitions", "vendor_name", "describe", "DeviceInfo", "classify_device",
           "is_battery_powered", "binding_policy", "shape_features", "tuya_dps", "translate_state", "decode_vendor_attributes", "decode_tuya_values",
           "decode_tuya_report", "encode_tuya_command", "remote_action"]
