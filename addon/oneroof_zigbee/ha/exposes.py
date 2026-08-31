"""Device description in the *exposes* format the previous setup published on
``<base>/bridge/devices``. Other One Roof apps (Bridge → Apple Home, NVR) build their
accessories from it, so the gateway publishes the same description for every device,
derived from our own feature list.

Shape (per device):
    {"ieee_address", "friendly_name", "type": "Router"|"EndDevice", "supported": true,
     "definition": {"vendor", "model", "description", "exposes": [...]}}

An *expose* is either a composite (light, switch, lock, cover, climate) with ``features``, or a
single feature: ``{"type": binary|numeric|enum|text, "name", "property", "access", ...}``.
``access`` bits: 1 = published in state, 2 = settable via <topic>/set, 4 = readable via /get.
"""

from __future__ import annotations

from typing import Any

from ..devices import Device
from ..features import features_for

ACCESS_STATE = 1
ACCESS_SET = 2
ACCESS_GET = 4


def _access(f: dict[str, Any]) -> int:
    if f["access"] == "rw":
        return ACCESS_STATE | ACCESS_SET | ACCESS_GET
    if f["access"] == "w":
        return ACCESS_SET
    return ACCESS_STATE


def _binary(f: dict[str, Any], on: Any = None, off: Any = None, toggle: Any = None, access: int | None = None) -> dict[str, Any]:
    d = {"type": "binary", "name": f["base"], "property": f["key"], "label": f["name"], "access": access if access is not None else _access(f),
         "value_on": f.get("value_on", True) if on is None else on, "value_off": f.get("value_off", False) if off is None else off}
    if toggle is not None:
        d["value_toggle"] = toggle
    return d


def _numeric(f: dict[str, Any], access: int | None = None) -> dict[str, Any]:
    d = {"type": "numeric", "name": f["base"], "property": f["key"], "label": f["name"], "access": access if access is not None else _access(f)}
    if f.get("unit"):
        d["unit"] = f["unit"]
    if f.get("min") is not None:
        d["value_min"] = f["min"]
    if f.get("max") is not None:
        d["value_max"] = f["max"]
    if f.get("step") is not None:
        d["value_step"] = f["step"]
    return d


def _enum(f: dict[str, Any], access: int | None = None) -> dict[str, Any]:
    return {"type": "enum", "name": f["base"], "property": f["key"], "label": f["name"], "access": access if access is not None else _access(f),
            "values": list(f.get("values") or [])}


def exposes_for(dev: Device) -> list[dict[str, Any]]:
    feats = features_for(dev)
    by_ep: dict[int, dict[str, dict[str, Any]]] = {}
    for f in feats:
        by_ep.setdefault(f["endpoint"], {})[f["base"]] = f
    handled: set[str] = set()
    out: list[dict[str, Any]] = []
    rw = ACCESS_STATE | ACCESS_SET | ACCESS_GET

    for _ep, bases in by_ep.items():
        st = bases.get("state")
        if st and st["cluster"] == 0x0006 and st["access"] == "rw":
            br, ct, col = bases.get("brightness"), bases.get("color_temp"), bases.get("color")
            state = _binary(st, "ON", "OFF", "TOGGLE", rw)
            if br or ct or col:
                features = [state]
                if br:
                    features.append(_numeric(br, rw))
                if ct:
                    features.append(_numeric(ct, rw))
                if col:
                    features.append({"type": "composite", "name": "color_xy", "property": col["key"], "label": col["name"], "access": rw,
                                     "features": [{"type": "numeric", "name": "x", "property": "x", "access": rw},
                                                  {"type": "numeric", "name": "y", "property": "y", "access": rw}]})
                out.append({"type": "light", "features": features})
                handled |= {x["key"] for x in (st, br, ct, col) if x}
            else:
                gang = st["key"][len("state"):].lstrip("_") if st["key"] != "state" else ""
                sw: dict[str, Any] = {"type": "switch", "features": [state]}
                if gang:
                    sw["endpoint"] = gang
                out.append(sw)
                handled.add(st["key"])
        elif st and st["cluster"] == 0x0101:
            out.append({"type": "lock", "features": [_binary(st, "LOCK", "UNLOCK", None, rw)]})
            handled.add(st["key"])
        pos, cov = bases.get("position"), bases.get("cover")
        if cov or (pos and pos["access"] == "rw"):
            features = []
            if cov:
                features.append({"type": "enum", "name": "state", "property": "state", "access": ACCESS_SET | ACCESS_STATE,
                                 "values": list(cov.get("values") or ["OPEN", "CLOSE", "STOP"])})
            if pos:
                features.append(_numeric(pos))
            out.append({"type": "cover", "features": features})
            handled |= {x["key"] for x in (pos, cov) if x}
        lt, sp, cp, tt = bases.get("local_temperature"), bases.get("current_heating_setpoint"), bases.get("current_cooling_setpoint"), bases.get("target_temperature")
        if sp or cp or tt:
            features = []
            if lt:
                features.append(_numeric(lt, ACCESS_STATE | ACCESS_GET))
            for x in (tt, sp, cp):
                if x:
                    features.append(_numeric(x, rw))
            mode = bases.get("system_mode")
            if mode:
                features.append(_enum(mode, rw if mode["access"] == "rw" else ACCESS_STATE))
                handled.add(mode["key"])
            fan = bases.get("fan_mode")
            if fan:
                features.append(_enum(fan, rw if fan["access"] == "rw" else ACCESS_STATE))
                handled.add(fan["key"])
            preset = bases.get("preset")
            if preset:
                features.append(_enum(preset, rw if preset["access"] == "rw" else ACCESS_STATE))
                handled.add(preset["key"])
            out.append({"type": "climate", "features": features})
            handled |= {x["key"] for x in (lt, sp, cp, tt) if x}

    for f in feats:
        key, typ = f["key"], f["type"]
        if key in handled or typ == "composite":
            continue
        if typ == "binary":
            if key == "child_lock":
                out.append(_binary(f, "LOCK", "UNLOCK", None))
            elif f["base"] == "contact":
                # Contact is the one sensor defined "backwards": the value is true when CLOSED, so
                # the alarm/active state (open) is value_on=false — exactly what the previous setup
                # declared and what Apple Home bridges key their polarity on.
                out.append(_binary(f, False, True))
            elif f["access"] == "r":
                out.append(_binary(f))
            else:
                out.append(_binary(f, f.get("value_on", "ON"), f.get("value_off", "OFF"), f.get("value_toggle")))
        elif typ == "numeric":
            out.append(_numeric(f))
        elif typ == "enum":
            out.append(_enum(f))
        elif typ == "action":
            out.append({"type": "enum", "name": f["base"], "property": f["key"], "label": f["name"], "access": ACCESS_STATE, "values": list(f.get("values") or [])})
        elif typ == "text":
            if f["access"] == "r":
                out.append({"type": "enum", "name": f["base"], "property": f["key"], "label": f["name"], "access": ACCESS_STATE, "values": list(f.get("values") or [])})
            else:
                out.append({"type": "text", "name": f["base"], "property": f["key"], "label": f["name"], "access": _access(f)})
    return out


def device_description(dev: Device) -> dict[str, Any]:
    return {
        "ieee_address": dev.ieee_str,
        "friendly_name": dev.friendly_name,
        "type": "Router" if dev.is_router else "EndDevice",
        "supported": True,
        "interview_completed": bool(dev.interviewed),
        "power_source": dev.power_source,
        "definition": {"vendor": dev.vendor or dev.manufacturer or "Zigbee", "model": dev.model or "unknown",
                       "description": dev.kind, "exposes": exposes_for(dev)},
    }
