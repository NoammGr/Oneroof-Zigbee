"""User-defined device definitions ("teach it").

A definition tells the gateway what a model *is* and what its Tuya datapoints
mean, for models the built-in table does not know or gets wrong.  Definitions
live in ``<data_dir>/definitions.yaml`` (0600), are keyed by a (manufacturer,
model) pattern pair, apply to every device of that model, take precedence over
the built-in table and are picked up without a restart.

Shape of one definition (YAML):

    - manufacturer: _TZE200_abcdefgh        # fnmatch pattern, case-insensitive
      model: TS0601
      kind: Soil sensor                      # optional overrides
      vendor: Tuya
      category: sensor                       # light plug switch sensor remote cover climate lock meter unknown
      on_off_as: contact                     # optional: read the On/Off attribute as this key
      remove: [power_on_behavior]            # generic feature keys to drop
      datapoints:
        - dp: 3
          key: soil_moisture
          name: Soil moisture
          type: numeric                      # numeric | binary | enum | text
          access: r                          # r | rw | w
          scale: 1                           # reported value / scale
          unit: "%"
          values: {0: closed, 1: open}       # enum labels (also binary labels)
          inverted: false
          dtype: value                       # wire type used for writes: bool value enum string raw bitmap
          device_class: moisture             # Home Assistant device class
          category: sensor                   # sensor | control | config | diagnostic
          min: 0
          max: 100
          step: 1

The compiled result is an ordinary :class:`quirks.Quirk`, merged over the
built-in entry for the same model when one exists (datapoints with the same id
replace the built-in ones, ``remove`` drops keys, ``kind``/``vendor``/
``category``/``on_off_as`` override).
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from . import quirks
from .zcl import vendor as vz

log = logging.getLogger("oneroof_zigbee.definitions")

CATEGORIES = ("light", "plug", "switch", "sensor", "remote", "cover", "climate", "lock", "meter", "unknown")
DP_TYPES = ("numeric", "binary", "enum", "text")
DP_ACCESS = ("r", "rw", "w")
DP_CATEGORIES = ("sensor", "control", "config", "diagnostic")
DTYPES = {"bool": vz.TUYA_BOOL, "value": vz.TUYA_VALUE, "enum": vz.TUYA_ENUM, "string": vz.TUYA_STRING, "raw": vz.TUYA_RAW, "bitmap": vz.TUYA_BITMAP}
DTYPE_NAMES = {v: k for k, v in DTYPES.items()}
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
_CLASS_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_PATTERN_RE = re.compile(r"^[\x21-\x7e]{1,64}$")  # printable ASCII, no spaces (a pattern may contain * and ?)
_DP_FIELDS = {"dp", "key", "name", "type", "access", "scale", "unit", "values", "inverted", "dtype", "device_class", "category", "min", "max", "step", "description"}
_TOP_FIELDS = {"manufacturer", "model", "kind", "vendor", "category", "on_off_as", "remove", "datapoints"}
MAX_DEFINITIONS = 500


def _str(v: Any, name: str, maxlen: int, *, allow_empty: bool = False) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError(f"{name} must be a string")
    v = v.strip()
    if not v:
        if allow_empty:
            return None
        raise ValueError(f"{name} must not be empty")
    if len(v) > maxlen:
        raise ValueError(f"{name} too long (max {maxlen})")
    return v


def _number(v: Any, name: str) -> float | None:
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError(f"{name} must be a number")
    return float(v) if isinstance(v, float) or v != int(v) else int(v)


def validate_datapoint(d: Any) -> dict[str, Any]:
    """Return a normalised datapoint dict or raise ``ValueError``."""
    if not isinstance(d, dict):
        raise ValueError("datapoint must be an object")
    unknown = set(d) - _DP_FIELDS
    if unknown:
        raise ValueError(f"unknown datapoint field(s): {', '.join(sorted(unknown))}")
    dp = d.get("dp")
    if isinstance(dp, str) and dp.strip().isdigit():
        dp = int(dp)
    if isinstance(dp, bool) or not isinstance(dp, int) or not 1 <= dp <= 255:
        raise ValueError("dp must be an integer 1..255")
    key = _str(d.get("key"), "key", 48)
    if not key or not _KEY_RE.match(key):
        raise ValueError(f"key {key!r} must be lowercase letters, digits and underscores, starting with a letter")
    if key.startswith("dp_") or key in ("linkquality", "last_seen"):
        raise ValueError(f"key {key!r} is reserved")
    typ = d.get("type", "numeric")
    if typ not in DP_TYPES:
        raise ValueError(f"type must be one of {', '.join(DP_TYPES)}")
    access = d.get("access", "r")
    if access not in DP_ACCESS:
        raise ValueError(f"access must be one of {', '.join(DP_ACCESS)}")
    cat = d.get("category", "sensor")
    if cat not in DP_CATEGORIES:
        raise ValueError(f"category must be one of {', '.join(DP_CATEGORIES)}")
    scale = _number(d.get("scale"), "scale")
    scale = 1 if scale is None else scale
    if scale <= 0:
        raise ValueError("scale must be positive")
    values: dict[int, str] | None = None
    if d.get("values") is not None:
        raw = d["values"]
        if isinstance(raw, list):
            raw = dict(enumerate(raw))
        if not isinstance(raw, dict) or not raw:
            raise ValueError("values must be a non-empty map of number → label")
        values = {}
        for k, v in raw.items():
            try:
                n = int(k)
            except (TypeError, ValueError) as e:
                raise ValueError(f"values key {k!r} must be an integer") from e
            if not isinstance(v, (str, int, float, bool)) or isinstance(v, str) and not v.strip():
                raise ValueError(f"values[{n}] must be a label")
            label = v.strip() if isinstance(v, str) else ("true" if v is True else "false" if v is False else str(v))
            if len(label) > 48:
                raise ValueError(f"values[{n}] too long")
            values[n] = label
        if len(values) > 64:
            raise ValueError("too many values")
    if typ == "enum" and not values:
        raise ValueError("enum datapoints need a values map")
    dtype = d.get("dtype")
    if dtype is None:
        dtype = {"binary": "bool", "enum": "enum", "text": "string"}.get(typ, "value")
    if isinstance(dtype, int) and not isinstance(dtype, bool):
        if dtype not in DTYPE_NAMES:
            raise ValueError("dtype must be 0..5")
        dtype = DTYPE_NAMES[dtype]
    if dtype not in DTYPES:
        raise ValueError(f"dtype must be one of {', '.join(DTYPES)}")
    inverted = d.get("inverted", False)
    if not isinstance(inverted, bool):
        raise ValueError("inverted must be true or false")
    device_class = _str(d.get("device_class"), "device_class", 32, allow_empty=True)
    if device_class and not _CLASS_RE.match(device_class):
        raise ValueError("device_class must be lowercase letters, digits and underscores")
    out: dict[str, Any] = {"dp": dp, "key": key, "name": _str(d.get("name"), "name", 64, allow_empty=True) or key.replace("_", " ").capitalize(),
                           "type": typ, "access": access, "category": cat}
    if scale != 1:
        out["scale"] = scale
    unit = _str(d.get("unit"), "unit", 16, allow_empty=True)
    if unit:
        out["unit"] = unit
    if values:
        out["values"] = values
    if inverted:
        out["inverted"] = True
    out["dtype"] = dtype
    if device_class:
        out["device_class"] = device_class
    for f in ("min", "max", "step"):
        n = _number(d.get(f), f)
        if n is not None:
            out[f] = n
    if out.get("min") is not None and out.get("max") is not None and out["min"] > out["max"]:
        raise ValueError("min must not exceed max")
    desc = _str(d.get("description"), "description", 200, allow_empty=True)
    if desc:
        out["description"] = desc
    return out


def validate_definition(manufacturer: Any, model: Any, body: Any) -> dict[str, Any]:
    """Return a normalised definition dict or raise ``ValueError``."""
    if not isinstance(body, dict):
        raise ValueError("definition must be an object")
    unknown = set(body) - _TOP_FIELDS
    if unknown:
        raise ValueError(f"unknown field(s): {', '.join(sorted(unknown))}")
    m = _str(manufacturer, "manufacturer", 64)
    d = _str(model, "model", 64)
    if not m or not _PATTERN_RE.match(m):
        raise ValueError("manufacturer must be 1..64 printable characters without spaces")
    if not d or not _PATTERN_RE.match(d):
        raise ValueError("model must be 1..64 printable characters without spaces")
    out: dict[str, Any] = {"manufacturer": m, "model": d}
    kind = _str(body.get("kind"), "kind", 64, allow_empty=True)
    if kind:
        out["kind"] = kind
    vendor = _str(body.get("vendor"), "vendor", 32, allow_empty=True)
    if vendor:
        out["vendor"] = vendor
    cat = body.get("category")
    if cat not in (None, ""):
        if cat not in CATEGORIES:
            raise ValueError(f"category must be one of {', '.join(CATEGORIES)}")
        out["category"] = cat
    ooa = _str(body.get("on_off_as"), "on_off_as", 48, allow_empty=True)
    if ooa:
        if not _KEY_RE.match(ooa):
            raise ValueError("on_off_as must be a state key")
        out["on_off_as"] = ooa
    rm = body.get("remove") or []
    if not isinstance(rm, list) or not all(isinstance(x, str) and _KEY_RE.match(x) for x in rm):
        raise ValueError("remove must be a list of state keys")
    if rm:
        out["remove"] = sorted(set(rm))
    dps = body.get("datapoints") or []
    if not isinstance(dps, list):
        raise ValueError("datapoints must be a list")
    if len(dps) > 255:
        raise ValueError("too many datapoints")
    seen_dp: set[int] = set()
    seen_key: set[str] = set()
    norm = []
    for x in dps:
        v = validate_datapoint(x)
        if v["dp"] in seen_dp:
            raise ValueError(f"dp {v['dp']} listed twice")
        if v["key"] in seen_key:
            raise ValueError(f"key {v['key']!r} used twice")
        seen_dp.add(v["dp"])
        seen_key.add(v["key"])
        norm.append(v)
    out["datapoints"] = sorted(norm, key=lambda x: x["dp"])
    return out


def datapoint_to_dp(d: dict[str, Any]) -> quirks.Dp:
    return quirks.Dp(d["dp"], d["key"], d["name"], type=d.get("type", "numeric"), access=d.get("access", "r"), scale=d.get("scale", 1),
                     values=d.get("values"), unit=d.get("unit"), category=d.get("category", "sensor"), icon=_icon(d),
                     dtype=DTYPES[d.get("dtype", "value")], min=d.get("min"), max=d.get("max"), step=d.get("step"),
                     description=d.get("description", ""), inverted=bool(d.get("inverted")), device_class=d.get("device_class"))


def _icon(d: dict[str, Any]) -> str:
    k = d["key"]
    dc = d.get("device_class") or ""
    if "temp" in k or dc == "temperature":
        return "thermometer"
    if "humid" in k or "moist" in k or "leak" in k or dc in ("humidity", "moisture"):
        return "drop"
    if "batter" in k:
        return "battery"
    if "lock" in k:
        return "lock"
    if "position" in k or "cover" in k:
        return "arrows"
    if "bright" in k or "illum" in k:
        return "sun"
    if "presence" in k or "occup" in k or "contact" in k:
        return "hand"
    if "power" in k or "energy" in k or "current" in k or "voltage" in k:
        return "bolt"
    if "time" in k or "delay" in k or "duration" in k or "countdown" in k:
        return "clock"
    if d.get("type") == "binary":
        return "power" if d.get("access") != "r" else "shield"
    return "sliders"


def compile_quirk(defn: dict[str, Any], base: quirks.Quirk | None) -> quirks.Quirk:
    """Merge a definition over the built-in quirk for the same model (or over an empty one)."""
    manufacturer, model = defn["manufacturer"], defn["model"]
    remove = tuple(defn.get("remove", ()))
    user_dps = {d["dp"]: datapoint_to_dp(d) for d in defn.get("datapoints", ())}
    placeholder = base is not None and base.category == "unknown" and not base.dps  # e.g. the generic "Tuya device (datapoints)" entry
    kind = defn.get("kind")
    if not kind:
        if defn.get("category") and (base is None or placeholder):
            kind = quirks.category_label(defn["category"])
        elif base is not None:
            kind = base.kind
        else:
            kind = "Device (user definition)"
    if base is not None:
        dps = [user_dps.pop(d.dp, d) for d in base.dps] + list(user_dps.values())
        q = replace(base, manufacturer=(manufacturer,), model=(model,), kind=kind, vendor=defn.get("vendor", base.vendor),
                    category=defn.get("category", base.category), on_off_as=defn.get("on_off_as", base.on_off_as),
                    remove=tuple(dict.fromkeys(base.remove + remove)), description=base.description or "User definition")
    else:
        dps = list(user_dps.values())
        q = quirks.Quirk(defn.get("vendor") or quirks.vendor_name(manufacturer) or manufacturer, kind, defn.get("category", "unknown"),
                         (manufacturer,), (model,), description="User definition", on_off_as=defn.get("on_off_as"), remove=remove)
    dps = [d for d in dps if d.key not in remove]
    return replace(q, dps=tuple(sorted(dps, key=lambda d: d.dp)), user_defined=True)


class Definitions:
    """Store + cache. ``quirk_for`` is on the hot path (every ``Device.kind`` access), so compiled quirks are cached."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._defs: dict[tuple[str, str], dict[str, Any]] = {}
        self._cache: dict[tuple[str, str], quirks.Quirk | None] = {}
        self.reload()

    # -- persistence -------------------------------------------------------

    def reload(self) -> None:
        self._defs.clear()
        self._cache.clear()
        if not self.path or not self.path.exists():
            return
        try:
            data = yaml.safe_load(self.path.read_text()) or {}
        except (OSError, yaml.YAMLError):
            log.exception("definitions.yaml unreadable; ignoring it")
            return
        for item in (data.get("definitions") if isinstance(data, dict) else None) or []:
            try:
                d = validate_definition(item.get("manufacturer"), item.get("model"), {k: v for k, v in item.items() if k not in ("manufacturer", "model")})
            except (ValueError, AttributeError) as e:
                log.warning("definitions.yaml: skipping entry %r: %s", item, e)
                continue
            self._defs[self._key(d["manufacturer"], d["model"])] = d

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(self.export_yaml())
        os.replace(tmp, self.path)

    @staticmethod
    def _key(manufacturer: str, model: str) -> tuple[str, str]:
        return manufacturer.strip().lower(), model.strip().lower()

    # -- access ------------------------------------------------------------

    def all(self) -> list[dict[str, Any]]:
        return [dict(d) for _, d in sorted(self._defs.items())]

    def get(self, manufacturer: str, model: str) -> dict[str, Any] | None:
        d = self._defs.get(self._key(manufacturer, model))
        return dict(d) if d else None

    def find(self, manufacturer: str | None, model: str | None) -> dict[str, Any] | None:
        """The definition whose patterns match a device's manufacturer/model (exact key first, then patterns)."""
        if not self._defs:
            return None
        m, d = (manufacturer or "").strip().lower(), (model or "").strip().lower()
        exact = self._defs.get((m, d))
        if exact:
            return exact
        for (pm, pd), defn in self._defs.items():
            if fnmatch.fnmatchcase(m, pm) and fnmatch.fnmatchcase(d, pd):
                return defn
        return None

    def quirk_for(self, manufacturer: str | None, model: str | None) -> quirks.Quirk | None:
        if not self._defs:
            return None
        key = self._key(manufacturer or "", model or "")
        if key in self._cache:
            return self._cache[key]
        defn = self.find(manufacturer, model)
        q = compile_quirk(defn, quirks.builtin_quirk(manufacturer, model)) if defn else None
        if len(self._cache) > 2000:
            self._cache.clear()
        self._cache[key] = q
        return q

    # -- mutation ----------------------------------------------------------

    def put(self, manufacturer: str, model: str, body: dict[str, Any]) -> dict[str, Any]:
        d = validate_definition(manufacturer, model, body)
        key = self._key(d["manufacturer"], d["model"])
        if key not in self._defs and len(self._defs) >= MAX_DEFINITIONS:
            raise ValueError(f"at most {MAX_DEFINITIONS} definitions")
        self._defs[key] = d
        self._changed([key])
        return dict(d)

    def delete(self, manufacturer: str, model: str) -> bool:
        key = self._key(manufacturer, model)
        if key not in self._defs:
            return False
        del self._defs[key]
        self._changed([key])
        return True

    def _changed(self, keys: list[tuple[str, str]]) -> None:
        self._cache.clear()
        self._save()

    # -- export / import ---------------------------------------------------

    def export_yaml(self) -> str:
        return yaml.safe_dump({"definitions": self.all()}, sort_keys=False, allow_unicode=True)

    def import_yaml(self, text: str, *, replace_all: bool = False) -> list[dict[str, Any]]:
        """Validate every entry first; nothing is written unless all of them pass. Returns the imported definitions."""
        if len(text) > 2_000_000:
            raise ValueError("file too large")
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"not valid YAML: {e}") from e
        items = data.get("definitions") if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ValueError("expected a list under 'definitions'")
        norm: list[dict[str, Any]] = []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(f"entry {i + 1}: not an object")
            try:
                norm.append(validate_definition(item.get("manufacturer"), item.get("model"), {k: v for k, v in item.items() if k not in ("manufacturer", "model")}))
            except ValueError as e:
                raise ValueError(f"entry {i + 1} ({item.get('manufacturer')}/{item.get('model')}): {e}") from e
        if (0 if replace_all else len(self._defs)) + len(norm) > MAX_DEFINITIONS:
            raise ValueError(f"at most {MAX_DEFINITIONS} definitions")
        keys = [self._key(d["manufacturer"], d["model"]) for d in norm]
        if replace_all:
            keys += list(self._defs)
            self._defs.clear()
        for d in norm:
            self._defs[self._key(d["manufacturer"], d["model"])] = d
        self._changed(sorted(set(keys)))
        return norm


__all__ = ["Definitions", "validate_definition", "validate_datapoint", "compile_quirk", "datapoint_to_dp", "CATEGORIES", "DP_TYPES", "DP_ACCESS",
           "DP_CATEGORIES", "DTYPES", "DTYPE_NAMES"]
