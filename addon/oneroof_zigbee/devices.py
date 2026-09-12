"""Persistent device registry (JSON on disk, atomic writes)."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .znp.wire import ieee_int, ieee_str

log = logging.getLogger("oneroof_zigbee.devices")


@dataclass
class Endpoint:
    id: int
    profile: int = 0
    device_id: int = 0
    in_clusters: list[int] = field(default_factory=list)
    out_clusters: list[int] = field(default_factory=list)
    category: str = "unknown"


@dataclass
class Device:
    ieee: int
    nwk: int
    friendly_name: str
    manufacturer: str | None = None
    model: str | None = None
    sw_build: str | None = None
    power_source: str | None = None
    is_router: bool = False
    rx_on_when_idle: bool = False
    endpoints: dict[int, Endpoint] = field(default_factory=dict)
    interviewed: bool = False
    joined_at: float = field(default_factory=time.time)
    last_seen: float = 0.0
    lqi: int | None = None
    state: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)  # per-device converter context (zone_type, divisors…)
    available: bool = True
    description: str | None = None
    wall_switched: bool = False     # lives behind a physical switch that cuts its power: silence means "off", not "gone"
    hw_version: int | None = None
    date_code: str | None = None
    zcl_version: int | None = None
    app_version: int | None = None
    stack_version: int | None = None
    interview_error: str | None = None
    activity: list[dict[str, Any]] = field(default_factory=list)      # last 50 {ts,key,old,new}
    reporting: list[dict[str, Any]] = field(default_factory=list)     # configured reports
    bindings: list[dict[str, Any]] = field(default_factory=list)      # bindings we created
    raw: dict[str, dict[str, Any]] = field(default_factory=dict)      # "<cluster>": {"<attr>": {name,value,ts}}

    def record_changes(self, changed: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        """Apply `changed` to state, returning the list of actual changes."""
        events = []
        for k, v in changed.items():
            old = self.state.get(k)
            if old != v:
                events.append({"ts": ts, "key": k, "old": old, "new": v})
            self.state[k] = v
        if events:
            self.activity.extend(events)
            del self.activity[:-50]
        return events

    @property
    def ieee_str(self) -> str:
        return ieee_str(self.ieee)

    # -- model knowledge (derived, never persisted as truth) ------------------

    def _info(self) -> Any:
        from .quirks import describe  # local import: quirks depends on this module
        return describe(self)

    @property
    def kind(self) -> str:
        """Human device kind, e.g. "Contact sensor", "Wall switch (2 gang)"."""
        return self._info().kind

    @property
    def vendor(self) -> str | None:
        """Display vendor name ("Aqara", "IKEA"…) derived from the manufacturer string."""
        return self._info().vendor

    @property
    def category(self) -> str:
        """Coarse device category: light, plug, switch, sensor, remote, cover, climate, lock, meter, unknown."""
        return self._info().category

    def primary_endpoint(self) -> Endpoint | None:
        if not self.endpoints:
            return None
        ranked = sorted(self.endpoints.values(), key=lambda e: (e.category == "unknown", e.id))
        return ranked[0]

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["ieee"] = self.ieee_str
        d["endpoints"] = {str(k): asdict(v) for k, v in self.endpoints.items()}
        info = self._info()
        d["kind"], d["vendor"], d["category"] = info.kind, info.vendor, info.category
        return d

    @staticmethod
    def from_json(d: dict[str, Any]) -> Device:
        # Only the fields this version knows: a devices.json written by a newer (or withdrawn)
        # version may carry more, and an unknown key must not stop the gateway from starting.
        known = {f.name for f in fields(Device)}
        d = {k: v for k, v in d.items() if k in known or k == "ieee"}
        d["ieee"] = ieee_int(d["ieee"])
        ep_known = {f.name for f in fields(Endpoint)}
        d["endpoints"] = {int(k): Endpoint(**{a: b for a, b in v.items() if a in ep_known})
                          for k, v in d.get("endpoints", {}).items()}
        return Device(**d)


class Registry:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._by_ieee: dict[int, Device] = {}
        self._by_nwk: dict[int, int] = {}
        if path and path.exists():
            self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        assert self.path
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            log.exception("device registry unreadable; starting empty")
            return
        for d in data.get("devices", []):
            dev = Device.from_json(d)
            self._by_ieee[dev.ieee] = dev
            self._by_nwk[dev.nwk] = dev.ieee

    def save(self) -> None:
        if not self.path:
            return
        tmp = self.path.with_suffix(".tmp")
        payload = json.dumps({"devices": [d.to_json() for d in self._by_ieee.values()]}, indent=1)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        os.replace(tmp, self.path)

    # -- access --------------------------------------------------------------

    def all(self) -> list[Device]:
        return list(self._by_ieee.values())

    def get(self, ieee: int) -> Device | None:
        return self._by_ieee.get(ieee)

    def by_nwk(self, nwk: int) -> Device | None:
        ieee = self._by_nwk.get(nwk)
        return self._by_ieee.get(ieee) if ieee is not None else None

    def by_name(self, name: str) -> Device | None:
        for d in self._by_ieee.values():
            if d.friendly_name == name:
                return d
        try:
            return self.get(ieee_int(name))
        except ValueError:
            return None

    def add_or_update(self, ieee: int, nwk: int, **caps: Any) -> Device:
        dev = self._by_ieee.get(ieee)
        if dev is None:
            dev = Device(ieee=ieee, nwk=nwk, friendly_name=ieee_str(ieee), **caps)
            self._by_ieee[ieee] = dev
        else:
            if dev.nwk != nwk:
                self._by_nwk.pop(dev.nwk, None)
                dev.nwk = nwk
            for k, v in caps.items():
                setattr(dev, k, v)
        if nwk != 0:  # 0 is the coordinator; an imported device's address is unknown until it talks
            self._by_nwk[nwk] = ieee
        self.save()
        return dev

    def remove(self, ieee: int) -> Device | None:
        dev = self._by_ieee.pop(ieee, None)
        if dev:
            self._by_nwk.pop(dev.nwk, None)
            self.save()
        return dev

    def rename(self, ieee: int, name: str) -> None:
        if any(c in name for c in "/+#"):
            raise ValueError("a device name must not contain '/', '+' or '#' — it becomes an MQTT topic")
        if self.by_name(name) not in (None, self.get(ieee)):
            raise ValueError(f"name {name!r} already in use")
        dev = self._by_ieee[ieee]
        dev.friendly_name = name
        self.save()
