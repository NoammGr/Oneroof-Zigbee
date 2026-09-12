"""Rooms: where a device is, in the owner's words - the one place the whole family reads it from.

A room exists because a device is in it; there is no separate list to keep. The gateway
publishes each device's room in the device list every One Roof add-on already reads, and hands
it to Home Assistant as the device's suggested area. What the gateway can offer before the
owner types anything: the room a device's own name carries ("Garage - Smart Plug"), and the
area Home Assistant already has for it (read from the read-only view of its config folder).
Rooms may carry a floor (optional; rooms.json)."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_SPLIT = re.compile(r"\s+[-–—]\s+|\s*:\s+")
_IEEE_IN_ID = re.compile(r"(0x[0-9a-fA-F]{16})$")
MAX_ROOM = 60


def clean_room(text: str) -> str:
    """One line, trimmed, no MQTT-hostile characters; '' means no room."""
    text = " ".join(str(text or "").split())
    if len(text) > MAX_ROOM:
        raise ValueError(f"a room name has at most {MAX_ROOM} characters")
    if any(ch in text for ch in "/+#"):
        raise ValueError("a room name cannot contain / + #")
    return text


def room_of_name(friendly_name: str) -> str:
    """The room a device's name carries: "Garage - Smart Plug" → Garage; '' when none."""
    parts = _SPLIT.split(str(friendly_name or "").strip(), maxsplit=1)
    if len(parts) == 2 and parts[0].strip() and parts[1].strip():
        return parts[0].strip()
    return ""


def ha_areas(roots: list[Path]) -> dict[str, str]:
    """{ieee (lower): area name} from Home Assistant's own registries, when the config folder is
    mounted read-only. Missing or unreadable files mean no suggestions, nothing more."""
    for root in roots:
        storage = Path(root) / ".storage"
        try:
            devices = json.loads((storage / "core.device_registry").read_text())["data"]["devices"]
            areas = {str(a.get("id")): str(a.get("name") or "").strip()
                     for a in json.loads((storage / "core.area_registry").read_text())["data"]["areas"]}
        except (OSError, ValueError, KeyError, TypeError):
            continue
        out: dict[str, str] = {}
        for d in devices:
            area = areas.get(str(d.get("area_id") or ""))
            if not area:
                continue
            for ident in d.get("identifiers") or []:
                parts = ident if isinstance(ident, list) else [ident]
                m = _IEEE_IN_ID.search(str(parts[-1]))
                if m:
                    out[m.group(1).lower()] = area
        return out
    return {}


class RoomBook:
    """rooms.json: the optional floor per room. Rooms themselves live on the devices."""

    def __init__(self, path: Path | None):
        self.path = path
        self.floors: dict[str, int] = {}
        if path and path.exists():
            try:
                data = json.loads(path.read_text())
                self.floors = {str(k): int(v) for k, v in (data.get("floors") or {}).items() if isinstance(v, int)}
            except (OSError, ValueError, TypeError) as e:
                log.warning("rooms.json unreadable (%s) - floors forgotten", e)

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"floors": self.floors}, indent=1, sort_keys=True))
        except OSError as e:
            log.warning("rooms.json not written: %s", e)

    def set_floor(self, room: str, floor: int | None) -> None:
        if floor is None:
            self.floors.pop(room, None)
        else:
            self.floors[room] = max(-5, min(50, int(floor)))
        self.save()

    def rename(self, old: str, new: str) -> None:
        if old in self.floors:
            self.floors[new] = self.floors.pop(old)
            self.save()


def summarize(devices: list[Any], book: RoomBook) -> list[dict[str, Any]]:
    """[{name, floor, devices, offline, wall_off}] for every room in use, alphabetical."""
    rooms: dict[str, dict[str, Any]] = {}
    for d in devices:
        if not d.room:
            continue
        r = rooms.setdefault(d.room, {"name": d.room, "floor": book.floors.get(d.room), "devices": 0, "offline": 0, "wall_off": 0})
        r["devices"] += 1
        if d.context.get("wall_off"):
            r["wall_off"] += 1
        elif not d.available:
            r["offline"] += 1
    return sorted(rooms.values(), key=lambda r: r["name"].lower())
