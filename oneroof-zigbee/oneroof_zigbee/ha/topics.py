"""Topic and discovery-identity layout.

Native layout (default):
    <base>/<ieee>/state|set|availability            availability payload: online|offline
    discovery unique_id  oneroof_zigbee_<ieee>_<object>, device identifiers [oneroof_zigbee_<ieee>]

Legacy layout (compat.legacy_layout: true) — the layout of an imported previous setup:
    <base>/<friendly name>/state|set|availability  availability payload: {"state":"online"}
    discovery unique_id  <ieee>_<object>_zigbee2mqtt, device identifiers [zigbee2mqtt_<ieee>]
    discovery topic      <prefix>/<component>/<ieee>/<object>/config

The legacy identities are what make Home Assistant keep the *same* entity
registry entries (entity ids, names, areas, history) after a migration, and
what keeps other MQTT consumers' subscriptions valid. The literal suffixes and
prefixes below are protocol constants of that layout and must not change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..devices import Device

# our object ids → legacy-layout object ids where they differ
_Z2M_OBJECT = {"voltage_ac": "voltage", "light": "light", "switch": "switch"}


@dataclass(frozen=True)
class Topics:
    base: str
    prefix: str
    legacy: bool = False

    # -- device topics ---------------------------------------------------

    def node(self, dev: Device) -> str:
        return dev.friendly_name if self.legacy else dev.ieee_str

    def state(self, dev: Device) -> str:
        return f"{self.base}/{self.node(dev)}/state" if not self.legacy else f"{self.base}/{self.node(dev)}"

    def set(self, dev: Device) -> str:
        return f"{self.base}/{self.node(dev)}/set"

    def availability(self, dev: Device) -> str:
        return f"{self.base}/{self.node(dev)}/availability"

    def availability_payload(self, online: bool) -> bytes:
        if self.legacy:
            return json.dumps({"state": "online" if online else "offline"}).encode()
        return b"online" if online else b"offline"

    def bridge_state_payload(self, online: bool) -> bytes:
        return self.availability_payload(online)

    def availability_template(self) -> str | None:
        return "{{ value_json.state }}" if self.legacy else None

    # -- discovery identity ---------------------------------------------

    def object_id(self, obj: str) -> str:
        return _Z2M_OBJECT.get(obj, obj) if self.legacy else obj

    def unique_id(self, dev: Device, obj: str) -> str:
        obj = self.object_id(obj)
        return f"{dev.ieee_str}_{obj}_zigbee2mqtt" if self.legacy else f"oneroof_zigbee_{dev.ieee_str}_{obj}"

    def device_identifiers(self, dev: Device) -> list[str]:
        return [f"zigbee2mqtt_{dev.ieee_str}"] if self.legacy else [f"oneroof_zigbee_{dev.ieee_str}"]

    def discovery_topic(self, component: str, dev: Device, obj: str) -> str:
        return f"{self.prefix}/{component}/{dev.ieee_str}/{self.object_id(obj)}/config"

    def via_device(self) -> str:
        return "zigbee2mqtt_bridge" if self.legacy else "oneroof_zigbee_bridge"

    def bridge_identifier(self) -> str:
        return "zigbee2mqtt_bridge" if self.legacy else "oneroof_zigbee_bridge"
