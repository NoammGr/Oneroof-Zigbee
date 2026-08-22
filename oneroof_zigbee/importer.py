"""Import a previous setup so devices do not need re-pairing.

The file formats handled are those of the common open-source gateway most people
migrate from; the parser is defensive and the names below are the files' own.

Inputs (any subset; more is better):
* configuration.yaml   — advanced.network_key / pan_id / ext_pan_id / channel, devices (names, descriptions)
* database.db          — newline-delimited JSON, one record per device (model, manufacturer, endpoints, clusters)
* coordinator_backup.json — zigpy open-backup format: network key + frame counter + per-device link keys

Two situations:
A. Same dongle (normal case). The network still lives in the coordinator's
   flash. We adopt the same key/PAN/extended PAN/channel in our keystore so the
   coordinator recognises its NV as matching and simply starts — no re-forming,
   no device notices anything.
B. Dongle wiped or replaced. We form a network with the same parameters and a
   frame counter above the backup's, so devices accept us as the same
   coordinator. Devices rejoin on their own. Per-device link keys are not
   restored (APS-encrypted commands to a few devices may need a re-pair).

Everything is parsed defensively: these files come from another program.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from .devices import Endpoint, Registry
from .security import NetworkSecrets
from .zcl import describe_endpoint
from .znp.wire import ieee_int, ieee_str

log = logging.getLogger("oneroof_zigbee.importer")

WELL_KNOWN_DEFAULT_KEY = bytes.fromhex("01030507090b0d0f00020406080a0c0d")


@dataclass
class ImportedNetwork:
    network_key: bytes | None = None
    pan_id: int | None = None
    ext_pan_id: int | None = None
    channel: int | None = None
    frame_counter: int | None = None
    coordinator_ieee: int | None = None
    source: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return None not in (self.network_key, self.pan_id, self.ext_pan_id, self.channel)


@dataclass
class ImportedDevice:
    ieee: int
    nwk: int = 0
    friendly_name: str | None = None
    description: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    sw_build: str | None = None
    date_code: str | None = None
    hw_version: int | None = None
    is_router: bool = False
    power_source: str | None = None
    endpoints: dict[int, Endpoint] = field(default_factory=dict)
    interviewed: bool = False
    last_state: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportedMqtt:
    """The previous setup's mqtt: section — lets us keep using the same broker and topics."""
    server: str | None = None
    user: str | None = None
    password: str | None = None
    ca: str | None = None
    base_topic: str = "zigbee2mqtt"
    homeassistant_prefix: str = "homeassistant"
    homeassistant_enabled: bool = True


@dataclass
class ImportPlan:
    network: ImportedNetwork
    devices: list[ImportedDevice]
    warnings: list[str] = field(default_factory=list)
    mqtt: ImportedMqtt = field(default_factory=ImportedMqtt)

    def summary(self) -> dict[str, Any]:
        n = self.network
        return {
            "mqtt": {"server": self.mqtt.server, "user": self.mqtt.user, "has_password": bool(self.mqtt.password),
                     "base_topic": self.mqtt.base_topic, "homeassistant_prefix": self.mqtt.homeassistant_prefix,
                     "homeassistant_enabled": self.mqtt.homeassistant_enabled},
            "network": {"found": n.complete, "source": n.source, "channel": n.channel,
                        "pan_id": f"{n.pan_id:#06x}" if n.pan_id is not None else None,
                        "ext_pan_id": f"0x{n.ext_pan_id:016x}" if n.ext_pan_id is not None else None,
                        "frame_counter": n.frame_counter, "key_is_well_known_default": n.network_key == WELL_KNOWN_DEFAULT_KEY,
                        "coordinator_ieee": ieee_str(n.coordinator_ieee) if n.coordinator_ieee else None},
            "devices": [{"ieee": ieee_str(d.ieee), "friendly_name": d.friendly_name, "model": d.model, "manufacturer": d.manufacturer,
                         "router": d.is_router, "endpoints": len(d.endpoints), "interviewed": d.interviewed} for d in self.devices],
            "warnings": self.warnings + n.warnings,
        }


# ----------------------------------------------------------------- parsing --


def _key_bytes(v: Any) -> bytes | None:
    if isinstance(v, str):
        if v.upper() == "GENERATE":
            return None
        h = re.sub(r"[^0-9a-fA-F]", "", v)
        return bytes.fromhex(h) if len(h) == 32 else None
    if isinstance(v, list) and len(v) == 16 and all(isinstance(x, int) and 0 <= x < 256 for x in v):
        return bytes(v)
    return None


def _ext_pan(v: Any) -> int | None:
    if isinstance(v, list) and len(v) == 8:
        return int.from_bytes(bytes(v), "little")
    if isinstance(v, str):
        h = re.sub(r"[^0-9a-fA-F]", "", v)
        return int(h, 16) if len(h) == 16 else None
    if isinstance(v, int):
        return v
    return None


def parse_mqtt_section(raw: dict[str, Any]) -> ImportedMqtt:
    m = raw.get("mqtt") if isinstance(raw.get("mqtt"), dict) else {}
    ha = raw.get("homeassistant")
    out = ImportedMqtt(
        server=str(m["server"]) if m.get("server") else None,
        user=str(m["user"]) if m.get("user") else None,
        password=str(m["password"]) if m.get("password") else None,
        ca=str(m["ca"]) if m.get("ca") else None,
        base_topic=str(m.get("base_topic") or "zigbee2mqtt").strip("/"),
    )
    if isinstance(ha, dict):
        out.homeassistant_prefix = str(ha.get("discovery_topic") or "homeassistant")
        out.homeassistant_enabled = bool(ha.get("enabled", True))
    elif ha is not None:
        out.homeassistant_enabled = bool(ha)
    # HA add-on convention: credentials come from the Supervisor when the section has none
    return out


def parse_configuration_yaml(text: str) -> tuple[ImportedNetwork, dict[int, dict[str, Any]], str | None]:
    """Returns (network, {ieee: {friendly_name, description}}, base_topic)."""
    net = ImportedNetwork(source="configuration.yaml")
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"configuration.yaml is not valid YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ValueError("configuration.yaml must be a mapping")
    adv = raw.get("advanced") or {}
    if isinstance(adv, dict):
        net.network_key = _key_bytes(adv.get("network_key"))
        if adv.get("network_key") == "GENERATE" or net.network_key is None and adv.get("network_key") is not None:
            net.warnings.append("network_key in configuration.yaml is GENERATE/unreadable — needs coordinator_backup.json")
        pan = adv.get("pan_id")
        if isinstance(pan, int):
            net.pan_id = pan
        elif isinstance(pan, str) and pan.lower() != "generate":
            try:
                net.pan_id = int(pan, 0)
            except ValueError:
                pass
        net.ext_pan_id = _ext_pan(adv.get("ext_pan_id"))
        ch = adv.get("channel")
        if isinstance(ch, int) and 11 <= ch <= 26:
            net.channel = ch
    if net.network_key is None and (raw.get("advanced") or {}).get("network_key") is None:
        net.network_key = WELL_KNOWN_DEFAULT_KEY
        net.warnings.append("configuration.yaml has no network_key: the previous setup used a well-known default key — "
                            "rotate it soon (Settings → Maintenance) once everything works")
    if net.pan_id is None:
        net.pan_id = 0x1A62  # the previous setup's default
    if net.ext_pan_id is None:
        net.ext_pan_id = int.from_bytes(bytes([0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD]), "little")
    if net.channel is None:
        net.channel = 11
    names: dict[int, dict[str, Any]] = {}
    for k, v in (raw.get("devices") or {}).items() if isinstance(raw.get("devices"), dict) else []:
        try:
            ieee = ieee_int(str(k))
        except ValueError:
            continue
        v = v if isinstance(v, dict) else {}
        names[ieee] = {"friendly_name": str(v.get("friendly_name") or "").strip() or None,
                       "description": str(v.get("description") or "").strip() or None}
    base = (raw.get("mqtt") or {}).get("base_topic") if isinstance(raw.get("mqtt"), dict) else None
    return net, names, base


def parse_database_db(text: str) -> list[ImportedDevice]:
    out: list[ImportedDevice] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("type") not in ("Router", "EndDevice"):
            continue
        try:
            ieee = ieee_int(str(rec.get("ieeeAddr")))
        except ValueError:
            continue
        d = ImportedDevice(ieee=ieee, nwk=int(rec.get("nwkAddr") or 0), manufacturer=rec.get("manufName"), model=rec.get("modelId"),
                           sw_build=rec.get("swBuildId"), date_code=rec.get("dateCode"),
                           hw_version=rec.get("hwVersion") if isinstance(rec.get("hwVersion"), int) else None,
                           is_router=rec.get("type") == "Router", interviewed=bool(rec.get("interviewCompleted")))
        ps = rec.get("powerSource")
        if isinstance(ps, str):
            d.power_source = ps.lower().replace(" ", "_")
        eps = rec.get("endpoints") or {}
        if isinstance(eps, dict):
            for k, ep in eps.items():
                try:
                    epid = int(k)
                except ValueError:
                    continue
                ep = ep if isinstance(ep, dict) else {}
                ins = [int(c) for c in ep.get("inClusterList") or [] if isinstance(c, int)]
                outs = [int(c) for c in ep.get("outClusterList") or [] if isinstance(c, int)]
                prof, devid = int(ep.get("profId") or 0x0104), int(ep.get("devId") or 0)
                cat = describe_endpoint(ins, outs, devid, prof)["category"]
                d.endpoints[epid] = Endpoint(epid, prof, devid, ins, outs, cat)
        out.append(d)
    return out


def parse_coordinator_backup(text: str) -> ImportedNetwork:
    try:
        b = json.loads(text)
    except ValueError as e:
        raise ValueError(f"coordinator_backup.json is not valid JSON: {e}") from e
    if not isinstance(b, dict) or "network_key" not in b:
        raise ValueError("coordinator_backup.json: unrecognised format (expected zigpy open backup)")
    net = ImportedNetwork(source="coordinator_backup.json")
    nk = b.get("network_key") or {}
    net.network_key = _key_bytes(nk.get("key"))
    fc = nk.get("frame_counter")
    net.frame_counter = int(fc) if isinstance(fc, int) else None
    pan = b.get("pan_id")
    net.pan_id = int(pan, 16) if isinstance(pan, str) else pan if isinstance(pan, int) else None
    ext = b.get("extended_pan_id")
    if isinstance(ext, str):
        h = re.sub(r"[^0-9a-fA-F]", "", ext)
        if len(h) == 16:
            net.ext_pan_id = int.from_bytes(bytes.fromhex(h), "big")  # zigpy backup prints big-endian
    ch = b.get("channel")
    net.channel = int(ch) if isinstance(ch, int) else None
    ci = b.get("coordinator_ieee")
    if isinstance(ci, str):
        try:
            net.coordinator_ieee = ieee_int(ci.replace(":", ""))
        except ValueError:
            pass
    return net


# -------------------------------------------------------------------- plan --


def parse_state_json(text: str) -> dict[str, dict[str, Any]]:
    """state.json: {"<ieee>": {<last state>}} — used to pre-fill device state so dashboards are not empty
    until devices report. Unknown shapes are ignored."""
    try:
        raw = json.loads(text)
    except ValueError:
        return {}
    out: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, dict):
                try:
                    out[ieee_str(ieee_int(str(k)))] = {kk: vv for kk, vv in v.items() if isinstance(vv, (int, float, str, bool, type(None), dict))}
                except ValueError:
                    continue
    return out


def build_plan(*, configuration_yaml: str | None, database_db: str | None, coordinator_backup: str | None,
               state_json: str | None = None) -> ImportPlan:
    warnings: list[str] = []
    net = ImportedNetwork(source="none")
    names: dict[int, dict[str, Any]] = {}
    mqtt = ImportedMqtt()
    if configuration_yaml:
        net, names, _ = parse_configuration_yaml(configuration_yaml)
        mqtt = parse_mqtt_section(yaml.safe_load(configuration_yaml) or {})
    if coordinator_backup:
        bk = parse_coordinator_backup(coordinator_backup)
        if net.network_key and bk.network_key and bk.network_key != net.network_key:
            warnings.append("network key differs between configuration.yaml and coordinator_backup.json — using the backup (it reflects the coordinator)")
        for f in ("network_key", "pan_id", "ext_pan_id", "channel"):
            if getattr(bk, f) is not None:
                setattr(net, f, getattr(bk, f))
        net.frame_counter = bk.frame_counter
        net.coordinator_ieee = bk.coordinator_ieee
        net.source = "coordinator_backup.json" + (" + configuration.yaml" if configuration_yaml else "")
    devices: list[ImportedDevice] = parse_database_db(database_db) if database_db else []
    by_ieee = {d.ieee: d for d in devices}
    for ieee, meta in names.items():
        d = by_ieee.get(ieee)
        if d is None:
            d = ImportedDevice(ieee=ieee)
            devices.append(d)
            by_ieee[ieee] = d
        d.friendly_name = meta.get("friendly_name") or d.friendly_name
        d.description = meta.get("description") or d.description
    if not devices:
        warnings.append("no devices found (upload database.db and/or configuration.yaml with a devices: section)")
    if not net.complete:
        warnings.append("network parameters incomplete — the import will only bring device names; devices will need re-pairing")
    if net.frame_counter is None and net.complete:
        warnings.append("no frame counter (no coordinator_backup.json): fine if you keep the same dongle; a replaced/wiped dongle "
                        "would need the backup so devices accept it")
    states = parse_state_json(state_json) if state_json else {}
    for d in devices:
        st = states.get(ieee_str(d.ieee))
        if st:
            d.last_state = st
    if mqtt.server and not mqtt.user:
        warnings.append("the mqtt: section has no user/password (the add-on got them from the Supervisor); "
                        "enter the broker login in the import form to keep using that broker")
    return ImportPlan(network=net, devices=devices, warnings=warnings, mqtt=mqtt)


def apply_plan(plan: ImportPlan, registry: Registry, current: NetworkSecrets) -> NetworkSecrets:
    """Write devices into the registry and return the NetworkSecrets to store.
    Caller persists the secrets and restarts the gateway."""
    n = plan.network
    secrets = current
    if n.complete:
        secrets = NetworkSecrets(network_key=n.network_key or current.network_key, pan_id=int(n.pan_id or current.pan_id),
                                 ext_pan_id=int(n.ext_pan_id or current.ext_pan_id), channel=int(n.channel or current.channel),
                                 tc_install_code=current.tc_install_code,
                                 frame_counter=(n.frame_counter or 0) + 100_000)  # margin so devices accept us after a re-form
    taken = {d.friendly_name for d in registry.all()}
    for d in plan.devices:
        dev = registry.add_or_update(d.ieee, d.nwk or 0, is_router=d.is_router)
        name = d.friendly_name
        if name and (name not in taken or registry.get(d.ieee) is not None and registry.get(d.ieee).friendly_name == name):
            dev.friendly_name = name
            taken.add(name)
        dev.description = d.description or dev.description
        dev.manufacturer = d.manufacturer or dev.manufacturer
        dev.model = d.model or dev.model
        dev.sw_build = d.sw_build or dev.sw_build
        dev.date_code = d.date_code or dev.date_code
        dev.hw_version = d.hw_version if d.hw_version is not None else dev.hw_version
        dev.power_source = d.power_source or dev.power_source
        if d.endpoints:
            dev.endpoints = dict(d.endpoints)
        dev.interviewed = bool(d.interviewed and d.endpoints)
        if d.last_state and not dev.state:
            dev.state.update({k: v for k, v in d.last_state.items() if k not in ("last_seen", "update", "update_available")})
        dev.available = True
        dev.context.setdefault("imported_from", "previous_setup")
    registry.save()
    return secrets
