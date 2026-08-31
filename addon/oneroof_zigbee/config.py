"""Gateway configuration (YAML).  Secrets are NOT in here — see security.keystore.

Example:

    serial:
      port: /dev/ttyUSB0
      baudrate: 115200
    zigbee:
      channel: 15
      strict_install_codes: false     # true → ONLY install-code joins possible
      permit_join_max_seconds: 120
      permit_join_require_install_code: false
    mqtt:
      listen: 0.0.0.0
      port: 1883
      tls:
        cert: /data/tls/server.crt     # optional; when set, plain TCP is disabled
        key:  /data/tls/server.key
      base_topic: oz
      password_file: /data/mqtt.passwd
      control_users: [admin]          # who may open the network / remove devices / rotate keys
      users:
        homeassistant:
          subscribe: ["oz/#", "homeassistant/#"]
          publish:   ["oz/+/set", "oz/bridge/request/#", "homeassistant/status"]
    homeassistant:
      discovery: true
      discovery_prefix: homeassistant
    ui:
      enabled: true
      listen: 127.0.0.1
      port: 8099
      acts_as: admin
    data_dir: /data
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ZIGBEE_CHANNELS = range(11, 27)


def _parse_tls(v: Any) -> TlsConfig:
    if v in (None, "", True, "auto"):
        return TlsConfig(mode="auto")
    if v in (False, "off", "false"):
        return TlsConfig(mode="off")
    if isinstance(v, dict):
        mode = str(v.get("mode", "custom" if v.get("cert") else "auto"))
        if mode not in ("auto", "custom", "off"):
            raise ConfigError("tls.mode must be auto|custom|off")
        if mode == "custom" and not (v.get("cert") and v.get("key")):
            raise ConfigError("tls.mode custom requires cert and key")
        return TlsConfig(mode=mode, cert=Path(v["cert"]) if v.get("cert") else None, key=Path(v["key"]) if v.get("key") else None,
                         client_ca=Path(v["client_ca"]) if v.get("client_ca") else None,
                         hostnames=[str(h) for h in v.get("hostnames", [])])
    raise ConfigError("tls must be auto|off|{mode,cert,key,client_ca,hostnames}")


class ConfigError(ValueError):
    pass


@dataclass
class SerialConfig:
    """`port` is a device path (/dev/ttyUSB0) or `tcp://host:port` for network
    coordinators (SMLIGHT SLZB-06, ZigStar LAN, ser2net). Only Z-Stack (zstack)
    adapters are supported; the field exists so the UI can show it."""
    port: str
    baudrate: int = 115200
    rtscts: bool = False
    adapter: str = "zstack"

    @property
    def is_network(self) -> bool:
        return self.port.startswith(("tcp://", "socket://"))


@dataclass
class ZigbeeConfig:
    channel: int = 15
    strict_install_codes: bool = False
    permit_join_max_seconds: int = 120
    permit_join_require_install_code: bool = False
    permit_join_close_after_first_join: bool = True   # one device per plain window
    rotate_key_after_plain_join: bool = True          # a key exposed during pairing must not live long
    permit_join_cooldown_seconds: int = 5
    rotation_require_all: bool = True                 # switch keys only when every device demonstrably has the new one
    rotation_max_window_seconds: int = 21600          # how long a rotation may wait for sleeping / unreachable devices
    rotation_interval_days: int = 30                  # rotate on a schedule too (0 = only after joins / by hand)


@dataclass
class TlsConfig:
    """mode "auto": a private CA + server cert are generated in data_dir/tls and renewed automatically.
    mode "custom": use the given cert/key. mode "off": plaintext (discouraged; only for loopback/tests)."""
    mode: str = "auto"
    cert: Path | None = None
    key: Path | None = None
    client_ca: Path | None = None   # when set, clients must present a certificate signed by it (mTLS)
    hostnames: list[str] = field(default_factory=list)  # extra SANs for the auto cert (e.g. homeassistant.local)

    @property
    def enabled(self) -> bool:
        return self.mode != "off"


@dataclass
class MqttUser:
    subscribe: list[str] = field(default_factory=list)
    publish: list[str] = field(default_factory=list)


@dataclass
class MqttConfig:
    listen: str = "0.0.0.0"
    port: int = 8883
    base_topic: str = "oneroof/zigbee"
    password_file: Path = Path("mqtt.passwd")
    tls: TlsConfig = field(default_factory=TlsConfig)
    # Optional additional PLAINTEXT listener for legacy devices that cannot do TLS.
    # None = disabled (default). Never expose this beyond a trusted network.
    plaintext_port: int | None = None
    users: dict[str, MqttUser] = field(default_factory=dict)
    gateway_user: str = "oneroof_zigbee"
    # users allowed to open the join window, remove devices, rotate keys. Explicit, never inferred from ACLs.
    control_users: list[str] = field(default_factory=list)
    # when set, the built-in broker is NOT started; the gateway connects to this broker instead
    external: ExternalBrokerConfig | None = None


@dataclass
class UiConfig:
    enabled: bool = True
    listen: str = "127.0.0.1"   # loopback only; the add-on exposes it through HA Ingress
    port: int = 8099
    acts_as: str = "admin"      # the MQTT user the UI acts as; must be in control_users to pair/remove/rotate
    tls: TlsConfig = field(default_factory=lambda: TlsConfig(mode="off"))  # "auto" is forced when listen is not loopback


@dataclass
class ExternalBrokerConfig:
    """Use an existing broker instead of the built-in one. Chosen by the importer of a previous
    setup so Home Assistant and other clients need no change."""
    server: str            # mqtt://host:1883 or mqtts://host:8883
    user: str | None = None
    password: str | None = None
    ca: Path | None = None
    client_id: str = "oneroof-zigbee"


@dataclass
class CompatConfig:
    """Legacy layout: after importing a previous setup, keep its topic layout (base/<friendly name>),
    availability payloads and Home Assistant discovery identities, so existing HA entities, dashboards,
    automations and other MQTT consumers keep working unchanged."""
    legacy_layout: bool = False


@dataclass
class HaConfig:
    discovery: bool = True
    discovery_prefix: str = "homeassistant"


@dataclass
class Config:
    serial: SerialConfig
    data_dir: Path
    zigbee: ZigbeeConfig = field(default_factory=ZigbeeConfig)
    mqtt: MqttConfig = field(default_factory=MqttConfig)
    homeassistant: HaConfig = field(default_factory=HaConfig)
    ui: UiConfig = field(default_factory=UiConfig)
    compat: CompatConfig = field(default_factory=CompatConfig)
    log_level: str = "INFO"
    # Folders the importer may read previous-setup files from (server-side import, no upload).
    import_roots: list[Path] = field(default_factory=list)

    @staticmethod
    def load(path: Path) -> Config:
        try:
            raw = yaml.safe_load(path.read_text()) or {}
        except OSError as e:
            raise ConfigError(f"cannot read {path}: {e}") from e
        return Config.from_dict(raw, base=path.parent)

    @staticmethod
    def from_dict(raw: dict[str, Any], base: Path = Path(".")) -> Config:
        if "serial" not in raw or "port" not in raw["serial"]:
            raise ConfigError("serial.port is required")
        data_dir = Path(raw.get("data_dir", base / "data"))
        z = raw.get("zigbee", {})
        zig = ZigbeeConfig(
            channel=int(z.get("channel", 15)),
            strict_install_codes=bool(z.get("strict_install_codes", False)),
            permit_join_max_seconds=int(z.get("permit_join_max_seconds", 120)),
            permit_join_require_install_code=bool(z.get("permit_join_require_install_code", False)),
            permit_join_close_after_first_join=bool(z.get("permit_join_close_after_first_join", True)),
            rotate_key_after_plain_join=bool(z.get("rotate_key_after_plain_join", True)),
            permit_join_cooldown_seconds=int(z.get("permit_join_cooldown_seconds", 5)),
            rotation_require_all=bool(z.get("rotation_require_all", True)),
            rotation_max_window_seconds=int(z.get("rotation_max_window_seconds", 21600)),
            rotation_interval_days=int(z.get("rotation_interval_days", 30)),
        )
        if not 0 <= zig.rotation_interval_days <= 3650:
            raise ConfigError("zigbee.rotation_interval_days must be 0..3650")
        if not 60 <= zig.rotation_max_window_seconds <= 7 * 86400:
            raise ConfigError("zigbee.rotation_max_window_seconds must be 60..604800")
        if zig.channel not in ZIGBEE_CHANNELS:
            raise ConfigError("zigbee.channel must be 11..26")
        if not 1 <= zig.permit_join_max_seconds <= 254:
            raise ConfigError("zigbee.permit_join_max_seconds must be 1..254 (never 'forever')")
        m = raw.get("mqtt", {})
        tls = _parse_tls(m.get("tls", "auto"))
        users = {name: MqttUser(subscribe=list(u.get("subscribe", [])), publish=list(u.get("publish", [])))
                 for name, u in (m.get("users") or {}).items()}
        mqtt = MqttConfig(
            listen=str(m.get("listen", "0.0.0.0")),
            port=int(m.get("port", 8883 if tls.enabled else 1883)),
            base_topic=str(m.get("base_topic", "oneroof/zigbee")).strip("/"),
            password_file=Path(m.get("password_file", data_dir / "mqtt.passwd")),
            tls=tls,
            plaintext_port=(int(m["plaintext_port"]) if m.get("plaintext_port") else None),
            users=users,
            gateway_user=str(m.get("gateway_user", "oneroof_zigbee")),
            control_users=[str(u) for u in (m.get("control_users") or [])],
        )
        ext = m.get("external")
        if isinstance(ext, dict) and ext.get("server"):
            srv = str(ext["server"])
            if not srv.startswith(("mqtt://", "mqtts://")):
                raise ConfigError("mqtt.external.server must start with mqtt:// or mqtts://")
            mqtt.external = ExternalBrokerConfig(server=srv, user=(str(ext["user"]) if ext.get("user") else None),
                                                 password=(str(ext["password"]) if ext.get("password") else None),
                                                 ca=Path(ext["ca"]) if ext.get("ca") else None,
                                                 client_id=str(ext.get("client_id", "oneroof-zigbee")))
        for u in mqtt.control_users:
            if u not in users and mqtt.external is None:
                raise ConfigError(f"mqtt.control_users: {u!r} is not a defined mqtt user")
        if not mqtt.base_topic or any(ch in mqtt.base_topic for ch in "+#"):
            raise ConfigError("mqtt.base_topic invalid")
        if mqtt.plaintext_port is not None and mqtt.plaintext_port == mqtt.port:
            raise ConfigError("mqtt.plaintext_port must differ from mqtt.port")
        h = raw.get("homeassistant", {})
        ha = HaConfig(discovery=bool(h.get("discovery", True)), discovery_prefix=str(h.get("discovery_prefix", "homeassistant")))
        s = raw["serial"]
        adapter = str(s.get("adapter", "zstack"))
        if adapter != "zstack":
            raise ConfigError("serial.adapter: only 'zstack' (TI CC2652/CC1352) is supported")
        serial = SerialConfig(port=str(s["port"]), baudrate=int(s.get("baudrate", 115200)), rtscts=bool(s.get("rtscts", False)), adapter=adapter)
        u = raw.get("ui", {}) or {}
        loopback = str(u.get("listen", "127.0.0.1")) in ("127.0.0.1", "::1", "localhost")
        ui = UiConfig(enabled=bool(u.get("enabled", True)), listen=str(u.get("listen", "127.0.0.1")),
                      port=int(u.get("port", 8099)), acts_as=str(u.get("acts_as", "admin")),
                      tls=_parse_tls(u.get("tls", "off" if loopback else "auto")))
        if not loopback and not u.get("i_know_this_exposes_the_ui_to_the_lan"):
            raise ConfigError("ui.listen must be loopback; use HA Ingress or a reverse proxy with auth "
                              "(set ui.i_know_this_exposes_the_ui_to_the_lan: true to override)")
        if not loopback and not ui.tls.enabled and not u.get("ingress"):
            raise ConfigError("ui.tls cannot be 'off' on a non-loopback address (the UI would be plaintext on the network)")
        comp = raw.get("compat", {}) or {}
        compat = CompatConfig(legacy_layout=bool(comp.get("legacy_layout", False)))
        import_roots = [Path(str(x)) for x in (raw.get("import_roots") or [])]
        return Config(serial=serial, data_dir=data_dir, zigbee=zig, mqtt=mqtt, homeassistant=ha, ui=ui, compat=compat,
                      log_level=str(raw.get("log_level", "INFO")).upper(), import_roots=import_roots)
