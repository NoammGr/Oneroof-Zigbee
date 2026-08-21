"""Add-on entrypoint: translate /data/options.json (written by the HA
supervisor) into an oneroof_zigbee config, then run the gateway.

No bashio, no shell: fewer moving parts, nothing that can be injected through
an option value.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
from pathlib import Path

import yaml

from oneroof_zigbee.__main__ import run
from oneroof_zigbee.config import Config
from oneroof_zigbee.mqtt import PasswordFile

OPTIONS = Path(os.environ.get("ONEROOF_OPTIONS", "/data/options.json"))   # written by the Supervisor into the add-on's private /data
DATA = Path(os.environ.get("ONEROOF_DATA", "/config"))                      # add-on config folder: keystore, users, tls/ca.crt, backups, firmware
CONFIG = DATA / "config.yaml"


OVERRIDES = None  # set in main_async: /config/overrides.yaml written by the import (legacy layout, base topic, ...)


def load_overrides() -> dict:
    """Settings the import decided (legacy layout, base topic, discovery prefix). In the add-on the
    Supervisor owns options.json, so the import writes these here and we merge them over the options."""
    p = DATA / "overrides.yaml"
    if not p.exists():
        return {}
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:  # noqa: BLE001
        return {}


def build_config(opts: dict) -> dict:
    ov = load_overrides()
    if ov.get("legacy_layout"):
        opts = {**opts, "legacy_layout": True, "base_topic": ov.get("base_topic") or opts.get("base_topic") or "zigbee2mqtt"}
    cfg = {
        "serial": {"port": coordinator_port(opts)},
        "data_dir": str(DATA),
        "log_level": str(opts.get("log_level", "info")).upper(),
        "zigbee": {
            "channel": int(opts.get("channel", 15)),
            "strict_install_codes": bool(opts.get("strict_install_codes", False)),
            "permit_join_max_seconds": int(opts.get("permit_join_max_seconds", 120)),
            "permit_join_require_install_code": bool(opts.get("permit_join_require_install_code", False)),
        },
        "mqtt": {
            "listen": "0.0.0.0",
            "port": int(opts.get("mqtt_port", 8883)),
            "plaintext_port": (int(opts["mqtt_plaintext_port"]) if opts.get("mqtt_plaintext_port") else None),
            "base_topic": "oneroof/zigbee",
            "password_file": str(DATA / "mqtt.passwd"),
            # Home Assistant can control devices but can NOT open the network unless
            # you opt in; pairing is meant to be done with the separate "admin" user.
            # Users are managed live from the UI (data/users.yaml); the two defaults are seeded on first start.
            "control_users": [],
            "users": {},
        },
        "homeassistant": {"discovery": True, "discovery_prefix": ov.get("discovery_prefix") or "homeassistant"},
        # Ingress proxies from 172.30.32.2 to the container; we must listen on the container interface,
        # but the server only accepts connections from loopback and that proxy address.
        "ui": {"enabled": True, "listen": "0.0.0.0", "i_know_this_exposes_the_ui_to_the_lan": True, "port": 8099, "acts_as": "admin"},
    }
    if opts.get("tls_cert") and opts.get("tls_key"):
        cfg["mqtt"]["tls"] = {"mode": "custom", "cert": opts["tls_cert"], "key": opts["tls_key"]}
    else:
        # default: our own CA + cert, generated in /data/tls; clients trust /data/tls/ca.crt
        cfg["mqtt"]["tls"] = {"mode": "auto", "hostnames": [h for h in [opts.get("tls_hostname", "")] if h]}
    if opts.get("tls_require_client_cert") and opts.get("tls_client_ca"):
        cfg["mqtt"]["tls"]["client_ca"] = opts["tls_client_ca"]
    # Ingress terminates HTTPS at Home Assistant and talks to us over the internal docker network.
    cfg["ui"]["tls"] = "off"
    cfg["ui"]["ingress"] = True
    # Migration from a previous setup: keep its broker + topics + HA entities until the user switches.
    if opts.get("base_topic"):
        cfg["mqtt"]["base_topic"] = str(opts["base_topic"])
    if opts.get("legacy_layout"):
        cfg["compat"] = {"legacy_layout": True}
        cfg["mqtt"].setdefault("base_topic", "zigbee2mqtt")
        if not opts.get("base_topic"):
            cfg["mqtt"]["base_topic"] = "zigbee2mqtt"
    if opts.get("external_broker"):
        cfg["mqtt"]["external"] = {"server": str(opts["external_broker"]), "user": str(opts.get("external_broker_user") or ""),
                                   "password": str(opts.get("external_broker_password") or ""), "client_id": "oneroof-zigbee"}
    return cfg


def coordinator_port(opts: dict) -> str:
    """serial_port wins; network_coordinator accepts 'host:port', 'tcp://host:port' or (by mistake) a /dev path."""
    serial = str(opts.get("serial_port") or "").strip()
    net = str(opts.get("network_coordinator") or "").strip()
    if serial:
        return serial
    if not net:
        return ""
    if net.startswith("/dev/"):
        return net
    net = net.removeprefix("tcp://").removeprefix("socket://")
    host, _, port = net.rpartition(":")
    if not host or not port.isdigit():
        print(f"network_coordinator must be host:port (e.g. 192.168.1.50:6638), got {net!r}. "
              "For a USB adapter leave it empty and set serial_port.", flush=True)
        return ""
    return f"tcp://{host}:{port}"


def _supervisor(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    import json as _json
    import urllib.error
    import urllib.request
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        return 0, {}
    data = _json.dumps(body).encode() if body is not None else None
    base = os.environ.get("SUPERVISOR_URL", "http://supervisor")
    req = urllib.request.Request(f"{base}{path}", data=data, method=method,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, _json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, _json.load(e)
        except Exception:  # noqa: BLE001
            return e.code, {}
    except Exception as e:  # noqa: BLE001
        print(f"Supervisor API unreachable: {e}", flush=True)
        return 0, {}


def register_mqtt_service(ha_user: str, ha_password: str, plaintext_port: int | None) -> None:
    """Become Home Assistant's MQTT service (what the Mosquitto add-on used to be). The MQTT
    integration set up through the Supervisor re-points itself to us, and add-ons that auto-detect
    the broker (One Roof Bridge) follow. Inside Home Assistant's private network we offer plain MQTT
    on the internal hostname; TLS 8883 stays for everything else."""
    host = os.environ.get("HOSTNAME", "")
    if not plaintext_port:
        print("MQTT service registration skipped: mqtt_plaintext_port is 0 (Home Assistant's Supervisor discovery needs the plain port).", flush=True)
        return
    status, resp = _supervisor("POST", "/services/mqtt", {"host": host, "port": plaintext_port, "ssl": False,
                                                            "username": ha_user, "password": ha_password, "protocol": "3.1.1"})
    if status == 200:
        print(f"Registered as Home Assistant's MQTT service ({host}:{plaintext_port}). The MQTT integration and "
              "add-ons that auto-detect the broker now use One Roof Zigbee.", flush=True)
    elif status == 400 and "provide" in str(resp).lower():
        print("Another add-on (the old broker) is still registered as Home Assistant's MQTT service. "
              "Stop the Mosquitto add-on and restart One Roof Zigbee; no other action is needed.", flush=True)
    elif status:
        print(f"MQTT service registration failed ({status}): {resp}", flush=True)


def unregister_mqtt_service() -> None:
    _supervisor("DELETE", "/services/mqtt")


SERVICE_SECRET = None  # /config/.service-login: the HA user's password, kept so we can re-register as the MQTT service on every start


def ensure_password(cfg: Config, user: str, purpose: str, role: str, control: bool) -> str | None:
    """Create the user on first start. Returns the password only when newly generated."""
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.mqtt import Acl
    pf = PasswordFile(cfg.mqtt.password_file)
    if pf.has_user(user):
        return None
    pw = secrets.token_urlsafe(24)
    Admin(cfg, CONFIG, pf, Acl(), set(), managed=True).upsert_user(user, role=role, password=pw, control=control, subscribe=None, publish=None)
    # Shown ONCE in the add-on log.  Never written anywhere else in plaintext.
    print("=" * 72)
    print(f"MQTT credentials — {purpose}  (user: {user})")
    print(f"password: {pw}")
    print("This is the only time it is shown. Change it any time in the web UI → Settings → Users & access.")
    print("=" * 72, flush=True)
    return pw


async def heartbeat() -> None:
    p = DATA / ".healthy"
    while True:
        p.touch()
        await asyncio.sleep(30)


def drop_privileges(serial_port: str, enabled: bool = True) -> None:
    """Automatic least privilege. The add-on starts as root (the Supervisor's device and volume
    handling assumes it). A throwaway child process then tries to open the serial device exactly
    as configured, as uid 1000 with the device's group. Only if that succeeds does the main
    process drop root; in every other case (device missing, open fails, check impossible) it
    stays root like other add-ons and says so. `drop_privileges: false` forces root."""
    if os.geteuid() != 0:
        return
    if not enabled:
        print("Running as root inside the add-on container (drop_privileges is off).", flush=True)
        return
    import grp
    import pwd
    uid, gid = pwd.getpwnam("oneroof").pw_uid, grp.getgrnam("oneroof").gr_gid
    for root, dirs, files in os.walk(DATA):
        for name in dirs + files:
            try:
                os.chown(os.path.join(root, name), uid, gid)
            except OSError:
                pass
    os.chown(DATA, uid, gid)
    if not serial_port or serial_port.startswith("tcp://") or not os.path.exists(serial_port):
        # network coordinator → nothing to prove on the device side; missing device → cannot prove, stay root
        if serial_port.startswith("tcp://"):
            _become(uid, gid, [gid])
            return
        print("Running as root inside the add-on container (serial device not present to verify unprivileged access).", flush=True)
        return
    groups = [gid]
    try:
        groups.append(os.stat(serial_port).st_gid)  # follows the by-id symlink; the device's group on THIS host
    except OSError:
        pass
    pid = os.fork()
    if pid == 0:  # child: can the unprivileged identity open the device exactly as configured?
        try:
            os.setgroups(groups)
            os.setgid(gid)
            os.setuid(uid)
            fd = os.open(serial_port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            os.close(fd)
            os._exit(0)
        except Exception:  # noqa: BLE001
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(status) != 0:
        print(f"Running as root inside the add-on container: {serial_port} is not accessible to an unprivileged "
              "user on this host (this is how other add-ons run too).", flush=True)
        return
    _become(uid, gid, groups)


def _become(uid: int, gid: int, groups: list[int]) -> None:
    try:
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)
        print(f"Running as uid {uid} (dropped root; verified the coordinator is accessible).", flush=True)
    except OSError as e:
        print(f"Could not drop privileges ({e}); running as root.", flush=True)


async def main_async() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    opts = json.loads(OPTIONS.read_text())
    drop_privileges(coordinator_port(opts), bool(opts.get("drop_privileges", True)))
    if not opts.get("serial_port") and not opts.get("network_coordinator"):
        print("No coordinator configured. Open the add-on Configuration tab and pick your USB adapter under "
              "'serial_port' (or enter host:port under 'network_coordinator'), then start the add-on again.", flush=True)
        return 1
    CONFIG.write_text(yaml.safe_dump(build_config(opts), sort_keys=False))
    os.chmod(CONFIG, 0o600)
    cfg = Config.load(CONFIG)
    logging.basicConfig(level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    ha_user = str(opts.get("homeassistant_mqtt_user", "homeassistant"))
    secret_file = DATA / ".service-login"
    new_pw = ensure_password(cfg, ha_user, "for the Home Assistant MQTT integration (handed to Home Assistant automatically)", "homeassistant",
                             bool(opts.get("homeassistant_can_permit_join")))
    if new_pw:
        fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(new_pw)
    ensure_password(cfg, "admin", "for pairing devices and the web UI", "admin", True)
    ha_pw = secret_file.read_text().strip() if secret_file.exists() else ""

    def announce_service() -> None:  # called by run() once the broker is listening
        if ha_pw and cfg.mqtt.external is None:
            register_mqtt_service(ha_user, ha_pw, cfg.mqtt.plaintext_port)
    ca = DATA / "tls" / "ca.crt"
    if ca.exists():
        from oneroof_zigbee.security.tls import fingerprint
        host = os.environ.get("HOSTNAME", "")
        print(f"MQTT TLS: CA certificate at {ca}  (SHA-256 {fingerprint(ca)})")
        print(f"Home Assistant → Settings → Integrations → MQTT → Configure: broker = {host or '<this add-on hostname>'}, "
              "port 8883, TLS on, user homeassistant; Advanced → upload this CA as 'Broker certificate'. "
              "(No host port is needed inside Home Assistant.)", flush=True)
    hb = asyncio.create_task(heartbeat())
    try:
        try:
            rc = await run(cfg, CONFIG, managed=True, on_broker_ready=announce_service)
        except (FileNotFoundError, PermissionError, ValueError, OSError) as e:
            print(f"Cannot open the coordinator at {cfg.serial.port!r}: {e}. "
                  "Check the add-on Configuration → serial_port (pick it from the list) and that no other add-on is using the adapter.", flush=True)
            return 1
        # exit code 4 = restart requested: the supervisor restarts us (boot: auto)
        return 0 if rc == 4 else rc
    finally:
        hb.cancel()
        unregister_mqtt_service()


if __name__ == "__main__":
    sys.exit(asyncio.run(main_async()))
