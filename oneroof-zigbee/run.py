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

DATA = Path("/data")
OPTIONS = DATA / "options.json"
CONFIG = DATA / "config.yaml"


def build_config(opts: dict) -> dict:
    cfg = {
        "serial": {"port": (f"tcp://{opts['network_coordinator']}" if opts.get("network_coordinator") else opts["serial_port"])},
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
        "homeassistant": {"discovery": True},
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
    elif opts.get("legacy_layout"):
        # zero-config migration: ask the Supervisor for the existing broker add-on's service
        svc = supervisor_mqtt_service()
        if svc:
            cfg["mqtt"]["external"] = {"server": f"{'mqtts' if svc.get('ssl') else 'mqtt'}://{svc['host']}:{svc['port']}",
                                       "user": svc.get("username", ""), "password": svc.get("password", ""), "client_id": "oneroof-zigbee"}
        else:
            print("legacy_layout is on but the Supervisor offered no MQTT service; "
                  "set external_broker/external_broker_user/external_broker_password.", flush=True)
    return cfg


def supervisor_mqtt_service() -> dict | None:
    """GET /services/mqtt from the Supervisor (token provided because of `services: mqtt:want`)."""
    import json as _json
    import urllib.request
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        return None
    try:
        req = urllib.request.Request("http://supervisor/services/mqtt", headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = _json.load(r).get("data") or {}
        return data if data.get("host") else None
    except Exception as e:  # noqa: BLE001 — best effort; the user can still type the login
        print(f"Supervisor MQTT service lookup failed: {e}", flush=True)
        return None


def ensure_password(cfg: Config, user: str, purpose: str, role: str, control: bool) -> None:
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.mqtt import Acl
    pf = PasswordFile(cfg.mqtt.password_file)
    if pf.has_user(user):
        return
    pw = secrets.token_urlsafe(24)
    Admin(cfg, CONFIG, pf, Acl(), set(), managed=True).upsert_user(user, role=role, password=pw, control=control, subscribe=None, publish=None)
    # Shown ONCE in the add-on log.  Never written anywhere else in plaintext.
    print("=" * 72)
    print(f"MQTT credentials — {purpose}  (user: {user})")
    print(f"password: {pw}")
    print("This is the only time it is shown. Change it any time in the web UI → Settings → Users & access.")
    print("=" * 72, flush=True)


async def heartbeat() -> None:
    p = DATA / ".healthy"
    while True:
        p.touch()
        await asyncio.sleep(30)


async def main_async() -> int:
    opts = json.loads(OPTIONS.read_text())
    CONFIG.write_text(yaml.safe_dump(build_config(opts), sort_keys=False))
    os.chmod(CONFIG, 0o600)
    cfg = Config.load(CONFIG)
    logging.basicConfig(level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    ha_user = str(opts.get("homeassistant_mqtt_user", "homeassistant"))
    ensure_password(cfg, ha_user, "for the Home Assistant MQTT integration", "homeassistant", bool(opts.get("homeassistant_can_permit_join")))
    ensure_password(cfg, "admin", "for pairing devices and the web UI", "admin", True)
    ca = DATA / "tls" / "ca.crt"
    if ca.exists():
        from oneroof_zigbee.security.tls import fingerprint
        print(f"MQTT TLS: CA certificate at {ca}  (SHA-256 {fingerprint(ca)})")
        print("In Home Assistant → Settings → Integrations → MQTT → Configure → Advanced: port 8883, upload this CA as 'Broker certificate'.", flush=True)
    hb = asyncio.create_task(heartbeat())
    try:
        rc = await run(cfg, CONFIG, managed=True)
        # exit code 4 = restart requested: the supervisor restarts us (boot: auto)
        return 0 if rc == 4 else rc
    finally:
        hb.cancel()


if __name__ == "__main__":
    sys.exit(asyncio.run(main_async()))
