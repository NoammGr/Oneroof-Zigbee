"""End-to-end: the production stack (`oneroof_zigbee.__main__.run`) with
TLS broker, UI server, keystore, audit, registry and admin — driven the way a
user and Home Assistant would drive it: MQTT over TLS, the HTTP API, and the
radio side via simulated devices.  The only fake is the serial port.

Scenarios run in order on one booted stack (module scope), like a first day:
  boot → HA connects over TLS → pair plug (plain) → pair sensor (install code)
  → discovery & state on MQTT → control from MQTT and from the UI → reports
  → rename/describe/bind/reporting → activity & audit → security (denials,
  eviction, anonymous, untrusted TLS, unknown traffic) → users live → config
  save / restart flag → backup/restore → OTA full transfer → import z2m
  → dongle disconnect → clean shutdown with audit chain intact.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import ssl
import time

import pytest
import pytest_asyncio

import oneroof_zigbee.__main__ as main_mod
from oneroof_zigbee.config import Config
from oneroof_zigbee.mqtt import Client, PasswordFile
from oneroof_zigbee.mqtt.client import ConnectRefused
from oneroof_zigbee.security import Audit
from oneroof_zigbee.security.tls import client_context
from tests.fake_znp import FakeZnp
from tests.sim import World, climate_sensor, contact_sensor, plug
from tests.test_ota_import import Z2M_BACKUP, Z2M_CONFIG, Z2M_DB, make_ota
from tests.test_ui import http as _http

PLUG_IEEE, PLUG_NWK = 0xA4C138DE0A1A36FE, 0x98C3
SENS_IEEE, SENS_NWK = 0x00158D0001C0FFEE, 0x1234
DOOR_IEEE, DOOR_NWK = 0x00158D0002D00FF1, 0x4321
BASE = "oneroof/zigbee"
pytestmark = pytest.mark.asyncio(loop_scope="module")


class Stack:
    def __init__(self) -> None:
        self.got: dict[str, bytes] = {}
        self.history: list[tuple[str, bytes]] = []
        self.events: list[dict] = []


async def wait_for(pred, timeout=5.0, step=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = pred()
        if v:
            return v
        await asyncio.sleep(step)
    raise AssertionError("condition not met in time")


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def stack(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    os.environ["ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE"] = "e2e-passphrase"
    fake = FakeZnp()
    world = World(fake)

    async def fake_open_serial(port, baudrate=115200, *, rtscts=False):
        return fake.reader, fake.writer

    main_mod.open_serial = fake_open_serial
    cfg_path = tmp / "config.yaml"
    cfg_path.write_text(
        f"serial:\n  port: /dev/ttyUSB-e2e\ndata_dir: {tmp}\n"
        "zigbee:\n  channel: 15\n  permit_join_cooldown_seconds: 0\n"
        "mqtt:\n  listen: 127.0.0.1\n  port: 0\n  control_users: [admin]\n"
        "  users:\n    homeassistant:\n      subscribe: ['oneroof/zigbee/#', 'homeassistant/#']\n"
        "      publish: ['oneroof/zigbee/+/set', 'oneroof/zigbee/bridge/request/#', 'homeassistant/status']\n"
        "    admin:\n      subscribe: ['#']\n      publish: ['#']\n"
        "ui:\n  listen: 127.0.0.1\n  port: 0\n  acts_as: admin\n"
    )
    cfg = Config.load(cfg_path)
    pw = PasswordFile(cfg.mqtt.password_file)
    pw.set_password("homeassistant", "ha-password-e2e!")
    pw.set_password("admin", "admin-password-e2e!")
    main_mod._last_broker = None
    main_mod._last_ui = None
    task = asyncio.create_task(main_mod.run(cfg, cfg_path))
    await wait_for(lambda: main_mod._last_broker and main_mod._last_broker.port and main_mod._last_ui and main_mod._last_ui.port, 10)
    s = Stack()
    s.tmp, s.cfg, s.cfg_path, s.fake, s.world, s.task = tmp, cfg, cfg_path, fake, world, task
    s.broker, s.ui = main_mod._last_broker, main_mod._last_ui
    s.ca = tmp / "tls" / "ca.crt"
    # Home Assistant's MQTT client, over TLS, trusting our CA
    s.ha = Client("127.0.0.1", s.broker.port, username="homeassistant", password="ha-password-e2e!", client_id="ha",
                  tls=client_context(s.ca, server_hostname_check=False))
    await s.ha.connect()

    async def on_msg(topic, payload):
        s.got[topic] = payload
        s.history.append((topic, payload))

    await s.ha.subscribe(f"{BASE}/#", on_msg)
    await s.ha.subscribe("homeassistant/#", on_msg)
    s.admin = Client("127.0.0.1", s.broker.port, username="admin", password="admin-password-e2e!", client_id="admin",
                     tls=client_context(s.ca, server_hostname_check=False))
    await s.admin.connect()
    await s.admin.subscribe(f"{BASE}/bridge/response/#", on_msg)
    await asyncio.sleep(0.3)
    yield s
    await s.ha.disconnect()
    await s.admin.disconnect()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


async def api(s: Stack, method: str, path: str, body=None):
    st, hdrs, payload = await _http(s.ui.port, method, path, body)
    try:
        return st, json.loads(payload)
    except ValueError:
        return st, payload


async def mqtt_request(s: Stack, client: Client, action: str, body: dict) -> dict:
    topic = f"{BASE}/bridge/response/{action}"
    s.got.pop(topic, None)
    await client.publish(f"{BASE}/bridge/request/{action}", json.dumps(body).encode(), qos=1)
    await wait_for(lambda: topic in s.got)
    return json.loads(s.got[topic])


# ------------------------------------------------------------------ 1. boot --


async def test_01_boot_secure_defaults(stack):
    s = stack
    assert s.fake.formed, "coordinator formed a network"
    assert s.fake.permit_durations[-1] == 0, "join window closed at boot"
    assert s.broker.tls is not None and s.ca.exists(), "TLS on by default with a local CA"
    for name in ("network.keystore", "mqtt.passwd", "audit.log", "tls/ca.key", "tls/server.key"):
        assert oct(os.stat(s.tmp / name).st_mode & 0o777) == "0o600", name
    assert s.got[f"{BASE}/bridge/state"] == b"online"
    info = json.loads(s.got[f"{BASE}/bridge/info"])
    assert info["channel"] == 15 and info["device_count"] == 0
    # HA discovery for the bridge itself is retained
    assert "homeassistant/switch/oneroof_zigbee_bridge/permit_join/config" in s.got
    st, b = await api(s, "GET", "/api/bridge")
    assert st == 200 and b["ui_can_control"] is True and b["strict_install_codes"] is False


# ---------------------------------------------------------------- 2. pairing --


async def test_02_ha_cannot_open_network_but_admin_can(stack):
    s = stack
    r = await mqtt_request(s, s.ha, "permit_join", {"seconds": 60})
    assert r == {"ok": False, "error": "not authorized"}
    assert s.fake.permit_durations[-1] == 0
    await wait_for(lambda: f"{BASE}/bridge/security" in s.got)
    assert json.loads(s.got[f"{BASE}/bridge/security"])["type"] == "request_denied"
    r = await mqtt_request(s, s.admin, "permit_join", {"seconds": 60})
    assert r["ok"] and r["seconds"] == 60 and s.fake.permit_durations[-1] == 60
    await wait_for(lambda: json.loads(s.got.get(f"{BASE}/bridge/permit_join", b"{}")).get("open") is True)


async def test_03_pair_plug_interview_discovery_state(stack):
    s = stack
    d = s.world.add(plug(PLUG_IEEE, PLUG_NWK))
    s.world.announce(d)
    dev = await wait_for(lambda: (lambda x: x if x and x.interviewed else None)(s.broker and _gw(s).registry.get(PLUG_IEEE)), 8)
    assert dev.model == "TS011F" and dev.manufacturer == "_TZ3000_ko6v90pg" and dev.sw_build == "1.0.0"
    assert dev.endpoints[1].category == "plug"
    ieee = dev.ieee_str
    # HA discovery: switch + power/energy sensors, with availability + device block
    await wait_for(lambda: f"homeassistant/switch/{ieee}/switch/config" in s.got)
    sw = json.loads(s.got[f"homeassistant/switch/{ieee}/switch/config"])
    assert sw["command_topic"] == f"{BASE}/{ieee}/set" and sw["device"]["model"] == "TS011F" and sw["device"]["manufacturer"] == "_TZ3000_ko6v90pg"
    assert f"homeassistant/sensor/{ieee}/power/config" in s.got and f"homeassistant/sensor/{ieee}/energy/config" in s.got
    # state on MQTT reflects the interview reads incl. divisors and StartUpOnOff
    state = json.loads(s.got[f"{BASE}/{ieee}/state"])
    assert state["state"] == "ON" and state["power"] == 71.0 and state["current"] == 0.3 and state["voltage"] == 236.0
    assert state["energy"] == 193.08 and state["power_on_behavior"] == "previous"
    assert s.got[f"{BASE}/{ieee}/availability"] == b"online"
    # bound + reporting configured for on/off, metering, electrical
    binds = {int.from_bytes(f.data[11:13], "little") for f in s.fake.requests if f.subsystem.name == "ZDO" and f.command == 0x21}
    assert {0x0006, 0x0702, 0x0B04} <= binds
    assert json.loads(s.got[f"{BASE}/bridge/info"])["device_count"] == 1


async def test_04_pair_sensor_with_install_code(stack):
    s = stack
    await _gw(s).coord._force_close_join()
    code = "83FE D340 7A93 9723 A5C6 39B2 6916 D505 C3B5"
    st, r = await api(s, "POST", "/api/permit_join", {"seconds": 60, "ieee": f"0x{SENS_IEEE:016x}", "install_code": code})
    assert st == 200 and r["ok"]
    assert s.fake.install_codes[-1] == (SENS_IEEE, bytes.fromhex("66b6900981e1ee3ca4206b6b861c02bb"))
    # a DIFFERENT device trying to join during this pinned window is evicted + alerted
    intruder = s.world.add(plug(0x00124B00BADBADBA, 0x6666))
    s.world.announce(intruder)
    await wait_for(lambda: any(f.subsystem.name == "ZDO" and f.command == 0x34 and int.from_bytes(f.data[2:10], "little") == intruder.ieee
                               for f in s.fake.requests))
    assert _gw(s).registry.get(intruder.ieee) is None
    await wait_for(lambda: json.loads(s.got[f"{BASE}/bridge/security"])["type"] == "unexpected_join")
    # the right device joins fine
    d = s.world.add(climate_sensor(SENS_IEEE, SENS_NWK))
    s.world.announce(d)
    dev = await wait_for(lambda: (lambda x: x if x and x.interviewed else None)(_gw(s).registry.get(SENS_IEEE)), 8)
    assert dev.model == "lumi.weather" and not dev.is_router
    state = json.loads(s.got[f"{BASE}/{dev.ieee_str}/state"])
    assert state["temperature"] == 21.35 and state["humidity"] == 45.12 and state["battery"] == 90
    assert f"homeassistant/sensor/{dev.ieee_str}/temperature/config" in s.got
    # window auto-closes when the expected device joined? (policy: stays open until timeout) → close it explicitly
    await _gw(s).coord._force_close_join()
    assert s.fake.permit_durations[-1] == 0


# ---------------------------------------------------------------- 3. control --


async def test_05_control_from_mqtt_and_ui_reaches_radio(stack):
    s = stack
    d = s.world.devices[PLUG_NWK]
    ieee = f"0x{PLUG_IEEE:016x}"
    # HA (MQTT) turns the plug off
    d.received_commands.clear()
    await s.ha.publish(f"{BASE}/{ieee}/set", b'{"state": "OFF"}', qos=1)
    await wait_for(lambda: (0x0006, 0x00, b"") in d.received_commands)
    await wait_for(lambda: json.loads(s.got[f"{BASE}/{ieee}/state"])["state"] == "OFF")
    # UI sets power-on behaviour (write attribute) and starts a countdown
    st, r = await api(s, "POST", f"/api/devices/{ieee}/set", {"power_on_behavior": "on"})
    assert st == 200
    await wait_for(lambda: (0x0006, 0x4003, 1) in d.written)
    st, r = await api(s, "POST", f"/api/devices/{ieee}/set", {"countdown": 45})
    assert st == 200
    await wait_for(lambda: any(c == (0x0006, 0x42) and int.from_bytes(p[1:3], "little") == 450 for c, p in [((x[0], x[1]), x[2]) for x in d.received_commands]))
    await wait_for(lambda: json.loads(s.got[f"{BASE}/{ieee}/state"])["state"] == "ON")
    # HA user may NOT remove a device
    r = await mqtt_request(s, s.ha, "remove", {"ieee": ieee})
    assert r["ok"] is False and _gw(s).registry.get(PLUG_IEEE) is not None


async def test_06_reports_flow_to_mqtt_activity_and_sse(stack):
    s = stack
    d = s.world.devices[PLUG_NWK]
    ieee = f"0x{PLUG_IEEE:016x}"
    # open an SSE stream like the browser does
    r, w = await asyncio.open_connection("127.0.0.1", s.ui.port)
    w.write(b"GET /api/events HTTP/1.1\r\nHost: x\r\n\r\n")
    await w.drain()
    await r.readuntil(b"\r\n\r\n")
    s.world.report(d, 0x0B04, 0x050B, 0x29, (120).to_bytes(2, "little"))
    await wait_for(lambda: json.loads(s.got[f"{BASE}/{ieee}/state"])["power"] == 120.0)
    buf = b""
    while b"event: activity" not in buf or b'"key":"power"' not in buf:
        buf += await asyncio.wait_for(r.read(4096), 3)
    w.close()
    st, a = await api(s, "GET", f"/api/activity?device={ieee}&key=power&n=5")
    assert a["rows"][-1]["new"] == 120.0 and a["rows"][-1]["old"] == 71.0 and a["rows"][-1]["friendly_name"]
    assert (s.tmp / "activity.log").exists()
    # IAS contact sensor: enrol flow + zone status → contact state + HA binary_sensor
    await api(s, "POST", "/api/permit_join", {"seconds": 30})
    door = s.world.add(contact_sensor(DOOR_IEEE, DOOR_NWK))
    s.world.announce(door)
    dev = await wait_for(lambda: (lambda x: x if x and x.interviewed else None)(_gw(s).registry.get(DOOR_IEEE)), 8)
    assert (0x0500, 0x0010, _gw(s).coord.ieee) in door.written, "CIE address written during enrolment"
    assert any(c == 0x0500 and cmd == 0x00 for c, cmd, _ in door.received_commands), "zone enroll response sent"
    await wait_for(lambda: f"homeassistant/binary_sensor/{dev.ieee_str}/contact/config" in s.got)
    s.world.ias_notify(door, 0x0001)  # alarm1 = open
    await wait_for(lambda: json.loads(s.got[f"{BASE}/{dev.ieee_str}/state"]).get("contact") is False)
    s.world.ias_notify(door, 0x0000)
    await wait_for(lambda: json.loads(s.got[f"{BASE}/{dev.ieee_str}/state"]).get("contact") is True)
    await _gw(s).coord._force_close_join()


async def test_07_rename_describe_bind_reporting_read(stack):
    s = stack
    ieee = f"0x{PLUG_IEEE:016x}"
    st, r = await api(s, "POST", f"/api/devices/{ieee}/rename", {"friendly_name": "Garage plug"})
    assert st == 200
    # discovery re-announced with the new name; MQTT state topic stays IEEE-based (stable)
    await wait_for(lambda: json.loads(s.got[f"homeassistant/switch/{ieee}/switch/config"])["device"]["name"] == "Garage plug")
    st, r = await api(s, "POST", f"/api/devices/{ieee}/describe", {"description": "Behind the workbench"})
    assert st == 200
    # set by friendly name over MQTT works too
    d = s.world.devices[PLUG_NWK]
    d.received_commands.clear()
    await s.ha.publish(f"{BASE}/Garage plug/set", b'{"state": "TOGGLE"}', qos=1)
    await wait_for(lambda: (0x0006, 0x02, b"") in d.received_commands)
    # live read, reporting reconfigure, bind to another device
    st, r = await api(s, "POST", f"/api/devices/{ieee}/read", {"endpoint": 1, "cluster": "0x0b04", "attributes": ["0x050b"]})
    assert st == 200 and r["decoded"]["power"] == 120.0
    st, r = await api(s, "POST", f"/api/devices/{ieee}/reporting", {"endpoint": 1, "cluster": 0x0B04, "attribute": 0x050B, "min": 1, "max": 60, "change": 1})
    assert st == 200 and r["ok"]
    st, r = await api(s, "POST", f"/api/devices/{ieee}/bind", {"endpoint": 1, "cluster": 6, "target": f"0x{SENS_IEEE:016x}", "target_endpoint": 1})
    assert st == 200 and any(b["target"] == f"0x{SENS_IEEE:016x}" for b in r["bindings"])
    bind_req = [f for f in s.fake.requests if f.subsystem.name == "ZDO" and f.command == 0x21][-1]
    assert int.from_bytes(bind_req.data[14:22], "little") == SENS_IEEE, "bind destination is the other device, not the coordinator"
    st, d_json = await api(s, "GET", f"/api/devices/{ieee}")
    assert d_json["friendly_name"] == "Garage plug" and d_json["description"] == "Behind the workbench" and d_json["oui_vendor"] == "Telink Semiconductor"
    assert {f["key"] for f in d_json["exposes"]} >= {"state", "power_on_behavior", "countdown", "power", "energy", "identify"}


# --------------------------------------------------------------- 4. security --


async def test_08_security_boundaries(stack):
    s = stack
    # anonymous MQTT → CONNACK 0x05 even over TLS
    from oneroof_zigbee.mqtt import packets as pk
    ctx = client_context(s.ca, server_hostname_check=False)
    r, w = await asyncio.open_connection("127.0.0.1", s.broker.port, ssl=ctx)
    w.write(pk.encode(pk.Connect(client_id="anon", keepalive=10)))
    await w.drain()
    raw = await asyncio.wait_for(r.read(4), 3)
    assert raw[0] == 0x20 and raw[3] == 0x05
    w.close()
    # a client that does not trust our CA cannot even complete the handshake
    bad = Client("127.0.0.1", s.broker.port, username="homeassistant", password="ha-password-e2e!", client_id="bad",
                 tls=client_context(None, server_hostname_check=False))
    with pytest.raises(ssl.SSLError):
        await bad.connect()
    # wrong password ×5 → lockout
    for _ in range(5):
        c = Client("127.0.0.1", s.broker.port, username="homeassistant", password="wrong-password-xx", client_id="guess",
                   tls=client_context(s.ca, server_hostname_check=False))
        with pytest.raises(ConnectRefused):
            await c.connect()
    good = Client("127.0.0.1", s.broker.port, username="homeassistant", password="ha-password-e2e!", client_id="locked",
                  tls=client_context(s.ca, server_hostname_check=False))
    with pytest.raises(ConnectRefused):
        await good.connect()  # locked out for 30 s even with the right password
    s.broker._lockouts.clear()  # don't make later tests wait
    s.broker._auth_failures.clear()
    # HA user cannot publish outside its ACL (state topics are gateway-owned)
    before = s.got.get(f"{BASE}/0xdead/state")
    await s.ha.publish(f"{BASE}/0xdead/state", b"forged", qos=1)
    await asyncio.sleep(0.2)
    assert s.got.get(f"{BASE}/0xdead/state") == before
    # traffic from a short address we never admitted → security alert, and nothing is published for it
    s.fake.emit_incoming(0x7777, 0x0006, bytes([0x18, 0x01, 0x0A, 0x00, 0x00, 0x10, 0x01]))
    await wait_for(lambda: json.loads(s.got[f"{BASE}/bridge/security"])["type"] == "traffic_from_unknown_device")
    assert not any(t.startswith(f"{BASE}/0x") and b"7777" in p for t, p in s.history if "/state" in t and "7777" in t)
    # UI: POST without the CSRF header is refused; a non-control UI user cannot open the network
    st, _ = await api(s, "GET", "/api/bridge")
    from tests.test_ui import http as raw_http
    st, _, _ = await raw_http(s.ui.port, "POST", "/api/permit_join", headers={"Content-Type": "application/json"}, raw_body=b'{"seconds":30}')
    assert st == 403
    # audit chain is intact and records all of the above with identities
    ok, line = Audit.verify(s.tmp / "audit.log")
    assert ok, f"audit chain broken at line {line}"
    text = (s.tmp / "audit.log").read_text()
    assert '"by":"homeassistant"' in text and '"by":"ui:admin"' in text and '"request_denied"' in text and '"unexpected_join"' in text


# ------------------------------------------------------ 5. users / config ----


async def test_09_users_live_without_restart(stack):
    s = stack
    st, r = await api(s, "POST", "/api/users", {"name": "dashboard", "role": "readonly", "password": "dashboard-pass-1"})
    assert st == 200
    ro = Client("127.0.0.1", s.broker.port, username="dashboard", password="dashboard-pass-1", client_id="ro",
                tls=client_context(s.ca, server_hostname_check=False))
    await ro.connect()  # works immediately — no restart
    seen = {}

    async def on(t, p):
        seen[t] = p

    await ro.subscribe(f"{BASE}/+/state", on)
    await wait_for(lambda: any(t.endswith("/state") for t in seen))  # retained state delivered
    # read-only user cannot control anything
    d = s.world.devices[PLUG_NWK]
    d.received_commands.clear()
    await ro.publish(f"{BASE}/0x{PLUG_IEEE:016x}/set", b'{"state":"OFF"}', qos=1)
    await asyncio.sleep(0.3)
    assert d.received_commands == []
    await ro.disconnect()
    st, r = await api(s, "POST", "/api/users/dashboard/remove", {})
    assert st == 200
    again = Client("127.0.0.1", s.broker.port, username="dashboard", password="dashboard-pass-1", client_id="ro2",
                   tls=client_context(s.ca, server_hostname_check=False))
    with pytest.raises(ConnectRefused):
        await again.connect()


async def test_10_config_save_backup_restore(stack):
    s = stack
    st, r = await api(s, "POST", "/api/config", {"zigbee": {"permit_join_max_seconds": 90}})
    assert st == 200 and "zigbee.permit_join_max_seconds" in r["restart_required"]
    import yaml
    assert yaml.safe_load(s.cfg_path.read_text())["zigbee"]["permit_join_max_seconds"] == 90
    st, b = await api(s, "GET", "/api/bridge")
    assert "zigbee.permit_join_max_seconds" in b["restart_required"]
    # encrypted backup round-trip, including the keystore the network depends on
    st, r = await api(s, "POST", "/api/backup", {"password": "backup-password-e2e"})
    assert st == 200
    blob = base64.b64decode(r["data_b64"])
    ks_before = (s.tmp / "network.keystore").read_bytes()
    devices_before = (s.tmp / "devices.json").read_text()
    (s.tmp / "devices.json").write_text('{"devices": []}')
    st, r2 = await api(s, "POST", "/api/restore", {"password": "backup-password-e2e", "data_b64": r["data_b64"]})
    assert st == 200 and "devices.json" in r2["restored"] and "network.keystore" in r2["restored"]
    assert (s.tmp / "devices.json").read_text() == devices_before and (s.tmp / "network.keystore").read_bytes() == ks_before
    assert b"Garage plug" not in blob, "backup is encrypted"


# ------------------------------------------------------------------- 6. OTA --


async def test_11_ota_full_transfer_to_device(stack):
    s = stack
    ieee = f"0x{PLUG_IEEE:016x}"
    d = s.world.devices[PLUG_NWK]
    image = make_ota(manuf=0x1037, itype=0x0001, version=5, body=bytes(range(256)) * 3)
    st, r = await api(s, "POST", "/api/firmware/upload", {"filename": "ts011f_v5.ota", "data_b64": base64.b64encode(image).decode()})
    assert st == 200 and r["image"]["file_version_decimal"] == 5
    # a file for another manufacturer is also in the library, and must never be offered
    other = make_ota(manuf=0x9999, itype=0x0001, version=9)
    await api(s, "POST", "/api/firmware/upload", {"filename": "other_vendor.ota", "data_b64": base64.b64encode(other).decode()})
    # ask the device what it runs
    st, r = await api(s, "POST", f"/api/devices/{ieee}/update/check", {})
    assert st == 200
    await wait_for(lambda: _gw(s).ota.last_query.get(PLUG_IEEE))
    st, u = await api(s, "GET", f"/api/devices/{ieee}/update")
    assert u["last_query"]["file_version"] == "0x00000003" and [c["file"] for c in u["candidates"]] == ["ts011f_v5.ota"]
    # wrong-vendor image refused at arm time
    st, r = await api(s, "POST", f"/api/devices/{ieee}/update/start", {"file": "other_vendor.ota"})
    assert st == 400 and "manufacturer" in r["error"]
    # start the real one → device pulls every block → upgrade end
    st, r = await api(s, "POST", f"/api/devices/{ieee}/update/start", {"file": "ts011f_v5.ota"})
    assert st == 200
    await wait_for(lambda: d.ota_done, 15)
    assert bytes(d.ota_received) == image, "device received the exact image"
    st, u = await api(s, "GET", f"/api/devices/{ieee}/update")
    assert u["session"]["finished"] and u["session"]["result"] == "success" and u["armed"] is None
    text = (s.tmp / "audit.log").read_text()
    assert '"firmware_update_armed"' in text and '"firmware_update_finished"' in text


# ---------------------------------------------------------------- 7. import --


async def test_12_import_z2m_keeps_devices_and_names(stack):
    s = stack
    st, r = await api(s, "POST", "/api/import/preview", {"configuration.yaml": Z2M_CONFIG, "database.db": Z2M_DB, "coordinator_backup.json": Z2M_BACKUP})
    assert st == 200 and r["network"]["found"] and r["network"]["frame_counter"] == 123456 and len(r["devices"]) == 2
    assert r["network"]["key_is_well_known_default"] is True
    st, r = await api(s, "POST", "/api/import/apply", {"configuration.yaml": Z2M_CONFIG, "database.db": Z2M_DB, "coordinator_backup.json": Z2M_BACKUP})
    assert st == 200 and r["network_adopted"] and "import: network parameters" in r["restart_required"]
    # the plug we already had keeps its identity but gets the imported name/description
    dev = _gw(s).registry.get(PLUG_IEEE)
    assert dev.friendly_name == "3D Printer - Smart Plug" and dev.description == "Garage" and dev.model == "TS011F"
    # the keystore now holds z2m's network → next start adopts it instead of re-forming
    from oneroof_zigbee.security import Keystore
    sec = Keystore(s.tmp / "network.keystore").load()
    assert sec.network_key.hex() == "01030507090b0d0f00020406080a0c0d" and sec.channel == 11 and sec.frame_counter == 123456 + 100_000
    # discovery updated with the new name, retained
    await wait_for(lambda: json.loads(s.got[f"homeassistant/switch/0x{PLUG_IEEE:016x}/switch/config"])["device"]["name"] == "3D Printer - Smart Plug")


# ------------------------------------------------------------- 8. lifecycle --


async def test_13_ui_pages_served_and_restart_flag(stack):
    s = stack
    st, hdrs, body = await _http(s.ui.port, "GET", "/")
    assert st == 200 and b"OneRoof" in body and "Content-Security-Policy" in hdrs
    assert b"<script src=\"http" not in body and b"fonts.googleapis" not in body, "UI makes no external requests"
    st, r = await api(s, "GET", "/api/config")
    assert r["managed"] is False and r["tls"]["mode"] == "auto" and r["tls"]["ca_fingerprint_sha256"]
    st, r = await api(s, "GET", "/api/users")
    assert {u["name"] for u in r["users"]} >= {"admin", "homeassistant", "oneroof_zigbee"}
    assert all("password" not in json.dumps(u) or u.get("has_password") in (True, False) for u in r["users"])


async def test_14_dongle_disconnect_exits_for_supervisor_restart(stack):
    s = stack
    # removing the USB dongle closes the serial stream → run() returns rc 3 (supervisor restarts the add-on)
    s.fake.reader.feed_eof()
    rc = await asyncio.wait_for(s.task, 10)
    assert rc == 3
    assert s.got[f"{BASE}/bridge/state"] == b"offline", "gateway announces offline to HA on the way down"
    ok, _ = Audit.verify(s.tmp / "audit.log")
    assert ok
    # rotate key request recorded earlier? no — but the whole day is in the audit log, chained
    n = sum(1 for _ in open(s.tmp / "audit.log"))
    assert n > 40


def _gw(s: Stack):
    # the Gateway instance is reachable through the UI API object attached to the server routes
    return _find_gateway(s.ui)


def _find_gateway(server):
    for _, _, handler in server._routes:
        self_ = getattr(handler, "__self__", None)
        if self_ is not None and hasattr(self_, "gw"):
            return self_.gw
    raise RuntimeError("gateway not found")


# --------------------------------------------- 9. zigbee2mqtt compatibility --


async def test_15_legacy_layout_keeps_existing_broker_topics_and_ha_entities(tmp_path_factory):
    """Migration promise: with compat on and an external broker, Home Assistant and any other
    MQTT consumer see exactly what zigbee2mqtt published — same broker, same topics,
    same discovery unique_ids/device identifiers — so nothing has to be reconfigured."""
    from oneroof_zigbee.mqtt import Acl, Broker
    tmp = tmp_path_factory.mktemp("compat")
    os.environ["ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE"] = "e2e-passphrase"
    # "Mosquitto": an independent broker with zigbee2mqtt's classic login
    mpw = PasswordFile(tmp / "mosq.passwd")
    mpw.set_password("mqtt-user", "mqtt-password-123")
    macl = Acl()
    macl.allow("mqtt-user", publish=["#"], subscribe=["#"])
    macl.allow("ha", publish=["#"], subscribe=["#"])
    mpw.set_password("ha", "ha-password-e2e!")
    mosq = Broker(auth=mpw, acl=macl, host="127.0.0.1", port=0, tls=None)
    await mosq.start()
    # Home Assistant already subscribed (as it is today)
    ha = Client("127.0.0.1", mosq.port, username="ha", password="ha-password-e2e!", client_id="ha-compat")
    await ha.connect()
    got: dict[str, bytes] = {}

    async def on(t, p):
        got[t] = p

    await ha.subscribe("zigbee2mqtt/#", on)
    await ha.subscribe("homeassistant/#", on)

    fake = FakeZnp()
    world = World(fake)

    async def fake_open_serial(port, baudrate=115200, *, rtscts=False):
        return fake.reader, fake.writer

    main_mod.open_serial = fake_open_serial
    # the config the importer writes: external broker + compat + base topic from configuration.yaml
    cfg_path = tmp / "config.yaml"
    cfg_path.write_text(
        f"serial:\n  port: /dev/ttyUSB-e2e\ndata_dir: {tmp}\nzigbee:\n  permit_join_cooldown_seconds: 0\n"
        f"mqtt:\n  base_topic: zigbee2mqtt\n  control_users: [admin]\n  external:\n    server: mqtt://127.0.0.1:{mosq.port}\n    user: mqtt-user\n    password: mqtt-password-123\n"
        "compat:\n  legacy_layout: true\nui:\n  listen: 127.0.0.1\n  port: 0\n  acts_as: admin\n"
    )
    cfg = Config.load(cfg_path)
    assert cfg.mqtt.external and cfg.compat.legacy_layout
    main_mod._last_broker = None
    main_mod._last_ui = None
    task = asyncio.create_task(main_mod.run(cfg, cfg_path))
    await wait_for(lambda: main_mod._last_ui and main_mod._last_ui.port, 10)
    ui = main_mod._last_ui
    assert getattr(main_mod._last_broker, "external", False), "built-in broker must not be running"
    await wait_for(lambda: got.get("zigbee2mqtt/bridge/state") == b'{"state": "online"}' or got.get("zigbee2mqtt/bridge/state") == b'{"state":"online"}', 5)

    # pair the plug; give it the friendly name it had in zigbee2mqtt
    st, _, body = await _http(ui.port, "POST", "/api/permit_join", {"seconds": 30})
    assert st == 200, body
    d = world.add(plug(PLUG_IEEE, PLUG_NWK))
    world.announce(d)
    gw = _find_gateway(ui)
    await wait_for(lambda: (lambda x: x and x.interviewed)(gw.registry.get(PLUG_IEEE)), 8)
    await _http(ui.port, "POST", f"/api/devices/0x{PLUG_IEEE:016x}/rename", {"friendly_name": "3D Printer - Smart Plug"})
    await asyncio.sleep(0.5)

    # 1. zigbee2mqtt topic layout on the external broker
    assert "zigbee2mqtt/3D Printer - Smart Plug" in got, sorted(t for t in got if t.startswith("zigbee2mqtt/3D"))
    state = json.loads(got["zigbee2mqtt/3D Printer - Smart Plug"])
    assert state["state"] == "ON" and state["power"] == 71.0 and state["linkquality"] == 200
    assert json.loads(got["zigbee2mqtt/3D Printer - Smart Plug/availability"]) == {"state": "online"}
    assert got.get(f"zigbee2mqtt/0x{PLUG_IEEE:016x}/state") is None, "no native-layout duplicates"
    # 2. Home Assistant identities identical to zigbee2mqtt's
    ieee = f"0x{PLUG_IEEE:016x}"
    sw = json.loads(got[f"homeassistant/switch/{ieee}/switch/config"])
    assert sw["unique_id"] == f"{ieee}_switch_zigbee2mqtt"
    assert sw["device"]["identifiers"] == [f"zigbee2mqtt_{ieee}"]
    assert sw["state_topic"] == "zigbee2mqtt/3D Printer - Smart Plug" and sw["command_topic"] == "zigbee2mqtt/3D Printer - Smart Plug/set"
    assert sw["availability"][1]["value_template"] == "{{ value_json.state }}"
    power = json.loads(got[f"homeassistant/sensor/{ieee}/power/config"])
    assert power["unique_id"] == f"{ieee}_power_zigbee2mqtt"
    volt = json.loads(got[f"homeassistant/sensor/{ieee}/voltage/config"])
    assert volt["unique_id"] == f"{ieee}_voltage_zigbee2mqtt", "z2m object id for mains voltage is 'voltage'"
    # 3. HA controls it exactly as before: publish to the friendly-name set topic on Mosquitto
    d.received_commands.clear()
    await ha.publish("zigbee2mqtt/3D Printer - Smart Plug/set", b'{"state": "OFF"}', qos=1)
    await wait_for(lambda: (0x0006, 0x00, b"") in d.received_commands, 5)
    await wait_for(lambda: json.loads(got["zigbee2mqtt/3D Printer - Smart Plug"])["state"] == "OFF", 5)
    # zigbee2mqtt-style state refresh request
    await ha.publish("zigbee2mqtt/3D Printer - Smart Plug/get", b'{"state": ""}', qos=1)
    await asyncio.sleep(0.3)
    # 4. security still holds: nobody can open the network through the external broker
    got.pop("zigbee2mqtt/bridge/response/permit_join", None)
    await ha.publish("zigbee2mqtt/bridge/request/permit_join", b'{"seconds": 60}', qos=1)
    await wait_for(lambda: "zigbee2mqtt/bridge/response/permit_join" in got, 5)
    assert json.loads(got["zigbee2mqtt/bridge/response/permit_join"]) == {"ok": False, "error": "not authorized"}
    # 5. rename clears the old friendly-name topics (retained) like zigbee2mqtt does
    await _http(ui.port, "POST", f"/api/devices/{ieee}/rename", {"friendly_name": "Garage plug"})
    await wait_for(lambda: got.get("zigbee2mqtt/3D Printer - Smart Plug") == b"" and "zigbee2mqtt/Garage plug" in got, 5)

    await ha.disconnect()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass
    await mosq.stop()


async def test_16_importer_reads_mqtt_section_and_admin_writes_legacy_layout(tmp_path_factory):
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.devices import Registry
    from oneroof_zigbee.importer import build_plan
    from oneroof_zigbee.mqtt import Acl
    from oneroof_zigbee.security import NetworkSecrets
    import yaml
    z2m = Z2M_CONFIG.replace("mqtt:\n  base_topic: zigbee2mqtt\n",
                             "mqtt:\n  base_topic: zigbee2mqtt\n  server: mqtt://core-mosquitto:1883\n  user: mqtt-user\n  password: s3cret-pass\n")
    plan = build_plan(configuration_yaml=z2m, database_db=Z2M_DB, coordinator_backup=None)
    assert plan.mqtt.server == "mqtt://core-mosquitto:1883" and plan.mqtt.user == "mqtt-user" and plan.mqtt.base_topic == "zigbee2mqtt"
    assert plan.summary()["mqtt"]["has_password"] is True and "s3cret" not in json.dumps(plan.summary())
    tmp = tmp_path_factory.mktemp("imp")
    cfg_path = tmp / "config.yaml"
    cfg_path.write_text(f"serial:\n  port: /dev/null\ndata_dir: {tmp}\nmqtt:\n  tls: off\n  port: 0\n")
    cfg = Config.load(cfg_path)
    admin = Admin(cfg, cfg_path, PasswordFile(tmp / "p"), Acl(), set())
    os.environ["ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE"] = "e2e-passphrase"
    r = admin.import_apply({"configuration.yaml": z2m, "database.db": Z2M_DB}, Registry(tmp / "devices.json"), NetworkSecrets.generate(15), set())
    assert "mqtt.external" in r["compat"] and "compat.legacy_layout" in r["compat"]
    saved = yaml.safe_load(cfg_path.read_text())
    assert saved["compat"]["legacy_layout"] is True and saved["mqtt"]["base_topic"] == "zigbee2mqtt"
    assert saved["mqtt"]["external"] == {"server": "mqtt://core-mosquitto:1883", "client_id": "oneroof-zigbee", "user": "mqtt-user", "password": "s3cret-pass"}
    Config.load(cfg_path)  # and it is a valid config
    assert oct(os.stat(cfg_path).st_mode & 0o777) in ("0o600", "0o644")
