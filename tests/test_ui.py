import asyncio
import json

import pytest

from oneroof_zigbee.config import Config, ConfigError
from oneroof_zigbee.devices import Registry
from oneroof_zigbee.gateway import Gateway
from oneroof_zigbee.security import Audit, JoinGuard, JoinPolicy, NetworkSecrets
from oneroof_zigbee.ui.api import EventBus, RingLogHandler, UiApi
from oneroof_zigbee.ui.server import Server
from oneroof_zigbee.znp import Coordinator, Transport
from tests.fake_znp import FakeZnp
from tests.test_gateway import FakeBroker, IEEE, NWK, _fake_device_responses


async def http(port, method, path, body=None, headers=None, raw_body=None):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    hdrs = {"Host": "x", **(headers or {})}
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else b"")
    if body is not None and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/json"
        hdrs.setdefault("X-OneRoof", "1")
    if data:
        hdrs["Content-Length"] = str(len(data))
    req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    w.write(req.encode() + data)
    await w.drain()
    raw = await asyncio.wait_for(r.read(), 5)
    w.close()
    head, _, payload = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    hmap = dict(line.decode().split(": ", 1) for line in head.split(b"\r\n")[1:])
    return status, hmap, payload


@pytest.fixture
async def ui(tmp_path):
    fake = FakeZnp()
    _fake_device_responses(fake)
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    guard = JoinGuard(JoinPolicy(cooldown_seconds=0), Audit(tmp_path / "audit.log"))
    coord = Coordinator(t, NetworkSecrets.generate(15), guard, guard.audit)
    await asyncio.wait_for(coord.start(), 5)
    cfg = Config.from_dict({"serial": {"port": "/dev/null"}, "data_dir": str(tmp_path)})
    broker = FakeBroker()
    gw = Gateway(cfg, coord, broker, guard.audit, Registry(tmp_path / "devices.json"), control_users={"admin"})
    await gw.start()
    bus = EventBus()
    ring = RingLogHandler(bus)
    import logging
    logging.getLogger("oneroof_zigbee").addHandler(ring)
    server = Server("127.0.0.1", 0)
    api = UiApi(gw, server, bus, ring, acts_as="admin")
    await server.start()
    yield fake, gw, server, api
    logging.getLogger("oneroof_zigbee").removeHandler(ring)
    await server.stop()
    await t.close()


async def pair_one(fake, gw, port):
    st, _, body = await http(port, "POST", "/api/permit_join", {"seconds": 30})
    assert st == 200 and json.loads(body)["ok"]
    fake.emit_announce(IEEE, NWK)
    for _ in range(100):
        await asyncio.sleep(0.02)
        d = gw.registry.get(IEEE)
        if d and d.interviewed:
            return d
    raise AssertionError("device never interviewed")


async def test_index_and_security_headers(ui):
    fake, gw, server, api = ui
    st, h, body = await http(server.port, "GET", "/")
    assert st == 200 and h["Content-Type"].startswith("text/html")
    assert h["X-Content-Type-Options"] == "nosniff" and "Content-Security-Policy" in h and h["Cache-Control"] == "no-store"


async def test_bridge_and_devices_flow(ui):
    fake, gw, server, api = ui
    st, _, body = await http(server.port, "GET", "/api/bridge")
    b = json.loads(body)
    assert st == 200 and b["device_count"] == 0 and b["ui_can_control"] is True and b["channel"] == 15
    dev = await pair_one(fake, gw, server.port)
    st, _, body = await http(server.port, "GET", "/api/devices")
    devs = json.loads(body)
    assert len(devs) == 1 and devs[0]["model"] == "Bulb-1" and devs[0]["endpoints"]["1"]["category"] == "light"
    # control a device through the UI → ZCL on the wire
    fake.requests.clear()
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/set", {"brightness": 100})
    assert st == 200 and json.loads(body)["state"]["brightness"] == 100
    assert any(f.subsystem.name == "AF" and f.command == 0x01 for f in fake.requests)
    # rename and remove
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/rename", {"friendly_name": "Kitchen"})
    assert st == 200 and gw.registry.get(IEEE).friendly_name == "Kitchen"
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/remove", {})
    assert st == 200 and gw.registry.get(IEEE) is None


async def test_post_without_csrf_header_or_wrong_content_type_rejected(ui):
    fake, gw, server, api = ui
    st, _, _ = await http(server.port, "POST", "/api/permit_join", headers={"Content-Type": "application/json"}, raw_body=b"{}")
    assert st == 403
    st, _, _ = await http(server.port, "POST", "/api/permit_join", headers={"X-OneRoof": "1", "Content-Type": "text/plain"}, raw_body=b"{}")
    assert st == 415
    st, _, _ = await http(server.port, "POST", "/api/permit_join", headers={"X-OneRoof": "1", "Content-Type": "application/json"}, raw_body=b"[1]")
    assert st == 400
    assert gw.coord.guard.window is None


async def test_ui_user_not_in_control_users_is_refused(ui):
    fake, gw, server, api = ui
    api.acts_as = "homeassistant"
    st, _, body = await http(server.port, "POST", "/api/permit_join", {"seconds": 30})
    assert st == 403 and "not authorized" in json.loads(body)["error"]
    st, _, body = await http(server.port, "GET", "/api/audit?level=security")
    assert json.loads(body)[-1]["type"] == "request_denied"
    api.acts_as = "admin"


async def test_limits_and_unknown_routes(ui):
    fake, gw, server, api = ui
    st, _, _ = await http(server.port, "GET", "/api/nope")
    assert st == 404
    st, _, _ = await http(server.port, "GET", "/api/permit_join")
    assert st == 405
    st, _, _ = await http(server.port, "POST", "/api/permit_join", headers={"X-OneRoof": "1", "Content-Type": "application/json"}, raw_body=b"x" * (3 * 1024 * 1024))
    assert st == 413
    st, _, _ = await http(server.port, "GET", "/api/devices/notanieee")
    assert st == 400


async def test_ingress_prefix_stripped(ui):
    fake, gw, server, api = ui
    st, _, body = await http(server.port, "GET", "/api/hassio_ingress/abc/api/bridge", headers={"X-Ingress-Path": "/api/hassio_ingress/abc"})
    assert st == 200 and "coordinator_ieee" in json.loads(body)


async def test_audit_logs_and_verify(ui):
    fake, gw, server, api = ui
    st, _, body = await http(server.port, "GET", "/api/audit?n=5")
    rows = json.loads(body)
    assert rows and all("prev" not in r for r in rows)
    st, _, body = await http(server.port, "GET", "/api/audit/verify")
    assert json.loads(body)["ok"] is True
    import logging
    logging.getLogger("oneroof_zigbee.test").warning("hello ring")
    st, _, body = await http(server.port, "GET", "/api/logs")
    assert any(r["msg"] == "hello ring" for r in json.loads(body))


async def test_sse_streams_events(ui):
    fake, gw, server, api = ui
    r, w = await asyncio.open_connection("127.0.0.1", server.port)
    w.write(b"GET /api/events HTTP/1.1\r\nHost: x\r\n\r\n")
    await w.drain()
    head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 3)
    assert b"text/event-stream" in head
    await pair_one(fake, gw, server.port)
    buf = b""
    for _ in range(50):
        buf += await asyncio.wait_for(r.read(4096), 3)
        if b"event: device" in buf and b"event: permit_join" in buf:
            break
    assert b"event: permit_join" in buf and b'"open":true' in buf
    assert b"event: device" in buf and b'"action":"joined"' in buf
    w.close()


async def test_map_refresh(ui):
    fake, gw, server, api = ui
    st, _, body = await http(server.port, "POST", "/api/map/refresh", {})
    m = json.loads(body)
    assert st == 200 and m["nodes"][0]["type"] == "coordinator"
    assert m["links"] and m["links"][0]["lqi"] == 180 and m["links"][0]["relationship"] == "child"


def test_ui_listen_must_be_loopback():
    with pytest.raises(ConfigError):
        Config.from_dict({"serial": {"port": "x"}, "ui": {"listen": "0.0.0.0"}})
    Config.from_dict({"serial": {"port": "x"}, "ui": {"listen": "0.0.0.0", "i_know_this_exposes_the_ui_to_the_lan": True}})


async def test_device_detail_shape(ui):
    fake, gw, server, api = ui
    dev = await pair_one(fake, gw, server.port)
    st, _, body = await http(server.port, "GET", f"/api/devices/{dev.ieee_str}")
    d = json.loads(body)
    assert st == 200
    assert d["oui_vendor"] == "Texas Instruments" and d["nwk_decimal"] == NWK and d["manufacturer_code"] == 0x1037
    assert d["mqtt"]["set_topic"].endswith(f"/{dev.ieee_str}/set")
    assert d["endpoints"]["1"]["in_clusters"][1] == {"id": 6, "name": "on_off"}
    keys = {f["key"] for f in d["exposes"]}
    assert {"state", "brightness", "power_on_behavior", "countdown", "linkquality"} <= keys
    assert any(r["cluster"] == 6 and r["status"] == "ok" for r in d["reporting"])
    assert any(b["cluster"] == 8 and b["target"] == "coordinator" for b in d["bindings"])
    assert d["raw"]["6"]["0"]["name"] == "on_off" and d["raw"]["6"]["0"]["value"] is True
    assert any(a["key"] == "state" for a in d["activity"]), d["activity"]


async def test_power_on_behavior_and_countdown_bytes(ui):
    fake, gw, server, api = ui
    dev = await pair_one(fake, gw, server.port)
    fake.requests.clear()
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/set", {"power_on_behavior": "previous"})
    assert st == 200
    reqs = [f for f in fake.requests if f.subsystem.name == "AF" and f.command == 0x01]
    z = reqs[0].data[10:]
    # write attributes: frame ctrl 0x00, seq, cmd 0x02, attr 0x4003 LE, type enum8 0x30, value 0xff
    assert z[2] == 0x02 and z[3:5] == b"\x03\x40" and z[5] == 0x30 and z[6] == 0xFF
    fake.requests.clear()
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/set", {"countdown": 30})
    assert st == 200 and json.loads(body)["state"]["state"] == "ON"
    z = [f for f in fake.requests if f.subsystem.name == "AF" and f.command == 0x01][0].data[10:]
    assert z[0] & 0x01 and z[2] == 0x42 and z[3] == 0 and int.from_bytes(z[4:6], "little") == 300
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/set", {"countdown": 0})
    assert st == 400


async def test_describe_read_reporting_bind(ui):
    fake, gw, server, api = ui
    dev = await pair_one(fake, gw, server.port)
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/describe", {"description": "Kitchen ceiling"})
    assert st == 200 and gw.registry.get(IEEE).description == "Kitchen ceiling"
    st, _, _ = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/describe", {"description": "x" * 201})
    assert st == 400
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/read", {"endpoint": 1, "cluster": "0x0008", "attributes": ["0x0000"]})
    r = json.loads(body)
    assert st == 200 and r["values"] == {"0x0000": 127} and r["decoded"]["brightness"] == 127
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/reporting", {"endpoint": 1, "cluster": 8, "attribute": 0, "min": 5, "max": 600, "change": 2})
    r = json.loads(body)
    assert st == 200 and r["ok"] and any(x["cluster"] == 8 and x["min"] == 5 and x["max"] == 600 for x in r["reporting"])
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/bind", {"endpoint": 1, "cluster": 6, "target": "coordinator"})
    assert st == 200
    fake.requests.clear()
    st, _, body = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/unbind", {"endpoint": 1, "cluster": 6, "target": "coordinator"})
    assert st == 200 and not any(b["cluster"] == 6 and b["target"] == "coordinator" for b in json.loads(body)["bindings"])
    assert any(f.subsystem.name == "ZDO" and f.command == 0x22 for f in fake.requests)
    # bind to another device by name must 400 when unknown
    st, _, _ = await http(server.port, "POST", f"/api/devices/{dev.ieee_str}/bind", {"endpoint": 1, "cluster": 6, "target": "nope"})
    assert st == 400


@pytest.fixture
async def admin_ui(ui, tmp_path):
    """Attach a real Admin (with a config file) to the running UI."""
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.mqtt import Acl, PasswordFile
    fake, gw, server, api = ui
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(f"serial:\n  port: /dev/null\ndata_dir: {tmp_path}\nmqtt:\n  tls: off\n  port: 0\n")
    pw = PasswordFile(tmp_path / "mqtt.passwd")
    acl = Acl()
    admin = Admin(gw.cfg, cfg_path, pw, acl, gw.control_users)
    restarted = []
    admin.set_restart_hook(lambda: restarted.append(True))
    api.admin = admin
    yield fake, gw, server, api, admin, acl, pw, restarted


async def test_users_live_and_roles(admin_ui):
    fake, gw, server, api, admin, acl, pw, _ = admin_ui
    st, _, body = await http(server.port, "POST", "/api/users", {"name": "ha", "role": "homeassistant", "password": "ha-secret-password"})
    assert st == 200
    users = {u["name"]: u for u in json.loads(body)["users"]}
    assert users["ha"]["has_password"] and users["ha"]["control"] is False and users["ha"]["role"] == "homeassistant"
    # ACL applied live (no restart): HA may set devices but not publish elsewhere; not a control user
    assert acl.can_publish("ha", "oneroof/zigbee/0xabc/set") and not acl.can_publish("ha", "oneroof/zigbee/0xabc/state")
    assert "ha" not in gw.control_users and pw.verify("ha", "ha-secret-password")
    st, _, body = await http(server.port, "POST", "/api/users", {"name": "ops", "role": "admin", "password": "ops-secret-password"})
    assert "ops" in gw.control_users
    # short password / bad name rejected
    st, _, _ = await http(server.port, "POST", "/api/users", {"name": "x", "role": "admin", "password": "short"})
    assert st == 400
    st, _, _ = await http(server.port, "POST", "/api/users", {"name": "bad name", "role": "admin", "password": "long-enough-password"})
    assert st == 400
    # no passwords ever leak
    st, _, body = await http(server.port, "GET", "/api/users")
    assert "secret" not in body.decode()
    # remove
    st, _, body = await http(server.port, "POST", "/api/users/ops/remove", {})
    assert st == 200 and "ops" not in gw.control_users and not pw.has_user("ops")
    # survives a reload from users.yaml
    from oneroof_zigbee.mqtt import Acl
    acl2 = Acl()
    type(admin)(gw.cfg, admin.config_path, pw, acl2, set())  # reload from users.yaml
    assert acl2.can_publish("ha", "oneroof/zigbee/0xabc/set")


async def test_config_save_validates_and_flags_restart(admin_ui):
    fake, gw, server, api, admin, acl, pw, _ = admin_ui
    st, _, body = await http(server.port, "GET", "/api/config")
    c = json.loads(body)
    assert st == 200 and c["config"]["zigbee"]["channel"] == 15 and c["managed"] is False and "homeassistant" in c["roles"]
    st, _, body = await http(server.port, "POST", "/api/config", {"zigbee": {"channel": 20}, "mqtt": {"port": 8884}})
    r = json.loads(body)
    assert st == 200 and set(r["changed"]) == {"zigbee.channel", "mqtt.port"} and "zigbee.channel" in r["restart_required"]
    import yaml
    saved = yaml.safe_load(admin.config_path.read_text())
    assert saved["zigbee"]["channel"] == 20 and saved["mqtt"]["port"] == 8884
    assert admin.config_path.with_suffix(".yaml.bak").exists()
    # invalid values are rejected and not written
    st, _, body = await http(server.port, "POST", "/api/config", {"zigbee": {"channel": 99}})
    assert st == 400 and yaml.safe_load(admin.config_path.read_text())["zigbee"]["channel"] == 20
    st, _, _ = await http(server.port, "POST", "/api/config", {"mqtt": {"password_file": "/etc/passwd"}})
    assert st == 400
    # managed mode refuses
    admin.managed = True
    st, _, _ = await http(server.port, "POST", "/api/config", {"zigbee": {"channel": 11}})
    assert st == 403


async def test_backup_restore_roundtrip_and_restart(admin_ui, tmp_path):
    fake, gw, server, api, admin, acl, pw, restarted = admin_ui
    import base64
    from oneroof_zigbee.security import Keystore
    Keystore(tmp_path / "network.keystore").load_or_create(15)
    (tmp_path / "devices.json").write_text('{"devices": []}')
    st, _, body = await http(server.port, "POST", "/api/backup", {"password": "short"})
    assert st == 400
    st, _, body = await http(server.port, "POST", "/api/backup", {"password": "a-long-backup-password"})
    r = json.loads(body)
    assert st == 200 and r["filename"].endswith(".ozbk")
    blob = base64.b64decode(r["data_b64"])
    assert blob.startswith(b"OZBK1") and b"devices" not in blob  # encrypted, no plaintext names
    original = (tmp_path / "network.keystore").read_bytes()
    (tmp_path / "network.keystore").write_bytes(b"garbage")
    st, _, body = await http(server.port, "POST", "/api/restore", {"password": "wrong-password-here", "data_b64": r["data_b64"]})
    assert st == 400 and (tmp_path / "network.keystore").read_bytes() == b"garbage"
    st, _, body = await http(server.port, "POST", "/api/restore", {"password": "a-long-backup-password", "data_b64": r["data_b64"]})
    assert st == 200 and "network.keystore" in json.loads(body)["restored"]
    assert (tmp_path / "network.keystore").read_bytes() == original
    st, _, _ = await http(server.port, "POST", "/api/restart", {})
    assert st == 200 and restarted == [True]


async def test_admin_routes_require_control(admin_ui):
    fake, gw, server, api, admin, acl, pw, restarted = admin_ui
    api.acts_as = "nobody"
    for path, body in [("/api/config", {"zigbee": {"channel": 11}}), ("/api/users", {"name": "x", "role": "admin", "password": "p" * 12}),
                       ("/api/backup", {"password": "p" * 12}), ("/api/restart", {})]:
        st, _, _ = await http(server.port, "POST", path, body)
        assert st == 403, path
    assert restarted == []
    api.acts_as = "admin"
