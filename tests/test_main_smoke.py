"""Boot the production wiring (real broker, real keystore, real registry) with a
fake ZNP in place of the serial port, then talk to it over real TCP MQTT."""

import asyncio
import json

import pytest

import oneroof_zigbee.__main__ as main_mod
from oneroof_zigbee.config import Config
from oneroof_zigbee.mqtt import Client, PasswordFile
from tests.fake_znp import FakeZnp


@pytest.fixture
async def running(tmp_path, monkeypatch):
    monkeypatch.setenv("ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE", "test-passphrase")
    fake = FakeZnp()

    async def fake_open_serial(port, baudrate=115200, *, rtscts=False):
        return fake.reader, fake.writer

    monkeypatch.setattr(main_mod, "open_serial", fake_open_serial)
    cfg = Config.from_dict({
        "serial": {"port": "fake"}, "data_dir": str(tmp_path),
        "mqtt": {"listen": "127.0.0.1", "port": 0, "tls": "off", "control_users": ["admin"], "users": {
            "homeassistant": {"subscribe": ["oneroof/zigbee/#", "homeassistant/#"], "publish": ["oneroof/zigbee/+/set", "oneroof/zigbee/bridge/request/#"]},
            "admin": {"subscribe": ["#"], "publish": ["#"]},
        }},
    })
    PasswordFile(cfg.mqtt.password_file).set_password("homeassistant", "ha-password-123")
    PasswordFile(cfg.mqtt.password_file).set_password("admin", "admin-password-123")

    main_mod._last_broker = None
    task = asyncio.create_task(main_mod.run(cfg))
    # wait until the broker is listening; grab its port by peeking at the Broker instance
    broker = None
    for _ in range(200):
        await asyncio.sleep(0.02)
        broker = getattr(main_mod, "_last_broker", None)
        if broker and broker.port:
            break
    assert broker is not None, "broker did not start"
    yield fake, broker, cfg
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


async def test_boot_and_talk_over_tcp(running):
    fake, broker, cfg = running
    assert fake.formed
    # files created with safe modes
    import os
    for name in ("network.keystore", "mqtt.passwd", "audit.log"):
        assert oct(os.stat(cfg.data_dir / name).st_mode & 0o777) == "0o600", name

    ha = Client("127.0.0.1", broker.port, username="homeassistant", password="ha-password-123", client_id="ha")
    got: dict[str, bytes] = {}
    ev = asyncio.Event()

    async def on_msg(topic, payload):
        got[topic] = payload
        ev.set()

    await ha.connect()
    await ha.subscribe("oneroof/zigbee/#", on_msg)
    await asyncio.sleep(0.2)
    assert got.get("oneroof/zigbee/bridge/state") == b"online"
    info = json.loads(got["oneroof/zigbee/bridge/info"])
    assert info["channel"] == 15 and info["device_count"] == 0

    # HA user is NOT allowed to open the network
    await ha.publish("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', qos=1)
    for _ in range(50):
        await asyncio.sleep(0.02)
        if "oneroof/zigbee/bridge/response/permit_join" in got:
            break
    assert json.loads(got["oneroof/zigbee/bridge/response/permit_join"]) == {"ok": False, "error": "not authorized"}
    assert fake.permit_durations[-1] == 0

    # admin user is
    admin = Client("127.0.0.1", broker.port, username="admin", password="admin-password-123", client_id="admin")
    await admin.connect()
    got.pop("oneroof/zigbee/bridge/response/permit_join")
    await admin.publish("oneroof/zigbee/bridge/request/permit_join", b'{"seconds": 30}', qos=1)
    for _ in range(50):
        await asyncio.sleep(0.02)
        if "oneroof/zigbee/bridge/response/permit_join" in got:
            break
    assert json.loads(got["oneroof/zigbee/bridge/response/permit_join"])["ok"] is True
    assert fake.permit_durations[-1] == 30
    await ha.disconnect()
    await admin.disconnect()


async def test_anonymous_rejected_on_real_broker(running):
    fake, broker, cfg = running
    from oneroof_zigbee.mqtt import packets as pk
    r, w = await asyncio.open_connection("127.0.0.1", broker.port)
    w.write(pk.encode(pk.Connect(client_id="anon", keepalive=10)))
    await w.drain()
    raw = await asyncio.wait_for(r.read(4), 3)
    assert raw[0] == 0x20 and raw[3] == 0x05  # CONNACK, not authorized
    w.close()


async def test_tls_auto_end_to_end(tmp_path, monkeypatch):
    """Default config: broker speaks TLS with the generated CA; a client that trusts ca.crt connects, plaintext fails."""
    import ssl
    monkeypatch.setenv("ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE", "t")
    fake = FakeZnp()

    async def fake_open_serial(port, baudrate=115200, *, rtscts=False):
        return fake.reader, fake.writer

    monkeypatch.setattr(main_mod, "open_serial", fake_open_serial)
    cfg = Config.from_dict({"serial": {"port": "fake"}, "data_dir": str(tmp_path),
                            "mqtt": {"listen": "127.0.0.1", "port": 0, "users": {"homeassistant": {"subscribe": ["#"], "publish": []}}},
                            "ui": {"enabled": False}})
    assert cfg.mqtt.tls.mode == "auto"
    PasswordFile(cfg.mqtt.password_file).set_password("homeassistant", "ha-password-123")
    main_mod._last_broker = None
    task = asyncio.create_task(main_mod.run(cfg))
    for _ in range(200):
        await asyncio.sleep(0.02)
        if main_mod._last_broker and main_mod._last_broker.port:
            break
    broker = main_mod._last_broker
    assert broker.tls is not None and (tmp_path / "tls" / "ca.crt").exists()
    from oneroof_zigbee.security.tls import client_context
    ctx = client_context(tmp_path / "tls" / "ca.crt", server_hostname_check=False)
    c = Client("127.0.0.1", broker.port, username="homeassistant", password="ha-password-123", client_id="tls", tls=ctx)
    await c.connect()
    await c.disconnect()
    # a client that does not trust our CA is refused by TLS itself
    bad = Client("127.0.0.1", broker.port, username="homeassistant", password="ha-password-123", client_id="bad",
                 tls=client_context(None, server_hostname_check=False))
    with pytest.raises(ssl.SSLError):
        await bad.connect()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


async def test_plaintext_port_alongside_tls(tmp_path, monkeypatch):
    monkeypatch.setenv("ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE", "t")
    fake = FakeZnp()

    async def fake_open_serial(port, baudrate=115200, *, rtscts=False):
        return fake.reader, fake.writer

    monkeypatch.setattr(main_mod, "open_serial", fake_open_serial)
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    cfg = Config.from_dict({"serial": {"port": "fake"}, "data_dir": str(tmp_path), "ui": {"enabled": False},
                            "mqtt": {"listen": "127.0.0.1", "port": 0, "plaintext_port": free,
                                     "users": {"legacy": {"subscribe": ["#"], "publish": []}}}})
    PasswordFile(cfg.mqtt.password_file).set_password("legacy", "legacy-password-1")
    main_mod._last_broker = None
    task = asyncio.create_task(main_mod.run(cfg))
    for _ in range(200):
        await asyncio.sleep(0.02)
        if main_mod._last_broker and main_mod._last_broker._extra_servers:
            break
    c = Client("127.0.0.1", free, username="legacy", password="legacy-password-1", client_id="legacy")
    await c.connect()  # plaintext, no TLS context
    await c.disconnect()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


def test_config_rejects_bad_adapter_and_same_ports():
    from oneroof_zigbee.config import ConfigError
    with pytest.raises(ConfigError):
        Config.from_dict({"serial": {"port": "x", "adapter": "ezsp"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"serial": {"port": "x"}, "mqtt": {"port": 8883, "plaintext_port": 8883}})
    c = Config.from_dict({"serial": {"port": "tcp://192.168.1.50:6638"}})
    assert c.serial.is_network
