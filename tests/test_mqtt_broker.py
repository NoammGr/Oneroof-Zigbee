from __future__ import annotations

import asyncio
import json
import os
import stat
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from oneroof_zigbee.mqtt import Acl, Broker, Client, PasswordFile
from oneroof_zigbee.mqtt import broker as broker_mod
from oneroof_zigbee.mqtt import packets as pk
from oneroof_zigbee.mqtt.client import ConnectRefused

# --- helpers -----------------------------------------------------------------


class DictAuth:
    """Fast authenticator for broker tests (PasswordFile has its own test)."""

    def __init__(self, users: dict[str, bytes]) -> None:
        self.users = users

    def verify(self, username: str, password: bytes) -> bool:
        return self.users.get(username) == password


def make_acl() -> Acl:
    acl = Acl()
    acl.allow("gw", publish=["oz/#", "homeassistant/#"], subscribe=["oz/#", "$SYS/#"])
    acl.allow("ha", publish=["oz/+/set", "oz/bridge/request/permit_join"], subscribe=["oz/#", "homeassistant/#"])
    acl.allow("ro", subscribe=["oz/+/state"])
    return acl


@pytest.fixture
async def broker() -> AsyncIterator[Broker]:
    b = Broker(
        auth=DictAuth({"gw": b"gwpw", "ha": b"hapw", "ro": b"ropw"}),
        acl=make_acl(),
        host="127.0.0.1",
        port=0,
        tls=None,
        sys_user="gw",
    )
    await b.start()
    try:
        yield b
    finally:
        await b.stop()


async def connect(broker: Broker, user: str, pw: str, **kw: object) -> Client:
    c = Client("127.0.0.1", broker.port, username=user, password=pw, reconnect=False, **kw)  # type: ignore[arg-type]
    await c.connect(timeout=5)
    return c


class Collector:
    def __init__(self) -> None:
        self.messages: list[tuple[str, bytes]] = []
        self.users: list[str | None] = []
        self.event = asyncio.Event()

    async def __call__(self, topic: str, payload: bytes, user: str | None = None) -> None:
        self.messages.append((topic, payload))
        self.users.append(user)
        self.event.set()

    async def wait(self, n: int = 1, timeout: float = 3.0) -> list[tuple[str, bytes]]:
        async with asyncio.timeout(timeout):
            while len(self.messages) < n:
                self.event.clear()
                await self.event.wait()
        return self.messages


async def raw_connect(broker: Broker, connect: pk.Connect) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, pk.Packet]:
    r, w = await asyncio.open_connection("127.0.0.1", broker.port)
    w.write(pk.encode(connect))
    await w.drain()
    pkt = await read_packet(r)
    return r, w, pkt


async def read_packet(r: asyncio.StreamReader, timeout: float = 3.0) -> pk.Packet:
    buf = bytearray()
    async with asyncio.timeout(timeout):
        while True:
            try:
                return pk.decode_one(bytes(buf))[0]
            except pk.NeedMoreData:
                buf += await r.readexactly(1)


# --- authentication ----------------------------------------------------------


async def test_anonymous_rejected(broker: Broker) -> None:
    _, w, ack = await raw_connect(broker, pk.Connect(client_id="anon"))
    assert ack == pk.Connack(False, pk.CONNACK_NOT_AUTHORIZED)
    w.close()


async def test_wrong_password_rejected(broker: Broker) -> None:
    with pytest.raises(ConnectRefused) as ei:
        await connect(broker, "gw", "nope")
    assert ei.value.code == pk.CONNACK_BAD_CREDENTIALS
    with pytest.raises(ConnectRefused) as ei:
        await connect(broker, "unknown", "gwpw")
    assert ei.value.code == pk.CONNACK_BAD_CREDENTIALS


async def test_good_password_accepted_and_session_present_false(broker: Broker) -> None:
    _, w, ack = await raw_connect(
        broker, pk.Connect(client_id="c", clean_session=False, username="gw", password=b"gwpw")
    )
    assert ack == pk.Connack(False, pk.CONNACK_ACCEPTED)
    w.close()


async def test_lockout_after_five_failures(broker: Broker, monkeypatch: pytest.MonkeyPatch) -> None:
    for _ in range(5):
        with pytest.raises(ConnectRefused) as ei:
            await connect(broker, "gw", "bad")
        assert ei.value.code == pk.CONNACK_BAD_CREDENTIALS
    # Locked out: even the correct password is refused with 0x05.
    with pytest.raises(ConnectRefused) as ei:
        await connect(broker, "gw", "gwpw")
    assert ei.value.code == pk.CONNACK_NOT_AUTHORIZED
    # After the lockout expires, we get back in.
    monkeypatch.setattr(broker_mod, "AUTH_LOCKOUT_SECONDS", 30.0)
    broker._lockouts["127.0.0.1|gw"] -= 31
    c = await connect(broker, "gw", "gwpw")
    await c.disconnect()


async def test_lockout_is_per_user_so_a_failing_login_cannot_block_another(broker: Broker) -> None:
    """Home Assistant's stored login may keep failing from the same address; a different, correct
    login from that address must still get in."""
    for _ in range(6):
        with pytest.raises(ConnectRefused):
            await connect(broker, "ro", "stale-password")
    with pytest.raises(ConnectRefused) as ei:
        await connect(broker, "ro", "ropw")
    assert ei.value.code == pk.CONNACK_NOT_AUTHORIZED, "the failing user itself is locked out"
    c = await connect(broker, "ha", "hapw")  # another user from the same address
    await c.disconnect()


async def test_password_file(tmp_path: Path) -> None:
    path = tmp_path / "passwd"
    pf = PasswordFile(path)
    pf.set_password("alice", "s3cret")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    line = path.read_text().strip()
    assert line.startswith("alice:scrypt$32768$8$1$")
    assert "s3cret" not in line
    assert pf.verify("alice", b"s3cret")
    assert not pf.verify("alice", b"S3cret")
    assert not pf.verify("bob", b"s3cret")
    # survives reload
    pf2 = PasswordFile(path)
    assert pf2.users() == ["alice"]
    assert pf2.verify("alice", "s3cret")
    assert pf2.remove("alice") and not pf2.verify("alice", "s3cret")


# --- ACL -------------------------------------------------------------------


def test_acl_rules() -> None:
    acl = make_acl()
    assert acl.can_publish("ha", "oz/0x00124b00deadbeef/set")
    assert not acl.can_publish("ha", "oz/0x00124b00deadbeef/state")
    assert not acl.can_publish("ha", "oz/bridge/request/rotate_network_key")
    assert not acl.can_publish("nobody", "oz/x/set")
    assert acl.can_publish("gw", "oz/bridge/state")
    assert not acl.can_publish("gw", "$SYS/x")  # '#' never matches $ topics
    # subscribe containment (conservative)
    assert acl.can_subscribe("ha", "oz/#")
    assert acl.can_subscribe("ha", "oz/+/state")
    assert acl.can_subscribe("ha", "oz/bridge/state")
    assert acl.can_subscribe("ha", "oz")
    assert not acl.can_subscribe("ha", "#")
    assert not acl.can_subscribe("ha", "ozz/#")
    assert not acl.can_subscribe("ha", "$SYS/#")
    assert acl.can_subscribe("gw", "$SYS/broker/clients/connected")
    assert acl.can_subscribe("ro", "oz/+/state")
    assert acl.can_subscribe("ro", "oz/abc/state")  # concrete topic covered by allowed filter
    assert not acl.can_subscribe("ro", "oz/#")
    assert not acl.can_subscribe("ro", "oz/+/+")
    assert not acl.can_subscribe("ro", "oz/abc#")  # invalid filter


async def test_acl_publish_denied_is_dropped_and_puback_still_sent(broker: Broker) -> None:
    gw = await connect(broker, "gw", "gwpw")
    ha = await connect(broker, "ha", "hapw")
    seen = Collector()
    assert await gw.subscribe("oz/#", seen) == 1
    # ha may not publish to .../state; the QoS1 publish must still be acked.
    await ha.publish("oz/dev1/state", b"forged", qos=1)
    await ha.publish("oz/dev1/set", b"legit", qos=1)
    msgs = await seen.wait(1)
    assert msgs == [("oz/dev1/set", b"legit")]
    # nothing retained from the denied publish either
    assert broker.retained("oz/dev1/state") is None
    await ha.disconnect()
    await gw.disconnect()


async def test_acl_subscribe_denied_gets_0x80(broker: Broker) -> None:
    ro = await connect(broker, "ro", "ropw")
    assert await ro.subscribe("oz/+/state", Collector()) == 1
    assert await ro.subscribe("oz/#", Collector()) == pk.SUBACK_FAILURE
    assert await ro.subscribe("$SYS/#", Collector()) == pk.SUBACK_FAILURE
    await ro.disconnect()


async def test_sys_topics_only_writable_by_sys_user(broker: Broker) -> None:
    gw = await connect(broker, "gw", "gwpw")
    ha = await connect(broker, "ha", "hapw")
    seen = Collector()
    await gw.subscribe("$SYS/#", seen)
    await ha.publish("$SYS/broker/clients/connected", b"999", qos=1, retain=True)
    await gw.publish("oz/probe", b"", qos=1)  # round trip to make sure the ha publish was processed
    await asyncio.sleep(0.05)
    assert broker.retained("$SYS/broker/clients/connected") == b"2"
    assert all(p != b"999" for _, p in seen.messages)
    await ha.disconnect()
    await gw.disconnect()


# --- messaging ---------------------------------------------------------------


async def test_retained_delivered_to_late_subscriber(broker: Broker) -> None:
    gw = await connect(broker, "gw", "gwpw")
    await gw.publish("oz/dev1/state", b'{"on":true}', qos=1, retain=True)
    await gw.publish("oz/dev2/state", b"", qos=1, retain=True)  # clears nothing, sets nothing
    ha = await connect(broker, "ha", "hapw")
    seen = Collector()
    await ha.subscribe("oz/+/state", seen)
    msgs = await seen.wait(1)
    assert msgs == [("oz/dev1/state", b'{"on":true}')]
    # retained delete
    await gw.publish("oz/dev1/state", b"", qos=1, retain=True)  # QoS1: PUBACK proves it was processed
    assert broker.retained("oz/dev1/state") is None
    await ha.disconnect()
    await gw.disconnect()


async def test_retained_flag_set_on_wire_for_late_subscriber(broker: Broker) -> None:
    gw = await connect(broker, "gw", "gwpw")
    await gw.publish("oz/dev1/state", b"x", retain=True)
    r, w, ack = await raw_connect(broker, pk.Connect(client_id="raw", username="ha", password=b"hapw"))
    w.write(pk.encode(pk.Subscribe(1, [("oz/dev1/state", 0)])))
    await w.drain()
    assert await read_packet(r) == pk.Suback(1, [0])
    assert await read_packet(r) == pk.Publish("oz/dev1/state", b"x", qos=0, retain=True)
    w.close()
    await gw.disconnect()


async def test_qos1_publish_gets_puback_and_subscriber_acks(broker: Broker) -> None:
    r, w, ack = await raw_connect(broker, pk.Connect(client_id="raw", username="gw", password=b"gwpw"))
    w.write(pk.encode(pk.Subscribe(5, [("oz/#", 1)])))
    await w.drain()
    assert await read_packet(r) == pk.Suback(5, [1])
    w.write(pk.encode(pk.Publish("oz/a", b"hi", qos=1, packet_id=42)))
    await w.drain()
    got = [await read_packet(r), await read_packet(r)]
    pubs = [p for p in got if isinstance(p, pk.Publish)]
    acks = [p for p in got if isinstance(p, pk.Puback)]
    assert acks == [pk.Puback(42)]
    assert len(pubs) == 1 and pubs[0].qos == 1 and pubs[0].payload == b"hi" and pubs[0].packet_id
    session = next(iter(broker._sessions))
    assert pubs[0].packet_id in session.inflight
    w.write(pk.encode(pk.Puback(pubs[0].packet_id)))
    await w.drain()
    await asyncio.sleep(0.05)
    assert not session.inflight
    w.close()


async def test_qos2_downgraded_to_qos1(broker: Broker) -> None:
    r, w, ack = await raw_connect(broker, pk.Connect(client_id="raw", username="gw", password=b"gwpw"))
    w.write(pk.encode(pk.Subscribe(1, [("oz/#", 2)])))
    await w.drain()
    assert await read_packet(r) == pk.Suback(1, [1])
    w.write(pk.encode(pk.Publish("oz/a", b"q2", qos=2, packet_id=9)))
    await w.drain()
    got = [await read_packet(r), await read_packet(r)]
    assert pk.Puback(9) in got
    pub = next(p for p in got if isinstance(p, pk.Publish))
    assert pub.qos == 1
    w.close()


async def test_will_delivered_on_abrupt_disconnect(broker: Broker) -> None:
    ha = await connect(broker, "ha", "hapw")
    seen = Collector()
    await ha.subscribe("oz/bridge/state", seen)
    r, w, ack = await raw_connect(
        broker,
        pk.Connect(
            client_id="gw",
            username="gw",
            password=b"gwpw",
            will_topic="oz/bridge/state",
            will_payload=b"offline",
            will_qos=1,
            will_retain=True,
        ),
    )
    assert ack.return_code == 0
    w.transport.abort()  # no DISCONNECT packet
    msgs = await seen.wait(1)
    assert msgs == [("oz/bridge/state", b"offline")]
    assert broker.retained("oz/bridge/state") == b"offline"
    await ha.disconnect()


async def test_will_not_sent_on_clean_disconnect(broker: Broker) -> None:
    ha = await connect(broker, "ha", "hapw")
    seen = Collector()
    await ha.subscribe("oz/bridge/state", seen)
    gw = await connect(
        broker, "gw", "gwpw", will=pk.Publish("oz/bridge/state", b"offline", qos=1)
    )
    await gw.disconnect()
    await ha.publish("oz/x/set", b"marker")  # flush
    await asyncio.sleep(0.1)
    assert seen.messages == []
    await ha.disconnect()


async def test_in_process_publish_reaches_tcp_subscriber(broker: Broker) -> None:
    ha = await connect(broker, "ha", "hapw")
    seen = Collector()
    await ha.subscribe("oz/#", seen)
    await broker.publish("oz/dev/state", b"from-gateway", qos=1)
    assert await seen.wait(1) == [("oz/dev/state", b"from-gateway")]
    await ha.disconnect()


async def test_tcp_publish_reaches_in_process_subscriber(broker: Broker) -> None:
    seen = Collector()
    unsub = broker.subscribe("oz/+/set", seen)
    ha = await connect(broker, "ha", "hapw")
    await ha.publish("oz/dev/set", b'{"on":1}', qos=1)
    assert await seen.wait(1) == [("oz/dev/set", b'{"on":1}')]
    assert seen.users == ["ha"]  # authenticated publisher is passed to local subscribers
    unsub()
    await ha.publish("oz/dev/set", b"again", qos=1)
    await asyncio.sleep(0.05)
    assert len(seen.messages) == 1
    await ha.disconnect()


async def test_in_process_subscribe_gets_retained(broker: Broker) -> None:
    await broker.publish("oz/dev/state", b"r", retain=True)
    seen = Collector()
    broker.subscribe("oz/#", seen)
    assert await seen.wait(1) == [("oz/dev/state", b"r")]


async def test_sys_client_count_retained(broker: Broker) -> None:
    assert broker.retained(broker_mod.SYS_CLIENTS_CONNECTED) == b"0"
    seen = Collector()
    broker.subscribe("$SYS/broker/clients/connected", seen)
    await seen.wait(1)  # retained "0"
    gw = await connect(broker, "gw", "gwpw")
    ha = await connect(broker, "ha", "hapw")
    await seen.wait(3)
    assert broker.retained(broker_mod.SYS_CLIENTS_CONNECTED) == b"2"
    await ha.disconnect()
    await gw.disconnect()
    await seen.wait(5)
    assert [p for _, p in seen.messages] == [b"0", b"1", b"2", b"1", b"0"]


async def test_keepalive_timeout_drops_client(broker: Broker, monkeypatch: pytest.MonkeyPatch) -> None:
    r, w, ack = await raw_connect(
        broker, pk.Connect(client_id="lazy", username="gw", password=b"gwpw", keepalive=1)
    )
    assert ack.return_code == 0
    async with asyncio.timeout(3):
        assert await r.read() == b""  # broker closed at 1.5 s
    assert broker.client_count == 0


async def test_ping_keeps_alive_and_unsubscribe(broker: Broker) -> None:
    r, w, ack = await raw_connect(broker, pk.Connect(client_id="p", username="gw", password=b"gwpw"))
    w.write(pk.encode(pk.Pingreq()))
    await w.drain()
    assert isinstance(await read_packet(r), pk.Pingresp)
    w.write(pk.encode(pk.Subscribe(1, [("oz/#", 0)])) + pk.encode(pk.Unsubscribe(2, ["oz/#"])))
    await w.drain()
    assert await read_packet(r) == pk.Suback(1, [0])
    assert await read_packet(r) == pk.Unsuback(2)
    assert broker._subs == {}
    w.close()


async def test_malformed_packet_closes_connection(broker: Broker) -> None:
    r, w, ack = await raw_connect(broker, pk.Connect(client_id="m", username="gw", password=b"gwpw"))
    w.write(b"\x30\x03\x00\x01#")  # wildcard in PUBLISH topic
    await w.drain()
    async with asyncio.timeout(3):
        assert await r.read() == b""


async def test_oversized_packet_closes_connection(broker: Broker) -> None:
    r, w, ack = await raw_connect(broker, pk.Connect(client_id="m", username="gw", password=b"gwpw"))
    w.write(b"\x30\xff\xff\xff\x7f")  # 268 MB remaining length
    await w.drain()
    async with asyncio.timeout(3):
        assert await r.read() == b""


async def test_subscription_limit(broker: Broker) -> None:
    gw = await connect(broker, "gw", "gwpw")
    for i in range(broker_mod.MAX_SUBSCRIPTIONS):
        assert await gw.subscribe(f"oz/{i}/state", Collector()) == 1
    assert await gw.subscribe("oz/overflow/state", Collector()) == pk.SUBACK_FAILURE
    await gw.disconnect()


async def test_client_id_takeover(broker: Broker) -> None:
    r1, w1, _ = await raw_connect(broker, pk.Connect(client_id="same", username="gw", password=b"gwpw"))
    r2, w2, ack2 = await raw_connect(broker, pk.Connect(client_id="same", username="gw", password=b"gwpw"))
    assert ack2.return_code == 0
    async with asyncio.timeout(3):
        assert await r1.read() == b""
    assert broker.client_count == 1
    w2.close()


async def test_client_reconnects_with_backoff(broker: Broker) -> None:
    c = Client("127.0.0.1", broker.port, username="ha", password="hapw", reconnect=True, max_backoff=0.5)
    await c.connect(timeout=5)
    seen = Collector()
    await c.subscribe("oz/#", seen)
    # kill the server side session
    for s in list(broker._sessions):
        s.close()
    await c.disconnected.wait()
    async with asyncio.timeout(5):
        await c.connected.wait()
    await broker.publish("oz/after", b"back")
    assert await seen.wait(1) == [("oz/after", b"back")]
    await c.disconnect()


# --------------------------------------------------------------------------- MQTT 5 ---


def _v5_connect(client_id: str, user: str, pw: str, *, session_expiry: int = 0) -> bytes:
    """Hand-built MQTT 5 CONNECT, as paho/Home Assistant send it (properties present)."""
    props = b"\x11" + session_expiry.to_bytes(4, "big") + b"\x21\x00\x14"  # session expiry, receive max 20
    body = pk.encode_string("MQTT") + bytes([5, 0xC2]) + (60).to_bytes(2, "big")
    body += pk.encode_remaining_length(len(props)) + props
    body += pk.encode_string(client_id) + pk.encode_string(user) + len(pw).to_bytes(2, "big") + pw.encode()
    return bytes([0x10]) + pk.encode_remaining_length(len(body)) + body


async def _read(reader: asyncio.StreamReader, version: int = 5) -> pk.Packet:
    head = await asyncio.wait_for(reader.readexactly(2), 3)
    buf = bytearray(head)
    while True:
        try:
            _, _, length, hsize = pk.decode_fixed_header(bytes(buf))
            break
        except pk.NeedMoreData:
            buf += await reader.readexactly(1)
    buf += await reader.readexactly(hsize + length - len(buf))
    return pk.decode_one(bytes(buf), version)[0]


async def test_mqtt5_client_full_session(broker: Broker) -> None:
    """An MQTT 5 client (properties everywhere) connects, subscribes, receives retained and live
    messages, unsubscribes and disconnects with a reason code — alongside a 3.1.1 client."""
    gw = await connect(broker, "gw", "gwpw")
    await gw.publish("oz/dev1/state", b"retained-state", qos=0, retain=True)
    await asyncio.sleep(0.05)
    r, w = await asyncio.open_connection("127.0.0.1", broker.port)
    w.write(_v5_connect("ha-v5", "ha", "hapw"))
    ack = await _read(r)
    assert isinstance(ack, pk.Connack) and ack.return_code == 0 and not ack.session_present
    # SUBSCRIBE v5: packet id, empty properties, filter + options (QoS 1, retain handling 0)
    w.write(pk.encode(pk.Subscribe(7, [("oz/#", 1)]), 5))
    suback = await _read(r)
    assert isinstance(suback, pk.Suback) and suback.packet_id == 7 and suback.return_codes == [1]
    retained = await _read(r)
    assert isinstance(retained, pk.Publish) and retained.topic == "oz/dev1/state" and retained.payload == b"retained-state" and retained.retain
    # live QoS1 message from the 3.1.1 client arrives as a v5 PUBLISH (properties block present) and is acked v5-style
    await gw.publish("oz/dev1/set", b'{"state":"ON"}', qos=1)
    live = await _read(r)
    assert isinstance(live, pk.Publish) and live.payload == b'{"state":"ON"}' and live.qos == 1 and live.packet_id
    w.write(bytes([0x40, 0x03]) + live.packet_id.to_bytes(2, "big") + b"\x00")  # PUBACK with reason code, no properties
    # v5 client publishes with properties (content type) — delivered to the 3.1.1 subscriber unchanged
    seen = Collector()
    assert await gw.subscribe("oz/dev1/set", seen) == 1
    props = b"\x03" + pk.encode_string("application/json")
    body = pk.encode_string("oz/dev1/set") + pk.encode_remaining_length(len(props)) + props + b'{"state":"OFF"}'
    w.write(bytes([0x30]) + pk.encode_remaining_length(len(body)) + body)
    assert (await seen.wait(1))[-1] == ("oz/dev1/set", b'{"state":"OFF"}')
    echo = await _read(r)  # the v5 client is subscribed to oz/# itself (no No-Local requested)
    assert isinstance(echo, pk.Publish) and echo.payload == b'{"state":"OFF"}'
    # SUBSCRIBE with retain handling 2 must not replay retained messages
    w.write(bytes([0x82]) + pk.encode_remaining_length(2 + 1 + 2 + len("oz/dev1/state") + 1)
            + (8).to_bytes(2, "big") + b"\x00" + pk.encode_string("oz/dev1/state") + bytes([0x21]))
    suback2 = await _read(r)
    assert isinstance(suback2, pk.Suback) and suback2.return_codes == [1]
    w.write(pk.encode(pk.Pingreq(), 5))
    assert isinstance(await _read(r), pk.Pingresp), "no retained replay before the ping response"
    # UNSUBSCRIBE v5 → UNSUBACK with per-filter reason codes (0x11 = no subscription existed)
    w.write(pk.encode(pk.Unsubscribe(9, ["oz/#", "never/subscribed"]), 5))
    unsuback = await _read(r)
    assert isinstance(unsuback, pk.Unsuback) and unsuback.reason_codes == [0x00, 0x11]
    w.write(pk.encode(pk.Disconnect(0x04), 5))  # disconnect with will message
    w.close()
    await gw.disconnect()


async def test_mqtt5_bad_credentials_use_v5_reason_code(broker: Broker) -> None:
    r, w = await asyncio.open_connection("127.0.0.1", broker.port)
    w.write(_v5_connect("x", "ha", "wrong"))
    ack = await _read(r)
    assert isinstance(ack, pk.Connack) and ack.return_code == pk.RC_BAD_CREDENTIALS
    w.close()


async def test_mqtt5_takeover_sends_disconnect_reason(broker: Broker) -> None:
    r1, w1 = await asyncio.open_connection("127.0.0.1", broker.port)
    w1.write(_v5_connect("same-id", "ha", "hapw"))
    assert isinstance(await _read(r1), pk.Connack)
    r2, w2 = await asyncio.open_connection("127.0.0.1", broker.port)
    w2.write(_v5_connect("same-id", "ha", "hapw"))
    assert isinstance(await _read(r2), pk.Connack)
    d = await _read(r1)
    assert isinstance(d, pk.Disconnect) and d.reason == pk.RC_SESSION_TAKEN_OVER
    w1.close()
    w2.close()


def test_mqtt5_connack_decodes_with_v5_flag() -> None:
    raw = pk.encode(pk.Connack(False, pk.CONNACK_ACCEPTED), 5, connack_props=pk.SERVER_CONNACK_PROPS)
    assert raw[:4] == bytes([0x20, len(raw) - 2, 0x00, 0x00])
    assert pk.encode(pk.Connack(False, pk.CONNACK_NOT_AUTHORIZED), 5)[3] == pk.RC_NOT_AUTHORIZED
    with pytest.raises(pk.MalformedPacket):
        pk.decode(pk.PUBLISH, 0, pk.encode_string("t") + b"\x03\x23\x00\x01" + b"x", 5)  # topic alias refused


# ------------------------------------------------------------ login adoption ---


async def test_addon_adopts_home_assistants_existing_login(tmp_path: Path) -> None:
    """Inside the add-on, for an hour after an import, the login Home Assistant still sends from its
    own address is adopted once; anything else keeps being refused."""
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.config import Config
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(f"serial:\n  port: /dev/null\ndata_dir: {tmp_path}\nmqtt:\n  password_file: {tmp_path}/passwd\n")
    cfg = Config.load(cfg_path)
    pf = PasswordFile(cfg.mqtt.password_file)
    pf.set_password("gw", "gwpw")
    admin = Admin(cfg, cfg_path, pf, make_acl(), set(), managed=True)
    events: list[dict] = []
    admin.audit = type("A", (), {"security": lambda self, t, **kw: events.append({"type": t, **kw})})()
    b = Broker(auth=pf, acl=make_acl(), host="127.0.0.1", port=0, tls=None, sys_user="gw")
    b.adopt_login = admin.adopt_login
    await b.start()
    try:
        # window closed → refused as before
        r, w = await asyncio.open_connection("127.0.0.1", b.port)
        w.write(_v5_connect("homeassistant", "addons", "previous-broker-password"))
        assert (await _read(r)).return_code == pk.RC_BAD_CREDENTIALS
        w.close()
        admin.open_login_adoption_window()
        # wrong source address → refused (the test client is 127.0.0.1)
        r, w = await asyncio.open_connection("127.0.0.1", b.port)
        w.write(_v5_connect("homeassistant", "addons", "previous-broker-password"))
        assert (await _read(r)).return_code == pk.RC_BAD_CREDENTIALS
        w.close()
        # Home Assistant's address during the window → adopted, connected, recorded, window closed
        admin.ADOPT_FROM = ("127.0.0.1",)
        r, w = await asyncio.open_connection("127.0.0.1", b.port)
        w.write(_v5_connect("homeassistant", "addons", "previous-broker-password"))
        assert (await _read(r)).return_code == 0
        w.close()
        assert pf.verify("addons", b"previous-broker-password") and next(u for u in admin.list_users() if u["name"] == "addons")["role"] == "homeassistant"
        assert events and events[-1]["type"] == "broker_login_adopted" and events[-1]["user"] == "addons"
        assert not admin.login_adoption_open()
        # an existing user with a wrong password is never adopted
        admin.open_login_adoption_window()
        r, w = await asyncio.open_connection("127.0.0.1", b.port)
        w.write(_v5_connect("x", "gw", "wrong"))
        assert (await _read(r)).return_code == pk.RC_BAD_CREDENTIALS
        w.close()
        assert not pf.verify("gw", b"wrong")
    finally:
        await b.stop()


async def test_mqtt5_subscription_identifiers_are_echoed(broker: Broker) -> None:
    """Home Assistant's client requires Subscription Identifiers: the broker advertises them and
    echoes the identifier of every matching subscription in delivered PUBLISHes (retained too)."""
    gw = await connect(broker, "gw", "gwpw")
    await gw.publish("oz/dev1/state", b"retained", qos=0, retain=True)
    await asyncio.sleep(0.05)
    r, w = await asyncio.open_connection("127.0.0.1", broker.port)
    w.write(_v5_connect("ha-ids", "ha", "hapw"))
    ack = await _read(r)
    assert isinstance(ack, pk.Connack) and ack.return_code == 0
    raw = pk.encode(pk.Connack(False, 0), 5, connack_props=pk.SERVER_CONNACK_PROPS)
    assert bytes([pk.PROP_SUBSCRIPTION_IDS_AVAILABLE, 1]) in raw, "advertised as available"
    w.write(pk.encode(pk.Subscribe(3, [("oz/#", 1)], subscription_id=42), 5))
    assert isinstance(await _read(r), pk.Suback)
    retained = await _read(r)
    assert isinstance(retained, pk.Publish) and retained.retain and retained.subscription_ids == (42,)
    w.write(pk.encode(pk.Subscribe(4, [("oz/dev1/+", 0)], subscription_id=7), 5))
    assert isinstance(await _read(r), pk.Suback)
    assert isinstance(await _read(r), pk.Publish)  # retained replay for the second filter
    await gw.publish("oz/dev1/state", b"live", qos=0)
    live = await _read(r)
    assert live.payload == b"live" and sorted(live.subscription_ids) == [7, 42], "both matching subscriptions identified"
    # identifier 0 is a protocol error (hand-built: the encoder never emits it)
    props = bytes([pk.PROP_SUBSCRIPTION_ID, 0x00])
    body = (5).to_bytes(2, "big") + pk.encode_remaining_length(len(props)) + props + pk.encode_string("oz/#") + b"\x00"
    w.write(bytes([0x82]) + pk.encode_remaining_length(len(body)) + body)
    d = await _read(r)
    assert isinstance(d, pk.Disconnect) and d.reason == pk.RC_MALFORMED
    w.close()
    await gw.disconnect()


def test_acl_deny_publish_with_specific_allow_override() -> None:
    acl = Acl()
    acl.allow("ha", publish=["#", "z/+/set", "z/bridge/request/#"], subscribe=["#"], deny_publish=["z/#"])
    assert acl.can_publish("ha", "anything/else")
    assert acl.can_publish("ha", "z/lamp/set") and acl.can_publish("ha", "z/bridge/request/permit_join")
    assert not acl.can_publish("ha", "z/lamp") and not acl.can_publish("ha", "z/bridge/devices") and not acl.can_publish("ha", "z/lamp/availability")
    acl.clear("ha")
    assert not acl.can_publish("ha", "anything/else")


async def test_login_failures_and_lockouts_are_audited(broker: Broker) -> None:
    from oneroof_zigbee.security import Audit
    audit = Audit(None)
    recs = []
    audit.subscribe(lambda r: recs.append(r))
    broker.audit = audit
    for _ in range(5):
        with pytest.raises(ConnectRefused):
            await connect(broker, "ro", "nope")
    types = [r["type"] for r in recs]
    assert types.count("auth_failed") >= 4 and "auth_lockout" in types
    lock = next(r for r in recs if r["type"] == "auth_lockout")
    assert lock["level"] == "security" and lock["user"] == "ro" and lock["failures"] == 5
    assert all("nope" not in json.dumps(r) for r in recs), "passwords never audited"


async def test_external_broker_carries_a_last_will(broker: Broker) -> None:
    """On an external broker the gateway's death must be announced by the broker itself: without
    a will, Home Assistant and the Apple Home bridge keep showing every device's last word."""
    from oneroof_zigbee.mqtt.external import ExternalBroker
    ext = ExternalBroker(f"mqtt://127.0.0.1:{broker.port}", user="gw", password="gwpw", ca=None, client_id="gw-ext",
                         will_topic="oz/bridge/state", will_payload=b"offline")
    await ext.start()
    watcher = await connect(broker, "ha", "hapw")
    got = Collector()
    await watcher.subscribe("oz/bridge/state", got)
    await ext.publish("oz/bridge/state", b"online", retain=True)
    assert (await got.wait(1)) == [("oz/bridge/state", b"online")]
    # the gateway process dies: the socket closes without a DISCONNECT
    ext._client.reconnect = False
    ext._client._writer.transport.abort()  # type: ignore[union-attr]
    msgs = await got.wait(2)
    assert msgs[-1] == ("oz/bridge/state", b"offline"), msgs
    assert broker.retained("oz/bridge/state") == b"offline"
    await watcher.disconnect()
