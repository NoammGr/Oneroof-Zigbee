from __future__ import annotations

import asyncio
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
    broker._lockouts["127.0.0.1"] -= 31
    c = await connect(broker, "gw", "gwpw")
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
